"""RemotePower — WG Access (WireGuard hub) subsystem: tunnels, clients, the
privileged-helper bridge, and the stats/TTL cadence.

A bound-module carve-out of api.py's request-coupled VPN handlers, following the
same pattern as tickets_handlers / cmdb_handlers / backups_handlers /
provisioning_handlers:

  - api.py execs a PRIVATE instance of this module and binds its own
    ``globals()`` here (see api.py's loader block for why), so every api
    service is reached as ``A.<name>`` — a DYNAMIC attribute lookup, which keeps
    the test suite's monkeypatching of api._wg_run / api._wg_helper_available /
    api.respond working, and resolves identically under the CGI (__main__) and
    imported-module (wsgi.py/scheduler.py) execution models.
  - api.py then from-imports every public and private name back into its own
    globals, so the route tables and every existing caller are untouched.
  - Calls BETWEEN these functions ALSO go through ``A.`` — the VPN tests patch
    api._wg_helper_available / api._wg_run and expect _vpn_sync_tunnel to see
    the patched versions, which only works through the api namespace.

Constants that other code / the tests reference (VPN_FILE, WG_HELPER) STAY in
api.py and are read here through A. as well. The helper-search dirs
(_WG_BIN_DIRS/_WG_SAFE_PATH) and the last-error scratch global (_wg_last_err)
are module-private and NOT re-exported: _wg_last_err is written by _wg_run and
read by handle_vpn_client_create, both here, so it must stay a live global of
THIS module (a re-exported copy in api.py would go stale).

The hub is the RP server HOST itself running wireguard-go (userspace, no kernel
module). Config apply goes through the root-owned ``remotepower-wg-apply`` helper
via scoped sudo (or directly when CAP_NET_ADMIN is held); stats are read on the
run_vpn_stats_if_due() cadence (integrations-style, NOT _host_checks — clients
aren't devices). Pure logic (validation / allocation / spec build / dump parse)
lives in the wg_access sibling module. Client private keys are generated in the
browser and never reach the server; the per-tunnel hub private key is generated
+ held root-only by the helper.
"""
import ipaddress
import json
import os
import secrets
import shutil
import subprocess
import time

import wg_access


class _ApiNamespace:
    __slots__ = ('_g',)

    def __init__(self, g):
        self._g = g

    def __getattr__(self, name):
        try:
            return self._g[name]
        except KeyError:
            raise AttributeError(f'api namespace has no {name!r}') from None


A = None


def bind(api_globals):
    """Called once by api.py right after importing this module, with
    api's ``globals()``."""
    global A
    A = _ApiNamespace(api_globals)


# fcgiwrap hands the CGI a minimal (often empty) PATH, so shutil.which('wg') /
# 'sudo' can return None even though they're installed — which silently made WG
# Access read "unavailable" and refused client creation. Resolve binaries against
# an explicit search path and run the helper with a sane PATH so the CGI behaves
# like the shell.
_WG_BIN_DIRS = ('/usr/bin', '/bin', '/usr/sbin', '/sbin', '/usr/local/bin', '/usr/local/sbin')
_WG_SAFE_PATH = ':'.join(_WG_BIN_DIRS)


def _wg_find(name):
    """Locate a binary by PATH first, then a fixed list of standard dirs (CGI
    PATH is often stripped). Returns the absolute path or None."""
    p = shutil.which(name)
    if p:
        return p
    for d in _WG_BIN_DIRS:
        cand = os.path.join(d, name)
        if os.path.exists(cand):
            return cand
    return None


def _wg_direct() -> bool:
    """Direct mode: invoke the helper WITHOUT sudo because this process already
    holds the needed privilege (CAP_NET_ADMIN granted ambiently in the
    remotepower-wsgi unit). This is the hardening-preserving path — it works
    under NoNewPrivileges=true, where sudo's setuid escalation is blocked. A
    process without that ambient capability (no caps, no sandbox) leaves this
    unset and uses sudo."""
    return str(os.environ.get('RP_WG_DIRECT', '')).strip().lower() in ('1', 'true', 'yes', 'on')


def _vpn_load() -> dict:
    d = A.load(A.VPN_FILE) or {}
    if not isinstance(d, dict):
        d = {}
    if not isinstance(d.get('tunnels'), list):
        d['tunnels'] = []
    return d


def _wg_helper_available() -> bool:
    """True only when WG Access is actually usable: the privileged helper is
    installed AND the WireGuard CLI (`wg`) is on PATH. Either missing → the
    feature degrades to store-only CRUD (no kernel-side apply), so handlers and
    tests still work and the UI shows a precise reason (_wg_unavailable_reason)."""
    if not (os.path.exists(A.WG_HELPER) and A._wg_find('wg') is not None):
        return False
    return A._wg_direct() or A._wg_find('sudo') is not None


def _wg_unavailable_reason() -> str:
    """Precise, actionable reason WG Access can't apply config — surfaced in the
    UI notice. Empty string when everything is present."""
    if not os.path.exists(A.WG_HELPER):
        return ('The privileged helper is not installed. Deploy '
                'remotepower-wg-apply to ' + A.WG_HELPER + ' with its scoped '
                'sudoers rule (the server installer / deploy script does this).')
    if not A._wg_direct() and A._wg_find('sudo') is None:
        return 'sudo was not found on the server — WG Access needs it to run the helper.'
    if A._wg_find('wg') is None:
        return ('The WireGuard CLI is missing. Install it on the host '
                '(apt install wireguard wireguard-tools, or '
                'pacman -S wireguard-tools), then reload.')
    return ''


# Last helper failure (rc/stderr), surfaced in the client-create 400 so an
# operator can see WHY `up` failed (stripped PATH, sudo blocked by a sandboxed
# service's NoNewPrivileges, missing wg, kernel perms) instead of a generic
# "unavailable". Per-request CGI process, so a module global is fine. NOT
# re-exported into api.py — see the module docstring.
_wg_last_err = ''


def _wg_run(args, stdin=None, timeout=20):
    """Invoke the root helper via scoped sudo. Returns (rc, stdout, stderr).
    argv-only (no shell). Never raises. Uses an absolute sudo path and a sane
    PATH env because the CGI's own PATH is often stripped by fcgiwrap (which made
    a bare 'sudo'/helper invocation fail with FileNotFoundError → empty hub key
    → 400 on client create)."""
    global _wg_last_err
    env = dict(os.environ)
    env['PATH'] = (env.get('PATH', '') + ':' + _WG_SAFE_PATH).strip(':')
    if A._wg_direct():
        # We already hold CAP_NET_ADMIN (worker unit) — run the helper directly,
        # no sudo (works under NoNewPrivileges). Keys go to RP_WG_DIR (writable).
        env.setdefault('RP_WG_DIR', str(A.DATA_DIR / 'wg'))
        cmd = [A.WG_HELPER] + list(args)
    else:
        cmd = [A._wg_find('sudo') or 'sudo', '-n', A.WG_HELPER] + list(args)
    try:
        r = subprocess.run(cmd,
                           input=stdin, capture_output=True, text=True,
                           timeout=timeout, env=env)
        if r.returncode != 0:
            _wg_last_err = (f'{" ".join(str(a) for a in args)}: rc={r.returncode} '
                            f'{(r.stderr or r.stdout or "").strip()}')[:300]
        return r.returncode, r.stdout, r.stderr
    except Exception as e:                       # nosec B603 — argv list, no shell
        _wg_last_err = (f'{" ".join(str(a) for a in args)}: {e}')[:300]
        return 127, '', str(e)


def _vpn_parse_expiry(v):
    """Absolute unix-ts expiry (the browser turns the number+unit UI into a ts)
    or None. Validates it is in the future. respond()s 400 on a bad value."""
    if v in (None, '', 0):
        return None
    try:
        v = int(v)
    except (TypeError, ValueError):
        A.respond(400, {'error': 'invalid expires_at'})
    if v <= int(time.time()):
        A.respond(400, {'error': 'expires_at must be in the future'})
    return v


def _vpn_expired(rec, now) -> bool:
    ex = rec.get('expires_at')
    return bool(ex and now >= int(ex))


def _vpn_reach_devices(tunnel) -> list:
    """The in-scope fleet devices a tunnel's clients may reach (those with a
    usable IP), as [{id, name, ip}]. Reuses the RBAC device-scope matcher. Empty
    for dashboard-only ('none'). 'all' = every device with a known IP."""
    st = (tunnel.get('reach_scope_type') or 'none').strip().lower()
    if st in ('', 'none'):
        return []
    devices = A.load(A.DEVICES_FILE) or {}
    if st == 'all':
        scope = {'type': 'all'}
    else:
        rbac_type = {'site': 'sites', 'group': 'groups', 'tag': 'tags'}.get(st)
        if not rbac_type:
            return []
        scope = {'type': rbac_type, 'values': [tunnel.get('reach_scope_value')]}
    out = []
    for did, d in devices.items():
        if not isinstance(d, dict):
            continue
        if st != 'all' and not A._device_in_scope(scope, d):
            continue
        ip = d.get('ip')
        if ip and wg_access.valid_host_ip(ip):
            out.append({'id': did, 'name': d.get('hostname') or d.get('name') or did,
                        'ip': str(ip)})
    return out


def _vpn_reach_cidrs(tunnel) -> list:
    """The fleet device /32s a tunnel's clients may reach, from its reach scope.
    Empty for dashboard-only. 'all' = every device with a known IP."""
    return sorted({d['ip'] + '/32' for d in A._vpn_reach_devices(tunnel)})


def _vpn_up_tunnel(tunnel) -> dict:
    """Bring the interface up + capture the hub pubkey from the helper. No-op
    (returns unchanged) when the helper is absent."""
    if not A._wg_helper_available():
        return tunnel
    rc, out, _err = A._wg_run(['up', tunnel['iface']])
    if rc == 0:
        try:
            d = json.loads(out or '{}')
            if wg_access.valid_pubkey(d.get('pubkey')):
                tunnel['hub_pubkey'] = d['pubkey']
        except Exception:
            pass
    return tunnel


def _vpn_sync_tunnel(tunnel) -> bool:
    """Push the tunnel's enabled, non-expired clients + reach policy to the hub.
    No-op when the helper is absent. A DISABLED tunnel is torn down (iface down)
    rather than synced — otherwise an admin who disables a tunnel to cut off
    road-warrior access would have the interface silently brought back up and
    every client re-installed."""
    if not A._wg_helper_available():
        return False
    if not tunnel.get('enabled', True):
        A._wg_run(['down', tunnel['iface']])
        return True
    now = int(time.time())
    clients = [c for c in tunnel.get('clients', [])
               if c.get('enabled', True) and not A._vpn_expired(c, now)]
    spec = wg_access.build_sync_spec(tunnel, clients, A._vpn_reach_cidrs(tunnel))
    rc, _out, _err = A._wg_run(['sync', tunnel['iface']], stdin=json.dumps(spec))
    return rc == 0


def _vpn_resync(tid) -> None:
    """Reload + re-sync one tunnel by id (after a store mutation)."""
    t = next((x for x in A._vpn_load()['tunnels'] if x.get('id') == tid), None)
    if t:
        A._vpn_sync_tunnel(t)


def _vpn_ensure_hub_key(tid) -> str:
    """Backfill a tunnel's hub public key when missing. A tunnel created BEFORE
    the helper was installed has hub_pubkey='' (up was a no-op), which would emit
    a client config with an empty PublicKey (WireGuard rejects it). Once the
    helper is available, bring the interface up to generate/capture the key and
    persist it. Returns the hub pubkey ('' if still unavailable). Runs subprocess
    OUTSIDE any VPN_FILE lock."""
    t = next((x for x in A._vpn_load()['tunnels'] if x.get('id') == tid), None)
    if not t:
        return ''
    if t.get('hub_pubkey'):
        return t['hub_pubkey']
    if not A._wg_helper_available():
        return ''
    t = A._vpn_up_tunnel(t)               # runs `up`, may set hub_pubkey
    pub = t.get('hub_pubkey', '')
    if pub:
        with A._LockedUpdate(A.VPN_FILE) as store:
            for x in store.get('tunnels', []):
                if x.get('id') == tid:
                    x['hub_pubkey'] = pub
    return pub


def _vpn_evt_payload(t, c) -> dict:
    return {'client_id': c.get('id'), 'client_name': c.get('name', ''),
            'tunnel_id': t.get('id'), 'tunnel_name': t.get('name', ''),
            'endpoint': c.get('endpoint', '')}


def _vpn_client_meta(c, now) -> dict:
    return {
        'id':             c.get('id'),
        'name':           c.get('name', ''),
        'address':        c.get('address', ''),
        'enabled':        c.get('enabled', True),
        'expires_at':     c.get('expires_at'),
        'created_by':     c.get('created_by', ''),
        'created_at':     c.get('created_at', 0),
        'last_handshake': c.get('last_handshake', 0),
        'rx_bytes':       c.get('rx_bytes', 0),
        'tx_bytes':       c.get('tx_bytes', 0),
        'endpoint':       c.get('endpoint', ''),
        'status':         wg_access.client_status(c.get('last_handshake', 0), now),
    }


def _vpn_tunnel_meta(t, now=None, with_clients=False) -> dict:
    now = now or int(time.time())
    clients = t.get('clients', [])
    connected = sum(1 for c in clients
                    if wg_access.client_status(c.get('last_handshake', 0), now) == 'connected')
    m = {
        'id':                t.get('id'),
        'name':              t.get('name', ''),
        'iface':             t.get('iface', ''),
        'listen_port':       t.get('listen_port', 0),
        'pool':              t.get('pool', ''),
        'endpoint':          t.get('endpoint', ''),
        'dns':               t.get('dns', ''),
        'hub_pubkey':        t.get('hub_pubkey', ''),
        'allow_internet':    bool(t.get('allow_internet')),
        'reach_scope_type':  t.get('reach_scope_type', 'none'),
        'reach_scope_value': t.get('reach_scope_value', ''),
        'enabled':           t.get('enabled', True),
        'expires_at':        t.get('expires_at'),
        'created_by':        t.get('created_by', ''),
        'created_at':        t.get('created_at', 0),
        'client_count':      len(clients),
        'connected_count':   connected,
    }
    if with_clients:
        m['clients'] = [A._vpn_client_meta(c, now) for c in clients]
    return m


# ── Tunnel handlers ─────────────────────────────────────────────────────────────
def handle_vpn_tunnels_list() -> None:
    """GET /api/vpn-tunnels — all tunnels with a client/connected rollup."""
    A.require_admin_or_auditor_auth()
    now = int(time.time())
    store = A._vpn_load()
    A.respond(200, {'ok': True,
                    'available': A._wg_helper_available(),
                    'reason': A._wg_unavailable_reason(),
                    'tunnels': [A._vpn_tunnel_meta(t, now) for t in store['tunnels']]})


def handle_vpn_default_template() -> None:
    """GET/POST /api/vpn-default-template — master-improvement-scoping #88.
    A saved default (allow_internet/reach_scope/dns) the tunnel-create form
    pre-fills from, so an admin creating the Nth tunnel with the same common
    settings doesn't retype them every time. Same validation as
    handle_vpn_tunnel_create's equivalent fields (kept in sync deliberately —
    a template accepting a value the real create endpoint would reject
    would be worse than no template). Purely a UI convenience: creating a
    tunnel still requires an explicit request: it inherits nothing
    automatically server-side."""
    if A.method() == 'GET':
        A.require_admin_or_auditor_auth()
        tmpl = (A.load(A.CONFIG_FILE) or {}).get('vpn_default_template') or {}
        A.respond(200, {'ok': True, 'template': tmpl})
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A.get_json_obj()
    allow_internet = bool(body.get('allow_internet'))
    rst = str(body.get('reach_scope_type', 'none')).strip().lower() or 'none'
    if rst not in ('none', 'all', 'site', 'group', 'tag'):
        A.respond(400, {'error': 'invalid reach_scope_type'})
    rsv = A._sanitize_str(body.get('reach_scope_value', ''), 128) if rst in ('site', 'group', 'tag') else ''
    if rst in ('site', 'group', 'tag') and not rsv:
        A.respond(400, {'error': 'reach_scope_value required'})
    dns = A._sanitize_str(body.get('dns', ''), 45)
    if dns and not wg_access.valid_host_ip(dns):
        A.respond(400, {'error': 'dns must be an IP address'})
    tmpl = {'allow_internet': allow_internet, 'reach_scope_type': rst,
            'reach_scope_value': rsv, 'dns': dns}
    cfg = A.load(A.CONFIG_FILE) or {}
    cfg['vpn_default_template'] = tmpl
    A.save(A.CONFIG_FILE, cfg)
    A.audit_log(actor, 'vpn_default_template_set',
                detail=f'internet={allow_internet} scope={rst}:{rsv}', source_ip=A._get_client_ip())
    A.respond(200, {'ok': True, 'template': tmpl})


def handle_vpn_tunnel_create() -> None:
    """POST /api/vpn-tunnels — create a tunnel (allocate iface/port/pool, bring
    the interface up, sync). Admin only."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A.get_json_obj()
    name = A._sanitize_str(body.get('name', ''), wg_access.MAX_NAME_LEN, allow_empty=False)
    if not wg_access.valid_name(name):
        A.respond(400, {'error': 'invalid tunnel name'})
    allow_internet = bool(body.get('allow_internet'))
    rst = str(body.get('reach_scope_type', 'none')).strip().lower() or 'none'
    if rst not in ('none', 'all', 'site', 'group', 'tag'):
        A.respond(400, {'error': 'invalid reach_scope_type'})
    rsv = A._sanitize_str(body.get('reach_scope_value', ''), 128) if rst in ('site', 'group', 'tag') else ''
    if rst in ('site', 'group', 'tag') and not rsv:
        A.respond(400, {'error': 'reach_scope_value required'})
    dns = A._sanitize_str(body.get('dns', ''), 45)
    if dns and not wg_access.valid_host_ip(dns):
        A.respond(400, {'error': 'dns must be an IP address'})
    expires_at = A._vpn_parse_expiry(body.get('expires_at'))
    cfg = A.load(A.CONFIG_FILE) or {}
    pool_base = cfg.get('vpn_pool_base', wg_access.POOL_BASE)
    port_base = int(cfg.get('vpn_port_base', wg_access.PORT_BASE) or wg_access.PORT_BASE)
    endpoint_host = (cfg.get('vpn_endpoint_host', '') or
                     A._env('HTTP_HOST', '').split(':')[0] or 'CHANGE-ME')
    tid = 'wgt_' + secrets.token_hex(8)
    try:
        with A._LockedUpdate(A.VPN_FILE) as store:
            tunnels = store.setdefault('tunnels', [])
            if len(tunnels) >= wg_access.MAX_TUNNELS:
                A.respond(400, {'error': f'max {wg_access.MAX_TUNNELS} tunnels'})
            iface = wg_access.next_iface([t.get('iface') for t in tunnels])
            port = wg_access.next_port([t.get('listen_port') for t in tunnels], base=port_base)
            pool = wg_access.next_pool([t.get('pool') for t in tunnels], base=pool_base)
            tunnel = {
                'id': tid, 'name': name, 'iface': iface, 'listen_port': port,
                'pool': pool, 'endpoint': f'{endpoint_host}:{port}', 'dns': dns,
                'hub_pubkey': '', 'allow_internet': allow_internet,
                'reach_scope_type': rst, 'reach_scope_value': rsv,
                'enabled': True, 'expires_at': expires_at,
                'created_by': actor, 'created_at': int(time.time()), 'clients': [],
            }
            tunnels.append(tunnel)
    except ValueError as e:
        A.respond(400, {'error': str(e)})
    # Kernel-side apply + hub-key capture happen OUTSIDE the lock (subprocess).
    tunnel = A._vpn_up_tunnel(tunnel)
    A._vpn_sync_tunnel(tunnel)
    if tunnel.get('hub_pubkey'):
        with A._LockedUpdate(A.VPN_FILE) as store:
            for t in store.get('tunnels', []):
                if t.get('id') == tid:
                    t['hub_pubkey'] = tunnel['hub_pubkey']
    A.audit_log(actor, 'vpn_tunnel_create',
                detail=f'tunnel={tid} name={name[:40]} iface={iface} internet={allow_internet} scope={rst}:{rsv}',
                source_ip=A._get_client_ip())
    A.respond(200, {'ok': True, 'id': tid, 'tunnel': A._vpn_tunnel_meta(tunnel)})


def handle_vpn_tunnel_update(tid) -> None:
    """PATCH /api/vpn-tunnels/{id} — edit name/internet/scope/dns/expiry/enabled.
    iface/port/pool/hub_pubkey are immutable. Admin only."""
    actor = A.require_admin_auth()
    if A.method() != 'PATCH':
        A.respond(405, {'error': 'Method not allowed'})
    if not tid.startswith('wgt_') or not A._validate_id(tid[len('wgt_'):]):
        A.respond(404, {'error': 'tunnel not found'})
    body = A.get_json_obj()
    with A._LockedUpdate(A.VPN_FILE) as store:
        t = next((x for x in store.get('tunnels', []) if x.get('id') == tid), None)
        if not t:
            A.respond(404, {'error': 'tunnel not found'})
        if 'name' in body:
            nm = A._sanitize_str(body.get('name', ''), wg_access.MAX_NAME_LEN, allow_empty=False)
            if not wg_access.valid_name(nm):
                A.respond(400, {'error': 'invalid tunnel name'})
            t['name'] = nm
        if 'allow_internet' in body:
            t['allow_internet'] = bool(body.get('allow_internet'))
        if 'reach_scope_type' in body:
            rst = str(body.get('reach_scope_type', 'none')).strip().lower() or 'none'
            if rst not in ('none', 'all', 'site', 'group', 'tag'):
                A.respond(400, {'error': 'invalid reach_scope_type'})
            t['reach_scope_type'] = rst
            if rst in ('none', 'all'):
                t['reach_scope_value'] = ''
        if 'reach_scope_value' in body:
            t['reach_scope_value'] = A._sanitize_str(body.get('reach_scope_value', ''), 128)
        if t.get('reach_scope_type') in ('site', 'group', 'tag') and not t.get('reach_scope_value'):
            A.respond(400, {'error': 'reach_scope_value required for this scope'})
        if 'dns' in body:
            dns = A._sanitize_str(body.get('dns', ''), 45)
            if dns and not wg_access.valid_host_ip(dns):
                A.respond(400, {'error': 'dns must be an IP address'})
            t['dns'] = dns
        if 'expires_at' in body:
            t['expires_at'] = A._vpn_parse_expiry(body.get('expires_at'))
        if 'enabled' in body:
            t['enabled'] = bool(body.get('enabled'))
    A._vpn_resync(tid)
    A.audit_log(actor, 'vpn_tunnel_update', detail=f'tunnel={tid}', source_ip=A._get_client_ip())
    A.respond(200, {'ok': True})


def handle_vpn_tunnel_delete(tid) -> None:
    """DELETE /api/vpn-tunnels/{id} — tear down the interface + delete the tunnel
    and ALL its clients (cascade). Admin only."""
    actor = A.require_admin_auth()
    if A.method() != 'DELETE':
        A.respond(405, {'error': 'Method not allowed'})
    if not tid.startswith('wgt_') or not A._validate_id(tid[len('wgt_'):]):
        A.respond(404, {'error': 'tunnel not found'})
    iface = None
    with A._LockedUpdate(A.VPN_FILE) as store:
        tunnels = store.get('tunnels', [])
        t = next((x for x in tunnels if x.get('id') == tid), None)
        if not t:
            A.respond(404, {'error': 'tunnel not found'})
        iface = t.get('iface')
        store['tunnels'] = [x for x in tunnels if x.get('id') != tid]
    if iface and A._wg_helper_available():
        A._wg_run(['down', iface])
    A.audit_log(actor, 'vpn_tunnel_delete', detail=f'tunnel={tid} iface={iface}',
                source_ip=A._get_client_ip())
    A.respond(200, {'ok': True})


def handle_vpn_tunnel_stats(tid) -> None:
    """GET /api/vpn-tunnels/{id}/stats — RP-host rollup for one tunnel."""
    A.require_admin_or_auditor_auth()
    now = int(time.time())
    t = next((x for x in A._vpn_load()['tunnels'] if x.get('id') == tid), None)
    if not t:
        A.respond(404, {'error': 'tunnel not found'})
    clients = t.get('clients', [])
    rx = sum(int(c.get('rx_bytes', 0) or 0) for c in clients)
    tx = sum(int(c.get('tx_bytes', 0) or 0) for c in clients)
    hs = [int(c.get('last_handshake', 0) or 0) for c in clients if c.get('last_handshake')]
    net = None
    try:
        net = ipaddress.ip_network(t.get('pool', ''), strict=False)
    except ValueError:
        pass
    pool_size = (net.num_addresses - 2) if net else 0
    # What this tunnel's clients can actually reach right now (resolved live from
    # the current fleet, so it reflects devices added/changed since last sync).
    reach_devices = A._vpn_reach_devices(t)
    A.respond(200, {'ok': True, 'available': A._wg_helper_available(),
                    'stats': {
                        'iface': t.get('iface'), 'listen_port': t.get('listen_port'),
                        'enabled': t.get('enabled', True),
                        'allow_internet': bool(t.get('allow_internet')),
                        'reach_scope_type': t.get('reach_scope_type', 'none'),
                        'reach_scope_value': t.get('reach_scope_value', ''),
                        'reach_count': len(reach_devices),
                        'reach_devices': reach_devices[:200],
                        'client_count': len(clients),
                        'connected_count': sum(1 for c in clients if wg_access.client_status(c.get('last_handshake', 0), now) == 'connected'),
                        'pool_used': len(clients), 'pool_size': pool_size,
                        'rx_bytes': rx, 'tx_bytes': tx,
                        'newest_handshake': max(hs) if hs else 0,
                        'oldest_handshake': min(hs) if hs else 0,
                    }})


# ── Client handlers ─────────────────────────────────────────────────────────────
def _vpn_require_tunnel(store, tid):
    if not tid.startswith('wgt_') or not A._validate_id(tid[len('wgt_'):]):
        A.respond(404, {'error': 'tunnel not found'})
    t = next((x for x in store.get('tunnels', []) if x.get('id') == tid), None)
    if not t:
        A.respond(404, {'error': 'tunnel not found'})
    return t


def handle_vpn_clients_list(tid) -> None:
    """GET /api/vpn-tunnels/{id}/clients — the tunnel's clients (no secrets)."""
    A.require_admin_or_auditor_auth()
    now = int(time.time())
    t = A._vpn_require_tunnel(A._vpn_load(), tid)
    A.respond(200, {'ok': True, 'clients': [A._vpn_client_meta(c, now) for c in t.get('clients', [])]})


def handle_vpn_client_create(tid) -> None:
    """POST /api/vpn-tunnels/{id}/clients — add a client. The browser generated
    the keypair and sends only the pubkey; we allocate a /32, sync, and return
    the params the browser needs to assemble the config + QR. Admin only."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A.get_json_obj()
    name = A._sanitize_str(body.get('name', ''), wg_access.MAX_NAME_LEN, allow_empty=False)
    if not wg_access.valid_name(name):
        A.respond(400, {'error': 'invalid client name'})
    pubkey = str(body.get('pubkey', '')).strip()
    if not wg_access.valid_pubkey(pubkey):
        A.respond(400, {'error': 'invalid public key'})
    expires_at = A._vpn_parse_expiry(body.get('expires_at'))
    cid = 'wgc_' + secrets.token_hex(8)
    # Backfill the hub key for tunnels created before the helper was installed
    # (runs `up` outside the lock). Without it the client config would carry an
    # empty PublicKey and WireGuard would reject it with a syntax error.
    A._vpn_ensure_hub_key(tid)
    with A._LockedUpdate(A.VPN_FILE) as store:
        t = A._vpn_require_tunnel(store, tid)
        if not t.get('hub_pubkey'):
            detail = (' Helper error: ' + _wg_last_err) if _wg_last_err else (
                ' ' + A._wg_unavailable_reason())
            A.respond(400, {'error': 'This tunnel has no hub key yet — the WireGuard '
                            'helper could not initialize the interface on the server.'
                            + detail})
        clients = t.setdefault('clients', [])
        if len(clients) >= wg_access.MAX_CLIENTS_PER_TUNNEL:
            A.respond(400, {'error': f'max {wg_access.MAX_CLIENTS_PER_TUNNEL} clients per tunnel'})
        if any(c.get('pubkey') == pubkey for c in clients):
            A.respond(400, {'error': 'a client with that public key already exists'})
        try:
            addr = wg_access.alloc_client_ip(t.get('pool', ''), [c.get('address') for c in clients])
        except ValueError as e:
            A.respond(400, {'error': str(e)})
        client = {'id': cid, 'name': name, 'pubkey': pubkey, 'address': addr,
                  'enabled': True, 'expires_at': expires_at, 'created_by': actor,
                  'created_at': int(time.time()), 'last_handshake': 0,
                  'rx_bytes': 0, 'tx_bytes': 0, 'endpoint': ''}
        clients.append(client)
        tunnel_meta = {'hub_pubkey': t.get('hub_pubkey', ''), 'endpoint': t.get('endpoint', ''),
                       'dns': t.get('dns', ''),
                       'allowed_ips': wg_access.client_allowed_ips(t, A._vpn_reach_cidrs(t))}
    A._vpn_resync(tid)
    A.audit_log(actor, 'vpn_client_create', detail=f'client={cid} tunnel={tid} name={name[:40]}',
                source_ip=A._get_client_ip())
    # Return everything the browser needs to build the .conf + QR (it holds the
    # private key already; the server never sees it).
    A.respond(200, {'ok': True, 'id': cid, 'address': addr + '/32',
                    'hub_pubkey': tunnel_meta['hub_pubkey'], 'endpoint': tunnel_meta['endpoint'],
                    'dns': tunnel_meta['dns'], 'allowed_ips': tunnel_meta['allowed_ips']})


def handle_vpn_client_update(tid, cid) -> None:
    """PATCH /api/vpn-tunnels/{id}/clients/{cid} — edit name/expiry/enabled.
    pubkey + address immutable. Admin only."""
    actor = A.require_admin_auth()
    if A.method() != 'PATCH':
        A.respond(405, {'error': 'Method not allowed'})
    if not cid.startswith('wgc_') or not A._validate_id(cid[len('wgc_'):]):
        A.respond(404, {'error': 'client not found'})
    body = A.get_json_obj()
    with A._LockedUpdate(A.VPN_FILE) as store:
        t = A._vpn_require_tunnel(store, tid)
        c = next((x for x in t.get('clients', []) if x.get('id') == cid), None)
        if not c:
            A.respond(404, {'error': 'client not found'})
        if 'name' in body:
            nm = A._sanitize_str(body.get('name', ''), wg_access.MAX_NAME_LEN, allow_empty=False)
            if not wg_access.valid_name(nm):
                A.respond(400, {'error': 'invalid client name'})
            c['name'] = nm
        if 'expires_at' in body:
            c['expires_at'] = A._vpn_parse_expiry(body.get('expires_at'))
        if 'enabled' in body:
            c['enabled'] = bool(body.get('enabled'))
    A._vpn_resync(tid)
    A.audit_log(actor, 'vpn_client_update', detail=f'client={cid} tunnel={tid}',
                source_ip=A._get_client_ip())
    A.respond(200, {'ok': True})


def handle_vpn_client_delete(tid, cid) -> None:
    """DELETE /api/vpn-tunnels/{id}/clients/{cid} — remove a client + re-sync
    (instant peer removal). Admin only."""
    actor = A.require_admin_auth()
    if A.method() != 'DELETE':
        A.respond(405, {'error': 'Method not allowed'})
    if not cid.startswith('wgc_') or not A._validate_id(cid[len('wgc_'):]):
        A.respond(404, {'error': 'client not found'})
    with A._LockedUpdate(A.VPN_FILE) as store:
        t = A._vpn_require_tunnel(store, tid)
        clients = t.get('clients', [])
        before = len(clients)
        t['clients'] = [x for x in clients if x.get('id') != cid]
        if len(t['clients']) == before:
            A.respond(404, {'error': 'client not found'})
    A._vpn_resync(tid)
    A.audit_log(actor, 'vpn_client_delete', detail=f'client={cid} tunnel={tid}',
                source_ip=A._get_client_ip())
    A.respond(200, {'ok': True})


def handle_vpn_client_stats(tid, cid) -> None:
    """GET /api/vpn-tunnels/{id}/clients/{cid}/stats — one peer's live stats."""
    A.require_admin_or_auditor_auth()
    now = int(time.time())
    t = A._vpn_require_tunnel(A._vpn_load(), tid)
    c = next((x for x in t.get('clients', []) if x.get('id') == cid), None)
    if not c:
        A.respond(404, {'error': 'client not found'})
    A.respond(200, {'ok': True, 'stats': A._vpn_client_meta(c, now)})


def handle_vpn_client_history(tid, cid) -> None:
    """GET /api/vpn-tunnels/{id}/clients/{cid}/history — per-peer RX/TX
    time-series (master-improvement-scoping #87). Samples are appended by
    run_vpn_stats_if_due() on its normal poll cadence, capped to
    VPN_STATS_HIST_MAX_SAMPLES (~24h at the default 120s interval) — a
    rolling window, not unbounded growth. Confirms the client actually
    exists (same 404 shape as /stats) before returning its history, even
    though the history itself lives in a separate keyed-by-id file, so a
    stale/foreign cid can't be probed for a tunnel it doesn't belong to."""
    A.require_admin_or_auditor_auth()
    t = A._vpn_require_tunnel(A._vpn_load(), tid)
    c = next((x for x in t.get('clients', []) if x.get('id') == cid), None)
    if not c:
        A.respond(404, {'error': 'client not found'})
    hist = (A.load(A.VPN_STATS_HIST_FILE) or {}).get(cid) or []
    A.respond(200, {'ok': True, 'samples': hist})


# ── Stats cadence + TTL reaper ──────────────────────────────────────────────────
def run_vpn_stats_if_due():
    """Refresh per-client WireGuard stats, fire connect/disconnect/stale edge
    events, and reap expired clients + tunnels. Integrations-style cadence (cheap
    when not due). Tunnel expiry is audit-log only (no event, per design);
    client transitions fire the registered events AFTER the lock."""
    if not A.backend_exists(A.VPN_FILE):
        return
    _ro = A._config_ro()   # v5.8.0 (PERF): not-due gate without the load() deepcopy
    interval = max(60, int(_ro.get('vpn_stats_interval', 120) or 120))
    last = int(_ro.get('last_vpn_stats_run', 0) or 0)
    now = int(time.time())
    if (now - last) < interval:
        return
    cfg = A.load(A.CONFIG_FILE) or {}
    cfg['last_vpn_stats_run'] = now
    A.save(A.CONFIG_FILE, cfg)
    store = A._vpn_load()
    if not store['tunnels']:
        return
    helper = A._wg_helper_available()
    # Read stats per tunnel BEFORE taking the lock (subprocess).
    dumps = {}
    # Re-resolve each fleet-scoped tunnel's reach from the CURRENT fleet so scope
    # tracks devices added / re-IP'd / re-tagged since the last sync. Computed
    # outside the lock (reads DEVICES_FILE); a tunnel whose resolved reach has
    # drifted from its last-synced set is re-synced after the lock. Full-tunnel
    # (internet) and dashboard-only tunnels don't depend on reach → skipped.
    reach_now = {}
    if helper:
        for t in store['tunnels']:
            if not t.get('enabled', True):
                continue
            rc, out, _err = A._wg_run(['show', t['iface']])
            if rc == 0 and (out or '').strip():
                dumps[t['iface']] = wg_access.parse_wg_dump(out)
            if (not t.get('allow_internet')
                    and (t.get('reach_scope_type') or 'none') not in ('none', '')):
                reach_now[t['id']] = A._vpn_reach_cidrs(t)
    pending_audit = []      # (action, detail)
    pending_events = []     # (event, payload)
    ifaces_down = []        # expired tunnels to tear down
    resync_tids = []        # tunnels whose client set shrank
    hist_samples = []       # (cid, {ts, rx_bytes, tx_bytes}) -- master-improvement-scoping #87
    with A._LockedUpdate(A.VPN_FILE) as st:
        keep = []
        for t in st.get('tunnels', []):
            # Tunnel TTL → tear down + drop (audit only, no event).
            if A._vpn_expired(t, now):
                pending_audit.append(('vpn_tunnel_expired',
                                      f"tunnel={t.get('id')} name={t.get('name','')[:40]} iface={t.get('iface')}"))
                if t.get('iface'):
                    ifaces_down.append(t['iface'])
                continue
            # Client TTL → drop (re-sync after).
            orig = t.get('clients', [])
            survivors = []
            for c in orig:
                if A._vpn_expired(c, now):
                    pending_audit.append(('vpn_client_expired',
                                          f"client={c.get('id')} tunnel={t.get('id')}"))
                    continue
                survivors.append(c)
            if len(survivors) != len(orig):
                t['clients'] = survivors
                resync_tids.append(t.get('id'))
            # Stats + edge events.
            dump = dumps.get(t.get('iface'), {})
            for c in t.get('clients', []):
                d = dump.get(c.get('pubkey'))
                if d:
                    c['last_handshake'] = d['last_handshake']
                    c['rx_bytes'] = d['rx_bytes']
                    c['tx_bytes'] = d['tx_bytes']
                    c['endpoint'] = d['endpoint']
                    # #87: one history sample per live-dump match this poll
                    # (skipped only when the peer isn't in the dump at all --
                    # not yet synced, or a parse miss -- not merely idle).
                    hist_samples.append((c.get('id'), {
                        'ts': now, 'rx_bytes': d['rx_bytes'], 'tx_bytes': d['tx_bytes']}))
                status = wg_access.client_status(c.get('last_handshake', 0), now)
                prev = c.get('_status')
                if prev is None:
                    c['_status'] = status          # seed silently on first sight
                elif status != prev:
                    if status == 'connected':
                        pending_events.append(('vpn_client_connected', A._vpn_evt_payload(t, c)))
                    elif status == 'idle' and prev == 'connected':
                        pending_events.append(('vpn_handshake_stale', A._vpn_evt_payload(t, c)))
                    elif status == 'offline':
                        pending_events.append(('vpn_client_disconnected', A._vpn_evt_payload(t, c)))
                    c['_status'] = status
            # Reach drift → re-sync so the hub nft rules track the fleet.
            rid = t.get('id')
            if rid in reach_now and reach_now[rid] != (t.get('_synced_reach') or []):
                t['_synced_reach'] = reach_now[rid]
                if rid not in resync_tids:
                    resync_tids.append(rid)
            keep.append(t)
        st['tunnels'] = keep
    # AFTER the lock: tear down expired tunnels, re-sync shrunk ones, fire
    # events + audit (all self-locking → must be outside the VPN_FILE lock).
    if helper:
        for iface in ifaces_down:
            A._wg_run(['down', iface])
        for tid in resync_tids:
            A._vpn_resync(tid)
    for action, detail in pending_audit:
        A.audit_log('system', action, detail=detail)
    for event, payload in pending_events:
        A.fire_webhook(event, payload)
    # #87: persist this poll's samples under VPN_STATS_HIST_FILE's OWN lock,
    # never nested inside the VPN_FILE lock above (SQLite/Postgres backend
    # would nest a second BEGIN IMMEDIATE on a different file and raise).
    if hist_samples:
        with A._LockedUpdate(A.VPN_STATS_HIST_FILE) as hist:
            for cid, sample in hist_samples:
                bucket = hist.setdefault(cid, [])
                bucket.append(sample)
                del bucket[:-A.VPN_STATS_HIST_MAX_SAMPLES]
