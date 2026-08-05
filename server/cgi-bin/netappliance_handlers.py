"""RemotePower — network-appliance management for MikroTik RouterOS and
OPNsense firewalls (per-device opt-in REST integrations): redacted config +
live overview, firewall/NAT + QoS + traffic detail, and the admin-only,
audited management actions.

Both mirror the same plumbing: a per-device config block (creds + port), an
SSRF pre-flight on the appliance host (allow_loopback=False — these handlers are
reachable by any authenticated user and the REST clients are an internal-TCP
oracle otherwise), and a generic action allow-list. The REST clients live in the
routeros.py / opnsense.py siblings (imported directly, per-call).

A bound-module carve-out following the dmarc/acme/apps_compose pattern: api.py
execs a PRIVATE instance, binds its own ``globals()`` here (every api service
reached as ``A.<name>`` — a dynamic lookup that keeps the suite's monkeypatching
+ inspect.getsource assertions working), then re-imports the names back so the
route table and the cadence caller of _routeros_target
(run_routeros_update_check_if_due, which stays in api.py) resolve unchanged.
DEVICES_FILE stays in api.py, read via A. All handlers live under
/api/devices/<id>/… so main()'s _enforce_device_scope covers their tenancy/scope;
the writes are admin-gated + audited.
"""
import time
import urllib.parse


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


def _routeros_target(dev):
    """(host:port, user, password, verify) for a RouterOS-enabled device, or
    None. Host comes from the device's ip/hostname; creds + port live in the
    device's `routeros` config block."""
    cfg = dev.get('routeros') or {}
    if not cfg.get('enabled'):
        return None
    host = dev.get('ip') or dev.get('hostname') or dev.get('host')
    user = cfg.get('username') or ''
    password = cfg.get('password') or ''
    if not host or not user:
        return None
    port = int(cfg.get('port') or 443)
    # v4.4.0 (SECURITY): SSRF pre-flight on the RouterOS REST host. These
    # handlers are reachable by any authenticated user (incl. viewer), and the
    # module fetched https://{host}/rest with no anti-rebinding check. Block
    # loopback + link-local/cloud-metadata (allow_loopback=False) while still
    # permitting the RFC1918 LAN address a real router lives on.
    if A._url_targets_local_or_meta(urllib.parse.urlparse(f'https://{host}'),
                                    allow_loopback=False):
        return None
    return (f'{host}:{port}', user, password, bool(cfg.get('verify', False)))


def _routeros_redacted(dev):
    cfg = dev.get('routeros') or {}
    return {
        'enabled':      bool(cfg.get('enabled')),
        'username':     cfg.get('username') or '',
        'has_password': bool(cfg.get('password')),
        'port':         int(cfg.get('port') or 443),
        'verify':       bool(cfg.get('verify', False)),
    }


def handle_device_routeros(dev_id):
    """GET /api/devices/<id>/routeros — redacted config + (if enabled) a live
    RouterOS REST overview. PATCH — admin; save {enabled, username, password,
    port, verify} (empty password preserves the stored one). v7+ REST."""
    if not A._validate_id(dev_id):
        A.respond(400, {'error': 'invalid device id'})
    devs = A.load(A.DEVICES_FILE)
    if dev_id not in devs:
        A.respond(404, {'error': 'device not found'})
    m = A.method()
    if m == 'GET':
        A.require_auth()
        dev = devs[dev_id]
        redacted = A._routeros_redacted(dev)
        tgt = A._routeros_target(dev)
        if not tgt:
            A.respond(200, {'config': redacted, 'overview': None})
        host, user, password, verify = tgt
        import routeros as routeros_mod
        ov, err = None, None
        try:
            ov = routeros_mod.overview(host, user, password, verify=verify)
        except Exception as e:
            err = str(e)[:200]
        resp = {'config': redacted, 'overview': ov}
        if err:
            resp['error'] = err
        A.respond(200, resp)
    elif m == 'PATCH':
        actor = A.require_admin_auth()
        body = A._read_valid(A.request_models.DeviceRouterosRequest)
        with A._LockedUpdate(A.DEVICES_FILE) as store:
            dev = store.get(dev_id) or {}
            rc = dict(dev.get('routeros') or {})
            if 'enabled' in body:
                rc['enabled'] = bool(body['enabled'])
            if 'username' in body:
                rc['username'] = A._sanitize_str(str(body['username']), 64)
            if 'password' in body:
                pw = str(body['password'])
                if pw:                       # empty preserves existing
                    rc['password'] = pw[:128]
            if 'port' in body:
                try:
                    p = int(body['port'])
                    if 1 <= p <= 65535:
                        rc['port'] = p
                except (TypeError, ValueError):
                    A.respond(400, {'error': 'port must be 1..65535'})
            if 'verify' in body:
                rc['verify'] = bool(body['verify'])
            if rc.get('enabled') and not rc.get('username'):
                A.respond(400, {'error': 'username required when RouterOS is enabled'})
            if rc.get('enabled') and not rc.get('password'):
                A.respond(400, {'error': 'password required when RouterOS is enabled'})
            dev['routeros'] = rc
            store[dev_id] = dev
        A.audit_log(actor, 'device_routeros_config',
                    f'dev={dev_id} enabled={rc.get("enabled")} user={rc.get("username")}')
        A.respond(200, {'ok': True, 'config': A._routeros_redacted({'routeros': rc})})
    else:
        A.respond(405, {'error': 'Method not allowed'})


def handle_device_routeros_firewall(dev_id):
    """GET /api/devices/<id>/routeros/firewall — filter + NAT rules detail."""
    A.require_auth()
    dev = A.device_get(dev_id)
    if not dev:
        A.respond(404, {'error': 'device not found'})
    tgt = A._routeros_target(dev)
    if not tgt:
        A.respond(200, {'filter': [], 'nat': [], 'enabled': False})
    host, user, password, verify = tgt
    import routeros as routeros_mod
    try:
        fw = routeros_mod.firewall(host, user, password, verify=verify)
    except Exception as e:
        A.respond(502, {'error': str(e)[:200]})
    fw['enabled'] = True
    A.respond(200, fw)


def handle_device_routeros_qos(dev_id):
    """GET /api/devices/<id>/routeros/qos — simple queues + queue tree."""
    A.require_auth()
    dev = A.device_get(dev_id)
    if not dev:
        A.respond(404, {'error': 'device not found'})
    tgt = A._routeros_target(dev)
    if not tgt:
        A.respond(200, {'simple': [], 'tree': [], 'enabled': False})
    host, user, password, verify = tgt
    import routeros as routeros_mod
    try:
        q = routeros_mod.qos(host, user, password, verify=verify)
    except Exception as e:
        A.respond(502, {'error': str(e)[:200]})
    q['enabled'] = True
    A.respond(200, q)


def handle_device_routeros_traffic(dev_id):
    """GET /api/devices/<id>/routeros/traffic — live per-interface bit/s."""
    A.require_auth()
    dev = A.device_get(dev_id)
    if not dev:
        A.respond(404, {'error': 'device not found'})
    tgt = A._routeros_target(dev)
    if not tgt:
        A.respond(200, {'interfaces': []})
    host, user, password, verify = tgt
    import routeros as routeros_mod
    try:
        rates = routeros_mod.traffic(host, user, password, verify=verify)
    except Exception as e:
        A.respond(502, {'error': str(e)[:200]})
    A.respond(200, {'interfaces': rates})


def handle_device_routeros_action(dev_id):
    """POST /api/devices/<id>/routeros/action {action, arg, rule?} — admin-only
    management command, gated on the device's routeros opt-in. Audited."""
    actor = A.require_admin_auth()
    if not A._validate_id(dev_id):
        A.respond(400, {'error': 'invalid device id'})
    dev = A.device_get(dev_id)
    if not dev:
        A.respond(404, {'error': 'device not found'})
    tgt = A._routeros_target(dev)
    if not tgt:
        A.respond(403, {'error': 'RouterOS not enabled/configured on this device'})
    body = A._read_valid(A.request_models.DeviceRouterosActionRequest)
    act = A._sanitize_str(body.get('action', ''), 32)
    arg = A._sanitize_str(str(body.get('arg', '')), 128) or None
    host, user, password, verify = tgt
    import routeros as routeros_mod
    if act not in routeros_mod.ACTIONS:
        A.respond(400, {'error': 'unknown action'})
    rule = body.get('rule') if isinstance(body.get('rule'), dict) else None
    try:
        res = routeros_mod.action(host, user, password, act, arg=arg, rule=rule,
                                  verify=verify)
    except Exception as e:
        A.respond(502, {'error': str(e)[:200]})
    # v3.3.4: cache the update state so the Patches page can show RouterOS
    # firmware alongside Linux package updates without a live fetch.
    if act == 'check_update' and isinstance(res, dict) and res.get('update'):
        try:
            with A._LockedUpdate(A.DEVICES_FILE) as store:
                d = store.get(dev_id)
                if d is not None:
                    d['routeros_update'] = {**res['update'], 'last_checked': int(time.time())}
        except Exception:
            pass
    A.audit_log(actor, 'device_routeros_action', f'dev={dev_id} action={act} arg={arg}')
    A.respond(200, {'ok': True, 'result': res})


# ─── v3.4.0: OPNsense firewall management (REST API) ────────────────────────
# Mirrors the RouterOS plumbing above: per-device opt-in config block with an
# API key + write-only API secret, admin-only + audited management actions,
# the same generic action allow-list pattern. opnsense.py holds the REST
# client + the firewall filter/NAT CRUD.

def _opnsense_target(dev):
    """(host:port, api_key, api_secret, verify) for an OPNsense-enabled
    device, or None. Host comes from the device's ip/hostname; key/secret +
    port live in the device's `opnsense` config block."""
    cfg = dev.get('opnsense') or {}
    if not cfg.get('enabled'):
        return None
    host = dev.get('ip') or dev.get('hostname') or dev.get('host')
    key = cfg.get('api_key') or ''
    secret = cfg.get('api_secret') or ''
    if not host or not key:
        return None
    port = int(cfg.get('port') or 443)
    # v4.6.0 (SECURITY): SSRF pre-flight on the OPNsense REST host — parity with
    # _routeros_target. These handlers are reachable by any authenticated user
    # and the module connects with CERT_NONE, returning distinct success/failure
    # text → an internal-TCP reachability/port oracle. Block loopback +
    # link-local/cloud-metadata while still allowing the RFC1918 LAN firewall.
    if A._url_targets_local_or_meta(urllib.parse.urlparse(f'https://{host}'),
                                    allow_loopback=False):
        return None
    return (f'{host}:{port}', key, secret, bool(cfg.get('verify', False)))


def _opnsense_redacted(dev):
    cfg = dev.get('opnsense') or {}
    return {
        'enabled':     bool(cfg.get('enabled')),
        'api_key':     cfg.get('api_key') or '',     # an access id, not the secret
        'has_secret':  bool(cfg.get('api_secret')),
        'port':        int(cfg.get('port') or 443),
        'verify':      bool(cfg.get('verify', False)),
    }


def _opnsense_cache_update(dev_id, fw):
    """Persist the OPNsense firmware/update verdict on the device so the
    Patches report can read it without a live fetch. `fw` is the normalised
    firmware dict from opnsense.overview()/check_update. Best-effort."""
    if not isinstance(fw, dict):
        return
    try:
        with A._LockedUpdate(A.DEVICES_FILE) as store:
            d = store.get(dev_id)
            if d is not None:
                d['opnsense_update'] = {
                    'installed':         fw.get('version'),
                    'latest':            fw.get('latest'),
                    'updates_available': fw.get('updates_available'),
                    'needs_reboot':      fw.get('needs_reboot'),
                    'status':            fw.get('status'),
                    'last_checked':      int(time.time()),
                }
    except Exception:
        pass


def handle_device_opnsense(dev_id):
    """GET /api/devices/<id>/opnsense — redacted config + (if enabled) a live
    overview. PATCH — admin; save {enabled, api_key, api_secret, port,
    verify} (empty api_secret preserves the stored one)."""
    if not A._validate_id(dev_id):
        A.respond(400, {'error': 'invalid device id'})
    devs = A.load(A.DEVICES_FILE)
    if dev_id not in devs:
        A.respond(404, {'error': 'device not found'})
    m = A.method()
    if m == 'GET':
        A.require_auth()
        dev = devs[dev_id]
        redacted = A._opnsense_redacted(dev)
        tgt = A._opnsense_target(dev)
        if not tgt:
            A.respond(200, {'config': redacted, 'overview': None})
        host, key, secret, verify = tgt
        import opnsense as opn_mod
        ov, err = None, None
        try:
            ov = opn_mod.overview(host, key, secret, verify=verify)
        except Exception as e:
            err = str(e)[:200]
        # Cache the firmware/update verdict on the device so the Patches
        # report can show OPNsense alongside Linux + RouterOS without a live
        # fetch per device — same pattern as routeros_update.
        if ov and isinstance(ov.get('firmware'), dict) and ov['firmware'].get('version'):
            A._opnsense_cache_update(dev_id, ov['firmware'])
        resp = {'config': redacted, 'overview': ov}
        if err:
            resp['error'] = err
        A.respond(200, resp)
    elif m == 'PATCH':
        actor = A.require_admin_auth()
        body = A._read_valid(A.request_models.DeviceOpnsenseRequest)
        with A._LockedUpdate(A.DEVICES_FILE) as store:
            dev = store.get(dev_id) or {}
            oc = dict(dev.get('opnsense') or {})
            if 'enabled' in body:
                oc['enabled'] = bool(body['enabled'])
            if 'api_key' in body:
                oc['api_key'] = A._sanitize_str(str(body['api_key']), 128)
            if 'api_secret' in body:
                sec = str(body['api_secret'])
                if sec:                      # empty preserves existing
                    oc['api_secret'] = sec[:256]
            if 'port' in body:
                try:
                    p = int(body['port'])
                    if 1 <= p <= 65535:
                        oc['port'] = p
                except (TypeError, ValueError):
                    A.respond(400, {'error': 'port must be 1..65535'})
            if 'verify' in body:
                oc['verify'] = bool(body['verify'])
            if oc.get('enabled') and not oc.get('api_key'):
                A.respond(400, {'error': 'api_key required when OPNsense is enabled'})
            if oc.get('enabled') and not oc.get('api_secret'):
                A.respond(400, {'error': 'api_secret required when OPNsense is enabled'})
            dev['opnsense'] = oc
            store[dev_id] = dev
        A.audit_log(actor, 'device_opnsense_config',
                    f'dev={dev_id} enabled={oc.get("enabled")} key={oc.get("api_key", "")[:8]}')
        A.respond(200, {'ok': True, 'config': A._opnsense_redacted({'opnsense': oc})})
    else:
        A.respond(405, {'error': 'Method not allowed'})


def handle_device_opnsense_firewall(dev_id):
    """GET /api/devices/<id>/opnsense/firewall — filter + NAT rules detail."""
    A.require_auth()
    dev = A.device_get(dev_id)
    if not dev:
        A.respond(404, {'error': 'device not found'})
    tgt = A._opnsense_target(dev)
    if not tgt:
        A.respond(200, {'filter': [], 'nat': [], 'enabled': False})
    host, key, secret, verify = tgt
    import opnsense as opn_mod
    try:
        fw = opn_mod.firewall(host, key, secret, verify=verify)
    except Exception as e:
        A.respond(502, {'error': str(e)[:200]})
    fw['enabled'] = True
    A.respond(200, fw)


def handle_device_opnsense_action(dev_id):
    """POST /api/devices/<id>/opnsense/action {action, arg, rule?} — admin-only
    firewall management, gated on the device's opnsense opt-in. Audited."""
    actor = A.require_admin_auth()
    if not A._validate_id(dev_id):
        A.respond(400, {'error': 'invalid device id'})
    dev = A.device_get(dev_id)
    if not dev:
        A.respond(404, {'error': 'device not found'})
    tgt = A._opnsense_target(dev)
    if not tgt:
        A.respond(403, {'error': 'OPNsense not enabled/configured on this device'})
    body = A._read_valid(A.request_models.DeviceOpnsenseActionRequest)
    act = A._sanitize_str(body.get('action', ''), 32)
    arg = A._sanitize_str(str(body.get('arg', '')), 64) or None
    host, key, secret, verify = tgt
    import opnsense as opn_mod
    if act not in opn_mod.ACTIONS:
        A.respond(400, {'error': 'unknown action'})
    rule = body.get('rule') if isinstance(body.get('rule'), dict) else None
    try:
        res = opn_mod.action(host, key, secret, act, arg=arg, rule=rule, verify=verify)
    except Exception as e:
        A.respond(502, {'error': str(e)[:200]})
    # Cache the firmware verdict from a check so the Patches report stays fresh.
    if act == 'check_update' and isinstance(res, dict) and isinstance(res.get('update'), dict):
        A._opnsense_cache_update(dev_id, res['update'])
    A.audit_log(actor, 'device_opnsense_action', f'dev={dev_id} action={act} arg={arg}')
    A.respond(200, {'ok': True, 'result': res})


# ── v6.4.2: network-appliance config archive ────────────────────────────────
# There was no appliance configuration backup, versioning or change diff
# anywhere. The sole retrieval path was the RouterOS `export` action, which
# returned text truncated at 256 KB straight into a `<pre>` in the drawer:
# not stored, not versioned, not diffed, not scheduled, and raising no event.
# OPNsense had no config call at all.
#
# Meanwhile Linux hosts get full hash-based config-drift detection. The devices
# that most need it — the switch and the firewall — got nothing, and "who
# changed the firewall rule at 3pm Friday, and what did it look like before?"
# is the canonical network-ops question. It is what RANCID and Oxidized exist
# for, and what LibreNMS / Unimus / Auvik / PRTG all ship.
#
# Modelled on config_revisions_handlers.py (the same revision/rollback pattern
# already used for RemotePower's OWN config), not on the drift subsystem: an
# appliance config is one opaque document, not a watch-list of file hashes.
_NETCONF_MAX_REVISIONS = 10
# Bodies larger than this are archived as hash + size only. Storing a TRUNCATED
# config would be worse than storing none: it looks complete, and an operator
# restoring from it would be restoring a fragment. Change DETECTION still works
# because the hash is of the whole document.
_NETCONF_MAX_BODY = 256 * 1024
_NETCONF_INTERVAL = 86400          # daily, like a config-backup tool


def _netconf_kind(dev):
    """Which appliance API this device speaks, or ''."""
    if A._routeros_target(dev):
        return 'routeros'
    if A._opnsense_target(dev):
        return 'opnsense'
    return ''


def _netconf_fetch(dev_id, dev):
    """Pull the running config. Returns text, or raises."""
    kind = A._netconf_kind(dev)
    if kind == 'routeros':
        import routeros as mod
        host, user, password, verify = A._routeros_target(dev)
        res = mod.action(host, user, password, 'export', verify=verify)
    elif kind == 'opnsense':
        import opnsense as mod
        host, key, secret, verify = A._opnsense_target(dev)
        res = mod.action(host, key, secret, 'export', verify=verify)
    else:
        raise RuntimeError('no appliance API configured on this device')
    return str((res or {}).get('export') or '')


def _netconf_store_revision(dev_id, text, actor='system'):
    """Archive `text` as a new revision IF it differs from the newest one.

    Returns (revision_or_None, changed_bool). Unchanged configs are not stored
    again — an archive that keeps a copy per poll is a disk-usage bug wearing a
    feature's clothes, and it buries the revisions that mean something.
    """
    import hashlib
    digest = hashlib.sha256(text.encode('utf-8', 'replace')).hexdigest()
    oversize = len(text.encode('utf-8', 'replace')) > _NETCONF_MAX_BODY
    rev = None
    changed = False
    with A._LockedUpdate(A.NETCONFIG_ARCHIVE_FILE) as store:
        revs = store.get(dev_id)
        if not isinstance(revs, list):
            revs = []
        prev = revs[-1] if revs else None
        if prev and prev.get('hash') == digest:
            # Same config — just note that we checked, so "last verified" is
            # honest rather than reading as "no backup since <last change>".
            prev['last_seen'] = int(time.time())
            store[dev_id] = revs
            return prev, False
        rev = {
            'id':    'nc-' + A.secrets.token_hex(6),
            'ts':    int(time.time()),
            'hash':  digest,
            'bytes': len(text.encode('utf-8', 'replace')),
            'lines': text.count('\n') + 1 if text else 0,
            'by':    str(actor or 'system')[:64],
            'oversize': oversize,
            'text':  '' if oversize else text,
        }
        rev['last_seen'] = rev['ts']
        revs.append(rev)
        del revs[:-_NETCONF_MAX_REVISIONS]
        store[dev_id] = revs
        changed = prev is not None      # the FIRST archive is a baseline, not a change
    return rev, changed


def _netconf_diff(a_text, b_text, limit=400):
    """Unified diff between two revisions, bounded."""
    import difflib
    lines = list(difflib.unified_diff(
        (a_text or '').splitlines(), (b_text or '').splitlines(),
        fromfile='previous', tofile='current', lineterm='', n=2))
    return lines[:limit], len(lines) > limit


def _netconf_meta(rev):
    """A revision without its body — the list view never ships config text."""
    return {k: rev.get(k) for k in
            ('id', 'ts', 'hash', 'bytes', 'lines', 'by', 'oversize', 'last_seen')}


def handle_device_netconfig(dev_id):
    """GET /api/devices/<id>/netconfig — archived revisions (metadata);
    POST — back up now. Under /api/devices/, so main()'s _enforce_device_scope
    covers tenancy and role scope before this runs."""
    if not A._validate_id(dev_id):
        A.respond(400, {'error': 'invalid device id'})
    dev = A.device_get(dev_id)
    if not dev:
        A.respond(404, {'error': 'device not found'})
    if A.method() == 'GET':
        A.require_auth()
        revs = (A.load(A.NETCONFIG_ARCHIVE_FILE) or {}).get(dev_id) or []
        A.respond(200, {
            'device_id': dev_id,
            'kind': A._netconf_kind(dev),
            'revisions': [A._netconf_meta(r) for r in reversed(revs)],
            'max_revisions': _NETCONF_MAX_REVISIONS,
        })
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    # A backup reads the appliance's full running config, including any secrets
    # it embeds — the same bar as reading its firewall rules.
    actor = A.require_admin_auth()
    if not A._netconf_kind(dev):
        A.respond(400, {'error': 'no RouterOS or OPNsense API configured on this device'})
    try:
        text = A._netconf_fetch(dev_id, dev)
    except Exception as e:
        A.respond(502, {'error': str(e)[:200]})
    if not text:
        A.respond(502, {'error': 'the appliance returned an empty configuration'})
    rev, changed = A._netconf_store_revision(dev_id, text, actor)
    A.audit_log(actor, 'netconfig_backup',
                f'dev={dev_id} changed={changed} bytes={rev.get("bytes")}')
    A.respond(200, {'ok': True, 'changed': changed, 'revision': A._netconf_meta(rev)})


def handle_device_netconfig_revision(dev_id, rev_id):
    """GET /api/devices/<id>/netconfig/<rev>[?format=download|diff&against=<id>]
    — one archived config, or a unified diff against another revision."""
    A.require_admin_auth()      # the body is the appliance's full config
    if not A._validate_id(dev_id):
        A.respond(400, {'error': 'invalid device id'})
    revs = (A.load(A.NETCONFIG_ARCHIVE_FILE) or {}).get(dev_id) or []
    by_id = {r.get('id'): r for r in revs if isinstance(r, dict)}
    rev = by_id.get(A._sanitize_str(str(rev_id or ''), 32))
    if not rev:
        A.respond(404, {'error': 'revision not found'})
    qs = A.urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
    fmt = (qs.get('format') or ['json'])[0].lower()
    if fmt == 'diff':
        other = by_id.get(A._sanitize_str((qs.get('against') or [''])[0], 32))
        if not other:
            # Default to the revision immediately before this one — the
            # question is nearly always "what changed in this one?".
            idx = next((i for i, r in enumerate(revs) if r.get('id') == rev['id']), 0)
            other = revs[idx - 1] if idx > 0 else None
        if not other:
            A.respond(400, {'error': 'no earlier revision to compare against'})
        if rev.get('oversize') or other.get('oversize'):
            A.respond(400, {'error': 'one of these revisions was too large to '
                                     'archive its body — only the hash was kept, '
                                     'so there is nothing to diff'})
        lines, truncated = A._netconf_diff(other.get('text'), rev.get('text'))
        A.respond(200, {'from': A._netconf_meta(other), 'to': A._netconf_meta(rev),
                        'diff': lines, 'truncated': truncated})
    if rev.get('oversize'):
        A.respond(400, {'error': 'this configuration exceeded the archive body '
                                 'limit, so only its hash and size were kept'})
    if fmt == 'download':
        data = (rev.get('text') or '').encode('utf-8', 'replace')
        stamp = time.strftime('%Y%m%d-%H%M%S', time.localtime(int(rev.get('ts') or 0)))
        print("Status: 200 OK")
        print("Content-Type: text/plain; charset=utf-8")
        print(f"Content-Disposition: attachment; filename=netconfig-{dev_id}-{stamp}.txt")
        print(f"Content-Length: {len(data)}")
        print("Cache-Control: no-store")
        print("X-Content-Type-Options: nosniff")
        print()
        A.sys.stdout.flush()
        A.sys.stdout.buffer.write(data)
        A.sys.stdout.buffer.flush()
        A.sys.exit(0)
    A.respond(200, {'revision': A._netconf_meta(rev), 'text': rev.get('text') or ''})


def run_netconfig_backup_if_due():
    """Cadence: archive every appliance's running config once a day, and fire
    `netconfig_changed` when one differs from the last archived copy.

    Opt-in (`netconfig_backup_enabled`, default off): it authenticates to every
    appliance in the fleet and stores its full configuration, which is an
    operator's decision to make, not a default to inherit on upgrade.
    """
    cfg = A._config_ro() or {}
    if not cfg.get('netconfig_backup_enabled'):
        return
    now = int(time.time())
    interval = _NETCONF_INTERVAL
    try:
        interval = max(3600, min(30 * 86400,
                                 int(cfg.get('netconfig_backup_interval_s') or interval)))
    except (TypeError, ValueError):
        pass
    state = A._load_ro(A.NETCONFIG_STATE_FILE) or {}
    if now - int(state.get('last_run') or 0) < interval:
        return
    with A._LockedUpdate(A.NETCONFIG_STATE_FILE) as st:
        # Re-check inside the lock: two workers passing the gate together would
        # both authenticate to every appliance in the fleet.
        if now - int(st.get('last_run') or 0) < interval:
            return
        st['last_run'] = now
    pending = []
    for dev_id, dev in (A.load(A.DEVICES_FILE) or {}).items():
        if not isinstance(dev, dict) or dev.get('quarantined'):
            continue
        if not A._netconf_kind(dev):
            continue
        try:
            text = A._netconf_fetch(dev_id, dev)
        except Exception as e:
            A.sys.stderr.write(f'[remotepower] netconfig backup failed '
                               f'dev={dev_id}: {str(e)[:160]}\n')
            continue
        if not text:
            continue
        rev, changed = A._netconf_store_revision(dev_id, text)
        if changed:
            pending.append((dev_id, dev, rev))
    # fire_webhook takes its own locks — outside every _LockedUpdate above.
    for dev_id, dev, rev in pending:
        try:
            A.fire_webhook('netconfig_changed', {
                'device_id': dev_id,
                'name': dev.get('name', dev_id),
                'kind': A._netconf_kind(dev),
                'revision': rev.get('id'),
                'lines': rev.get('lines'),
                'bytes': rev.get('bytes'),
            })
        except Exception as e:                       # pragma: no cover
            A.sys.stderr.write(f'[remotepower] netconfig_changed fire failed: {e}\n')
