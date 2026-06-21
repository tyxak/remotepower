#!/usr/bin/env python3
"""
proxmox_client.py — RemotePower ↔ Proxmox VE API client (v2.3.0)

Talks to a single Proxmox VE node's REST API from the RemotePower
server. No agent runs on the Proxmox node — this is a direct
server-to-API integration.

Scope (deliberately small for the first release):
  - list QEMU virtual machines        → Virtualization page
  - list LXC containers               → Containers page
  - start / graceful-shutdown / status on either type

Auth is a Proxmox API token (Datacenter → Permissions → API Tokens).
The token is sent as an Authorization header:

    Authorization: PVEAPIToken=USER@REALM!TOKENID=SECRET

Configuration lives in RemotePower's config.json under `proxmox_*`
keys (entered via Settings). NOTE: the token secret is stored in
plaintext in config.json — see the SECURITY note in the README.
config.json is written 0600 by the api.py save path.

Everything here is stdlib-only (urllib + ssl + json) to match the
rest of RemotePower — no `requests`, no `proxmoxer`.
"""

import json
import re
import os
import ssl
import time
import urllib.request
import urllib.error
import urllib.parse


# v2.3.1: the token secret may be supplied via an environment variable
# instead of config.json. When RP_PROXMOX_TOKEN_SECRET is set in the
# server's environment it takes precedence — the secret then lives in
# the systemd unit / container env, never in the data directory, and
# is not swept into the backup export. config.json remains a working
# fallback for setups that don't use the env var.
ENV_TOKEN_SECRET = 'RP_PROXMOX_TOKEN_SECRET'


# ── Action allow-list ───────────────────────────────────────────────────
#
# Only these actions may be invoked. `stop` is the hard pull-the-plug;
# `shutdown` is graceful (ACPI for QEMU, init signal for LXC). The UI
# defaults to `shutdown`. `stop` is allowed here so a future "force
# stop" button has a path, but the UI does not expose it in v2.3.0.
# `status` is read-only. Anything not in this set is rejected before a
# request is ever built — migrate / delete / clone are intentionally
# absent.
ALLOWED_VM_ACTIONS = ('start', 'shutdown', 'stop', 'status')

# Proxmox guest types this module understands.
GUEST_QEMU = 'qemu'
GUEST_LXC  = 'lxc'
_GUEST_TYPES = (GUEST_QEMU, GUEST_LXC)

# Network timeout for a single API call (seconds). Proxmox task
# endpoints return immediately with a task id — they don't block — so
# a short timeout is fine.
_HTTP_TIMEOUT = 10

# Cap on guests parsed from a listing — defensive against a huge or
# malformed response.
_LISTING_CAP = 500


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow HTTP redirects — a 3xx from a hostile/rebound Proxmox
    host must not replay the Authorization token to an attacker-chosen URL."""

    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


# v5.0.0 SSRF: set-time pre-flight blocks obvious local/meta targets, but every
# runtime call re-resolves the saved host, leaving a DNS-rebinding window (save
# once → each poll rebinds to 169.254.169.254 / loopback). These guard the peer
# IP at connect time so a rebound host is refused before the token is sent.
# Stdlib-only, mirroring the rest of this module. RFC1918/LAN stays allowed.
def _peer_ip_blocked(ip_str: str) -> bool:
    import ipaddress
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return bool(ip.is_loopback or ip.is_link_local or ip.is_unspecified)


import http.client as _httpclient


class _SSRFGuardHTTPSConnection(_httpclient.HTTPSConnection):
    def connect(self):
        super().connect()
        try:
            peer = self.sock.getpeername()[0]
        except (OSError, AttributeError, IndexError):
            return
        if _peer_ip_blocked(peer):
            self.close()
            raise OSError(f'SSRF guard: Proxmox peer {peer} is a blocked address')


def _ssrf_opener(ctx):
    """An opener that refuses redirects AND re-validates the peer IP at connect
    (mirrors api.py's _ssrf_safe_opener(no_redirect=True), stdlib-only here)."""
    class _GuardHTTPSHandler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(_SSRFGuardHTTPSConnection, req, context=ctx)
    return urllib.request.build_opener(_NoRedirect, _GuardHTTPSHandler())


class ProxmoxError(Exception):
    """Raised for any Proxmox interaction failure. The message is
    safe to surface to the UI — it never contains the token."""


# ── Configuration ───────────────────────────────────────────────────────

def config_from(cfg: dict) -> dict:
    """Extract the Proxmox connection settings out of a RemotePower
    config dict. Returns a normalised dict; missing keys get safe
    defaults. Does NOT validate completeness — use is_configured().

    v2.3.1: the token secret is sourced from the RP_PROXMOX_TOKEN_SECRET
    environment variable when that is set, falling back to config.json
    otherwise. The env var keeps the secret out of the data directory
    (and therefore out of the backup export).
    """
    env_secret = os.environ.get(ENV_TOKEN_SECRET, '').strip()
    token_secret = env_secret or str(cfg.get('proxmox_token_secret', ''))
    return {
        'enabled':      bool(cfg.get('proxmox_enabled', False)),
        'host':         str(cfg.get('proxmox_host', '')).strip(),
        'node':         str(cfg.get('proxmox_node', '')).strip(),
        'token_id':     str(cfg.get('proxmox_token_id', '')).strip(),
        'token_secret': token_secret,
        # Where did the secret come from — used by the UI so it can
        # tell the operator "secret is set via environment variable"
        # rather than implying it's in config.json.
        'token_secret_from_env': bool(env_secret),
        # TLS verification ON by default. Proxmox ships a self-signed
        # cert, so operators with the default cert must explicitly
        # opt out — a deliberate, visible choice rather than a silent
        # insecure default.
        'verify_tls':   bool(cfg.get('proxmox_verify_tls', True)),
    }


def is_configured(pc: dict) -> bool:
    """True if the connection dict has the minimum needed to talk to
    Proxmox: host, node, token id and secret all present."""
    return all((pc.get('host'), pc.get('node'),
                pc.get('token_id'), pc.get('token_secret')))


# ── Low-level request ───────────────────────────────────────────────────

def _ssl_context(verify_tls: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify_tls:
        # Self-signed Proxmox cert — operator opted out of verification.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _base_url(host: str) -> str:
    """Build the API base URL. `host` may be a bare hostname/IP, or
    include a scheme and/or port — we normalise to https and the
    default Proxmox port 8006 when not specified."""
    h = host.strip()
    # Strip any scheme the operator pasted in
    if '://' in h:
        h = h.split('://', 1)[1]
    h = h.rstrip('/')
    # Append the default API port if none given. IPv6 literals in
    # brackets are left alone.
    if not h.startswith('[') and ':' not in h:
        h = f'{h}:8006'
    return f'https://{h}/api2/json'


def _auth_header(token_id: str, token_secret: str) -> str:
    """Construct the PVEAPIToken Authorization header value.

    token_id is the full `user@realm!tokenid` string as shown in the
    Proxmox UI. The header format is:
        PVEAPIToken=user@realm!tokenid=secret
    """
    return f'PVEAPIToken={token_id}={token_secret}'


def _request(pc: dict, path: str, method: str = 'GET',
             data: dict | None = None) -> dict:
    """Make one Proxmox API call and return the parsed `data` payload.

    `path` is the API path below /api2/json, e.g. '/nodes/pve/qemu'.
    Raises ProxmoxError on any failure, with a message safe for the
    UI (the token is never echoed).
    """
    if not is_configured(pc):
        raise ProxmoxError('Proxmox connection is not fully configured.')

    url = _base_url(pc['host']) + path
    body = None
    headers = {
        'Authorization': _auth_header(pc['token_id'], pc['token_secret']),
        'Accept': 'application/json',
    }
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'

    req = urllib.request.Request(url, data=body, method=method,
                                 headers=headers)
    ctx = _ssl_context(pc.get('verify_tls', True))
    try:
        # Do NOT follow redirects: the Proxmox API never legitimately 3xx's, and
        # a redirect from a hostile / DNS-rebound host would replay the
        # Authorization token to an attacker-chosen location. Any 3xx is treated
        # as an error. (SSRF hardening — set-time pre-flight already blocks the
        # obvious local/meta targets.)
        _opener = _ssrf_opener(ctx)
        with _opener.open(req, timeout=_HTTP_TIMEOUT) as resp:
            raw = resp.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        # Proxmox returns useful status codes — translate the common
        # ones into operator-friendly messages.
        if e.code in (401, 403):
            raise ProxmoxError(
                'Proxmox rejected the API token (401/403). Check the '
                'token id, secret, and its permissions.') from None
        if e.code == 404:
            raise ProxmoxError('Proxmox API path not found (404) — '
                               'check the node name.') from None
        raise ProxmoxError(f'Proxmox API error (HTTP {e.code}).') from None
    except urllib.error.URLError as e:
        # Network / TLS failure. ssl errors land here too.
        reason = str(getattr(e, 'reason', e))
        if 'CERTIFICATE' in reason.upper() or 'SSL' in reason.upper():
            raise ProxmoxError(
                'TLS certificate verification failed. Proxmox uses a '
                'self-signed certificate by default — either install a '
                'trusted cert or turn off "Verify TLS" for this '
                'connection.') from None
        raise ProxmoxError(f'Could not reach Proxmox: {reason}') from None
    except (TimeoutError, OSError) as e:
        raise ProxmoxError(f'Proxmox connection failed: {e}') from None

    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        raise ProxmoxError('Proxmox returned a non-JSON response.') from None

    # The real payload is under the top-level `data` key.
    return parsed.get('data') if isinstance(parsed, dict) else None


# ── Listing ─────────────────────────────────────────────────────────────

def _norm_guest(raw: dict, guest_type: str) -> dict | None:
    """Normalise one Proxmox guest object into RemotePower's shape.

    Proxmox returns slightly different keys per type but the fields we
    care about (vmid, name, status, cpu, mem) are common. Anything
    malformed returns None and is dropped by the caller.
    """
    if not isinstance(raw, dict):
        return None
    vmid = raw.get('vmid')
    if vmid is None:
        return None
    try:
        vmid = int(vmid)
    except (ValueError, TypeError):
        return None

    # cpu is a 0..1 fraction of total cores; mem/maxmem are bytes.
    try:
        cpu_pct = round(float(raw.get('cpu', 0)) * 100, 1)
    except (ValueError, TypeError):
        cpu_pct = None
    mem = raw.get('mem') or 0
    maxmem = raw.get('maxmem') or 0
    try:
        mem_pct = round(float(mem) / float(maxmem) * 100, 1) if maxmem else None
    except (ValueError, TypeError, ZeroDivisionError):
        mem_pct = None

    return {
        'vmid':        vmid,
        'name':        str(raw.get('name', '') or f'{guest_type}-{vmid}'),
        'type':        guest_type,                    # 'qemu' | 'lxc'
        'status':      str(raw.get('status', 'unknown')),
        'cpu_percent': cpu_pct,
        'mem_percent': mem_pct,
        'mem_bytes':   int(mem) if str(mem).isdigit() else 0,
        'maxmem_bytes':int(maxmem) if str(maxmem).isdigit() else 0,
        'uptime':      int(raw.get('uptime', 0) or 0),
        'tags':        str(raw.get('tags', '') or ''),
    }


def list_guests(pc: dict, guest_type: str) -> list[dict]:
    """List QEMU VMs or LXC containers on the configured node.

    guest_type must be GUEST_QEMU or GUEST_LXC. Returns a list of
    normalised guest dicts, sorted by vmid.
    """
    if guest_type not in _GUEST_TYPES:
        raise ProxmoxError(f'Unknown guest type: {guest_type!r}')
    node = pc['node']
    raw = _request(pc, f'/nodes/{urllib.parse.quote(node)}/{guest_type}')
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw[:_LISTING_CAP]:
        g = _norm_guest(item, guest_type)
        if g:
            out.append(g)
    out.sort(key=lambda g: g['vmid'])
    return out


# ── Actions ─────────────────────────────────────────────────────────────

def guest_action(pc: dict, guest_type: str, vmid: int, action: str) -> dict:
    """Perform an action on a guest. Returns a small result dict.

    action must be in ALLOWED_VM_ACTIONS. 'status' is a GET (read
    current status); start/shutdown/stop are POSTs to the matching
    /status/<action> endpoint.
    """
    if guest_type not in _GUEST_TYPES:
        raise ProxmoxError(f'Unknown guest type: {guest_type!r}')
    if action not in ALLOWED_VM_ACTIONS:
        # Hard fail before building any request — this is the gate.
        raise ProxmoxError(f'Action not allowed: {action!r}')
    try:
        vmid = int(vmid)
    except (ValueError, TypeError):
        raise ProxmoxError('Invalid vmid.') from None

    node = urllib.parse.quote(pc['node'])
    base = f'/nodes/{node}/{guest_type}/{vmid}/status'

    if action == 'status':
        data = _request(pc, f'{base}/current')
        return {
            'vmid':   vmid,
            'type':   guest_type,
            'status': (data or {}).get('status', 'unknown'),
            'action': 'status',
        }

    # start / shutdown / stop are POSTs. Proxmox returns a task UPID
    # string in `data` — the action is asynchronous on its side.
    upid = _request(pc, f'{base}/{action}', method='POST')
    return {
        'vmid':   vmid,
        'type':   guest_type,
        'action': action,
        'task':   upid if isinstance(upid, str) else '',
        'ok':     True,
    }


# ── Snapshots (v2.4.0) ──────────────────────────────────────────────────
#
# Proxmox snapshots, for QEMU and LXC alike, live under
# /nodes/<node>/<type>/<vmid>/snapshot. The endpoint set:
#   GET    .../snapshot                 → list
#   POST   .../snapshot                 → create  (param: snapname, description)
#   POST   .../snapshot/<name>/rollback → roll back to a snapshot
#   DELETE .../snapshot/<name>          → delete a snapshot
#
# A Proxmox snapshot name must match ^[A-Za-z][A-Za-z0-9_]*$ — we
# validate before sending so a bad name is rejected locally with a
# clear message rather than as an opaque Proxmox 400.

_SNAPSHOT_NAME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_]{0,39}$')

# Proxmox always has a synthetic 'current' pseudo-snapshot in the list;
# it is the live state, not a real snapshot — never rollback/delete it.
_SNAPSHOT_RESERVED = {'current'}


def _valid_snapshot_name(name: str) -> bool:
    return bool(name) and bool(_SNAPSHOT_NAME_RE.match(name))


def list_snapshots(pc: dict, guest_type: str, vmid: int) -> list[dict]:
    """List snapshots for a guest. The synthetic 'current' entry that
    Proxmox always returns (the live state) is filtered out."""
    if guest_type not in _GUEST_TYPES:
        raise ProxmoxError(f'Unknown guest type: {guest_type!r}')
    try:
        vmid = int(vmid)
    except (ValueError, TypeError):
        raise ProxmoxError('Invalid vmid.') from None
    node = urllib.parse.quote(pc['node'])
    raw = _request(pc, f'/nodes/{node}/{guest_type}/{vmid}/snapshot')
    if not isinstance(raw, list):
        return []
    out = []
    for s in raw:
        if not isinstance(s, dict):
            continue
        name = str(s.get('name', ''))
        if name in _SNAPSHOT_RESERVED or not name:
            continue
        out.append({
            'name':        name,
            'description': str(s.get('description', '') or ''),
            'snaptime':    int(s.get('snaptime', 0) or 0),
            'parent':      str(s.get('parent', '') or ''),
            # vmstate=1 means the snapshot includes RAM state
            'vmstate':     bool(s.get('vmstate', 0)),
        })
    out.sort(key=lambda s: s['snaptime'])
    return out


def create_snapshot(pc: dict, guest_type: str, vmid: int,
                     name: str, description: str = '') -> dict:
    """Create a snapshot. Disk-only (no RAM state) — RemotePower does
    not expose the vmstate option in this release."""
    if guest_type not in _GUEST_TYPES:
        raise ProxmoxError(f'Unknown guest type: {guest_type!r}')
    if not _valid_snapshot_name(name):
        raise ProxmoxError(
            'Invalid snapshot name. Use a letter followed by letters, '
            'digits or underscores (max 40 chars).')
    try:
        vmid = int(vmid)
    except (ValueError, TypeError):
        raise ProxmoxError('Invalid vmid.') from None
    node = urllib.parse.quote(pc['node'])
    data = {'snapname': name}
    if description:
        data['description'] = description[:500]
    upid = _request(pc, f'/nodes/{node}/{guest_type}/{vmid}/snapshot',
                    method='POST', data=data)
    return {'vmid': vmid, 'type': guest_type, 'snapshot': name,
            'action': 'create', 'task': upid if isinstance(upid, str) else '',
            'ok': True}


def rollback_snapshot(pc: dict, guest_type: str, vmid: int, name: str) -> dict:
    """Roll a guest back to a snapshot. DESTRUCTIVE — discards all
    state since the snapshot was taken."""
    if guest_type not in _GUEST_TYPES:
        raise ProxmoxError(f'Unknown guest type: {guest_type!r}')
    if not _valid_snapshot_name(name) or name in _SNAPSHOT_RESERVED:
        raise ProxmoxError('Invalid snapshot name.')
    try:
        vmid = int(vmid)
    except (ValueError, TypeError):
        raise ProxmoxError('Invalid vmid.') from None
    node = urllib.parse.quote(pc['node'])
    sn = urllib.parse.quote(name)
    upid = _request(pc, f'/nodes/{node}/{guest_type}/{vmid}/snapshot/{sn}/rollback',
                    method='POST')
    return {'vmid': vmid, 'type': guest_type, 'snapshot': name,
            'action': 'rollback', 'task': upid if isinstance(upid, str) else '',
            'ok': True}


def delete_snapshot(pc: dict, guest_type: str, vmid: int, name: str) -> dict:
    """Delete a snapshot. Irreversible, but does not affect the
    running guest."""
    if guest_type not in _GUEST_TYPES:
        raise ProxmoxError(f'Unknown guest type: {guest_type!r}')
    if not _valid_snapshot_name(name) or name in _SNAPSHOT_RESERVED:
        raise ProxmoxError('Invalid snapshot name.')
    try:
        vmid = int(vmid)
    except (ValueError, TypeError):
        raise ProxmoxError('Invalid vmid.') from None
    node = urllib.parse.quote(pc['node'])
    sn = urllib.parse.quote(name)
    upid = _request(pc, f'/nodes/{node}/{guest_type}/{vmid}/snapshot/{sn}',
                    method='DELETE')
    return {'vmid': vmid, 'type': guest_type, 'snapshot': name,
            'action': 'delete', 'task': upid if isinstance(upid, str) else '',
            'ok': True}


# ── Connection test (for the Settings page) ─────────────────────────────

# ── LXC creation (v3.4.0) ────────────────────────────────────────────────
#
# A small "create container" wizard sits on top of the existing API token.
# Proxmox creates an LXC via POST /nodes/<node>/lxc; the call returns a task
# UPID and the container builds asynchronously. We expose the few read
# endpoints the wizard needs to populate its dropdowns (storages, templates,
# bridges, next free vmid) and one validated create call.

_HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-.]{0,61}[a-zA-Z0-9])?$')
_BRIDGE_RE   = re.compile(r'^[a-zA-Z0-9_.\-]{1,15}$')
_VOLID_RE    = re.compile(r'^[a-zA-Z0-9_.\-]+:[a-zA-Z0-9_./\-]+$')


def _valid_ipv4(s: str) -> bool:
    """True for a dotted-quad IPv4 with every octet in 0–255. The regex alone
    accepts nonsense like 999.1.1.1, so range-check each octet here."""
    parts = s.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 and p.isdigit() for p in parts)
    except ValueError:
        return False


def _valid_ipv4_cidr(s: str) -> bool:
    """True for ``a.b.c.d/N`` with valid octets and a 0–32 prefix length."""
    if '/' not in s:
        return False
    addr, _, prefix = s.partition('/')
    if not (prefix.isdigit() and 0 <= int(prefix) <= 32):
        return False
    return _valid_ipv4(addr)


def next_vmid(pc: dict) -> int:
    """Return the next free VMID from /cluster/nextid (Proxmox suggestion)."""
    raw = _request(pc, '/cluster/nextid')
    try:
        return int(raw)
    except (ValueError, TypeError):
        return 0


def list_storages(pc: dict) -> list[dict]:
    """Storages on the node, annotated with what they can hold.

    Returns [{storage, type, content:[...], rootdir:bool, vztmpl:bool,
    avail_bytes}]. `rootdir` storages can host a container's root disk;
    `vztmpl` storages can hold OS templates.
    """
    node = urllib.parse.quote(pc['node'])
    raw = _request(pc, f'/nodes/{node}/storage')
    out = []
    for s in raw if isinstance(raw, list) else []:
        if not isinstance(s, dict):
            continue
        content = [c for c in str(s.get('content', '')).split(',') if c]
        out.append({
            'storage':     str(s.get('storage', '')),
            'type':        str(s.get('type', '')),
            'content':     content,
            'rootdir':     'rootdir' in content,
            'vztmpl':      'vztmpl' in content,
            'avail_bytes': int(s.get('avail', 0) or 0),
        })
    return out


def list_templates(pc: dict) -> list[dict]:
    """LXC OS templates available across all vztmpl-capable storages.

    Returns [{volid, storage, name, size_bytes}], sorted by name.
    """
    node = urllib.parse.quote(pc['node'])
    out = []
    for st in list_storages(pc):
        if not st['vztmpl']:
            continue
        storage = st['storage']
        try:
            raw = _request(pc, f'/nodes/{node}/storage/'
                               f'{urllib.parse.quote(storage)}/content?content=vztmpl')
        except ProxmoxError:
            continue
        for item in raw if isinstance(raw, list) else []:
            if not isinstance(item, dict):
                continue
            volid = str(item.get('volid', ''))
            if not volid:
                continue
            name = volid.split('/', 1)[-1] if '/' in volid else volid
            out.append({
                'volid':      volid,
                'storage':    storage,
                'name':       name,
                'size_bytes': int(item.get('size', 0) or 0),
            })
    out.sort(key=lambda t: t['name'])
    return out


def list_backups(pc: dict) -> list[dict]:
    """v3.6.0: vzdump backup archives across all backup-capable storages.

    Returns [{volid, storage, vmid, ctime, size_bytes}] — one entry per archive
    (a guest usually has several). Callers group by vmid and take the newest
    ctime for per-guest recency. ctime is an epoch (seconds); 0 if absent.
    """
    node = urllib.parse.quote(pc['node'])
    out = []
    for st in list_storages(pc):
        if 'backup' not in st['content']:
            continue
        storage = st['storage']
        try:
            raw = _request(pc, f'/nodes/{node}/storage/'
                               f'{urllib.parse.quote(storage)}/content?content=backup')
        except ProxmoxError:
            continue
        for item in raw if isinstance(raw, list) else []:
            if not isinstance(item, dict):
                continue
            volid = str(item.get('volid', ''))
            if not volid:
                continue
            out.append({
                'volid':      volid,
                'storage':    storage,
                'vmid':       int(item.get('vmid', 0) or 0),
                'ctime':      int(item.get('ctime', 0) or 0),
                'size_bytes': int(item.get('size', 0) or 0),
            })
    return out


def list_isos(pc: dict) -> list[dict]:
    """v3.7.0: ISO images across all iso-capable storages (for the VM-create
    CD-ROM dropdown). Returns [{volid, storage, name, size_bytes}], by name."""
    node = urllib.parse.quote(pc['node'])
    out = []
    for st in list_storages(pc):
        if 'iso' not in st['content']:
            continue
        storage = st['storage']
        try:
            raw = _request(pc, f'/nodes/{node}/storage/'
                               f'{urllib.parse.quote(storage)}/content?content=iso')
        except ProxmoxError:
            continue
        for item in raw if isinstance(raw, list) else []:
            if not isinstance(item, dict):
                continue
            volid = str(item.get('volid', ''))
            if not volid:
                continue
            out.append({'volid': volid, 'storage': storage,
                        'name': volid.split('/', 1)[-1] if '/' in volid else volid,
                        'size_bytes': int(item.get('size', 0) or 0)})
    out.sort(key=lambda t: t['name'])
    return out


def create_qemu(pc: dict, params: dict) -> dict:
    """v3.7.0: Create a QEMU/KVM virtual machine. Validates locally before the
    POST so bad input fails clearly. Mirrors create_lxc.

    Expected `params`: vmid, name, cores, memory_mb, disk_gb, storage,
    bridge (default vmbr0), iso (volid, optional), ostype (default l26),
    start (bool), onboot (bool).

    Returns {ok, vmid, task}. Raises ProxmoxError on validation/API failure.
    """
    try:
        vmid = int(params.get('vmid'))
    except (ValueError, TypeError):
        raise ProxmoxError('A numeric VMID is required.') from None
    if not (100 <= vmid <= 999999999):
        raise ProxmoxError('VMID must be between 100 and 999999999.')

    name = str(params.get('name', '')).strip()
    if not _HOSTNAME_RE.match(name):
        raise ProxmoxError('Name must be a valid DNS label '
                           '(letters, digits, hyphens; 1–63 chars).')

    storage = str(params.get('storage', '')).strip()
    if not _BRIDGE_RE.match(storage):
        raise ProxmoxError('Pick a disk storage.')

    def _int(field, lo, hi, label):
        try:
            v = int(params.get(field))
        except (ValueError, TypeError):
            raise ProxmoxError(f'{label} must be a number.') from None
        if not (lo <= v <= hi):
            raise ProxmoxError(f'{label} must be between {lo} and {hi}.')
        return v

    cores     = _int('cores', 1, 128, 'Cores')
    memory_mb = _int('memory_mb', 16, 4 * 1024 * 1024, 'Memory (MB)')
    disk_gb   = _int('disk_gb', 1, 65536, 'Disk (GB)')

    bridge = str(params.get('bridge', 'vmbr0')).strip() or 'vmbr0'
    if not _BRIDGE_RE.match(bridge):
        raise ProxmoxError('Invalid network bridge name.')

    ostype = str(params.get('ostype', 'l26')).strip() or 'l26'
    if not re.match(r'^[a-z0-9]{2,8}$', ostype):
        raise ProxmoxError('Invalid OS type.')

    iso = str(params.get('iso', '') or '').strip()
    if iso and not _VOLID_RE.match(iso):
        raise ProxmoxError('Invalid ISO selection.')

    data = {
        'vmid':    vmid,
        'name':    name,
        'cores':   cores,
        'memory':  memory_mb,
        'ostype':  ostype,
        'scsihw':  'virtio-scsi-single',
        'scsi0':   f'{storage}:{disk_gb}',
        'net0':    f'virtio,bridge={bridge}',
        'onboot':  1 if params.get('onboot', False) else 0,
        'start':   1 if params.get('start', False) else 0,
    }
    if iso:
        data['ide2'] = f'{iso},media=cdrom'
        data['boot'] = 'order=ide2;scsi0'

    node = urllib.parse.quote(pc['node'])
    upid = _request(pc, f'/nodes/{node}/qemu', method='POST', data=data)
    return {'ok': True, 'vmid': vmid, 'task': upid if isinstance(upid, str) else ''}


def list_bridges(pc: dict) -> list[str]:
    """Network bridges on the node, for the net0 dropdown — both Linux Bridges
    (type "bridge") AND Open vSwitch bridges (type "OVSBridge"). The old
    `?type=bridge` filter only returned Linux Bridges, so an OVS bridge like
    vmbr1 was missing from the wizard. Best-effort. Proxmox uses the same
    `bridge=<name>` net0 syntax for both, so nothing downstream changes."""
    node = urllib.parse.quote(pc['node'])
    try:
        raw = _request(pc, f'/nodes/{node}/network')
    except ProxmoxError:
        return []
    if not isinstance(raw, list):
        return []
    names = [str(n.get('iface', '')) for n in raw
             if isinstance(n, dict) and n.get('iface')
             and str(n.get('type', '')) in ('bridge', 'OVSBridge')]
    return sorted(n for n in names if _BRIDGE_RE.match(n))


def create_lxc(pc: dict, params: dict) -> dict:
    """Create an LXC container. Validates every field locally before the
    POST so a bad value fails with a clear message, not an opaque 500.

    Expected `params` (already type-coerced by the caller is fine, we
    re-check): vmid, hostname, ostemplate (volid), storage, disk_gb, cores,
    memory_mb, swap_mb, bridge, ip ('dhcp' or CIDR), gateway (optional),
    password (optional), ssh_public_key (optional), unprivileged (bool),
    start (bool), onboot (bool).

    Returns {ok, vmid, task}. Raises ProxmoxError on any validation or API
    failure.
    """
    # ── validate ────────────────────────────────────────────────────
    try:
        vmid = int(params.get('vmid'))
    except (ValueError, TypeError):
        raise ProxmoxError('A numeric VMID is required.') from None
    if not (100 <= vmid <= 999999999):
        raise ProxmoxError('VMID must be between 100 and 999999999.')

    hostname = str(params.get('hostname', '')).strip()
    if not _HOSTNAME_RE.match(hostname):
        raise ProxmoxError('Hostname must be a valid DNS label '
                           '(letters, digits, hyphens; 1–63 chars).')

    ostemplate = str(params.get('ostemplate', '')).strip()
    if not _VOLID_RE.match(ostemplate):
        raise ProxmoxError('Pick an OS template.')

    storage = str(params.get('storage', '')).strip()
    if not _BRIDGE_RE.match(storage):   # same safe charset as a storage id
        raise ProxmoxError('Pick a root-disk storage.')

    def _int(field, lo, hi, label):
        try:
            v = int(params.get(field))
        except (ValueError, TypeError):
            raise ProxmoxError(f'{label} must be a number.') from None
        if not (lo <= v <= hi):
            raise ProxmoxError(f'{label} must be between {lo} and {hi}.')
        return v

    disk_gb   = _int('disk_gb', 1, 8192, 'Disk size (GB)')
    cores     = _int('cores', 1, 512, 'CPU cores')
    memory_mb = _int('memory_mb', 16, 4 * 1024 * 1024, 'Memory (MB)')
    swap_mb   = _int('swap_mb', 0, 4 * 1024 * 1024, 'Swap (MB)') \
        if params.get('swap_mb') not in (None, '') else 0

    bridge = str(params.get('bridge', 'vmbr0')).strip() or 'vmbr0'
    if not _BRIDGE_RE.match(bridge):
        raise ProxmoxError('Invalid network bridge name.')

    ip = str(params.get('ip', 'dhcp')).strip() or 'dhcp'
    if ip != 'dhcp' and not _valid_ipv4_cidr(ip):
        raise ProxmoxError('IP must be "dhcp" or a CIDR like 192.168.1.50/24.')
    gateway = str(params.get('gateway', '')).strip()
    if gateway and not _valid_ipv4(gateway):
        raise ProxmoxError('Gateway must be a plain IPv4 address.')

    password = str(params.get('password', '') or '')
    ssh_key  = str(params.get('ssh_public_key', '') or '').strip()
    if not password and not ssh_key:
        raise ProxmoxError('Set a root password or an SSH public key so you '
                           'can log into the container.')
    if password and len(password) < 5:
        raise ProxmoxError('Root password must be at least 5 characters '
                           '(Proxmox requirement).')

    # ── build the Proxmox payload ───────────────────────────────────
    net0 = f'name=eth0,bridge={bridge},ip={ip}'
    if ip != 'dhcp' and gateway:
        net0 += f',gw={gateway}'

    data = {
        'vmid':        vmid,
        'hostname':    hostname,
        'ostemplate':  ostemplate,
        'rootfs':      f'{storage}:{disk_gb}',
        'cores':       cores,
        'memory':      memory_mb,
        'swap':        swap_mb,
        'net0':        net0,
        'unprivileged': 1 if params.get('unprivileged', True) else 0,
        'onboot':      1 if params.get('onboot', False) else 0,
        'start':       1 if params.get('start', False) else 0,
    }
    if password:
        data['password'] = password
    if ssh_key:
        data['ssh-public-keys'] = ssh_key

    node = urllib.parse.quote(pc['node'])
    upid = _request(pc, f'/nodes/{node}/lxc', method='POST', data=data)
    return {'ok': True, 'vmid': vmid, 'task': upid if isinstance(upid, str) else ''}


def delete_lxc(pc: dict, vmid, auto_stop: bool = True) -> dict:
    """Delete an LXC container. DESTRUCTIVE — Proxmox wipes its rootfs.

    Proxmox refuses to delete a *running* container, so when auto_stop is set
    we force-stop it and poll until it's down (bounded) before issuing the
    DELETE. No purge — backup/replication entries are left alone. Returns
    {ok, vmid, task, stopped}; raises ProxmoxError on any failure.
    """
    try:
        vmid = int(vmid)
    except (ValueError, TypeError):
        raise ProxmoxError('Invalid vmid.') from None

    node = urllib.parse.quote(pc['node'])
    base = f'/nodes/{node}/lxc/{vmid}'

    cur = _request(pc, f'{base}/status/current') or {}
    status = str(cur.get('status', '')).lower()
    stopped_by_us = False
    if status == 'running':
        if not auto_stop:
            raise ProxmoxError('Container is running — stop it first.')
        _request(pc, f'{base}/status/stop', method='POST')   # async on Proxmox
        stopped_by_us = True
        deadline = time.time() + 25
        while time.time() < deadline:
            time.sleep(1.0)
            st = _request(pc, f'{base}/status/current') or {}
            if str(st.get('status', '')).lower() == 'stopped':
                break
        else:
            raise ProxmoxError('Container did not stop within 25 s — not '
                               'deleting. Stop it manually and retry.')

    upid = _request(pc, base, method='DELETE')   # no purge param
    return {'ok': True, 'vmid': vmid,
            'task': upid if isinstance(upid, str) else '',
            'stopped': stopped_by_us}


def test_connection(pc: dict) -> dict:
    """Probe the Proxmox connection for the Settings 'Test' button.

    Returns {ok: bool, message: str, node_count: int}. Never raises —
    failures come back as ok:false with a human-readable message so
    the settings UI can show them inline.
    """
    if not is_configured(pc):
        return {'ok': False,
                'message': 'Host, node, token id and token secret are '
                           'all required.'}
    try:
        nodes = _request(pc, '/nodes')
    except ProxmoxError as e:
        return {'ok': False, 'message': str(e)}
    if not isinstance(nodes, list):
        return {'ok': False,
                'message': 'Unexpected response from Proxmox /nodes.'}
    node_names = [str(n.get('node', '')) for n in nodes if isinstance(n, dict)]
    if pc['node'] not in node_names:
        return {'ok': False,
                'message': f"Connected, but node '{pc['node']}' was not "
                           f"found. Available: {', '.join(node_names) or '—'}."}
    return {'ok': True,
            'message': f"Connected to Proxmox — node '{pc['node']}' found.",
            'node_count': len(node_names)}


# ── v3.14.0 (#33): VM/CT lifecycle (destructive — gated server-side) ─────────
# Power + snapshot + clone + migrate via the PVE API. These are the actions a
# Proxmox API token with the right privileges can perform; the RemotePower
# server gates *who* may call them (admin + per-deployment opt-in + audit) in
# api.py. Every call returns the PVE task UPID string (or None).
_POWER_ACTIONS = ('start', 'stop', 'shutdown', 'reboot', 'suspend', 'resume')
LIFECYCLE_ACTIONS = _POWER_ACTIONS + ('snapshot', 'snapshot_delete', 'clone', 'migrate')


def lifecycle(pc: dict, guest_type: str, vmid, action: str,
              params: dict | None = None):
    """Perform one lifecycle action on a guest. Raises ProxmoxError on bad
    input or API failure. `params` carries action-specific fields:
      snapshot         → {snapname, description?}
      snapshot_delete  → {snapname}
      clone            → {newid, name?, full?}
      migrate          → {target, online?}
    """
    params = params or {}
    if guest_type not in _GUEST_TYPES:
        raise ProxmoxError('Unknown guest type.')
    if action not in LIFECYCLE_ACTIONS:
        raise ProxmoxError(f'Unsupported action: {action}')
    try:
        vmid = int(vmid)
    except (TypeError, ValueError):
        raise ProxmoxError('Invalid vmid.')
    base = f"/nodes/{pc['node']}/{guest_type}/{vmid}"

    if action in _POWER_ACTIONS:
        return _request(pc, f'{base}/status/{action}', 'POST')

    if action == 'snapshot':
        snap = str(params.get('snapname', '')).strip()
        if not re.match(r'^[A-Za-z][A-Za-z0-9_\-]{0,39}$', snap):
            raise ProxmoxError('Snapshot name must be 1–40 chars [A-Za-z0-9_-], letter-first.')
        data = {'snapname': snap}
        if params.get('description'):
            data['description'] = str(params['description'])[:200]
        return _request(pc, f'{base}/snapshot', 'POST', data)

    if action == 'snapshot_delete':
        snap = str(params.get('snapname', '')).strip()
        if not re.match(r'^[A-Za-z][A-Za-z0-9_\-]{0,39}$', snap):
            raise ProxmoxError('Invalid snapshot name.')
        return _request(pc, f'{base}/snapshot/{urllib.parse.quote(snap)}', 'DELETE')

    if action == 'clone':
        try:
            newid = int(params.get('newid'))
        except (TypeError, ValueError):
            raise ProxmoxError('clone requires a numeric newid.')
        data = {'newid': newid}
        if params.get('name'):
            data['name'] = str(params['name'])[:64]
        if params.get('full') is not None:
            data['full'] = 1 if params['full'] else 0
        return _request(pc, f'{base}/clone', 'POST', data)

    # migrate
    target = str(params.get('target', '')).strip()
    if not re.match(r'^[A-Za-z0-9_\-.]{1,64}$', target):
        raise ProxmoxError('migrate requires a valid target node name.')
    data = {'target': target}
    if params.get('online') is not None:
        data['online'] = 1 if params['online'] else 0
    return _request(pc, f'{base}/migrate', 'POST', data)
