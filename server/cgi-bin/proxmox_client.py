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
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT,
                                    context=ctx) as resp:
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
