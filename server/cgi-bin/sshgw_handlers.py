"""RemotePower — SSH gateway: operator public keys, per-device opt-in, and the
daemon's authorize / agent-check / audit endpoints.

The gateway daemon (server/sshgw/remotepower-sshgw.py) holds no policy of its
own. It asks this module three questions over loopback, authenticated with the
shared secret in config `sshgw_daemon_secret`:

  * POST /api/sshgw/agent-check — is this device token valid, and has the
    device been opted in? (asked when an agent opens its tunnel)
  * POST /api/sshgw/authorize   — may this user's key reach this target?
    (asked at SSH login with no target, then again for every channel)
  * POST /api/sshgw/audit       — a stream finished; record it.

Keeping the decision here means the role, scope and tenancy rules that every
other device action follows apply to the gateway unchanged, instead of being
re-implemented in a second process.

A bound-module carve-out following the tls_ct_handlers / dmarc_handlers /
rack_ipam_handlers pattern:

  - api.py execs a PRIVATE instance and binds its own ``globals()`` here, so
    every api service is reached as ``A.<name>`` — a DYNAMIC attribute lookup,
    which keeps the test suite's monkeypatching of api.respond / api.save / …
    working, and resolves identically under the CGI (__main__) and
    imported-module (wsgi.py/scheduler.py) models.
  - api.py then from-imports every public + private name back into its own
    globals, so the route tables, main()'s _safe() cadence and scheduler.py's
    CADENCE tuple keep resolving the names unchanged.
  - Calls BETWEEN these functions ALSO go through ``A.`` so a test that patches
    one of them is seen by its caller.

Constants stay in api.py and are read here through A. Pure logic goes in a
sibling module (imported directly, like dmarc_monitor / tls_monitor).
"""


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



import hmac
import os
import secrets
import time
import urllib.parse

import sshgw

SESSIONS_CAP = 2000
STATE_CAP = 5000


# ── shared checks ──────────────────────────────────────────────────────────────

def _daemon_secret():
    """The secret the gateway daemon must present. Settings wins; otherwise
    RP_SSHGW_SECRET from the app server's environment (/etc/remotepower/api.env),
    which is how install-server.sh --with-sshgw wires both sides without anyone
    pasting it. Process-level deploy config, not request data."""
    cfg = A._config_ro() or {}
    return str(cfg.get('sshgw_daemon_secret') or os.environ.get('RP_SSHGW_SECRET', '') or '')


def _require_daemon():
    """403 unless the request carries the gateway daemon's shared secret."""
    expected = _daemon_secret()
    provided = A._env('HTTP_X_SSHGW_SECRET', '')
    if not expected or not provided or not hmac.compare_digest(expected, provided):
        A.respond(403, {'error': 'Daemon secret mismatch'})


def _require_module():
    if not A._module_on('sshgw'):
        A.respond(404, {'error': 'The SSH gateway module is turned off'})


def _user_keys(user_rec):
    keys = (user_rec or {}).get('sshgw_keys')
    return [k for k in keys if isinstance(k, dict)] if isinstance(keys, list) else []


def _key_public(k, username=None):
    row = {
        'fingerprint': k.get('fingerprint', ''),
        'type': k.get('type', ''),
        'name': k.get('name', ''),
        'comment': k.get('comment', ''),
        'added': int(k.get('added') or 0),
        'last_used': int(k.get('last_used') or 0),
    }
    if username is not None:
        row['username'] = username
    return row


def _user_may_reach(username, user_rec, dev):
    """(True, '') when this user's role, scope and tenant admit the device.

    The gateway has no request token for the user — the SSH key is the
    credential — so this evaluates the account's own role record directly,
    with the same rules require_perm('ssh', …) and the tenant gate apply to a
    logged-in caller.
    """
    if not isinstance(user_rec, dict) or user_rec.get('disabled'):
        return False, 'account disabled'
    role = user_rec.get('role') or 'viewer'
    rd = A._resolve_role(role)
    if not rd.get('admin'):
        if 'ssh' not in rd.get('permissions', set()):
            return False, "role lacks the 'ssh' permission"
        scope = rd.get('scope') or {'type': 'all'}
        if scope.get('type', 'all') != 'all' and not A._device_in_scope(scope, dev):
            return False, 'device outside role scope'
    if A._tenancy_enforced():
        tenant = A._user_tenant(username)
        superadmin = role == 'admin' and tenant == A.DEFAULT_TENANT
        if not superadmin and A._device_tenant(dev) != tenant:
            return False, 'device belongs to another tenant'
    return True, ''


def _device_gateway_ok(dev):
    """(True, '') when the device may be reached through the gateway at all."""
    if not isinstance(dev, dict):
        return False, 'unknown device'
    if not dev.get('sshgw_enabled'):
        return False, 'device is not opted in to the SSH gateway'
    if dev.get('decommissioned'):
        return False, 'device is decommissioned'
    if A._device_quarantined(dev):
        return False, 'device is quarantined'
    return True, ''


def _stamp_state(dev_id, **fields):
    with A._LockedUpdate(A.SSHGW_STATE_FILE) as st:
        if not isinstance(st, dict):
            st.clear()
        row = st.get(dev_id) if isinstance(st.get(dev_id), dict) else {}
        row.update(fields)
        st[dev_id] = row
        if len(st) > STATE_CAP:
            for k in sorted(st, key=lambda d: (st[d] or {}).get('tunnel_seen', 0))[:len(st) - STATE_CAP]:
                st.pop(k, None)


# ── operator endpoints ─────────────────────────────────────────────────────────

def handle_sshgw_keys():
    """GET /api/sshgw/keys — your registered public keys (admins also get every
    account's keys, for revocation). POST — register a key {public_key, name,
    password|totp_code}. DELETE — remove one {fingerprint[, username]}."""
    m = A.method()
    if m == 'GET':
        actor = A.require_auth()
        users = A._load_ro(A.USERS_FILE) or {}
        out = {'ok': True,
               'keys': [_key_public(k) for k in _user_keys(users.get(actor))]}
        role = A.verify_token(A.get_token_from_request())[1]
        if A._resolve_role(role).get('admin'):
            rows = []
            for uname, rec in users.items():
                if not isinstance(rec, dict) or not A._user_tenant_visible(uname):
                    continue
                rows.extend(_key_public(k, uname) for k in _user_keys(rec))
            out['all_keys'] = sorted(rows, key=lambda r: (r['username'], r['name']))
        A.respond(200, out)

    if m == 'POST':
        actor = A.require_write_role('register SSH gateway keys')
        # A key is a standing credential, so only a person may add one: an API
        # key has no account of its own to attach it to, and its `user` field is
        # a display label rather than a login.
        tkey, _entry, _tokens = A._step_up_token_entry()
        if not tkey:
            A.respond(403, {'error': 'Register SSH keys from a signed-in session, not an API key'})
        body = A._read_valid(A.request_models.SshgwKeyAddRequest)
        users = A._load_ro(A.USERS_FILE) or {}
        me = users.get(actor) or {}
        # Re-verify the person: a stolen session should not be able to plant a
        # credential that outlives it. Accounts with no local password and no
        # TOTP (SSO-only) have nothing to re-verify, matching require_step_up.
        if me.get('password_hash') or me.get('totp_secret'):
            ok = False
            pw = str(body.get('password') or '')
            if me.get('password_hash') and pw:
                ok = A.verify_password(pw, me['password_hash'])
            code = str(body.get('totp_code') or '').strip()
            if not ok and me.get('totp_secret') and code:
                ok = code in A._totp(me['totp_secret'])
            if not ok:
                A.audit_log(actor, 'sshgw_key_add_failed', 'password/TOTP did not verify')
                A.respond(403, {'error': 'Password or TOTP code did not verify'})
        try:
            parsed = sshgw.parse_public_key(body.get('public_key', ''))
        except ValueError as e:
            A.respond(400, {'error': str(e)})
        fp = parsed['fingerprint']
        for uname, rec in users.items():
            if any(k.get('fingerprint') == fp for k in _user_keys(rec)):
                A.respond(409, {'error': 'That key is already registered'
                                         + ('' if uname != actor else ' on your account')})
        name = sshgw.clean_key_name(body.get('name'), parsed['comment'] or parsed['type'])
        entry = {'fingerprint': fp, 'type': parsed['type'],
                 'key': f"{parsed['type']} {parsed['b64']}",
                 'name': name, 'comment': parsed['comment'],
                 'added': int(time.time()), 'last_used': 0}
        with A._LockedUpdate(A.USERS_FILE) as store:
            rec = store.get(actor)
            if not isinstance(rec, dict):
                A.respond(404, {'error': 'User not found'})
            keys = _user_keys(rec)
            if len(keys) >= sshgw.MAX_KEYS_PER_USER:
                A.respond(400, {'error': f'At most {sshgw.MAX_KEYS_PER_USER} keys per account'})
            keys.append(entry)
            rec['sshgw_keys'] = keys
        A.audit_log(actor, 'sshgw_key_added', f'fp={fp} type={parsed["type"]} name={name}')
        A.respond(200, {'ok': True, 'key': _key_public(entry)})

    if m == 'DELETE':
        actor = A.require_auth()
        body = A._read_valid(A.request_models.SshgwKeyDeleteRequest)
        fp = str(body.get('fingerprint') or '')
        if not sshgw.valid_fingerprint(fp):
            A.respond(400, {'error': 'fingerprint required'})
        owner = str(body.get('username') or '') or actor
        if owner != actor:
            # Revoking someone else's key is an admin action, inside the
            # admin's own tenant.
            role = A.verify_token(A.get_token_from_request())[1]
            if not A._resolve_role(role).get('admin'):
                A.respond(403, {'error': 'This action requires admin role'})
            if not A._user_tenant_visible(owner):
                A.respond(404, {'error': 'Key not found'})
        removed = False
        with A._LockedUpdate(A.USERS_FILE) as store:
            rec = store.get(owner)
            if isinstance(rec, dict):
                keys = _user_keys(rec)
                kept = [k for k in keys if k.get('fingerprint') != fp]
                removed = len(kept) != len(keys)
                if removed:
                    rec['sshgw_keys'] = kept
        if not removed:
            A.respond(404, {'error': 'Key not found'})
        A.audit_log(actor, 'sshgw_key_removed', f'owner={owner} fp={fp}')
        A.respond(200, {'ok': True})

    A.respond(405, {'error': 'Method not allowed'})


def handle_sshgw_status():
    """GET /api/sshgw/status — what the SSH gateway page needs to render: the
    public endpoint to put in ~/.ssh/config, whether the caller's role may use
    the gateway, and whether the daemon secret has been set."""
    actor = A.require_auth()
    cfg = A._config_ro() or {}
    role = A.verify_token(A.get_token_from_request())[1]
    rd = A._resolve_role(role)
    users = A._load_ro(A.USERS_FILE) or {}
    A.respond(200, {
        'ok': True,
        'enabled': A._module_on('sshgw'),
        'public_host': str(cfg.get('sshgw_public_host') or ''),
        'public_port': int(cfg.get('sshgw_public_port') or 2222),
        'daemon_secret_set': bool(_daemon_secret()),
        'username': actor,
        'can_connect': bool(rd.get('admin') or 'ssh' in rd.get('permissions', set())),
        'is_admin': bool(rd.get('admin')),
        'key_count': len(_user_keys(users.get(actor))),
        'target_suffix': sshgw.TARGET_SUFFIX,
    })


def handle_sshgw_devices():
    """GET /api/sshgw/devices — the devices the caller can see, with their
    gateway opt-in and when each agent last opened its tunnel."""
    A.require_auth()
    devices = A._scope_filter_devices(A._load_ro(A.DEVICES_FILE) or {})
    state = A._load_ro(A.SSHGW_STATE_FILE) or {}
    rows = []
    for did, dev in devices.items():
        if not isinstance(dev, dict) or dev.get('agentless'):
            continue
        st = state.get(did) if isinstance(state.get(did), dict) else {}
        os_name = str(dev.get('os') or (dev.get('sysinfo') or {}).get('os') or '')
        rows.append({
            'device_id': did,
            'name': dev.get('name') or did,
            'hostname': dev.get('hostname') or '',
            'os': os_name,
            'linux': A._sshgw_is_linux(dev),
            'enabled': bool(dev.get('sshgw_enabled')),
            'tunnel_seen': int(st.get('tunnel_seen') or 0),
            'last_session': int(st.get('last_session') or 0),
        })
    rows.sort(key=lambda r: str(r['name']).lower())
    A.respond(200, {'ok': True, 'devices': rows})


def _sshgw_is_linux(dev):
    """The first version carries the tunnel in the Linux agent only."""
    return A._device_os_family(dev) == 'linux'


def handle_device_sshgw(dev_id):
    """GET /api/devices/<id>/sshgw — opt-in state. PATCH {enabled} — admin only:
    turning it on gives every user whose role holds 'ssh' a path to this host's
    sshd. The host's own sshd still decides who may log in."""
    if not A._validate_id(dev_id):
        A.respond(400, {'error': 'invalid device id'})
    m = A.method()
    if m == 'GET':
        A.require_auth()
        dev = A.device_get(dev_id)
        if dev is None:
            A.respond(404, {'error': 'Device not found'})
        st = (A._load_ro(A.SSHGW_STATE_FILE) or {}).get(dev_id) or {}
        A.respond(200, {'ok': True, 'enabled': bool(dev.get('sshgw_enabled')),
                        'module_enabled': A._module_on('sshgw'),
                        'tunnel_seen': int(st.get('tunnel_seen') or 0)})
    if m != 'PATCH':
        A.respond(405, {'error': 'Method not allowed'})
    actor = A.require_admin_auth()
    _require_module()
    body = A._read_valid(A.request_models.SshgwDeviceRequest)
    enabled = bool(body.get('enabled'))
    with A._DeviceUpdate(dev_id) as devices:
        dev = devices.get(dev_id)
        if not isinstance(dev, dict):
            A.respond(404, {'error': 'Device not found'})
        if enabled and not A._sshgw_is_linux(dev):
            A.respond(409, {'error': 'The SSH gateway tunnel is available on Linux agents only'})
        dev['sshgw_enabled'] = enabled
        name = dev.get('name', dev_id)
    A.audit_log(actor, 'sshgw_device_' + ('enabled' if enabled else 'disabled'),
                f'device={dev_id} name={name}')
    A.respond(200, {'ok': True, 'enabled': enabled})


def handle_sshgw_sessions():
    """GET /api/sshgw/sessions — finished gateway sessions, newest first.
    Admins and auditors; rows are limited to devices the caller can see."""
    A.require_admin_or_auditor_auth()
    store = A._load_ro(A.SSHGW_SESSIONS_FILE) or {}
    rows = store.get('sessions') if isinstance(store, dict) else None
    rows = rows if isinstance(rows, list) else []
    visible = A._scope_filter_devices(A._load_ro(A.DEVICES_FILE) or {})
    out = [dict(r) for r in rows
           if isinstance(r, dict) and (not r.get('device_id') or r.get('device_id') in visible)]
    out.sort(key=lambda r: int(r.get('started') or 0), reverse=True)
    A.respond(200, {'ok': True, 'sessions': out[:500]})


def handle_sshgw_sessions_clear():
    """DELETE /api/sshgw/sessions — admin. Empties the session list the page
    shows. The audit log keeps its `sshgw_open` and `sshgw_denied` lines, so
    clearing hides history from this card without erasing who connected.

    Rows are removed only for what the caller could see in the list. An admin
    scoped to part of the fleet, or a tenant admin, leaves the rest alone; rows
    whose device no longer exists go only to an unscoped platform admin."""
    if A.method() != 'DELETE':
        A.respond(405, {'error': 'Method not allowed'})
    actor = A.require_admin_auth()
    _require_module()
    everything = A._load_ro(A.DEVICES_FILE) or {}
    visible = A._scope_filter_devices(everything)
    unscoped = A._caller_scope() is None and not (A._tenancy_enforced() and not A._caller_is_superadmin())
    removed = 0
    with A._LockedUpdate(A.SSHGW_SESSIONS_FILE) as store:
        rows = store.get('sessions') if isinstance(store.get('sessions'), list) else []
        keep = []
        for r in rows:
            did = r.get('device_id') if isinstance(r, dict) else None
            gone = bool(did) and did not in everything
            if not isinstance(r, dict) or not did or did in visible or (gone and unscoped):
                removed += 1
            else:
                keep.append(r)
        store['sessions'] = keep
    A.audit_log(actor, 'sshgw_sessions_cleared', f'removed={removed}')
    A.respond(200, {'ok': True, 'removed': removed})


# ── daemon endpoints ───────────────────────────────────────────────────────────

def handle_sshgw_agent_check():
    """POST /api/sshgw/agent-check {device_id, token} — daemon only. 200 when
    the token is the device's own and the device is opted in; 403 otherwise."""
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    _require_daemon()
    body = A._read_valid(A.request_models.SshgwAgentCheckRequest)
    dev_id = str(body.get('device_id') or '')
    if not A._validate_id(dev_id):
        A.respond(400, {'error': 'invalid device id'})
    dev = A.device_get(dev_id)
    if dev is None or not A._device_token_ok(dev, str(body.get('token') or '')):
        A.respond(403, {'ok': False, 'error': 'device authentication failed'})
    ok, why = _device_gateway_ok(dev)
    if not ok:
        A.respond(403, {'ok': False, 'error': why})
    _stamp_state(dev_id, tunnel_seen=int(time.time()))
    A.respond(200, {'ok': True, 'device_id': dev_id})


def handle_sshgw_authorize():
    """POST /api/sshgw/authorize {username, fingerprint, target, client_ip} —
    daemon only.

    Without a target: is this key registered to this account? (SSH login.)
    With a target: may the account reach it right now? (each direct-tcpip
    channel.) The answer is re-derived every time, so revoking a key, removing
    the 'ssh' permission or opting a device out takes effect on the next
    channel without restarting anything.
    """
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    _require_daemon()
    body = A._read_valid(A.request_models.SshgwAuthorizeRequest)
    username = A._sanitize_str(str(body.get('username') or ''), 64)
    fp = str(body.get('fingerprint') or '')
    target = str(body.get('target') or '')
    client_ip = A._sanitize_str(str(body.get('client_ip') or ''), 64)
    users = A._load_ro(A.USERS_FILE) or {}
    rec = users.get(username)
    if (not sshgw.valid_fingerprint(fp) or not isinstance(rec, dict)
            or rec.get('disabled')
            or not any(k.get('fingerprint') == fp for k in _user_keys(rec))):
        # One answer for "no such user" and "wrong key", so the gateway cannot
        # be used to enumerate account names.
        A.respond(403, {'ok': False, 'error': 'key not authorized'})
    if not target:
        A.respond(200, {'ok': True, 'username': username})

    def _deny(why):
        A.audit_log(username, 'sshgw_denied',
                    f'target={target[:120]} reason={why} ip={client_ip} fp={fp}')
        A.respond(403, {'ok': False, 'error': why})

    # Resolve the name among the devices this account may reach and that are
    # opted in, so a name that exists only in another tenant reads the same as
    # one that does not exist, and cannot collide with a reachable one.
    devices = A._load_ro(A.DEVICES_FILE) or {}
    reachable = {}
    for did, dev in devices.items():
        if _device_gateway_ok(dev)[0] and _user_may_reach(username, rec, dev)[0]:
            reachable[did] = dev
    dev_id, why = sshgw.resolve_target(reachable, target)
    if not dev_id:
        _deny(why or 'no such device')
    session_id = secrets.token_hex(8)
    now = int(time.time())
    with A._LockedUpdate(A.USERS_FILE) as store:
        r = store.get(username)
        if isinstance(r, dict):
            for k in _user_keys(r):
                if k.get('fingerprint') == fp:
                    k['last_used'] = now
    dev = reachable[dev_id]
    A.audit_log(username, 'sshgw_open',
                f'device={dev_id} name={dev.get("name", dev_id)} session={session_id} '
                f'ip={client_ip} fp={fp}')
    A.respond(200, {'ok': True, 'username': username, 'device_id': dev_id,
                    'device_name': dev.get('name') or dev_id,
                    'session_id': session_id})


def handle_sshgw_audit():
    """POST /api/sshgw/audit — daemon only. One finished stream."""
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    _require_daemon()
    body = A._read_valid(A.request_models.SshgwAuditRequest)
    s = A._sanitize_str
    row = {
        'session_id': s(str(body.get('session_id') or ''), 32),
        'username': s(str(body.get('username') or ''), 64),
        'fingerprint': s(str(body.get('fingerprint') or ''), 80),
        'device_id': s(str(body.get('device_id') or ''), 64),
        'target': s(str(body.get('target') or ''), 128),
        'client_ip': s(str(body.get('client_ip') or ''), 64),
        'started': max(0, int(body.get('started') or 0)),
        'duration_s': max(0, int(body.get('duration_s') or 0)),
        'bytes_in': max(0, int(body.get('bytes_in') or 0)),
        'bytes_out': max(0, int(body.get('bytes_out') or 0)),
        'reason': s(str(body.get('reason') or ''), 128),
    }
    if row['device_id'] and not A._validate_id(row['device_id']):
        A.respond(400, {'error': 'invalid device id'})
    with A._LockedUpdate(A.SSHGW_SESSIONS_FILE) as store:
        rows = store.get('sessions') if isinstance(store.get('sessions'), list) else []
        rows.append(row)
        store['sessions'] = rows[-SESSIONS_CAP:]
    if row['device_id']:
        _stamp_state(row['device_id'], last_session=row['started'] + row['duration_s'])
    A.audit_log(row['username'] or 'unknown', 'sshgw_session',
                (f"device={row['device_id']} session={row['session_id']} "
                 f"duration={row['duration_s']}s bytes_in={row['bytes_in']} "
                 f"bytes_out={row['bytes_out']} ip={row['client_ip']} "
                 f"reason={row['reason']}")[:600])
    A.respond(200, {'ok': True})
