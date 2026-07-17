"""RemotePower — per-device SSH management for agentless devices: the SSH
credential config (write-only password OR private key, per-device opt-in) and
the one built-in action, the Synology DSM upgrade+reboot over SSH.

Agentless devices have no RemotePower agent, and some jobs have no management
API either (a Synology can't trigger its own DSM upgrade via SNMP) — but root
SSH can. A deliberately tiny, gated surface: admin-only + audited + per-device
opt-in; the exec lives in the ssh_exec.py sibling (imported per-call).

A bound-module carve-out following the dmarc/netappliance pattern: api.py execs
a PRIVATE instance, binds its own ``globals()`` here (every api service reached
as ``A.<name>`` — a dynamic lookup that keeps the suite's monkeypatching +
inspect.getsource assertions working), then re-imports the names back so the
route table resolves unchanged. DEVICES_FILE stays in api.py, read via A. Both
handlers live under /api/devices/<id>/… so main()'s _enforce_device_scope covers
their tenancy/scope. (NB: this _ssh_target is the agentless-device SSH-config
accessor — distinct from the RouterOS/OPNsense targets and from ssh_exec's own
connection plumbing.)
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


def _ssh_target(dev):
    """{host, user, port, password, key} for an SSH-enabled device, or None."""
    cfg = dev.get('ssh') or {}
    if not cfg.get('enabled'):
        return None
    host = dev.get('ip') or dev.get('hostname') or dev.get('host')
    if not host:
        return None
    if not (cfg.get('password') or cfg.get('private_key')):
        return None
    return {
        'host':     host,
        'user':     cfg.get('username') or 'root',
        'port':     int(cfg.get('port') or 22),
        'password': cfg.get('password') or None,
        'key':      cfg.get('private_key') or None,
    }


def _ssh_redacted(dev):
    cfg = dev.get('ssh') or {}
    return {
        'enabled':      bool(cfg.get('enabled')),
        'username':     cfg.get('username') or 'root',
        'port':         int(cfg.get('port') or 22),
        'has_password': bool(cfg.get('password')),
        'has_key':      bool(cfg.get('private_key')),
    }


def handle_device_ssh(dev_id):
    """GET /api/devices/<id>/ssh — redacted SSH config. PATCH — admin; save
    {enabled, username, port, password, private_key} (empty password/key
    preserves the stored one). For agentless management actions over SSH."""
    if not A._validate_id(dev_id):
        A.respond(400, {'error': 'invalid device id'})
    devs = A.load(A.DEVICES_FILE)
    if dev_id not in devs:
        A.respond(404, {'error': 'device not found'})
    m = A.method()
    if m == 'GET':
        A.require_auth()
        A.respond(200, {'config': A._ssh_redacted(devs[dev_id])})
    elif m == 'PATCH':
        actor = A.require_admin_auth()
        body = A._read_valid(A.request_models.DeviceSshRequest)
        with A._LockedUpdate(A.DEVICES_FILE) as store:
            dev = store.get(dev_id) or {}
            sc = dict(dev.get('ssh') or {})
            if 'enabled' in body:
                sc['enabled'] = bool(body['enabled'])
            if 'username' in body:
                sc['username'] = A._sanitize_str(str(body['username']), 64) or 'root'
            if 'port' in body:
                try:
                    p = int(body['port'])
                    if 1 <= p <= 65535:
                        sc['port'] = p
                except (TypeError, ValueError):
                    A.respond(400, {'error': 'port must be 1..65535'})
            if 'password' in body:
                pw = str(body['password'])
                if pw:                       # empty preserves existing
                    sc['password'] = pw[:256]
            if 'private_key' in body:
                k = str(body['private_key'])
                if k:                        # empty preserves existing
                    sc['private_key'] = k[:8192]
            if sc.get('enabled') and not (sc.get('password') or sc.get('private_key')):
                A.respond(400, {'error': 'an SSH key or password is required when SSH is enabled'})
            dev['ssh'] = sc
            store[dev_id] = dev
        A.audit_log(actor, 'device_ssh_config',
                    f'dev={dev_id} enabled={sc.get("enabled")} user={sc.get("username")}')
        A.respond(200, {'ok': True, 'config': A._ssh_redacted({'ssh': sc})})
    else:
        A.respond(405, {'error': 'Method not allowed'})


def handle_device_synology_upgrade(dev_id):
    """POST /api/devices/<id>/synology/upgrade — SSH in and launch the DSM
    upgrade + reboot. admin-only, audited, gated on the SSH opt-in."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    if not A._validate_id(dev_id):
        A.respond(400, {'error': 'invalid device id'})
    dev = A.device_get(dev_id)
    if not dev:
        A.respond(404, {'error': 'device not found'})
    tgt = A._ssh_target(dev)
    if not tgt:
        A.respond(403, {'error': 'SSH not enabled/configured on this device. '
                                 'Add SSH credentials first.'})
    import ssh_exec
    A.audit_log(actor, 'device_synology_upgrade',
                f'dev={dev_id} host={tgt["host"]} user={tgt["user"]}')
    try:
        res = ssh_exec.synology_upgrade(tgt['host'], tgt['user'], tgt['port'],
                                        password=tgt['password'], key=tgt['key'])
    except ssh_exec.SshError as e:
        A.respond(502, {'error': str(e)[:300]})
    except Exception as e:
        A.respond(502, {'error': f'{type(e).__name__}: {e}'[:300]})
    if not res.get('ok'):
        A.respond(502, {'error': res.get('error', 'upgrade failed to start')})
    A.respond(200, res)
