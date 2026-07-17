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
