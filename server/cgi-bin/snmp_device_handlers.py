"""RemotePower — per-device SNMP: the SNMP config (v2c community / SNMPv3
credentials, write-only secrets) + latest polled data, the on-demand poll, and
the on-demand "deep" read (interface table + Host Resources MIB + vendor-specific
health). Polling itself lives in the snmp.py sibling; the cadence sweep + the
_device_snmp_target / _do_snmp_poll helpers stay in api.py.

A bound-module carve-out following the dmarc/netappliance pattern: api.py execs
a PRIVATE instance, binds its own ``globals()`` here (every api service reached
as ``A.<name>`` — a dynamic lookup that keeps the suite's monkeypatching
working), then re-imports the names back so the route table resolves unchanged.
DEVICES_FILE / SNMP_DATA_FILE / SNMP_TRAPS_FILE + the _device_snmp_target /
_do_snmp_poll helpers stay in api.py, read via A. All handlers live under
/api/devices/<id>/… so main()'s _enforce_device_scope covers their tenancy/scope.
"""
import time


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


def handle_device_snmp(dev_id):
    """GET/PATCH /api/devices/<id>/snmp

    GET   → returns the device's SNMP config + latest polled data.
    PATCH → admin-only; saves SNMP config (community, port, enabled).
    """
    if not A._validate_id(dev_id):
        A.respond(400, {'error': 'invalid device id'})
    devs = A.load(A.DEVICES_FILE)
    if dev_id not in devs:
        A.respond(404, {'error': 'device not found'})
    m = A.method()
    if m == 'GET':
        A.require_auth()
        snmp_cfg = devs[dev_id].get('snmp') or {}
        # Redact community for the GET — show prefix only. v3 secrets are
        # fully write-only (has_* booleans, never a preview).
        community = snmp_cfg.get('community') or ''
        redacted_cfg = {
            'enabled':            bool(snmp_cfg.get('enabled')),
            'port':               int(snmp_cfg.get('port') or 161),
            'community_preview':  (community[:3] + '…') if community else '',
            'has_community':      bool(community),
            'version':            str(snmp_cfg.get('version') or '2c'),
            'v3_user':            snmp_cfg.get('v3_user') or '',
            'v3_auth_proto':      snmp_cfg.get('v3_auth_proto') or 'none',
            'v3_priv_proto':      snmp_cfg.get('v3_priv_proto') or 'none',
            'v3_context':         snmp_cfg.get('v3_context') or '',
            'has_v3_auth_secret': bool(snmp_cfg.get('v3_auth_secret')),
            'has_v3_priv_secret': bool(snmp_cfg.get('v3_priv_secret')),
        }
        data = A.load(A.SNMP_DATA_FILE).get(dev_id) or {}
        traps = A.load(A.SNMP_TRAPS_FILE).get(dev_id) or []
        A.respond(200, {'config': redacted_cfg, 'data': data, 'traps': traps[-50:][::-1]})
    elif m == 'PATCH':
        actor = A.require_admin_auth()
        body = A._read_valid(A.request_models.DeviceSnmpRequest)
        if 'community' in body:
            c = str(body['community'])
            if any(ws in c for ws in (' ', '\t', '\n', '\r')):
                A.respond(400, {'error': 'community must not contain whitespace'})
            if len(c) > 128:
                A.respond(400, {'error': 'community too long (max 128)'})
        port_in = None
        if 'port' in body:
            try:
                port_in = int(body['port'])
                if not (1 <= port_in <= 65535):
                    A.respond(400, {'error': 'port must be 1..65535'})
            except (TypeError, ValueError):
                A.respond(400, {'error': 'port must be an integer'})
        # v5.8.0: SNMPv3 fields. Validate protocols against what snmp.py
        # actually implements (DES is deliberately rejected there — broken
        # cipher), so a typo'd protocol fails at save, not at poll time.
        import snmp as _snmp_mod
        if 'version' in body and str(body['version']) not in ('2c', '3'):
            A.respond(400, {'error': "version must be '2c' or '3'"})
        if 'v3_auth_proto' in body and \
                str(body['v3_auth_proto']).lower() not in _snmp_mod.V3_AUTH_PROTOCOLS:
            A.respond(400, {'error': 'v3_auth_proto must be one of: '
                                     + ', '.join(_snmp_mod.V3_AUTH_PROTOCOLS)})
        if 'v3_priv_proto' in body and \
                str(body['v3_priv_proto']).lower() not in _snmp_mod.V3_PRIV_PROTOCOLS:
            A.respond(400, {'error': 'v3_priv_proto must be one of: '
                                     + ', '.join(_snmp_mod.V3_PRIV_PROTOCOLS)
                                     + ' (DES is not supported — broken cipher)'})
        for sk in ('v3_auth_secret', 'v3_priv_secret'):
            if body.get(sk) and len(str(body[sk])) < 8:
                A.respond(400, {'error': f'{sk} must be at least 8 characters '
                                         '(RFC 3414 minimum)'})
        with A._LockedUpdate(A.DEVICES_FILE) as store:
            dev = store.get(dev_id) or {}
            snmp_cfg = dict(dev.get('snmp') or {})
            if 'enabled' in body:
                snmp_cfg['enabled'] = bool(body['enabled'])
            if 'community' in body:
                snmp_cfg['community'] = A._sanitize_str(str(body['community']), 128)
            if port_in is not None:
                snmp_cfg['port'] = port_in
            if 'version' in body:
                snmp_cfg['version'] = str(body['version'])
            if 'v3_user' in body:
                snmp_cfg['v3_user'] = A._sanitize_str(str(body['v3_user']), 64)
            if 'v3_auth_proto' in body:
                snmp_cfg['v3_auth_proto'] = str(body['v3_auth_proto']).lower()
            if 'v3_priv_proto' in body:
                snmp_cfg['v3_priv_proto'] = str(body['v3_priv_proto']).lower()
            if 'v3_context' in body:
                snmp_cfg['v3_context'] = A._sanitize_str(str(body['v3_context']), 64)
            # Secrets are write-only: a blank/absent field keeps the stored
            # value (the integrations pattern), so re-saving the form doesn't
            # wipe them.
            for sk in ('v3_auth_secret', 'v3_priv_secret'):
                if body.get(sk):
                    snmp_cfg[sk] = A._sanitize_str(str(body[sk]), 128)
            # If enabling, require a complete credential set + a reachable
            # host on the device record. Catches the "I ticked enabled but
            # forgot the community/user" path before the polling layer sees
            # nothing to do.
            if snmp_cfg.get('enabled'):
                if str(snmp_cfg.get('version') or '2c') == '3':
                    ap = snmp_cfg.get('v3_auth_proto') or 'none'
                    pp = snmp_cfg.get('v3_priv_proto') or 'none'
                    if not snmp_cfg.get('v3_user'):
                        A.respond(400, {'error': 'v3_user required when SNMPv3 '
                                                 'is enabled'})
                    if pp != 'none' and ap == 'none':
                        A.respond(400, {'error': 'privacy requires authentication '
                                                 '(authPriv) — pick an auth protocol'})
                    if ap != 'none' and not snmp_cfg.get('v3_auth_secret'):
                        A.respond(400, {'error': 'auth password required for '
                                                 f'auth protocol {ap}'})
                    if pp != 'none' and not snmp_cfg.get('v3_priv_secret'):
                        A.respond(400, {'error': 'priv password required for '
                                                 f'priv protocol {pp}'})
                elif not snmp_cfg.get('community'):
                    A.respond(400, {
                        'error': 'community required when SNMP is enabled — '
                                 'set it in the same PATCH, or untick "enabled"'})
                if not (dev.get('ip') or dev.get('hostname') or dev.get('host')):
                    A.respond(400, {
                        'error': 'device has no ip/hostname; cannot poll'})
            dev['snmp'] = snmp_cfg
            store[dev_id] = dev
        A.audit_log(actor, 'device_snmp_config',
                    f'device={dev_id} enabled={snmp_cfg.get("enabled")} port={snmp_cfg.get("port")}')
        A.respond(200, {'ok': True})
    else:
        A.respond(405, {'error': 'Method not allowed'})


def handle_device_snmp_poll(dev_id):
    """POST /api/devices/<id>/snmp/poll — trigger an immediate SNMP poll."""
    actor = A.require_admin_auth()
    if A.method() != 'POST': A.respond(405, {'error': 'Method not allowed'})
    if not A._validate_id(dev_id):
        A.respond(400, {'error': 'invalid device id'})
    devs = A.load(A.DEVICES_FILE)
    dev = devs.get(dev_id)
    if not dev:
        A.respond(404, {'error': 'device not found'})
    target = A._device_snmp_target(dev)
    if not target:
        A.respond(400, {'error': 'SNMP not configured/enabled on this device'})
    entry = A._do_snmp_poll(dev_id, dev)
    A.audit_log(actor, 'device_snmp_poll', f'device={dev_id} ok={entry.get("last_ok") is not None}')
    A.respond(200, {'ok': True, 'data': entry})


def handle_device_snmp_deep(dev_id):
    """GET /api/devices/<id>/snmp/deep — admin-only, on-demand richer SNMP read.

    Returns interface table + Host Resources MIB scalars + vendor-specific
    health (Mikrotik) on top of the sys-group. Everything best-effort —
    a row missing from the response just means the agent doesn't expose
    that MIB. Slower than the standard poll (multiple round trips for
    table walks), so it's not in the 5-minute sweep.
    """
    A.require_admin_auth()
    if A.method() != 'GET': A.respond(405, {'error': 'Method not allowed'})
    if not A._validate_id(dev_id):
        A.respond(400, {'error': 'invalid device id'})
    devs = A.load(A.DEVICES_FILE)
    dev = devs.get(dev_id)
    if not dev:
        A.respond(404, {'error': 'device not found'})
    target = A._device_snmp_target(dev)
    if not target:
        A.respond(400, {'error': 'SNMP not configured/enabled on this device'})
    host, community, port = target
    import snmp as snmp_mod
    out = {'host': host, 'port': port, 'errors': {}}
    # 1. sys-group (also cached on disk by the regular poll)
    try:
        out['system'] = snmp_mod.poll_system(host, community,
                                              port=port, timeout=2.5)
        out['system'].pop('_oids', None)
    except Exception as e:
        out['errors']['system'] = f'{type(e).__name__}: {e}'

    # 2. Interfaces (ifTable walk) — capped at 64 interfaces
    try:
        out['interfaces'] = snmp_mod.poll_interfaces(host, community,
                                                      port=port, timeout=2.5)
    except Exception as e:
        out['errors']['interfaces'] = f'{type(e).__name__}: {e}'

    # 3. Host Resources MIB scalars
    try:
        out['host_resources'] = snmp_mod.poll_host_resources(host, community,
                                                              port=port, timeout=2.5)
    except Exception as e:
        out['errors']['host_resources'] = f'{type(e).__name__}: {e}'

    # 4. hrStorageTable
    try:
        out['storage'] = snmp_mod.poll_hr_storage(host, community,
                                                   port=port, timeout=2.5)
    except Exception as e:
        out['errors']['storage'] = f'{type(e).__name__}: {e}'

    # 5. hrProcessorTable — per-CPU load %. Standard MIB-2, works on
    #    Mikrotik + Linux + BSD + most enterprise gear.
    try:
        out['processors'] = snmp_mod.poll_processors(host, community,
                                                      port=port, timeout=2.5)
    except Exception as e:
        out['errors']['processors'] = f'{type(e).__name__}: {e}'

    # 6. UCD-SNMP-MIB — load averages + raw CPU ticks + UCD memory totals.
    #    Empty on devices that don't run net-snmp (Mikrotik, most switches).
    try:
        out['ucd_snmp'] = snmp_mod.poll_ucd_snmp(host, community,
                                                  port=port, timeout=2.5)
    except Exception as e:
        out['errors']['ucd_snmp'] = f'{type(e).__name__}: {e}'

    # 7. Vendor-specific (gated by sysObjectID prefix)
    sys_obj = (out.get('system') or {}).get('sysObjectID') or ''
    if sys_obj.startswith('1.3.6.1.4.1.14988'):
        try:
            out['mikrotik'] = snmp_mod.poll_mikrotik(host, community,
                                                     port=port, timeout=2.5)
        except Exception as e:
            out['errors']['mikrotik'] = f'{type(e).__name__}: {e}'
    if sys_obj.startswith('1.3.6.1.4.1.41112'):
        try:
            out['ubnt'] = snmp_mod.poll_ubnt(host, community,
                                              port=port, timeout=2.5)
        except Exception as e:
            out['errors']['ubnt'] = f'{type(e).__name__}: {e}'
    # v3.3.4: Synology — probed unconditionally (DSM's sysObjectID is the
    # generic net-snmp OID). Returns {} for non-Synology, so it's safe to
    # always attempt; only Synology boxes get the disk/RAID walks.
    try:
        syno = snmp_mod.poll_synology(host, community, port=port, timeout=2.5)
        if syno:
            out['synology'] = syno
    except Exception as e:
        out['errors']['synology'] = f'{type(e).__name__}: {e}'

    out['polled_at'] = int(time.time())
    A.respond(200, out)
