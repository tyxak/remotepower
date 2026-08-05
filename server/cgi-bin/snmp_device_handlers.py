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
import re
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
        # v6.4.1: the OID browser's preset list rides here rather than on the
        # deep poll. The deep poll is exactly the call that fails on the
        # devices where hand-exploration matters most, and the browser is
        # rendered on those failure paths too.
        A.respond(200, {'config': redacted_cfg, 'data': data,
                        'traps': traps[-50:][::-1],
                        'walk_presets': [{'oid': o, 'label': lbl}
                                         for o, lbl in SNMP_WALK_PRESETS]})
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


# Where an operator actually starts when exploring an unknown device. Offered as
# presets so the common cases need no OID typing at all.
SNMP_WALK_PRESETS = (
    ('1.3.6.1.2.1.1',    'System (sysDescr, uptime, contact, location)'),
    ('1.3.6.1.2.1.2.2.1', 'Interface table (ifTable)'),
    ('1.3.6.1.2.1.31.1.1.1', 'Interface names and aliases (ifXTable)'),
    ('1.3.6.1.2.1.25.2.3.1', 'Storage table (hrStorageTable)'),
    ('1.3.6.1.2.1.25.3.3.1', 'Processor load (hrProcessorTable)'),
    ('1.3.6.1.2.1.4.20.1',   'IP address table'),
    ('1.3.6.1.4.1',          'Enterprises (vendor subtree — large, expect a cap hit)'),
)

_WALK_MAX_ARCS = 64          # a legal OID is nowhere near this long
_WALK_MAX_ARC  = 2 ** 32 - 1  # sub-identifiers are unsigned 32-bit


def _validate_walk_oid(raw):
    """Strict dotted-decimal OID, or None.

    The value is BER-encoded into a packet we send, so it never reaches a
    shell — but an unbounded arc count or a huge sub-identifier still lets a
    caller inflate the request, and `int()` on junk would surface as a 500
    rather than a 400. Validate rather than rely on the encoder raising.
    """
    s = str(raw or '').strip().lstrip('.')
    if not s:
        return None
    parts = s.split('.')
    if len(parts) < 2 or len(parts) > _WALK_MAX_ARCS:
        return None
    for p in parts:
        if not p.isdigit() or len(p) > 10:
            return None
        if int(p) > _WALK_MAX_ARC:
            return None
    # First two arcs are constrained by BER's combined first byte.
    if int(parts[0]) > 2 or (int(parts[0]) < 2 and int(parts[1]) > 39):
        return None
    return s


def handle_device_snmp_walk(dev_id):
    """POST /api/devices/<id>/snmp/walk {oid, max} — browse an OID subtree.

    The exploration tool the deep-poll page was missing: the deep poll answers
    "what does RemotePower already know how to read", this answers "what does
    this device actually expose", which is the question you have when a vendor
    counter is not in any of our parsers.

    Admin-only and audited — it reads arbitrary OIDs from a device using the
    stored community/v3 credentials, which is a broader read than the fixed
    poll set. Bounded by max_results so a walk of `enterprises` on a big switch
    returns a capped page rather than running until the request times out.
    """
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    if not A._validate_id(dev_id):
        A.respond(400, {'error': 'invalid device id'})
    devs = A.load(A.DEVICES_FILE)
    dev = devs.get(dev_id)
    if not dev:
        A.respond(404, {'error': 'device not found'})
    target = A._device_snmp_target(dev)
    if not target:
        A.respond(400, {'error': 'SNMP not configured/enabled on this device'})
    body = A.get_json_obj()
    oid = _validate_walk_oid(body.get('oid') or '1.3.6.1.2.1.1')
    if not oid:
        A.respond(400, {'error': 'oid must be a dotted-decimal OID, e.g. 1.3.6.1.2.1.1'})
    try:
        limit = max(1, min(2000, int(body.get('max') or 256)))
    except (TypeError, ValueError):
        limit = 256
    host, community, port = target
    import snmp as snmp_mod
    started = time.time()
    try:
        raw = snmp_mod.snmp_walk(host, community, oid, port=port,
                                 timeout=2.5, max_results=limit)
    except snmp_mod.SnmpError as e:
        # The device answered with something we understood as a refusal — that
        # is a useful answer, not a server fault.
        A.respond(502, {'error': f'SNMP walk failed: {str(e)[:200]}'})
        return
    except Exception as e:
        A.respond(502, {'error': f'{type(e).__name__}: {str(e)[:200]}'})
        return
    rows = []
    for k, v in raw.items():
        if isinstance(v, bytes):
            v = v.decode('utf-8', 'replace')
        rows.append({'oid': k, 'name': snmp_mod.oid_label(k),
                     'value': A._sanitize_str(str(v), 512)})
    rows.sort(key=lambda r: [int(x) for x in r['oid'].split('.') if x.isdigit()])
    A.audit_log(actor, 'device_snmp_walk',
                f'device={dev_id} oid={oid} rows={len(rows)}')
    A.respond(200, {
        'ok': True, 'host': host, 'port': port, 'oid': oid,
        'rows': rows, 'count': len(rows),
        # A full page means the cap was hit, so there is probably more below.
        'truncated': len(rows) >= limit,
        'elapsed_ms': int((time.time() - started) * 1000),
        'presets': [{'oid': o, 'label': lbl} for o, lbl in SNMP_WALK_PRESETS],
    })


# ── v6.4.2: SNMP trap rules ─────────────────────────────────────────────────
# Inbound traps were stored as raw dotted OID strings and raised as ONE
# coalesced `snmp_trap_received` per host with no identity field. A UPS
# reporting `.1.3.6.1.4.1.318.0.5` (on battery) and a switch reporting a
# chatty linkDown both arrived as "SNMP trap received", at the same severity,
# folded into the same open alert row. Paging on the first while ignoring the
# second — the entire reason to run a trap receiver — was not expressible.
#
# A rule maps an OID prefix (and optionally a value regex) to a severity, or
# to `ignore`. It is deliberately NOT a new event name: an operator-defined
# event could never be in EVENT_REGISTRY, and every consumer downstream —
# routing matrix, alert rules, the webhook event list — is keyed on that
# registry. So a matched trap stays `snmp_trap_received` and carries the rule
# name, which IS in _ALERT_IDENTITY_FIELDS, so distinct traps stop coalescing.
_TRAP_SEVERITIES = ('critical', 'high', 'medium', 'low', 'info', 'ignore')
_MAX_TRAP_RULES = 200


def _trap_rules_load():
    st = A.load(A.SNMP_TRAP_RULES_FILE) or {}
    rules = st.get('rules')
    return rules if isinstance(rules, list) else []


def _clean_trap_rule(raw, existing_id=''):
    """Validate one rule. Responds 400 rather than dropping — this is an
    operator editing a form, not a bulk import, so a silent drop would leave
    them looking at a rule that saved and does nothing."""
    if not isinstance(raw, dict):
        A.respond(400, {'error': 'rule must be an object'})
    oid = A._sanitize_str(str(raw.get('oid_prefix', '')), 128).strip()
    if not oid:
        A.respond(400, {'error': 'oid_prefix is required'})
    if not re.fullmatch(r'[0-9]+(\.[0-9]+)*', oid.lstrip('.')):
        A.respond(400, {'error': 'oid_prefix must be a dotted numeric OID'})
    sev = str(raw.get('severity', 'medium')).lower()
    if sev not in _TRAP_SEVERITIES:
        A.respond(400, {'error': 'severity must be one of ' + ', '.join(_TRAP_SEVERITIES)})
    vm = A._sanitize_str(str(raw.get('value_match', '')), 200)
    if vm:
        # Compile now so a bad regex is the operator's problem at save time,
        # not a silently non-matching rule discovered during an outage.
        try:
            re.compile(vm)
        except Exception as e:
            A.respond(400, {'error': f'value_match is not a valid regex: {str(e)[:120]}'})
    dev = A._sanitize_str(str(raw.get('device_id', '')), 64)
    if dev and not A._validate_id(dev):
        A.respond(400, {'error': 'device_id is not a valid device id'})
    return {
        'id':          existing_id or ('trap-' + A.secrets.token_hex(6)),
        'name':        A._sanitize_str(str(raw.get('name', '')), 60) or oid.lstrip('.'),
        'oid_prefix':  oid.lstrip('.'),
        'value_match': vm,
        'severity':    sev,
        'device_id':   dev,
        'enabled':     bool(raw.get('enabled', True)),
    }


def handle_snmp_trap_rules():
    """GET /api/snmp/trap-rules — list; POST — create. Admin.

    Rules are instance-wide (like log-alert rules), so they are admin-gated
    rather than tenant-scoped; an optional `device_id` narrows one rule to a
    single host, and that id is scope-checked on save.
    """
    actor = A.require_admin_auth()
    if A.method() == 'GET':
        A.respond(200, {'rules': _trap_rules_load(),
                        'severities': list(_TRAP_SEVERITIES)})
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    rule = _clean_trap_rule(A.get_json_obj())
    if rule['device_id']:
        A._scope_block_device(rule['device_id'])
    with A._LockedUpdate(A.SNMP_TRAP_RULES_FILE) as st:
        rules = st.get('rules')
        if not isinstance(rules, list):
            rules = []
        if len(rules) >= _MAX_TRAP_RULES:
            A.respond(400, {'error': f'trap rule limit reached (max {_MAX_TRAP_RULES})'})
        rules.append(rule)
        st['rules'] = rules
    A.audit_log(actor, 'snmp_trap_rule_create',
                detail=f'oid={rule["oid_prefix"]} severity={rule["severity"]}')
    A.respond(201, {'ok': True, 'rule': rule})


def handle_snmp_trap_rule(rule_id):
    """PATCH /api/snmp/trap-rules/<id> — replace; DELETE — remove. Admin."""
    actor = A.require_admin_auth()
    rule_id = A._sanitize_str(str(rule_id or ''), 64)
    if A.method() == 'DELETE':
        with A._LockedUpdate(A.SNMP_TRAP_RULES_FILE) as st:
            rules = [r for r in (st.get('rules') or []) if r.get('id') != rule_id]
            if len(rules) == len(st.get('rules') or []):
                A.respond(404, {'error': 'rule not found'})
            st['rules'] = rules
        A.audit_log(actor, 'snmp_trap_rule_delete', detail=f'id={rule_id}')
        A.respond(200, {'ok': True})
    if A.method() != 'PATCH':
        A.respond(405, {'error': 'Method not allowed'})
    rule = _clean_trap_rule(A.get_json_obj(), existing_id=rule_id)
    if rule['device_id']:
        A._scope_block_device(rule['device_id'])
    with A._LockedUpdate(A.SNMP_TRAP_RULES_FILE) as st:
        rules = st.get('rules') or []
        for i, r in enumerate(rules):
            if r.get('id') == rule_id:
                rules[i] = rule
                break
        else:
            A.respond(404, {'error': 'rule not found'})
        st['rules'] = rules
    A.audit_log(actor, 'snmp_trap_rule_update', detail=f'id={rule_id}')
    A.respond(200, {'ok': True, 'rule': rule})


def handle_snmp_trap_rule_test():
    """POST /api/snmp/trap-rules/test — which rule would this trap match?

    The finding this closes is that an operator cannot tell what a trap will
    do until it arrives at 3am. `{oid, value}` in, the matching rule (or the
    default) out — including the resolved MIB name, so they can confirm they
    typed the right OID prefix without waiting for the device to emit one.
    """
    A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A.get_json_obj()
    oid = A._sanitize_str(str(body.get('oid', '')), 256)
    val = A._sanitize_str(str(body.get('value', '')), 512)
    dev = A._sanitize_str(str(body.get('device_id', '')), 64)
    # The dry run takes a device id from the BODY, so main()'s pre-dispatch
    # _enforce_device_scope (which only covers /api/devices/<id>/…) does not
    # reach it. Left ungated, a tenant admin could ask which rules apply to a
    # host in another tenant and read the rule set back — small, but it is the
    # exact shape that has produced cross-tenant HIGHs four times in this
    # codebase.
    if dev:
        A._scope_block_device(dev)
    import snmp as snmp_mod          # sibling module; api.py imports it lazily too
    rule = A._snmp_trap_rule_match(oid, val, dev, _trap_rules_load())
    A.respond(200, {
        'oid': oid,
        'oid_label': snmp_mod.oid_label(oid.lstrip('.')),
        'matched': rule,
        'severity': (rule or {}).get('severity', 'medium'),
        'action': ('suppressed' if (rule or {}).get('severity') == 'ignore'
                   else 'alert'),
    })
