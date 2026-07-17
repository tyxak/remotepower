"""RemotePower — physical rack registry + elevation view (W5-3) and IPAM
subnet registry + occupancy + duplicate-IP/MAC detection (W5-2).

A bound-module carve-out of api.py's request-coupled rack/IPAM handlers,
following the tls_ct_handlers / dmarc_handlers / cmdb_handlers pattern:

  - api.py execs a PRIVATE instance and binds its own ``globals()`` here, so
    every api service is reached as ``A.<name>`` — a DYNAMIC attribute lookup,
    which keeps the test suite's monkeypatching of api.fire_webhook / api.load /
    api.save working, and resolves identically under the CGI (__main__) and
    imported-module (wsgi.py/scheduler.py) models.
  - api.py then from-imports every public + private name back into its own
    globals, so the route tables, main()'s _safe() cadence and scheduler.py's
    CADENCE tuple keep resolving the names unchanged, and the behavioural tests
    that call api._rack_elevation / api.run_ipam_conflicts_if_due see them.
  - Calls BETWEEN these functions ALSO go through ``A.``.

Constants (RACKS_FILE / SUBNETS_FILE / IPAM_STATE_FILE / SITES_FILE / CMDB_FILE /
DEVICES_FILE) stay in api.py and are read here through A. The shared
_normalize_mac util also stays in api.py (reached as A._normalize_mac).

The three model builders (_rack_elevation, _ipam_assignments, _ipam_occupancy)
are PURE — they take every input as an argument and touch no api global.
"""
import secrets
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


# ── W5-3: rack registry + elevation view ────────────────────────────────────
# A rack = {name, site, height_u}. Assets are placed via their CMDB record
# (rack_id + rack_unit bottom-U + rack_height_u). The elevation endpoint renders
# occupancy and flags overlapping U spans. Admin-gated writes.

def _rack_elevation(rack, rack_id, cmdb, devices):
    """Pure: build the elevation model for one rack. Returns
    {height_u, units:[{u, asset}|None...], assets:[...], conflicts:[u...]}.
    Assets whose U spans overlap are flagged (conflict=True on each)."""
    height = int(rack.get('height_u') or 42)
    placed = []
    for did, rec in (cmdb or {}).items():
        if not isinstance(rec, dict) or rec.get('rack_id') != rack_id:
            continue
        u = int(rec.get('rack_unit') or 0)
        if u < 1:
            continue
        h = max(1, int(rec.get('rack_height_u') or 1))
        placed.append({'device_id': did, 'name': (devices.get(did) or {}).get('name', did),
                       'rack_unit': u, 'rack_height_u': h, 'top_u': u + h - 1,
                       'conflict': False})
    # overlap detection
    conflict_units = set()
    for i, a in enumerate(placed):
        for b in placed[i + 1:]:
            if a['rack_unit'] <= b['top_u'] and b['rack_unit'] <= a['top_u']:
                a['conflict'] = b['conflict'] = True
                for uu in range(max(a['rack_unit'], b['rack_unit']),
                                min(a['top_u'], b['top_u']) + 1):
                    conflict_units.add(uu)
    return {'height_u': height, 'assets': sorted(placed, key=lambda x: -x['rack_unit']),
            'conflicts': sorted(conflict_units)}


def handle_racks():
    """GET /api/racks — list racks (+ placed count); POST — create. Admin write."""
    if A.method() == 'GET':
        A.require_auth()
        racks = A.load(A.RACKS_FILE) or {}
        cmdb = A._cmdb_load()
        counts = {}
        for rec in cmdb.values():
            rid = isinstance(rec, dict) and rec.get('rack_id')
            if rid:
                counts[rid] = counts.get(rid, 0) + 1
        sites = A.load(A.SITES_FILE) or {}
        out = [{'id': rid, 'name': r.get('name', rid), 'site': r.get('site', ''),
                'site_name': (sites.get(r.get('site', '')) or {}).get('name', ''),
                'height_u': r.get('height_u', 42), 'placed': counts.get(rid, 0)}
               for rid, r in racks.items() if isinstance(r, dict)]
        A.respond(200, {'racks': sorted(out, key=lambda x: x['name'].lower())})
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.RacksRequest)
    name = A._sanitize_str(str(body.get('name', '')), 64).strip()
    if not name:
        A.respond(400, {'error': 'name required'})
    try:
        height = int(body.get('height_u') or 42)
    except (TypeError, ValueError):
        height = 42
    if not (1 <= height <= 60):
        A.respond(400, {'error': 'height_u must be 1–60'})
    site = A._sanitize_str(str(body.get('site', '')), 32)
    if site and site not in (A.load(A.SITES_FILE) or {}):
        A.respond(400, {'error': 'unknown site'})
    rid = secrets.token_hex(8)
    with A._LockedUpdate(A.RACKS_FILE) as racks:
        if len(racks) >= 500:
            A.respond(400, {'error': 'rack limit reached (max 500)'})
        racks[rid] = {'name': name, 'site': site, 'height_u': height,
                      'created': int(time.time())}
    A.audit_log(actor, 'rack_create', detail=f'name={name} id={rid}')
    A.respond(201, {'ok': True, 'id': rid})


def handle_rack(rid):
    """PATCH /api/racks/{id} — update; DELETE — remove (unplaces its assets).
    Admin only."""
    actor = A.require_admin_auth()
    rid = A._sanitize_str(rid, 32)
    if A.method() == 'DELETE':
        with A._LockedUpdate(A.RACKS_FILE) as racks:
            existed = racks.pop(rid, None) is not None
        if not existed:
            A.respond(404, {'error': 'rack not found'})
        # unplace assets that referenced it
        with A._LockedUpdate(A.CMDB_FILE) as cmdb:
            for rec in cmdb.values():
                if isinstance(rec, dict) and rec.get('rack_id') == rid:
                    rec['rack_id'] = ''
                    rec['rack_unit'] = 0
        A.audit_log(actor, 'rack_delete', detail=f'id={rid}')
        A.respond(200, {'ok': True})
    if A.method() != 'PATCH':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.RackRequest)
    with A._LockedUpdate(A.RACKS_FILE) as racks:
        r = racks.get(rid)
        if not isinstance(r, dict):
            A.respond(404, {'error': 'rack not found'})
        if 'name' in body:
            nm = A._sanitize_str(str(body['name']), 64).strip()
            if nm:
                r['name'] = nm
        if 'height_u' in body:
            try:
                h = int(body['height_u'])
            except (TypeError, ValueError):
                A.respond(400, {'error': 'height_u must be an integer'})
            if not (1 <= h <= 60):
                A.respond(400, {'error': 'height_u must be 1–60'})
            r['height_u'] = h
        if 'site' in body:
            site = A._sanitize_str(str(body['site']), 32)
            if site and site not in (A.load(A.SITES_FILE) or {}):
                A.respond(400, {'error': 'unknown site'})
            r['site'] = site
    A.audit_log(actor, 'rack_update', detail=f'id={rid}')
    A.respond(200, {'ok': True})


def handle_rack_elevation(rid):
    """GET /api/racks/{id}/elevation — the rack's occupancy model + conflicts."""
    A.require_auth()
    rid = A._sanitize_str(rid, 32)
    rack = (A.load(A.RACKS_FILE) or {}).get(rid)
    if not isinstance(rack, dict):
        A.respond(404, {'error': 'rack not found'})
    model = A._rack_elevation(rack, rid, A._cmdb_load(), A.load(A.DEVICES_FILE) or {})
    model['id'] = rid
    model['name'] = rack.get('name', rid)
    A.respond(200, model)


# ── W5-2: IPAM (IP address management) ───────────────────────────────────────
# Subnets (CIDR/site/vlan/notes + static reservations) with an occupancy view
# DERIVED from known device NICs (device.ip + CMDB interfaces incl. NAT). A
# duplicate IP across two devices fires ip_conflict (edge-triggered).

def _ipam_assignments(devices, cmdb):
    """{ip_str: [{device_id, name, source}]} over every known device address —
    the device record's primary ip, plus each CMDB interface ip/nat_ip. Pure."""
    import ipaddress as _ipa
    out = {}

    def add(ip, did, name, source):
        ip = str(ip or '').strip()
        if not ip:
            return
        try:
            ip = str(_ipa.ip_address(ip))
        except ValueError:
            return
        out.setdefault(ip, []).append({'device_id': did, 'name': name, 'source': source})

    for did, dev in (devices or {}).items():
        if not isinstance(dev, dict):
            continue
        name = dev.get('name', did)
        add(dev.get('ip'), did, name, 'device')
        rec = (cmdb or {}).get(did) or {}
        for nic in (rec.get('interfaces') or []):
            if isinstance(nic, dict):
                add(nic.get('ip'), did, name, 'nic')
                add(nic.get('nat_ip'), did, name, 'nat')
    return out


def _ipam_occupancy(subnet, assignments):
    """Occupancy model for one subnet. Pure over the assignments map."""
    import ipaddress as _ipa
    try:
        net = _ipa.ip_network(subnet.get('cidr', ''), strict=False)
    except ValueError:
        return {'cidr': subnet.get('cidr', ''), 'error': 'invalid CIDR',
                'total': 0, 'used': 0, 'reserved': 0, 'free': 0, 'addresses': []}
    reservations = subnet.get('reservations') or {}
    addresses = []
    used = 0
    for ip, holders in assignments.items():
        try:
            if _ipa.ip_address(ip) not in net:
                continue
        except ValueError:
            continue
        distinct = {h['device_id'] for h in holders}
        conflict = len(distinct) > 1
        addresses.append({'ip': ip, 'devices': holders, 'conflict': conflict,
                          'reserved_label': reservations.get(ip, '')})
        used += 1
    # reservations that aren't otherwise occupied still count as "reserved"
    for rip, label in reservations.items():
        if rip not in assignments:
            try:
                if _ipa.ip_address(rip) in net:
                    addresses.append({'ip': rip, 'devices': [], 'conflict': False,
                                      'reserved_label': label})
            except ValueError:
                pass
    # total host capacity (bounded for display on large v6 nets)
    try:
        total = net.num_addresses
        if net.version == 4 and net.prefixlen <= 30:
            total -= 2   # network + broadcast
    except Exception:
        total = 0
    reserved = len([a for a in addresses if a['reserved_label']])
    addresses.sort(key=lambda a: _ipa.ip_address(a['ip']))
    return {'cidr': str(net), 'total': int(total), 'used': used,
            'reserved': reserved, 'free': max(0, int(total) - used),
            'addresses': addresses}


def handle_ipam_subnets():
    """GET /api/ipam/subnets — list (scoped by site); POST — create. Admin write."""
    if A.method() == 'GET':
        A.require_auth()
        subnets = A.load(A.SUBNETS_FILE) or {}
        scope = A._caller_scope()
        sites = A.load(A.SITES_FILE) or {}
        out = []
        for sid, s in subnets.items():
            if not isinstance(s, dict):
                continue
            if scope is not None and scope.get('type') == 'sites' \
                    and (s.get('site') or '') not in (scope.get('values') or []):
                continue
            out.append({'id': sid, 'cidr': s.get('cidr', ''), 'site': s.get('site', ''),
                        'site_name': (sites.get(s.get('site', '')) or {}).get('name', ''),
                        'vlan': s.get('vlan', ''), 'notes': s.get('notes', ''),
                        'reservations': len(s.get('reservations') or {})})
        A.respond(200, {'subnets': sorted(out, key=lambda x: x['cidr'])})
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    import ipaddress as _ipa
    body = A._read_valid(A.request_models.IpamSubnetsRequest)
    try:
        cidr = str(_ipa.ip_network(str(body.get('cidr', '')), strict=False))
    except ValueError:
        A.respond(400, {'error': 'cidr must be a valid network (e.g. 10.0.0.0/24)'})
    site = A._sanitize_str(str(body.get('site', '')), 32)
    if site and site not in (A.load(A.SITES_FILE) or {}):
        A.respond(400, {'error': 'unknown site'})
    sid = secrets.token_hex(8)
    with A._LockedUpdate(A.SUBNETS_FILE) as subnets:
        if len(subnets) >= 1000:
            A.respond(400, {'error': 'subnet limit reached (max 1000)'})
        subnets[sid] = {'cidr': cidr, 'site': site,
                        'vlan': A._sanitize_str(str(body.get('vlan', '')), 64),
                        'notes': A._sanitize_str(str(body.get('notes', '')), 512),
                        'reservations': {}, 'created': int(time.time())}
    A.audit_log(actor, 'ipam_subnet_create', detail=f'cidr={cidr} id={sid}')
    A.respond(201, {'ok': True, 'id': sid})


def handle_ipam_subnet(sid):
    """PATCH /api/ipam/subnets/{id} — update (incl. reservations); DELETE — remove.
    Admin only."""
    actor = A.require_admin_auth()
    sid = A._sanitize_str(sid, 32)
    if A.method() == 'DELETE':
        with A._LockedUpdate(A.SUBNETS_FILE) as subnets:
            existed = subnets.pop(sid, None) is not None
        if not existed:
            A.respond(404, {'error': 'subnet not found'})
        A.audit_log(actor, 'ipam_subnet_delete', detail=f'id={sid}')
        A.respond(200, {'ok': True})
    if A.method() != 'PATCH':
        A.respond(405, {'error': 'Method not allowed'})
    import ipaddress as _ipa
    body = A._read_valid(A.request_models.IpamSubnetRequest)
    with A._LockedUpdate(A.SUBNETS_FILE) as subnets:
        s = subnets.get(sid)
        if not isinstance(s, dict):
            A.respond(404, {'error': 'subnet not found'})
        if 'vlan' in body:
            s['vlan'] = A._sanitize_str(str(body['vlan']), 64)
        if 'notes' in body:
            s['notes'] = A._sanitize_str(str(body['notes']), 512)
        if 'site' in body:
            site = A._sanitize_str(str(body['site']), 32)
            if site and site not in (A.load(A.SITES_FILE) or {}):
                A.respond(400, {'error': 'unknown site'})
            s['site'] = site
        if 'reservations' in body and isinstance(body['reservations'], dict):
            clean = {}
            for ip, label in list(body['reservations'].items())[:500]:
                try:
                    clean[str(_ipa.ip_address(str(ip)))] = A._sanitize_str(str(label), 128)
                except ValueError:
                    continue
            s['reservations'] = clean
    A.audit_log(actor, 'ipam_subnet_update', detail=f'id={sid}')
    A.respond(200, {'ok': True})


def handle_ipam_occupancy(sid):
    """GET /api/ipam/subnets/{id}/occupancy — derived address inventory."""
    A.require_auth()
    sid = A._sanitize_str(sid, 32)
    subnet = (A.load(A.SUBNETS_FILE) or {}).get(sid)
    if not isinstance(subnet, dict):
        A.respond(404, {'error': 'subnet not found'})
    assignments = A._ipam_assignments(A._scope_filter_devices(A.load(A.DEVICES_FILE) or {}),
                                      A._cmdb_load())
    model = A._ipam_occupancy(subnet, assignments)
    model['id'] = sid
    model['site'] = subnet.get('site', '')
    model['vlan'] = subnet.get('vlan', '')
    A.respond(200, model)


def run_ipam_conflicts_if_due():
    """W5-2 cadence: detect duplicate IPs within any defined subnet and fire
    ip_conflict (edge-triggered — only for IPs not already flagged).

    v6.1.2 also detects duplicate MACs here. Note the two halves have DIFFERENT
    preconditions: the IP check is meaningless without a subnet to judge "same
    network" against, but a duplicate MAC is wrong everywhere and must still be
    detected when no subnet is configured — which is the common homelab case, and
    exactly the setup most likely to be cloning Proxmox VMs. So the no-subnet
    early-return skips only the IP half, never the whole sweep.
    """
    subnets = A.load(A.SUBNETS_FILE) or {}
    now = int(time.time())
    state = A.load(A.IPAM_STATE_FILE) or {}
    if now - int(state.get('last_run', 0) or 0) < 300:
        return
    devices = A.load(A.DEVICES_FILE) or {}
    conflicts = set()
    fires = []
    if subnets:
        assignments = A._ipam_assignments(devices, A._cmdb_load())
        import ipaddress as _ipa
        known = set()   # IPs inside any defined subnet
        for s in subnets.values():
            if not isinstance(s, dict):
                continue
            try:
                net = _ipa.ip_network(s.get('cidr', ''), strict=False)
            except ValueError:
                continue
            for ip in assignments:
                try:
                    if _ipa.ip_address(ip) in net:
                        known.add(ip)
                except ValueError:
                    pass
        conflicts = {ip for ip in known
                     if len({h['device_id'] for h in assignments.get(ip, [])}) > 1}
        prev = set(state.get('conflicts') or [])
        for ip in sorted(conflicts - prev):
            holders = assignments.get(ip, [])
            fires.append({'ip': ip,
                          'devices': ', '.join(sorted({h['name'] for h in holders}))})

    # v6.1.2: duplicate MAC. Sibling of the IP conflict above and it rides the
    # same sweep/state — a MAC on two devices is almost always a cloned VM whose
    # NIC was never regenerated, a Proxmox-homelab classic that produces exactly
    # the kind of baffling intermittent networking nobody thinks to blame on a
    # MAC. Runs whether or not subnets are defined (see the docstring).
    mac_holders = {}
    for did, dev in devices.items():
        if not isinstance(dev, dict) or dev.get('decommissioned'):
            continue
        macs = set()
        for m in ([dev.get('mac')] + [i.get('mac') for i in (dev.get('interfaces') or [])
                                      if isinstance(i, dict)]):
            m = A._normalize_mac(m)
            if m:
                macs.add(m)
        for m in macs:
            mac_holders.setdefault(m, set()).add(dev.get('name', did))
    mac_conflicts = {m for m, owners in mac_holders.items() if len(owners) > 1}
    prev_macs = set(state.get('mac_conflicts') or [])
    mac_fires = [{'mac': m, 'devices': ', '.join(sorted(mac_holders[m]))}
                 for m in sorted(mac_conflicts - prev_macs)]

    A.save(A.IPAM_STATE_FILE, {'last_run': now, 'conflicts': sorted(conflicts),
                              'mac_conflicts': sorted(mac_conflicts)})
    for f in fires:
        A.fire_webhook('ip_conflict', {'ip': f['ip'], 'detail': f'assigned to {f["devices"]}',
                                       'name': f['devices']})
    for f in mac_fires:
        A.fire_webhook('mac_conflict', {
            'mac': f['mac'], 'name': f['devices'],
            'detail': f'the same MAC is on {f["devices"]} — a cloned VM whose NIC '
                      'was never regenerated?'})
