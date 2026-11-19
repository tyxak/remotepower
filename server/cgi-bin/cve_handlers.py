"""RemotePower — CVE scan lifecycle, findings, campaigns and the ignore list

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
import re


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


# ── handlers ─────────────────────────────────────────────────────────────────


def handle_cve_realert():
    """POST /api/cve/realert — re-raise cve_found for the CURRENT backlog.

    The normal cve_found alert is edge-triggered (fires only for findings new
    since the last scan), so once you clear/resolve those alerts the existing
    CVEs won't re-alert. This admin action fires cve_found now for every device
    whose current findings (in the configured severity filter, not ignored)
    are non-empty — useful after clearing the inbox or onboarding alerting on a
    fleet that already had findings."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    if not A.is_webhook_event_enabled('cve_found'):
        A.respond(400, {'error': 'cve_found alerting is disabled (Settings → Notifications)'})
    findings_all = A.load(A.CVE_FINDINGS_FILE) or {}
    # v6.2.2 (SECURITY): require_admin_auth() passes a TENANT admin (role=='admin',
    # scope=None), so without this a tenant admin could re-fire cve_found for —
    # and read the CVE counts of — every tenant's hosts. Filter to the visible
    # set: this fixes BOTH the returned count AND the cross-tenant alert side
    # effect (findings for a device this caller can't see are skipped below).
    # No-op for a single-org admin (whole fleet stays visible).
    devices = A._scope_filter_devices(A.load(A.DEVICES_FILE) or {})
    ignore_data = A.load(A.CVE_IGNORE_FILE) or {}
    sev_filter = set(A.get_cve_severity_filter())
    # v7.4.6 (#57): the same rule the scan applies when it raises cve_found.
    fixable_only = A.get_cve_alert_fixable_only()
    kev = A._kev_epss()[0] if fixable_only else set()
    fired = 0
    for dev_id, rec in findings_all.items():
        if dev_id not in devices:
            continue
        alerted = []
        for f in (rec or {}).get('findings') or []:
            vid = f.get('vuln_id')
            if not vid or f.get('severity') not in sev_filter:
                continue
            if not A.cve_fixes.alert_candidate(f, fixable_only, kev):
                continue
            ig = ignore_data.get(vid)
            if A.cve_ignore_applies(ig, dev_id, devices.get(dev_id)):
                continue
            alerted.append(f)
        if not alerted:
            continue
        dev = devices.get(dev_id, {})
        A.fire_webhook('cve_found', {
            'device_id': dev_id, 'name': dev.get('name', dev_id),
            'count':     len(alerted),
            'critical':  sum(1 for f in alerted if f['severity'] == 'critical'),
            'high':      sum(1 for f in alerted if f['severity'] == 'high'),
            'sample':    [{'id': f['vuln_id'], 'pkg': f.get('package'), 'sev': f['severity']}
                          for f in alerted[:5]],
        })
        fired += 1
    A.audit_log(actor, 'cve_realert', f'{A.plural(fired, "host", "hosts")} re-alerted')
    A.respond(200, {'ok': True, 'devices': fired})


# How soon one organisation may start another scan. One scan runs at a time for the whole installation, so a tenant's administrator
# who started scans of its own hosts back to back held the slot, and the other organisations were refused for as long as it did.
_SCAN_COOLDOWN_S = 30

# The scan marker holds more than progress: `owner` (the tenant the scan belongs to, None for the operator's, whose scan may cover
# every host) and `starts` (when each tenant last started one). Neither goes to a caller. A caller reads the numbers of a scan that
# is its own organisation's; the scan of another organisation is running or not, and that is all it learns of it.
_SCAN_MARKER_PRIVATE = ('run', 'owner', 'starts')
_SCAN_MARKER_PUBLIC = ('running', 'updated', 'started_at', 'finished_at')


def _scan_status_view(st):
    """The scan marker as the caller may read it (see _SCAN_MARKER_PRIVATE). A caller no tenant gate applies to (the operator, or
    any user of an installation without tenancy) reads the numbers of every scan, as before."""
    st = st if isinstance(st, dict) else {}
    gate = A._tenant_gate()
    if gate is None or st.get('owner') == gate:
        return {k: v for k, v in st.items() if k not in _SCAN_MARKER_PRIVATE}
    return {k: st[k] for k in _SCAN_MARKER_PUBLIC if k in st}


def _scan_starts(st, now):
    """{tenant: when its last scan started} from the marker, without what is older than an hour or is not a pair of a name and a time."""
    starts = st.get('starts') if isinstance(st, dict) else None
    if not isinstance(starts, dict):
        return {}
    return {k: v for k, v in starts.items()
            if isinstance(k, str) and isinstance(v, int) and not isinstance(v, bool) and 0 <= now - v < 3600}


def handle_cve_scan():
    """POST /api/cve/scan — queue a background scan for one host, or for all the caller's hosts.

    The scan runs in a detached process so the UI stays responsive; it returns
    202 immediately. Poll GET /api/cve/scan-status for progress.

    Without a `device_id` the scan covers the hosts the caller can see: every host for the
    operator (or on an installation without tenancy), the hosts of its own organisation for a
    tenant's administrator. It covered every host of every organisation for anyone who could
    start a scan, and sent the OSV requests and the cve_found alerts of other organisations'
    hosts through the operator's channels."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.CveScanRequest)
    body = A.get_json_obj() if A._env('CONTENT_LENGTH', '0') != '0' else {}
    target = body.get('device_id')
    gate = A._tenant_gate()            # None: the operator, or no tenancy. Else the organisation whose hosts this scan may reach
    if target is not None:
        target = str(target).strip()
        if not A._validate_id(target):
            A.respond(400, {'error': 'Invalid device_id'})
        A._scope_block_device(target)   # SEC: scans that device's packages
        spec = target
    else:
        spec = A._CVE_SCAN_TENANT + gate if gate is not None else None
    # Refuse to stack a second concurrent scan (stale >30 min markers ignored).
    st = A.load(A.CVE_SCAN_STATUS_FILE) or {}
    # v6.4.3: a crashed worker leaves `running: True` and nothing ever clears
    # it — there is no reaper, and the only routes are this one and
    # /scan-status, so there was no way to cancel. The 1800 s staleness window
    # below already meant the operator's retry was refused for HALF AN HOUR
    # after a crash. Two changes: the window is shorter (a live worker
    # checkpoints every 3 devices, so 5 minutes of silence means it is gone),
    # and the refusal now tells the operator when it will clear instead of
    # just saying no.
    now = int(A.time.time())
    _age = now - (st.get('updated') or 0)
    if st.get('running') and _age < A._CVE_SCAN_STALE_S:
        A.respond(409, {'error': 'A scan is already running', 'status': _scan_status_view(st),
                      'retry_after_seconds': max(0, A._CVE_SCAN_STALE_S - _age),
                      'detail': ('If the previous scan crashed, this clears '
                                 f'{A._CVE_SCAN_STALE_S // 60} minutes after its '
                                 'last checkpoint.')})
    starts = _scan_starts(st, now)
    if gate is not None:
        wait = _SCAN_COOLDOWN_S - (now - starts[gate]) if gate in starts else 0
        if wait > 0:
            A.respond(429, {'error': 'Your last scan started a moment ago. Try again shortly.',
                          'retry_after_seconds': wait})
        starts[gate] = now
        # a marker that names more organisations than exist keeps the latest ones
        starts = dict(sorted(starts.items(), key=lambda kv: -kv[1])[:200])
    if target:
        total = 1
    elif gate is not None:
        # the hosts of this organisation that hold a package list, which is what the scan walks
        mine = A._scope_filter_devices(A.load(A.DEVICES_FILE) or {})
        total = sum(1 for dev_id in (A.load(A.PACKAGES_FILE) or {}) if dev_id in mine)
    else:
        total = len(A.load(A.PACKAGES_FILE) or {})
    # v6.1.2: the status marker is written non_blocking so a wedged writer can
    # never hang the request — but a CONTENDED write then raises LockBusy, which
    # used to propagate uncaught and render as a 500 (the production symptom on
    # the Postgres backend, whose non_blocking acquire had no retry budget at
    # all until this release; see storage_pg._try_lock). Contention here just
    # means a scan runner is mid-write, so say so with a retryable 409.
    try:
        A.save(A.CVE_SCAN_STATUS_FILE, {'running': True, 'total': total, 'done': 0,
                                    'scanned': 0, 'skipped': 0, 'errors': 0,
                                    'updated': now, 'started_at': now,
                                    'owner': gate, 'starts': starts}, non_blocking=True)
    except A.LockBusy:
        A.respond(409, {'error': 'A scan is starting or running — try again shortly'})
    A._spawn_cve_scan(actor, spec)
    A.respond(202, {'queued': True, 'total': total,
                  'message': 'Scan queued — running in the background.'})


def handle_cve_scan_status():
    """GET /api/cve/scan-status — progress of the background CVE scan, as far as the caller may read it (_scan_status_view)."""
    A.require_auth()
    A.respond(200, _scan_status_view(A.load(A.CVE_SCAN_STATUS_FILE) or {'running': False}))


def _campaign_visible(camp):
    """May this caller see this campaign?

    Campaigns carried no tenant at all, so any authenticated caller could read
    every tenant's remediation plan and any admin could DELETE one. They are
    stamped at create now; a row with no stamp predates that and stays visible
    to everyone, because hiding existing campaigns on upgrade would look like
    data loss. Mutating an unstamped row is restricted separately, below.
    """
    t = A._tenant_gate()
    if t is None:                       # superadmin, or tenancy switched off
        return True
    return camp.get('tenant') in (None, t)


def _campaign_mutable(camp):
    """Stricter than visibility: an unstamped legacy campaign belongs to the
    instance, so only an unscoped caller may edit or delete it."""
    t = A._tenant_gate()
    return True if t is None else camp.get('tenant') == t


def handle_cve_campaigns():
    """GET /api/cve/campaigns — remediation campaigns with live affected counts.
    POST — create one (admin). A campaign scopes a set of CVEs (explicit ids OR a
    severity/KEV filter) with an owner + target date; the server tracks its
    affected-host burn-down."""
    if A.method() == 'GET':
        A.require_auth()
        cve_all = A.load(A.CVE_FINDINGS_FILE) or {}
        cve_ignore = A.load(A.CVE_IGNORE_FILE) or {}
        # Scope-filtered: the burn-down counts are computed over this set, so an
        # unfiltered fleet also inflates every campaign's affected-host numbers
        # with hosts the caller cannot see.
        devices = A._scope_filter_devices(A.load(A.DEVICES_FILE) or {})
        camps = [c for c in ((A.load(A.CVE_CAMPAIGNS_FILE) or {}).get('campaigns') or [])
                 if isinstance(c, dict) and _campaign_visible(c)]
        kev = A._cve_kev_ids()
        gate = A._tenant_gate()
        rows = []
        for c in camps:
            row = A._campaign_public(c, cve_all, cve_ignore, devices, kev)
            if gate is not None and c.get('tenant') != gate:
                # 8.0.1: a campaign of the whole installation, listed to one tenant's administrator. The
                # numbers above are that tenant's own hosts. The stored samples and the completion were
                # worked out over every tenant's hosts, so the samples are not shown and the campaign
                # reads as completed only when this tenant has no host left in it.
                row['samples'] = []
                if row['affected_hosts']:
                    row['completed_at'] = None
            rows.append(row)
        rows.sort(key=lambda r: (r['completed_at'] is not None, -(r.get('created_at') or 0)))
        A.respond(200, {'ok': True, 'campaigns': rows})
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    actor = A.require_admin_auth()
    body = A._read_valid(A.request_models.CveCampaignsRequest)
    name = A._sanitize_str(str(body.get('name', '')), 120).strip()
    if not name:
        A.respond(400, {'error': 'name required'})
    cve_ids = [A.re.sub(r'[^A-Za-z0-9\-]', '', str(x))[:32]
               for x in A.as_list(body.get('cve_ids'), 500)]
    cve_ids = [c for c in cve_ids if c]
    sevs = [s for s in (str(x).lower() for x in A.as_list(body.get('severities')))
            if s in ('critical', 'high', 'medium', 'low')]
    now = int(A.time.time())
    camp = {'id': 'camp_' + A.secrets.token_hex(5), 'name': name,
            # Stamped at create: there is no request context later, and this is
            # the only thing that tells the read and delete paths who owns it.
            'tenant': A._tenant_gate(),
            'owner': A._sanitize_str(str(body.get('owner') or actor), 64),
            'cve_ids': cve_ids, 'severities': sevs,
            'kev_only': bool(body.get('kev_only')),
            'target_date': A.re.sub(r'[^0-9\-]', '', str(body.get('target_date', '')))[:10],
            'created_at': now, 'completed_at': None, 'samples': []}
    with A._LockedUpdate(A.CVE_CAMPAIGNS_FILE) as store:
        camps = store.setdefault('campaigns', [])
        if len(camps) >= 200:
            A.respond(400, {'error': 'campaign limit reached'})
        camps.append(camp)
    A.audit_log(actor, 'cve_campaign_create', f'id={camp["id"]} {name}')
    A.respond(200, {'ok': True, 'id': camp['id']})


def handle_cve_campaign(cid):
    """PATCH /api/cve/campaigns/{id} — edit (admin). DELETE — remove (admin)."""
    if A.method() == 'DELETE':
        actor = A.require_admin_auth()
        removed = False
        with A._LockedUpdate(A.CVE_CAMPAIGNS_FILE) as store:
            before = store.get('campaigns') or []
            # Keep a row whose id matches but which this caller may not mutate,
            # so a cross-tenant delete falls through to the 404 below rather
            # than silently succeeding.
            after = [c for c in before
                     if c.get('id') != cid or not _campaign_mutable(c)]
            removed = len(after) != len(before)
            store['campaigns'] = after
        if not removed:
            A.respond(404, {'error': 'campaign not found'})
        A.audit_log(actor, 'cve_campaign_delete', f'id={cid}')
        A.respond(200, {'ok': True})
    if A.method() not in ('PATCH', 'POST'):
        A.respond(405, {'error': 'Method not allowed'})
    actor = A.require_admin_auth()
    body = A._read_valid(A.request_models.CveCampaignRequest)
    found = False
    with A._LockedUpdate(A.CVE_CAMPAIGNS_FILE) as store:
        camp = next((c for c in (store.get('campaigns') or [])
                     if c.get('id') == cid and _campaign_mutable(c)), None)
        if camp:
            found = True
            if 'name' in body:
                camp['name'] = A._sanitize_str(str(body['name']), 120) or camp['name']
            if 'owner' in body:
                camp['owner'] = A._sanitize_str(str(body['owner']), 64)
            if 'target_date' in body:
                camp['target_date'] = A.re.sub(r'[^0-9\-]', '', str(body['target_date']))[:10]
    if not found:
        A.respond(404, {'error': 'campaign not found'})
    A.audit_log(actor, 'cve_campaign_update', f'id={cid}')
    A.respond(200, {'ok': True})


def handle_cve_exposure_ranked():
    """GET /api/cve/exposure-ranked — hosts ranked by real exploitability: their
    critical/high CVE counts WEIGHTED by whether the host has world-reachable
    listening ports. A critical CVE on a world-exposed host is far more urgent than
    the same CVE on a loopback-only service — this combines the two datasets the CVE
    and Exposure pages hold separately into one 'fix this first' order. Tenant/
    scope-safe (a fleet aggregate; filtered like the others)."""
    A.require_auth()
    devices = A._scope_filter_devices(A.load(A.DEVICES_FILE) or {})
    findings_all = A.load(A.CVE_FINDINGS_FILE) or {}
    cmdb = A.load(A.CMDB_FILE) or {}          # v6.2.3: business criticality weighting
    rows = []
    for dev_id, dev in devices.items():
        if not isinstance(dev, dict):
            continue
        rec = findings_all.get(dev_id) or {}
        findings = [f for f in (rec.get('findings') or [])
                    if isinstance(f, dict) and not f.get('ignored')]
        if not findings:
            continue
        crit = sum(1 for f in findings if f.get('severity') == 'critical')
        high = sum(1 for f in findings if f.get('severity') == 'high')
        fixable = sum(1 for f in findings if A.cve_fixes.is_fixable(f))
        exposed = A._host_world_exposed_ports(dev)
        wx = bool(exposed)
        criticality = str((cmdb.get(dev_id) or {}).get('criticality') or '')
        # A critical on a world-exposed host dominates the order; a fixable one
        # outranks an unfixable one at the same severity; and the whole score is
        # scaled by the asset's business criticality (CMDB) so exposure × severity
        # × importance all land in one "fix this first" number.
        score = (crit * (10 if wx else 1) + high * (3 if wx else 0.5)
                 + min(fixable, 50) * 0.05) * A._CMDB_CRIT_WEIGHT.get(criticality, 1.0)
        rows.append({
            'device_id': dev_id, 'device_name': dev.get('name', dev_id),
            'critical': crit, 'high': high, 'fixable': fixable,
            'world_exposed': wx, 'criticality': criticality,
            'exposed_ports': sorted({f"{p.get('proto', 'tcp')}/{p.get('port')}" for p in exposed})[:12],
            'score': round(score, 2),
            'monitored': dev.get('monitored', True) is not False,
        })
    rows.sort(key=lambda r: (-r['score'], -r['critical'], r['device_name']))
    A.respond(200, {
        'hosts': rows, 'total': len(rows),
        'exposed_with_critical': sum(1 for r in rows if r['world_exposed'] and r['critical']),
    })


def handle_cve_findings():
    """GET /api/cve/findings — aggregate CVE report across all devices."""
    A.require_auth()
    findings_all = A.load(A.CVE_FINDINGS_FILE)
    ignore_data  = A.load(A.CVE_IGNORE_FILE)
    pkg_store    = A.load(A.PACKAGES_FILE)
    devices      = A.load(A.DEVICES_FILE)
    devices = A._scope_filter_devices(devices)  # v3.5.0 RBAC v2
    now = int(A.time.time())

    kev, epss = A._kev_epss()   # v3.14.0: KEV/EPSS prioritization overlay
    # The count option: with it on, the severity totals and each host's counts leave out a finding that no
    # update can clear (the fix tiles still count every finding that is not accepted as risk).
    fixable_only = A.get_cve_count_fixable_only()
    report = {
        'generated_at': now,
        'counting':     'fixable_only' if fixable_only else 'all',
        'devices':      [],
        'summary':      {'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
                         'unknown':  0, 'ignored':  0, 'kev': 0,
                         # v7.4.6 (#57): the findings an update can clear, the ones fixed only in a newer
                         # release, the ones with no fix yet and the ones the distribution cannot tell
                         'fix':      dict.fromkeys(A.cve_fixes.FIX_KEYS, 0),
                         # 8.0.1: what the scans counted per package and did not store one by one
                         'rollup':   0,
                         # 8.0.2: how many of the packages the hosts listed were checked, and why the rest were not.
                         # `hosts_unstated` is how many scanned hosts are in neither number: their last scan is from
                         # before the block existed, and an upgrade starts no scan.
                         'covered':  {'listed': 0, 'checked': 0, 'not_checked': 0, 'reasons': {}, 'hosts_unstated': 0},
                         'devices_scanned': 0,
                         'devices_with_findings': 0,
                         'devices_unsupported': 0},
    }

    most_not_checked = []
    for dev_id, dev in devices.items():
        pkg_entry = pkg_store.get(dev_id) or {}
        ecosystem = A.cve_scanner.entry_ecosystem(pkg_entry)   # 8.0.1: the name the scan uses
        f_entry = findings_all.get(dev_id) or {}
        findings = f_entry.get('findings') or []
        kev_count, epss_max = A._enrich_cve_findings(findings, kev, epss)
        ignore_ids = {k for k, v in ignore_data.items() if A.cve_ignore_applies(v, dev_id, dev)}
        summary = A.cve_scanner.summarize_findings(findings, ignore_ids)
        fix = A.cve_fixes.summarize(findings, ignore_ids)
        if fixable_only:
            ignored = summary['ignored']
            summary = A.cve_scanner.summarize_findings(
                [f for f in findings if A.cve_fixes.counted(f, True, kev)], ignore_ids)
            summary['ignored'] = ignored
        status = 'scanned'
        if not pkg_entry:
            status = 'no_packages'
        elif not ecosystem:
            # the applications of a Windows or macOS host are listed and not checked: "unsupported" says the
            # distribution has no OSV feed, which is not what is wrong with a list of applications
            status = 'no_matcher' if A.software_inventory.is_inventory_host(pkg_entry.get('pkg_manager')) else 'unsupported'
            report['summary']['devices_unsupported'] += 1
        elif not f_entry:
            status = 'not_scanned'

        if f_entry:
            report['summary']['devices_scanned'] += 1
            if sum(summary[k] for k in ('critical', 'high', 'medium', 'low')) > 0:
                report['summary']['devices_with_findings'] += 1
            for k in ('critical', 'high', 'medium', 'low', 'unknown', 'ignored'):
                report['summary'][k] += summary[k]
            for k in fix:
                report['summary']['fix'][k] += fix[k]
            report['summary']['kev'] += kev_count
            report['summary']['rollup'] += A.cve_fixes.rollup_total(f_entry)

        # 8.0.2: which of the host's packages were checked: what its last scan stored, or, for a host nothing is
        # matched against, all of them not. A host that is scannable and was not scanned since 8.0.2 states none.
        covered = A.cve_scanner.entry_package_coverage(pkg_entry, f_entry, with_packages=False)
        if covered:
            A.cve_fixes.covered_add(report['summary']['covered'], covered)
            if covered['not_checked']:
                most_not_checked.append({'device_id': dev_id, 'name': dev.get('name', dev_id),
                                         'listed': covered['listed'], 'not_checked': covered['not_checked'],
                                         'reasons': covered['reasons']})
        elif status == 'scanned':
            # scanned before 8.0.2: the record says nothing of its packages, so the totals do not hold them. Said as a
            # number, or "Packages checked: 0 / 8" beside thirty scanned hosts reads as if they were the ones not checked.
            report['summary']['covered']['hosts_unstated'] += 1

        report['devices'].append({
            'device_id':   dev_id,
            'name':        dev.get('name', dev_id),
            'group':       dev.get('group', ''),
            'os':          dev.get('os', ''),
            'ecosystem':   ecosystem or 'unsupported',
            'status':      status,
            'scanned_at':  f_entry.get('scanned_at', 0),
            'package_count': pkg_entry.get('count', 0),
            'counts':      summary,
            'fix':         fix,          # v7.4.6 (#57)
            'rollup':      A.cve_fixes.rollup_total(f_entry),   # 8.0.1: counted per package, not listed
            'covered':     covered,      # 8.0.2: packages checked and not checked, or None
            'kev':         kev_count,    # v3.14.0
            'epss_max':    epss_max,     # v3.14.0 (0–1)
        })

    # the hosts with the most packages not checked, for the line under the tiles
    most_not_checked.sort(key=lambda r: (-r['not_checked'], str(r['name']).lower()))
    report['summary']['most_not_checked'] = most_not_checked[:5]

    # v3.14.0: prioritize by exploited-in-wild (KEV) → criticals → highs → EPSS.
    report['devices'].sort(
        key=lambda d: (-d.get('kev', 0), -d['counts']['critical'],
                       -d['counts']['high'], -d.get('epss_max', 0), d['name'].lower())
    )
    # v3.14.0 fix: surface the KEV/EPSS feed state so "why is there no KEV?" is
    # answerable — distinguishes "feed not loaded / errored" from " no
    # known-exploited CVEs on these hosts".
    _ke = A.load(A.KEV_EPSS_FILE) or {}
    report['kev_feed'] = {
        'kev_count':    len(kev),
        'epss_count':   len(epss),
        'last_checked': _ke.get('last_checked', 0),
        'kev_error':    _ke.get('kev_error', ''),
        'epss_error':   _ke.get('epss_error', ''),
    }
    A.respond(200, report)


def handle_cve_refresh_feeds():
    """POST /api/cve/refresh-feeds — force a KEV/EPSS refresh now (admin). Lets
    an operator populate the feeds immediately instead of waiting for the daily
    sweep, and see any feed error."""
    A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    try:
        A.refresh_kev_epss_if_due(force=True)
    except Exception as e:
        A.respond(502, {'error': f'Feed refresh failed: {A.integrations_mod.explain_failure(e)}'})
    s = A.load(A.KEV_EPSS_FILE) or {}
    A.respond(200, {'ok': True, 'kev_count': len(s.get('kev') or []),
                  'epss_count': len(s.get('epss') or {}),
                  'kev_error': s.get('kev_error', ''),
                  'epss_error': s.get('epss_error', '')})


def handle_cve_device(dev_id):
    """GET /api/devices/{id}/cve — detailed findings for one device."""
    A.require_auth()
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'Host not found'})

    dev = A.device_get(dev_id)   # v4.3.0: single-row read
    if dev is None:
        A.respond(404, {'error': 'Host not found'})

    findings_all = A.load(A.CVE_FINDINGS_FILE)
    ignore_data  = A.load(A.CVE_IGNORE_FILE)
    pkg_store    = A.load(A.PACKAGES_FILE)

    f_entry   = findings_all.get(dev_id) or {}
    pkg_entry = pkg_store.get(dev_id) or {}
    if not isinstance(pkg_entry, dict):
        pkg_entry = {}
    ecosystem = A.cve_scanner.entry_ecosystem(pkg_entry)
    cut       = f_entry.get('cut')
    cut       = cut if isinstance(cut, list) else []
    findings  = f_entry.get('findings') or []
    findings  = A.cve_scanner.apply_ignore_list(findings, ignore_data, dev_id, A._device_tenant(dev))
    _kev, _epss = A._kev_epss()                       # v3.14.0
    A._enrich_cve_findings(findings, _kev, _epss)     # stamp kev/epss per finding

    A.respond(200, {
        'device_id':      dev_id,
        'name':           dev.get('name', dev_id),
        'group':          dev.get('group', ''),
        'os':             dev.get('os', ''),
        'ecosystem':      ecosystem or 'unsupported',
        'scanned_at':     f_entry.get('scanned_at', 0),
        'packages_count': pkg_entry.get('count', 0),
        'collected_at':   pkg_entry.get('collected_at', 0),
        'findings':       findings,
        'error':          f_entry.get('error', ''),
        # 8.0.1: what this scan leaves out (a word, see cve_scanner.coverage) and the packages whose
        # advisory list was longer than a scan reads
        # 'no_matcher': there is a list and nothing it names is checked: the applications of a Windows or
        # macOS host, the packages of Arch
        'coverage':       A.cve_scanner.entry_coverage(pkg_entry),
        'cut':            [str(n) for n in cut if isinstance(n, str)][:20],
        # 8.0.1: what the scan counted per package and did not store one by one (cve_fixes.split)
        'rollup':         _rollup_view(f_entry),
        # 8.0.2: which of the host's packages the last scan checked, and why the others were not (the first 200)
        'covered':        A.cve_scanner.entry_package_coverage(pkg_entry, f_entry),
        # 8.0.2: which kernel the host runs, the package it is, and a kernel installed beside it that is newer; or
        # that the scan could not tell, and why
        'kernel':         A.cve_fixes.kernel_view(f_entry.get('kernel')),
    })


def _rollup_view(f_entry):
    """The roll-up of one host's scan result as the page gets it: the numbers, and the packages cut to
    what the scanner writes. A result without one, or with one of another shape, gives None."""
    counted = f_entry.get('rollup') if isinstance(f_entry, dict) else None
    total = A.cve_fixes.rollup_total(f_entry)
    if not total:
        return None

    def numbers(value, keys):
        value = value if isinstance(value, dict) else {}
        return {k: value[k] for k in keys
                if isinstance(value.get(k), int) and not isinstance(value.get(k), bool) and value[k] > 0}

    packages = []
    for row in counted.get('packages') if isinstance(counted.get('packages'), list) else []:
        if not isinstance(row, dict) or not isinstance(row.get('name'), str):
            continue
        count = row.get('count')
        packages.append({'name': row['name'][:200],
                         'version': str(row.get('version') or '')[:128],
                         'count': count if isinstance(count, int) and not isinstance(count, bool) else 0})
        if len(packages) >= A.cve_fixes.ROLLUP_PACKAGES:
            break
    more = numbers(counted.get('more'), ('packages', 'count'))
    return {'total': total,
            'severity': numbers(counted.get('severity'), A.cve_fixes.SEVERITIES),
            'fix': numbers(counted.get('fix'), A.cve_fixes.FIX_KEYS),
            'packages': packages,
            'more': {'packages': more.get('packages', 0), 'count': more.get('count', 0)}}



def _ignore_owner_gate(entry):
    """The tenant an accepted-risk record belongs to: a tenant id, or None for the operator's own.

    A record written from v7.0.3 by a tenant carries the tenant. An older one, and every record of the operator's, does not,
    so the owner is the tenant of the account that wrote it. A record whose author is gone belongs to the operator."""
    owner = entry.get('tenant')
    if owner:
        return owner
    if not A._tenancy_enforced():
        return None
    actor = entry.get('actor')
    if not isinstance(actor, str) or not actor:
        return None
    tid = A._user_tenant(actor)
    return None if tid == A.DEFAULT_TENANT else tid


def _ignore_entry_visible(entry):
    """Can the caller see this accepted-risk record?

    The platform operator sees all of them. A user of the operator's organisation sees the operator's own. A tenant sees the
    records its own users wrote, and the ones the operator wrote for one of its hosts. 7.4.9: the operator's `global` records
    used to be listed to every tenant, with the account that wrote them and its reason, and a tenant administrator could delete
    them, which lifts the acceptance for the whole installation.
    """
    if not isinstance(entry, dict):
        return True
    gate = A._tenant_gate()
    if gate is None:
        return True
    owner = _ignore_owner_gate(entry)                  # None: the operator's own
    mine = None if gate == A.DEFAULT_TENANT else gate  # whose records the caller reads
    if owner is not None:
        return owner == mine
    scope = entry.get('scope')
    if scope and scope != 'global':
        dev = A.device_get(scope)
        return mine is None if dev is None else A._tenant_visible(dev)
    return mine is None


def visible_ignore_records(value):
    """The accepted-risk records under one id that the caller may see, each without the `others` list of the value it came from.

    The one place a reader that hands the content of a record to a caller (its reason, the account that wrote it, the host it
    names) gets the records from, so that none of them has to ask `_ignore_entry_visible` of the right object itself. The census
    in tests/test_v802_cve_flow_tenancy.py lists every reader of the store and holds each one that shows content to this."""
    return [{k: v for k, v in r.items() if k != 'others'}
            for r in A.checks_mod.cve_ignore_records(value) if _ignore_entry_visible(r)]


def _pack_ignore_records(records):
    """The value to keep under one id for these records: the first as it is, the rest in its `others`. None for no records."""
    if not records:
        return None
    first = {k: v for k, v in records[0].items() if k != 'others'}
    rest = [{k: v for k, v in r.items() if k != 'others'} for r in records[1:]]
    if rest:
        first['others'] = rest
    return first


# What an accepted-risk record may be filed under. The ids of the advisory databases use letters, digits and a few separators
# (CVE-2024-3094, DEBIAN-CVE-2024-3094, GHSA-xxxx-xxxx-xxxx, ALSA-2024:1234, openSUSE-SU-2024:1234-1). Free text of up to 64
# characters was accepted before, which filled the page with names that match no finding.
_VULN_ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:+-]{0,63}$')

# How many records one organisation may hold. The page lists them all and every reader of the store reads all of them. A fleet
# that accepts a risk host by host (500 hosts, ten CVEs) holds 5,000, so the ceiling sits above that.
MAX_IGNORES_PER_OWNER = 5000


def _is_vuln_id(value):
    # fullmatch: `$` accepts a newline after the last character, so `match` let "CVE-2024-3094\n" through
    return bool(_VULN_ID_RE.fullmatch(value))


def handle_cve_ignore_add():
    """POST /api/cve/ignore — mark a vuln as accepted risk."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})

    body     = A._read_valid(A.request_models.CveIgnoreAddRequest)
    vuln_id  = A._sanitize_str(body.get('vuln_id', ''), 64, allow_empty=False)
    reason   = A._sanitize_str(body.get('reason', ''), 256)
    scope    = A._sanitize_str(body.get('scope', 'global'), 64)
    if not vuln_id:
        A.respond(400, {'error': 'vuln_id required'})
    if not _is_vuln_id(vuln_id):
        A.respond(400, {'error': 'Invalid vuln_id'})
    if scope != 'global' and not A._validate_id(scope):
        A.respond(400, {'error': 'scope must be "global" or a valid device_id'})
    # v7.0.3 (SECURITY): `scope` names a device and was validated for SHAPE only.
    # require_admin_auth() passes a TENANT admin, so any device id was accepted
    # and a finding could be marked accepted risk on another tenant's host.
    if scope != 'global':
        A._scope_block_device(scope)

    # Stamp the tenant that accepted the risk. The store is keyed by
    # vulnerability id alone, so without this a `global` record from one tenant
    # silenced the same CVE on every other tenant's hosts — and overwrote their
    # record for it. `_tenant_gate()` is None for a superadmin and on every
    # single-tenant install, where a global record stays exactly that.
    owner = A._tenant_gate()

    entry = {
        'scope':  scope,
        'reason': reason,
        'actor':  actor,
        'ts':     int(A.time.time()),
    }
    if owner:
        entry['tenant'] = owner
    # Read and written under the store's lock: two administrators who accept a risk together took one another's record away.
    with A._LockedUpdate(A.CVE_IGNORE_FILE) as ignore_data:
        records = A.checks_mod.cve_ignore_records(ignore_data.get(vuln_id))
        # The caller's own record under this id is replaced by this one. The records of other organisations under the
        # same id stay as they are. The store is keyed by the id alone, and refusing an id because another organisation
        # holds it let one tenant take every id away from the others and told them which ids were taken (the 404 that
        # stood here was that answer). Each organisation's records are its own.
        kept = [r for r in records if _ignore_owner_gate(r) != owner]
        held = sum(1 for value in ignore_data.values() for r in A.checks_mod.cve_ignore_records(value)
                   if _ignore_owner_gate(r) == owner) - (len(records) - len(kept))
        if held >= MAX_IGNORES_PER_OWNER:
            A.respond(400, {'error': 'Too many accepted risks. Remove some first.', 'limit': MAX_IGNORES_PER_OWNER})
        ignore_data[vuln_id] = _pack_ignore_records(kept + [entry])
    A.audit_log(actor, 'cve_ignore_add',
              detail=f'{vuln_id} scope={scope} reason={reason[:80]}')
    A.respond(200, {'ok': True, 'ignored': vuln_id})


def handle_cve_ignore_delete(vuln_id):
    """DELETE /api/cve/ignore/{vuln_id} — lift the acceptance of this id: the records under it that the caller may see."""
    actor = A.require_admin_auth()
    vuln_id = A._sanitize_str(vuln_id, 64, allow_empty=False)
    if not vuln_id:
        A.respond(400, {'error': 'Invalid vuln_id'})
    removed = 0
    with A._LockedUpdate(A.CVE_IGNORE_FILE) as ignore_data:
        records = A.checks_mod.cve_ignore_records(ignore_data.get(vuln_id))
        mine = [r for r in records if _ignore_entry_visible(r)]
        if mine:
            removed = len(mine)
            packed = _pack_ignore_records([r for r in records if not _ignore_entry_visible(r)])
            if packed is None:
                del ignore_data[vuln_id]
            else:
                ignore_data[vuln_id] = packed
    # v7.0.3 (SECURITY): 404 rather than 403 on another tenant's record — the
    # same shape every other device-keyed store uses, so the response does not
    # confirm that the record exists. An id that nobody holds answers the same
    # to a tenant's user: it used to answer 200, which told a tenant that a 404
    # meant another organisation's record. A caller no tenant gate applies to
    # (the operator, or any user of an install without tenancy) sees every
    # record, so for them "not there" has no one to hide, and the answer is the
    # idempotent 200 it has always been.
    if not removed and A._tenant_gate() is not None:
        A.respond(404, {'error': 'Not found'})
    if removed:
        A.audit_log(actor, 'cve_ignore_remove', detail=vuln_id)
    A.respond(200, {'ok': True})


def handle_cve_ignore_list():
    """GET /api/cve/ignore — list all active ignores."""
    A.require_auth()
    ignore_data = A.load(A.CVE_IGNORE_FILE)
    # v7.0.3 (SECURITY): the rows carry a device id in `scope`, so an
    # unfiltered list handed every caller the other tenants' host ids.
    items = [{'vuln_id': k, **record} for k, v in ignore_data.items()
             for record in visible_ignore_records(v)]
    items.sort(key=lambda x: -x.get('ts', 0))
    A.respond(200, {'ignores': items})
