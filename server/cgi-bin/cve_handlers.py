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
    fired = 0
    for dev_id, rec in findings_all.items():
        if dev_id not in devices:
            continue
        alerted = []
        for f in (rec or {}).get('findings') or []:
            vid = f.get('vuln_id')
            if not vid or f.get('severity') not in sev_filter:
                continue
            ig = ignore_data.get(vid)
            if ig and ig.get('scope') in ('global', dev_id):
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
    A.audit_log(actor, 'cve_realert', f'{fired} device(s) re-alerted')
    A.respond(200, {'ok': True, 'devices': fired})


def handle_cve_scan():
    """POST /api/cve/scan — queue a background scan for one or all devices.

    The scan runs in a detached process so the UI stays responsive; it returns
    202 immediately. Poll GET /api/cve/scan-status for progress."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.CveScanRequest)
    body = A.get_json_obj() if A._env('CONTENT_LENGTH', '0') != '0' else {}
    target = body.get('device_id')
    if target is not None:
        target = str(target).strip()
        if not A._validate_id(target):
            A.respond(400, {'error': 'Invalid device_id'})
        A._scope_block_device(target)   # SEC: scans that device's packages
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
    _age = int(A.time.time()) - (st.get('updated') or 0)
    if st.get('running') and _age < A._CVE_SCAN_STALE_S:
        A.respond(409, {'error': 'A scan is already running', 'status': st,
                      'retry_after_seconds': max(0, A._CVE_SCAN_STALE_S - _age),
                      'detail': ('If the previous scan crashed, this clears '
                                 f'{A._CVE_SCAN_STALE_S // 60} minutes after its '
                                 'last checkpoint.')})
    total = 1 if target else len(A.load(A.PACKAGES_FILE) or {})
    # v6.1.2: the status marker is written non_blocking so a wedged writer can
    # never hang the request — but a CONTENDED write then raises LockBusy, which
    # used to propagate uncaught and render as a 500 (the production symptom on
    # the Postgres backend, whose non_blocking acquire had no retry budget at
    # all until this release; see storage_pg._try_lock). Contention here just
    # means a scan runner is mid-write, so say so with a retryable 409.
    try:
        A.save(A.CVE_SCAN_STATUS_FILE, {'running': True, 'total': total, 'done': 0,
                                    'scanned': 0, 'skipped': 0, 'errors': 0,
                                    'updated': int(A.time.time()),
                                    'started_at': int(A.time.time())}, non_blocking=True)
    except A.LockBusy:
        A.respond(409, {'error': 'A scan is starting or running — try again shortly'})
    A._spawn_cve_scan(actor, target)
    A.respond(202, {'queued': True, 'total': total,
                  'message': 'Scan queued — running in the background.'})


def handle_cve_scan_status():
    """GET /api/cve/scan-status — progress of the background CVE scan."""
    A.require_auth()
    A.respond(200, A.load(A.CVE_SCAN_STATUS_FILE) or {'running': False})


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
        rows = [A._campaign_public(c, cve_all, cve_ignore, devices) for c in camps]
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
               for x in (body.get('cve_ids') or [])[:500]]
    cve_ids = [c for c in cve_ids if c]
    sevs = [s for s in (str(x).lower() for x in (body.get('severities') or []))
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
        fixable = sum(1 for f in findings if str(f.get('fixed_version') or '').strip())
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
    report = {
        'generated_at': now,
        'devices':      [],
        'summary':      {'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
                         'unknown':  0, 'ignored':  0, 'kev': 0,
                         'devices_scanned': 0,
                         'devices_with_findings': 0,
                         'devices_unsupported': 0},
    }

    for dev_id, dev in devices.items():
        pkg_entry = pkg_store.get(dev_id) or {}
        ecosystem = pkg_entry.get('ecosystem', '')
        f_entry = findings_all.get(dev_id) or {}
        findings = f_entry.get('findings') or []
        kev_count, epss_max = A._enrich_cve_findings(findings, kev, epss)
        summary = A.cve_scanner.summarize_findings(
            findings,
            {k for k, v in ignore_data.items()
             if v.get('scope') == 'global' or v.get('scope') == dev_id}
        )
        status = 'scanned'
        if not pkg_entry:
            status = 'no_packages'
        elif not ecosystem:
            status = 'unsupported'
            report['summary']['devices_unsupported'] += 1
        elif not f_entry:
            status = 'not_scanned'

        if f_entry:
            report['summary']['devices_scanned'] += 1
            if sum(summary[k] for k in ('critical', 'high', 'medium', 'low')) > 0:
                report['summary']['devices_with_findings'] += 1
            for k in ('critical', 'high', 'medium', 'low', 'unknown', 'ignored'):
                report['summary'][k] += summary[k]
            report['summary']['kev'] += kev_count

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
            'kev':         kev_count,    # v3.14.0
            'epss_max':    epss_max,     # v3.14.0 (0–1)
        })

    # v3.14.0: prioritize by exploited-in-wild (KEV) → criticals → highs → EPSS.
    report['devices'].sort(
        key=lambda d: (-d.get('kev', 0), -d['counts']['critical'],
                       -d['counts']['high'], -d.get('epss_max', 0), d['name'].lower())
    )
    # v3.14.0 fix: surface the KEV/EPSS feed state so "why is there no KEV?" is
    # answerable — distinguishes "feed not loaded / errored" from "genuinely no
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
        A.respond(502, {'error': f'Feed refresh failed: {str(e)[:200]}'})
    s = A.load(A.KEV_EPSS_FILE) or {}
    A.respond(200, {'ok': True, 'kev_count': len(s.get('kev') or []),
                  'epss_count': len(s.get('epss') or {}),
                  'kev_error': s.get('kev_error', ''),
                  'epss_error': s.get('epss_error', '')})


def handle_cve_device(dev_id):
    """GET /api/devices/{id}/cve — detailed findings for one device."""
    A.require_auth()
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'Device not found'})

    dev = A.device_get(dev_id)   # v4.3.0: single-row read
    if dev is None:
        A.respond(404, {'error': 'Device not found'})

    findings_all = A.load(A.CVE_FINDINGS_FILE)
    ignore_data  = A.load(A.CVE_IGNORE_FILE)
    pkg_store    = A.load(A.PACKAGES_FILE)

    f_entry   = findings_all.get(dev_id) or {}
    pkg_entry = pkg_store.get(dev_id) or {}
    findings  = f_entry.get('findings') or []
    findings  = A.cve_scanner.apply_ignore_list(findings, ignore_data, dev_id)
    _kev, _epss = A._kev_epss()                       # v3.14.0
    A._enrich_cve_findings(findings, _kev, _epss)     # stamp kev/epss per finding

    A.respond(200, {
        'device_id':      dev_id,
        'name':           dev.get('name', dev_id),
        'group':          dev.get('group', ''),
        'os':             dev.get('os', ''),
        'ecosystem':      pkg_entry.get('ecosystem', '') or 'unsupported',
        'scanned_at':     f_entry.get('scanned_at', 0),
        'packages_count': pkg_entry.get('count', 0),
        'collected_at':   pkg_entry.get('collected_at', 0),
        'findings':       findings,
        'error':          f_entry.get('error', ''),
    })


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
    if scope != 'global' and not A._validate_id(scope):
        A.respond(400, {'error': 'scope must be "global" or a valid device_id'})

    ignore_data = A.load(A.CVE_IGNORE_FILE)
    ignore_data[vuln_id] = {
        'scope':  scope,
        'reason': reason,
        'actor':  actor,
        'ts':     int(A.time.time()),
    }
    A.save(A.CVE_IGNORE_FILE, ignore_data)
    A.audit_log(actor, 'cve_ignore_add',
              detail=f'{vuln_id} scope={scope} reason={reason[:80]}')
    A.respond(200, {'ok': True, 'ignored': vuln_id})


def handle_cve_ignore_delete(vuln_id):
    """DELETE /api/cve/ignore/{vuln_id}"""
    actor = A.require_admin_auth()
    vuln_id = A._sanitize_str(vuln_id, 64, allow_empty=False)
    if not vuln_id:
        A.respond(400, {'error': 'Invalid vuln_id'})
    ignore_data = A.load(A.CVE_IGNORE_FILE)
    if vuln_id in ignore_data:
        del ignore_data[vuln_id]
        A.save(A.CVE_IGNORE_FILE, ignore_data)
        A.audit_log(actor, 'cve_ignore_remove', detail=vuln_id)
    A.respond(200, {'ok': True})


def handle_cve_ignore_list():
    """GET /api/cve/ignore — list all active ignores."""
    A.require_auth()
    ignore_data = A.load(A.CVE_IGNORE_FILE)
    items = [{'vuln_id': k, **v} for k, v in ignore_data.items()]
    items.sort(key=lambda x: -x.get('ts', 0))
    A.respond(200, {'ignores': items})
