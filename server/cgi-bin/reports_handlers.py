"""RemotePower — fleet/site posture reports, evidence pack, scheduled + custom report definitions

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


# ── v3.4.1: fleet posture report ───────────────────────────────────────────────
# One report that binds together the four posture surfaces operators otherwise
# read on separate pages — patches, CVEs, health score, and compliance — so a
# single export (or scheduled email) captures "how is the fleet doing right now".

def _period_activity(devices, now, days=30):
    """Activity over the window plus deltas against the start of it.

    Alerts come from the alert store rather than the fleet-event log on
    purpose: FLEET_EVENTS_FILE caps at MAX_FLEET_EVENTS and spills the overflow
    to a gzip archive nothing reads, so on a busy fleet a month of activity is
    simply not reconstructable from it.

    Opened is counted from `_alert_first_seen`, not `ts` — `ts` is rewritten on
    every coalesced re-fire, so counting it would inflate a noisy week.
    """
    out = {'days': days}
    cutoff = now - days * 86400
    try:
        store = A.load(A.ALERTS_FILE) or {}
        alerts = store.get('alerts', []) if isinstance(store, dict) else []
        visible = set(devices)
        # Scope to the report's own device set; fleet-level alerts (no device)
        # belong to every report.
        mine = [a for a in alerts if isinstance(a, dict)
                and (not a.get('device_id') or a.get('device_id') in visible)]
        out['alerts_opened'] = sum(1 for a in mine
                                   if (A._alert_first_seen(a) or 0) >= cutoff)
        stats = A._alert_resolution_stats(mine, days)
        out['alerts_resolved'] = stats.get('resolved_count', 0)
        out['mttr_median'] = stats.get('mttr_median', 0)
        out['mttr_mean'] = stats.get('mttr_mean', 0)
        out['mtta_mean'] = stats.get('mtta_mean', 0)
    except Exception as e:
        A.sys.stderr.write(f'[remotepower] report period/alerts failed: {e}\n')

    def _delta(hist_file, key):
        """Value at the start of the window vs now, from a daily sampler."""
        try:
            # Both daily samplers write {'fleet': [{date, ts, score, …}], …} —
            # verified against _maybe_sample_health / _maybe_sample_compliance
            # rather than assumed. A guessed key here would have returned an
            # empty list forever and the delta would simply never appear, which
            # is indistinguishable from "no history yet".
            blob = A.load(hist_file) or {}
            rows = blob.get('fleet') if isinstance(blob, dict) else blob
            rows = rows if isinstance(rows, list) else []
            rows = [r for r in rows if isinstance(r, dict) and r.get(key) is not None]
            if not rows:
                return None, None
            rows.sort(key=lambda r: r.get('ts') or 0)
            prior = [r for r in rows if (r.get('ts') or 0) <= cutoff]
            # No sample that old yet → report the value without a delta rather
            # than inventing one against the oldest point we happen to have.
            before = prior[-1].get(key) if prior else None
            return before, rows[-1].get(key)
        except Exception as e:
            A.sys.stderr.write(f'[remotepower] report delta {key} failed: {e}\n')
            return None, None

    h_before, h_now = _delta(A.HEALTH_HIST_FILE, 'score')
    c_before, c_now = _delta(A.COMPLIANCE_HIST_FILE, 'score')
    out['previous'] = {'health_score': h_before, 'compliance_pct': c_before}
    out['delta'] = {
        'health_score': (round(h_now - h_before, 1)
                         if h_before is not None and h_now is not None else None),
        'compliance_pct': (round(c_now - c_before, 1)
                           if c_before is not None and c_now is not None else None),
    }
    try:
        logs = A.load(A.UPDATE_LOGS_FILE) or {}
        applied = 0
        for did, runs in (logs.items() if isinstance(logs, dict) else []):
            if did not in devices:
                continue
            for r in (runs or []):
                if isinstance(r, dict) and int(r.get('ts') or 0) >= cutoff:
                    applied += 1
        out['patches_applied_runs'] = applied
    except Exception as e:
        A.sys.stderr.write(f'[remotepower] report period/patches failed: {e}\n')
    return out


def _build_fleet_report(site_id=None):
    """Assemble the fleet (or single-site) posture report from data RemotePower
    already holds.

    Reuses the existing single-source-of-truth helpers (_fleet_health,
    _compliance_facts/compliance.build_report, the CVE findings store) rather
    than recomputing, so the report can never disagree with the live pages.
    When `site_id` is given, devices / patches / SLA / CVE / health are scoped to
    that site; compliance is scoped to the caller's visible devices (v6.3.1 —
    was fleet-wide, a cross-scope hostname leak via the evidence strings)."""
    devices = A.load(A.DEVICES_FILE) or {}
    if site_id is not None:
        devices = {k: v for k, v in devices.items()
                   if isinstance(v, dict) and (v.get('site') or '') == site_id}
    # v5.7.0 (SECURITY): confine the report to the caller's role scope + tenant.
    # Reached from handle_fleet_report / handle_evidence_pack after require_auth;
    # without this a group/tag/site-scoped operator (or, under multi-tenancy, a
    # tenant user) got fleet-wide device names, worst-10 health, and CVE/patch/
    # SLA aggregates. Mirrors handle_fleet_health's re-filter.
    _pre_scope_n = len(devices)
    devices = A._scope_filter_devices(devices)
    # `site_ids` restricts the CVE + health rosters below. Use the visible id set
    # whenever a site filter is active OR the caller's scope/tenant actually
    # trimmed the fleet; None (all findings) only for a fully-unscoped admin, so
    # the admin path is byte-for-byte unchanged.
    _caller_restricted = len(devices) != _pre_scope_n
    site_ids = (set(devices) if (site_id is not None or _caller_restricted)
                else None)
    now = int(A.time.time())
    ttl = A.get_online_ttl()
    online = sum(1 for d in devices.values()
                 if isinstance(d, dict) and (now - d.get('last_seen', 0)) < ttl)

    with_patches = 0
    total_pending = 0
    for d in devices.values():
        up = ((d.get('sysinfo') or {}).get('packages') or {}).get('upgradable')
        if isinstance(up, int) and up > 0:
            with_patches += 1
            total_pending += up

    cve = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'devices_affected': 0}
    # v3.4.2: apply the per-device CVE ignore list exactly like the live CVE
    # page (handle_cve_findings) so the posture report can't over-count by the
    # ignored set. Iterate items() to keep the device id apply_ignore_list needs.
    cve_ignore = A.load(A.CVE_IGNORE_FILE) or {}
    for did, rec in (A.load(A.CVE_FINDINGS_FILE) or {}).items():
        if site_ids is not None and did not in site_ids:
            continue
        affected = False
        findings = (rec or {}).get('findings') or []
        for f in A.cve_scanner.apply_ignore_list(findings, cve_ignore, did):
            if f.get('ignored'):
                continue
            sev = str(f.get('severity', '')).lower()
            if sev in cve:
                cve[sev] += 1
                affected = True
        if affected:
            cve['devices_affected'] += 1

    health = A._fleet_health()
    if site_ids is not None:
        # Scope the health roster + recompute the headline score/grade/counts.
        hdevs = [d for d in health['devices'] if d.get('device_id') in site_ids]
        hscore = round(sum(d['score'] for d in hdevs) / len(hdevs)) if hdevs else 100
        health = {
            'score': hscore, 'grade': A._health_grade(hscore), 'devices': hdevs,
            'counts': {'critical': sum(d.get('critical', 0) for d in hdevs),
                       'warning':  sum(d.get('warning', 0) for d in hdevs),
                       'info':     sum(d.get('info', 0) for d in hdevs)},
        }
    # v6.3.1 (SECURITY): scope compliance to the caller's visible devices too —
    # it was fleet-wide, leaking other scopes'/tenants' hostnames via the
    # offender-list evidence strings. `devices` here is already
    # _scope_filter_devices'd above.
    comp = A.compliance.build_report(A._compliance_facts(devices))
    comp['generated_ts'] = now
    if site_id is not None:
        comp['scope'] = 'fleet'   # compliance frameworks are graded fleet-wide

    # v3.4.1: fleet uptime % over the last 30 days (SLA headline).
    uptime = A.load(A.UPTIME_FILE) or {}
    win = now - 30 * 86400
    sla_pcts = []
    for did, d in devices.items():
        if not isinstance(d, dict) or d.get('monitored') is False:
            continue
        pct, _down, covered = A._uptime_pct((uptime.get(did) or {}).get('events') or [], win, now)
        if covered and pct is not None:
            sla_pcts.append(pct)
    fleet_uptime = round(sum(sla_pcts) / len(sla_pcts), 3) if sla_pcts else None

    # v6.4.2 (audit): host security POSTURE in the report. Firewall, sshd
    # hardening and encryption-at-rest reached the Checks page and the risk score
    # but never the artefact an auditor is handed. Aggregated from the sysinfo
    # already loaded above — no extra store reads. Each dimension carries its own
    # "reporting" denominator so an absent signal is never counted as a pass.
    pos = {'firewall_off': [], 'ssh_weak': [], 'autoupdate_off': [],
           'encryption_off': [],
           'firewall_reporting': 0, 'ssh_reporting': 0,
           'autoupdate_reporting': 0, 'encryption_reporting': 0}
    for did, d in devices.items():
        if not isinstance(d, dict) or d.get('monitored') is False:
            continue
        si = d.get('sysinfo') or {}
        nm = d.get('name', did)
        fw = si.get('firewall')
        if isinstance(fw, dict) and fw.get('active') is not None:
            pos['firewall_reporting'] += 1
            if fw.get('active') is False:
                pos['firewall_off'].append(nm)
        sc = si.get('ssh_config')
        if isinstance(sc, dict) and sc:
            pos['ssh_reporting'] += 1
            if (str(sc.get('permit_empty_passwords', '')).lower() == 'yes'
                    or str(sc.get('permit_root_login', '')).lower() == 'yes'
                    or str(sc.get('password_authentication', '')).lower() == 'yes'):
                pos['ssh_weak'].append(nm)
        au = si.get('autoupdate')
        if isinstance(au, dict) and 'enabled' in au:
            pos['autoupdate_reporting'] += 1
            if au.get('enabled') is False:
                pos['autoupdate_off'].append(nm)
        # encryption-at-rest: FileVault (macOS bool) / BitLocker (Windows, per OS
        # volume). Present-and-off only; absence is not counted.
        mp = si.get('mac_posture')
        de = si.get('disk_encryption')
        if isinstance(mp, dict) and 'filevault' in mp:
            pos['encryption_reporting'] += 1
            if not mp.get('filevault'):
                pos['encryption_off'].append(nm)
        elif isinstance(de, dict) and isinstance(de.get('encrypted'), bool):
            pos['encryption_reporting'] += 1          # v6.4.3: Linux LUKS
            if not de['encrypted']:
                pos['encryption_off'].append(nm)
        else:
            wp = si.get('win_posture')
            bl = wp.get('bitlocker') if isinstance(wp, dict) else None
            if isinstance(bl, list) and bl:
                pos['encryption_reporting'] += 1
                if any(isinstance(v, dict)
                       and str(v.get('status', '')).lower() not in ('on', 'encrypted')
                       for v in bl):
                    pos['encryption_off'].append(nm)
    # keep the offender lists bounded like the health `worst` list
    for _k in ('firewall_off', 'ssh_weak', 'autoupdate_off', 'encryption_off'):
        pos[_k + '_count'] = len(pos[_k])
        pos[_k] = pos[_k][:10]

    # v6.4.2: white-labelling. The printable report (report.html) hardcoded the
    # RemotePower name + logo even on an install that had set brand_name /
    # brand_accent, so the one artefact most likely to be sent to a CUSTOMER was
    # the one surface that ignored the operator's branding. Read-only shared
    # config (never mutated here) — the same accessor the patch-SLA block below
    # already uses, so this adds no extra load()/deepcopy on the read path.
    _brand_cfg = A._config_ro() or {}

    out = {
        'generated_ts':   now,
        'server_version': A.SERVER_VERSION,
        'server_name':    A.get_server_name(),
        'brand':          {'name':   _brand_cfg.get('brand_name', ''),
                           'accent': _brand_cfg.get('brand_accent', '')},
        'devices':        {'total': len(devices), 'online': online,
                           'offline': len(devices) - online},
        'sla':            {'days': 30, 'fleet_uptime_pct': fleet_uptime},
        'patches':        {'devices_with_patches': with_patches,
                           'total_pending': total_pending,
                           # W1-33: hosts currently past a patch-SLA deadline
                           'sla_violations': len(A._eval_patch_sla(
                               devices, A._config_ro(), dict(A.load(A.PATCH_AGE_FILE) or {}),
                               now)[1])},
        'cve':            cve,
        'health':         {'score': health['score'], 'grade': health['grade'],
                           'worst': health['devices'][:10]},
        'attention':      health['counts'],
        'posture':        pos,
        'compliance':     comp,
        # v6.4.2: what CHANGED, not just where things stand. Every section above
        # is a live counter, so two consecutive weekly reports were
        # indistinguishable — the recipient could not tell whether the team was
        # winning. No new collection: MTTR/MTTA come from the alert store and
        # the deltas from the daily health/compliance history samplers.
        'period':         _period_activity(devices, now),
    }
    if site_id is not None:
        out['site_id'] = site_id
        out['site_name'] = ((A.load(A.SITES_FILE) or {}).get(site_id) or {}).get('name', site_id)
    return out


# v3.14.0: custom report builder — selectable sections + saved definitions.
_REPORT_SECTIONS = ('devices', 'sla', 'patches', 'cve', 'health', 'attention',
                    'posture', 'compliance', 'period')
# v6.4.2: sections that cost real money and latency to produce. Deliberately
# OUTSIDE the default tuple, because `sections or list(_REPORT_SECTIONS)` would
# otherwise switch AI billing on for every install that has ever saved a report
# definition. Opt-in per definition, and a no-op when AI is disabled.
_REPORT_OPT_IN_SECTIONS = ('summary',)
_ALL_REPORT_SECTIONS = _REPORT_SECTIONS + _REPORT_OPT_IN_SECTIONS


def _report_summary_context(report):
    """The figures the summary model is allowed to see — the report's own
    numbers, nothing else.

    Built as an explicit projection rather than handing over the whole report:
    the report carries per-device rows (names, IPs, scores) and this goes to a
    possibly-cloud provider. `ai_provider.chat` redacts per the privacy config
    on top of this, but the narrower input is the one that cannot leak a
    hostname the operator forgot to redact.
    """
    def _pick(section, *keys):
        src = report.get(section) or {}
        return {k: src.get(k) for k in keys if src.get(k) is not None}

    ctx = {
        'health':     _pick('health', 'score', 'grade'),
        'devices':    _pick('devices', 'total', 'online', 'offline', 'monitored'),
        'attention':  _pick('attention', 'critical', 'warning', 'info'),
        'patches':    _pick('patches', 'devices_with_patches', 'total_pending',
                            'security_pending'),
        'cve':        _pick('cve', 'critical', 'high', 'medium', 'devices_affected',
                            'kev_count'),
        'sla':        _pick('sla', 'days', 'fleet_uptime_pct'),
        'compliance': _pick('compliance', 'score', 'passing', 'failing'),
        'period':     report.get('period') or {},
    }
    if report.get('site_name'):
        ctx['scope'] = f"one site: {report['site_name']}"
    return {k: v for k, v in ctx.items() if v}


def _build_report_summary(report):
    """The narrative paragraph, or a dict saying why there isn't one.

    Never raises and never blocks the report: a provider outage must cost the
    covering paragraph, not the artifact the operator scheduled. The reason is
    RETURNED rather than swallowed, so the email can say "AI summary
    unavailable" instead of silently looking like a report that was never
    configured for one.
    """
    try:
        cfg = A._ai_cfg() or {}
        if not cfg.get('enabled'):
            return {'error': 'AI is disabled in settings'}
        ctx = _report_summary_context(report)
        if not ctx:
            return {'error': 'report has no figures to summarise'}
        res = A.ai_provider.chat(
            cfg,
            [{'role': 'user',
              'content': 'Fleet posture report figures:\n'
                         + A.json.dumps(ctx, indent=2, default=str)}],
            system=A.ai_provider.SYSTEM_PROMPTS['report_summary'],
            max_tokens=600)
        if not res.get('ok'):
            return {'error': str(res.get('error') or 'AI request failed')[:200]}
        text = (res.get('text') or '').strip()
        if not text:
            return {'error': 'the model returned an empty summary'}
        return {'text': text[:4000], 'model': res.get('model', ''),
                'generated_ts': int(A.time.time())}
    except Exception as e:                              # pragma: no cover
        return {'error': f'{type(e).__name__}: {str(e)[:160]}'}


def _attach_report_summary(report, sections):
    """Add the narrative to `report` in place when the caller asked for it.

    Separate from _build_fleet_report so the ~30 places that build a report for
    the UI never pay for an AI call they did not ask for.
    """
    if 'summary' not in set(sections or ()):
        return report
    report['summary'] = _build_report_summary(report)
    return report


def _filter_report_sections(report, sections):
    """Keep report metadata + only the requested sections (empty/None = all)."""
    keep = set(sections or ()) & set(_ALL_REPORT_SECTIONS)
    if not keep:
        return report
    # v6.4.2: 'brand' is metadata, not a section — without it here a SECTIONED
    # custom report silently dropped the white-label name/accent and printed as
    # stock RemotePower, which is exactly the report most likely to be sent out.
    out = {k: report[k] for k in ('generated_ts', 'server_version', 'server_name', 'brand')
           if k in report}
    out['sections'] = sorted(keep)
    for k in _ALL_REPORT_SECTIONS:
        if k in keep and k in report:
            out[k] = report[k]
    return out


def _fleet_report_csv_bytes(report):
    """Flatten the posture report into a single summary CSV (Section,Metric,Value)."""
    import csv, io
    buf = io.StringIO()
    w = csv.writer(buf)

    def row(cells):
        """Every cell through _csv_safe, like _csv_emit / handle_patch_report_csv /
        _fleet_query_bytes already do. This exporter was the one that didn't, and
        the worst-devices block below writes the operator-set display name — a
        name starting with '=' (or +/-/@) executes as a formula when the fleet or
        site posture report, the CSV most likely to be mailed to a customer, is
        opened in Excel/Sheets. Mapping here rather than at each call site so a
        future row can't reintroduce the gap."""
        w.writerow([A._csv_safe(c) for c in cells])

    row(['Section', 'Metric', 'Value'])
    # Tolerate custom reports that omit sections, exactly like the sibling
    # _render_report_email has since v3.14.0. This renderer never got the same
    # treatment, so every ?sections= subset that dropped one of the six blocks
    # below raised an uncaught KeyError out of handle_fleet_report -> HTTP 500 —
    # i.e. the URL the Custom reports "Download" button builds for any saved
    # definition with a box unticked.
    d = report.get('devices') or {}
    h = report.get('health') or {}
    a = report.get('attention') or {}
    sla = report.get('sla') or {}
    p = report.get('patches') or {}
    c = report.get('cve') or {}
    if d:
        row(['Devices', 'Total', d.get('total', 0)])
        row(['Devices', 'Online', d.get('online', 0)])
        row(['Devices', 'Offline', d.get('offline', 0)])
    if h:
        row(['Health', 'Fleet score', h.get('score', 0)])
        row(['Health', 'Grade', h.get('grade', '')])
    if a:
        row(['Attention', 'Critical', a.get('critical', 0)])
        row(['Attention', 'Warning', a.get('warning', 0)])
        row(['Attention', 'Info', a.get('info', 0)])
    if sla:
        # 'sla' is a selectable section that this renderer never emitted at all,
        # so a CSV report including it silently dropped the fleet-uptime headline
        # the JSON and emailed forms both carry. Uncovered fleets report 'N/A'
        # (same idiom as compliance below) rather than nothing — a selected
        # section that writes no row is indistinguishable from a deselected one.
        pct = sla.get('fleet_uptime_pct')
        row(['SLA', f"Fleet uptime ({sla.get('days', 30)}d) %",
             pct if pct is not None else 'N/A'])
    if p:
        row(['Patches', 'Devices with patches', p.get('devices_with_patches', 0)])
        row(['Patches', 'Total pending', p.get('total_pending', 0)])
    if c:
        for sev in ('critical', 'high', 'medium', 'low'):
            row(['CVE', sev.capitalize(), c.get(sev, 0)])
        row(['CVE', 'Devices affected', c.get('devices_affected', 0)])
    per = report.get('period') or {}
    if per:
        row(['Period', 'Window (days)', per.get('days', 30)])
        row(['Period', 'Alerts opened', per.get('alerts_opened', 0)])
        row(['Period', 'Alerts resolved', per.get('alerts_resolved', 0)])
        row(['Period', 'MTTR median (s)', per.get('mttr_median', 0)])
        row(['Period', 'MTTR mean (s)', per.get('mttr_mean', 0)])
        row(['Period', 'MTTA mean (s)', per.get('mtta_mean', 0)])
        row(['Period', 'Update runs', per.get('patches_applied_runs', 0)])
        _dl = per.get('delta') or {}
        # '' rather than 0 when there is no comparable sample yet — a 0 delta
        # would read as "no change" when the truth is "not enough history".
        row(['Period', 'Health score change',
             '' if _dl.get('health_score') is None else _dl['health_score']])
        row(['Period', 'Compliance change (pp)',
             '' if _dl.get('compliance_pct') is None else _dl['compliance_pct']])
    for fw, fwrep in ((report.get('compliance') or {}).get('frameworks') or {}).items():
        row(['Compliance', fw.upper() + ' pass %',
             fwrep.get('score') if fwrep.get('score') is not None else 'N/A'])
    if h:
        row([])
        row(['Worst devices', 'Score', 'Critical/Warning'])
        for dev in h.get('worst') or []:
            row([dev.get('device_name', ''), dev.get('score', 0),
                 f"{dev.get('critical', 0)}/{dev.get('warning', 0)}"])
    return buf.getvalue().encode()


def handle_fleet_report():
    """GET /api/report/fleet?format=json|csv — fleet posture report.

    Auth: require_auth (read-only summary, no secrets). The printable view is the
    static report.html page, which fetches this JSON and renders a light document
    with external CSS/JS (CSP-clean) for the browser's Print / Save-as-PDF."""
    A.require_auth()
    qs = A.urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
    fmt = (qs.get('format') or ['json'])[0].lower()
    report = A._build_fleet_report()
    # v3.14.0: optional ?sections=devices,cve,health filter (custom reports).
    sections = (qs.get('sections') or [''])[0]
    if sections:
        _want = [s.strip() for s in sections.split(',') if s.strip()]
        report = A._filter_report_sections(report, _want)
        # v6.4.2: only when explicitly asked for — an AI call per report view
        # would be a bill nobody agreed to.
        _attach_report_summary(report, _want)
    if fmt == 'csv':
        data = A._fleet_report_csv_bytes(report)
        ts = A.time.strftime('%Y%m%d-%H%M%S')
        print("Status: 200 OK")
        print("Content-Type: text/csv")
        print(f"Content-Disposition: attachment; filename=fleet-report-{ts}.csv")
        print(f"Content-Length: {len(data)}")
        print("Cache-Control: no-store")
        print("X-Content-Type-Options: nosniff")
        print()
        A.sys.stdout.flush()
        A.sys.stdout.buffer.write(data)
        A.sys.stdout.buffer.flush()
        A.sys.exit(0)
    A.respond(200, report)


def handle_site_report(site_id):
    """GET /api/report/site/{site_id}?format=json|csv — per-site (customer)
    posture report: the same fleet report scoped to one site. RBAC-scoped — a
    caller can only pull a site whose devices fall within their scope."""
    A.require_auth()
    if not isinstance((A.load(A.SITES_FILE) or {}).get(site_id), dict):
        A.respond(404, {'error': 'site not found'})
    # v5.0.1 (SECURITY): a whole-SITE posture report requires site-level scope.
    # The old check only rejected sites-typed scopes, so a group/tag/host-scoped
    # operator (non-None scope of another type) fell through and pulled the full
    # site's device names/health/CVE/SLA — cross-scope leak. Now: unrestricted
    # ('all', scope is None) OR a sites-scope that covers this site; else 403.
    scope = A._caller_scope()
    if scope is not None and not (
            scope.get('type') == 'sites' and site_id in (scope.get('values') or [])):
        A.respond(403, {'error': 'site outside your role scope'})
    qs = A.urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
    fmt = (qs.get('format') or ['json'])[0].lower()
    report = A._build_fleet_report(site_id=site_id)
    if fmt == 'csv':
        data = A._fleet_report_csv_bytes(report)
        ts = A.time.strftime('%Y%m%d-%H%M%S')
        print("Status: 200 OK")
        print("Content-Type: text/csv")
        print(f"Content-Disposition: attachment; filename=site-report-{A._site_slugify(report.get('site_name', site_id))}-{ts}.csv")
        print(f"Content-Length: {len(data)}")
        print("Cache-Control: no-store")
        print("X-Content-Type-Options: nosniff")
        print()
        A.sys.stdout.flush()
        A.sys.stdout.buffer.write(data)
        A.sys.stdout.buffer.flush()
        A.sys.exit(0)
    A.respond(200, report)


def handle_evidence_pack():
    """GET /api/report/evidence?days=N — a compliance EVIDENCE PACK (admin-only).

    Bundles the data an auditor asks for into one downloadable JSON document: the
    current fleet posture report (health, patches, CVE, CIS compliance, uptime),
    the compliance-baseline trend, and an audit-log excerpt for the period — all
    from data RemotePower already holds, no recompute. The act of generating it is
    itself audit-logged."""
    actor = A.require_admin_or_auditor_auth()
    qs = A.urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
    try:
        days = int((qs.get('days') or ['90'])[0])
    except ValueError:
        days = 90
    days = max(1, min(366, days))
    now = int(A.time.time())
    since = now - days * 86400
    comp_hist = [s for s in ((A.load(A.COMPLIANCE_HIST_FILE) or {}).get('fleet') or [])
                 if isinstance(s, dict) and int(s.get('ts', 0) or 0) >= since][-days:]
    audit = [e for e in ((A.load(A.AUDIT_LOG_FILE) or {}).get('entries') or [])
             if isinstance(e, dict) and int(e.get('ts', 0) or 0) >= since]
    pack = {
        'schema':         'remotepower.evidence.v1',
        'generated_ts':   now,
        'generated_by':   actor,
        'server_name':    A.get_server_name(),
        'server_version': A.SERVER_VERSION,
        'period_days':    days,
        'period_start':   since,
        'posture':        A._build_fleet_report(),
        # v6.4.2: `posture` is TODAY's numbers sitting next to a `period_days`
        # label, which reads like a period summary and is not one. Say so in
        # the document rather than relying on the field name, and ship the
        # reports actually DELIVERED inside the window alongside it — that is
        # the part of the pack that genuinely covers the period.
        'posture_note':   'The `posture` block is the CURRENT fleet posture at '
                          'generated_ts, not an average or an end-of-period '
                          'snapshot. Period coverage comes from '
                          'compliance_history, audit_excerpt and '
                          'archived_reports.',
        'archived_reports': _archive_index(since=since, until=now),
        'compliance_history': comp_hist,
        'audit_excerpt':  audit[-2000:],   # cap so the pack can't balloon
        'audit_count':    len(audit),
    }
    # v5.4.1 (C4): tamper-evidence signature over the canonical pack (computed
    # before the `signature` field is added; verify = recompute over the pack
    # minus `signature`). Closes the "evidence exports are unsigned" gap.
    pack['signature'] = {
        'alg': 'hmac-sha256',
        'value': A._export_sign(A.json.dumps(pack, sort_keys=True, separators=(',', ':'))),
    }
    A.audit_log(actor, 'evidence_pack_generated', detail=f'period={days}d entries={len(audit)}')
    fmt = (qs.get('format') or ['json'])[0].lower()
    if fmt == 'download':
        data = A.json.dumps(pack, indent=2).encode('utf-8')
        ts = A.time.strftime('%Y%m%d-%H%M%S')
        print("Status: 200 OK")
        print("Content-Type: application/json")
        print(f"Content-Disposition: attachment; filename=evidence-pack-{ts}.json")
        print(f"Content-Length: {len(data)}")
        print("Cache-Control: no-store")
        print("X-Content-Type-Options: nosniff")
        print()
        A.sys.stdout.flush()
        A.sys.stdout.buffer.write(data)
        A.sys.stdout.buffer.flush()
        A.sys.exit(0)
    A.respond(200, pack)


# ── v6.4.2: the report archive ──────────────────────────────────────────────
# Every report path — _build_fleet_report, the evidence pack, the scheduled
# email — computed from live state and threw the result away. Nothing wrote a
# generated report anywhere, and no report endpoint took an as-of date.
#
# That would be recoverable if the inputs had history, but they largely do not:
# fleet health and fleet compliance % are sampled daily, while CVE counts,
# patch backlog and per-framework control pass/fail have no history at all. So
# a past-dated posture report was not merely unstored, it was unreconstructable.
#
# An ISO 27001 auditor asks for the posture report as it stood at the end of
# Q1. The operator had the March email in their inbox — plain text, if it was
# even scheduled — and nothing else: no artifact to hand over, no way to
# regenerate one.
#
# The archive stores what was actually DELIVERED, which is the artifact the
# question is about. Generating a report for the UI still archives nothing.
_REPORT_ARCHIVE_MAX = 60
# A 200-host report serialises to ~12 KB (it is aggregates, not per-device
# rows), so the cap is about retention, not size. The byte guard is a backstop
# against a future section that changes that assumption without anyone noticing.
_REPORT_ARCHIVE_MAX_BYTES = 4 * 1024 * 1024


def _archive_report(report, kind, name='', site=''):
    """Keep a delivered report. Best-effort: an archive failure must never cost
    the operator the delivery that just succeeded."""
    try:
        entry = {
            'id':      'rpt-' + A.secrets.token_hex(6),
            'ts':      int(report.get('generated_ts') or A.time.time()),
            'kind':    str(kind)[:32],
            'name':    A._sanitize_str(str(name or ''), 64),
            'site':    A._sanitize_str(str(site or ''), 64),
            'site_name': A._sanitize_str(str(report.get('site_name') or ''), 96),
            'sections': sorted(report.get('sections')
                               or [k for k in _ALL_REPORT_SECTIONS if k in report]),
            'health':  ((report.get('health') or {}).get('score')),
            'report':  report,
        }
        with A._LockedUpdate(A.REPORT_ARCHIVE_FILE) as st:
            entries = st.get('entries')
            if not isinstance(entries, list):
                entries = []
            entries.append(entry)
            entries = entries[-_REPORT_ARCHIVE_MAX:]
            # Trim oldest-first until it fits. Reported rather than silent —
            # "the archive quietly stopped keeping things" is the failure mode
            # that makes an archive worse than useless.
            while len(entries) > 1 and len(A.json.dumps(entries,
                                                        default=str).encode()) \
                    > _REPORT_ARCHIVE_MAX_BYTES:
                entries.pop(0)
                st['trimmed'] = int(st.get('trimmed') or 0) + 1
            st['entries'] = entries
        return entry['id']
    except Exception as e:                                   # pragma: no cover
        A.sys.stderr.write(f'[remotepower] report archive write failed: {e}\n')
        return ''


def _archive_index(since=0, until=0):
    """Archive metadata (no report bodies) newest-first, optionally windowed."""
    out = []
    for e in ((A._load_ro(A.REPORT_ARCHIVE_FILE) or {}).get('entries') or []):
        if not isinstance(e, dict):
            continue
        ts = int(e.get('ts') or 0)
        if since and ts < since:
            continue
        if until and ts > until:
            continue
        out.append({k: e.get(k) for k in
                    ('id', 'ts', 'kind', 'name', 'site', 'site_name',
                     'sections', 'health')})
    out.sort(key=lambda e: e.get('ts') or 0, reverse=True)
    return out


def _archive_scope_guard():
    """A stored report is a snapshot of whatever the fleet looked like when it
    was DELIVERED, with no per-row scope tags to filter on afterwards.

    v6.4.2 (audit): the archive was gated on admin-or-auditor alone, so a
    TENANT admin — whose role is `admin`, and whose `_caller_scope()` is
    therefore None — could download another tenant's whole-fleet posture
    report, device counts, health scores and CVE totals included. A role-scoped
    admin could read the same for hosts outside their scope.

    Filtering after the fact is not possible: the report is an aggregate, not a
    list of rows carrying device ids. So this refuses, with the same reasoning
    and the same wording shape as handle_ai_rag_search's refusal for the RAG
    corpus — until the artifact carries scope, the honest answer is no.
    """
    if A._caller_scope() is not None or A._tenant_gate() is not None:
        A.respond(403, {'error': 'The report archive is limited to full-access '
                                 'roles — a stored report is a whole-fleet '
                                 'snapshot and carries no per-role or '
                                 'per-tenant scope to filter on. Use a '
                                 'site-scoped report definition instead.'})


def handle_report_archive():
    """GET /api/report/archive — list delivered reports (metadata only).

    Query: ?since=<epoch>&until=<epoch> to window it, or ?as_of=<epoch> for the
    nearest report AT OR BEFORE that moment — which is how an auditor asks the
    question ("what did this look like at the end of Q1?").
    """
    A.require_admin_or_auditor_auth()
    if A.method() != 'GET':
        A.respond(405, {'error': 'Method not allowed'})
    _archive_scope_guard()
    qs = A.urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')

    def _num(key):
        try:
            return int((qs.get(key) or ['0'])[0])
        except (TypeError, ValueError):
            return 0

    as_of = _num('as_of')
    if as_of:
        # Nearest AT OR BEFORE — never after. Handing back a report generated
        # a week after the date asked about would be worse than handing back
        # nothing, because it looks like an answer.
        rows = _archive_index(until=as_of)
        A.respond(200, {'as_of': as_of, 'entry': rows[0] if rows else None,
                        'count': len(rows)})
    rows = _archive_index(since=_num('since'), until=_num('until'))
    st = A._load_ro(A.REPORT_ARCHIVE_FILE) or {}
    A.respond(200, {'entries': rows, 'total': len(rows),
                    'cap': _REPORT_ARCHIVE_MAX,
                    'trimmed': int(st.get('trimmed') or 0)})


def handle_report_archive_entry(entry_id):
    """GET /api/report/archive/<id>[?format=json|csv|download] — one archived
    report exactly as it was delivered; DELETE — remove it (admin)."""
    actor = A.require_admin_or_auditor_auth()
    _archive_scope_guard()
    entry_id = A._sanitize_str(str(entry_id or ''), 32)
    if A.method() == 'DELETE':
        A.require_admin_auth()
        with A._LockedUpdate(A.REPORT_ARCHIVE_FILE) as st:
            entries = st.get('entries') or []
            kept = [e for e in entries if e.get('id') != entry_id]
            if len(kept) == len(entries):
                A.respond(404, {'error': 'archived report not found'})
            st['entries'] = kept
        A.audit_log(actor, 'report_archive_delete', detail=f'id={entry_id}')
        A.respond(200, {'ok': True})
    if A.method() != 'GET':
        A.respond(405, {'error': 'Method not allowed'})
    entry = None
    for e in ((A.load(A.REPORT_ARCHIVE_FILE) or {}).get('entries') or []):
        if isinstance(e, dict) and e.get('id') == entry_id:
            entry = e
            break
    if not entry:
        A.respond(404, {'error': 'archived report not found'})
    report = entry.get('report') or {}
    qs = A.urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
    fmt = (qs.get('format') or ['json'])[0].lower()
    if fmt in ('csv', 'download'):
        if fmt == 'csv':
            data, ctype, ext = _fleet_report_csv_bytes(report), 'text/csv', 'csv'
        else:
            data = A.json.dumps(report, indent=2, default=str).encode()
            ctype, ext = 'application/json', 'json'
        stamp = A.time.strftime('%Y%m%d-%H%M%S',
                                A.time.localtime(int(entry.get('ts') or 0)))
        print("Status: 200 OK")
        print(f"Content-Type: {ctype}")
        print(f"Content-Disposition: attachment; filename=report-{stamp}.{ext}")
        print(f"Content-Length: {len(data)}")
        print("Cache-Control: no-store")
        print("X-Content-Type-Options: nosniff")
        print()
        A.sys.stdout.flush()
        A.sys.stdout.buffer.write(data)
        A.sys.stdout.buffer.flush()
        A.sys.exit(0)
    A.respond(200, {'entry': {k: v for k, v in entry.items() if k != 'report'},
                    'report': report})


def _render_report_email(report):
    """Plain-text body + subject for a (possibly section-filtered) fleet report."""
    # v3.14.0: tolerate custom reports that omit sections — default each to {}.
    d = report.get('devices') or {}
    h = report.get('health') or {}
    a = report.get('attention') or {}
    p = report.get('patches') or {}
    c = report.get('cve') or {}
    sla = report.get('sla') or {}
    when = A.time.strftime('%Y-%m-%d %H:%M', A.time.localtime(report.get('generated_ts', int(A.time.time()))))
    subject = f"{report.get('server_name', 'RemotePower')} fleet report"
    if h:
        subject += f" — health {h.get('score', '?')}/100 ({h.get('grade', '?')})"
    lines = [
        f"{report.get('server_name', 'RemotePower')} — fleet posture report",
        f"Generated {when}  ·  RemotePower {report.get('server_version', '')}",
        "",
    ]
    # v6.4.2: the narrative goes FIRST, above the figures, because it exists for
    # the reader who stops there. An "AI summary unavailable" line rather than
    # silence when the provider is down — otherwise a report configured for a
    # summary is indistinguishable from one that never was, and nobody notices
    # the covering paragraph has been missing for a month.
    _sm = report.get('summary') or {}
    if _sm.get('text'):
        lines += ['Summary', '-------', _sm['text'].strip(), '']
    elif _sm.get('error'):
        lines += [f"(AI summary unavailable: {_sm['error']})", '']
    if h:
        lines.append(f"Fleet health score : {h.get('score', '?')}/100 ({h.get('grade', '?')})")
    if d:
        lines.append(f"Devices            : {d.get('total',0)} total, {d.get('online',0)} online, "
                     f"{d.get('offline',0)} offline")
    if a:
        lines.append(f"Needs attention    : {a.get('critical',0)} critical, "
                     f"{a.get('warning',0)} warning, {a.get('info',0)} info")
    if sla and sla.get('fleet_uptime_pct') is not None:
        lines.append(f"SLA uptime ({sla.get('days',30)}d) : {sla.get('fleet_uptime_pct')}%")
    if p:
        lines.append(f"Patches            : {p.get('devices_with_patches',0)} device(s) pending, "
                     f"{p.get('total_pending',0)} update(s) total")
    if c:
        lines.append(f"CVEs               : {c.get('critical',0)} critical, {c.get('high',0)} high, "
                     f"{c.get('medium',0)} medium ({c.get('devices_affected',0)} device(s) affected)")
    per = report.get('period') or {}
    if per:
        def _dur(sec):
            sec = int(sec or 0)
            if not sec:
                return '—'
            h_, m_ = sec // 3600, (sec % 3600) // 60
            return f'{h_}h{m_:02d}' if h_ else f'{m_}m'

        def _signed(v, suffix=''):
            if v is None:
                return 'n/a'
            return f'{v:+g}{suffix}'
        lines.append('')
        lines.append(f"Last {per.get('days', 30)} days")
        lines.append(f"  Alerts             : {per.get('alerts_opened', 0)} opened, "
                     f"{per.get('alerts_resolved', 0)} resolved")
        lines.append(f"  Median time to fix : {_dur(per.get('mttr_median'))}"
                     f"  (mean {_dur(per.get('mttr_mean'))}, "
                     f"ack {_dur(per.get('mtta_mean'))})")
        if per.get('patches_applied_runs'):
            lines.append(f"  Update runs        : {per['patches_applied_runs']}")
        _dl = per.get('delta') or {}
        if _dl.get('health_score') is not None or _dl.get('compliance_pct') is not None:
            lines.append(f"  Change             : health {_signed(_dl.get('health_score'))}, "
                         f"compliance {_signed(_dl.get('compliance_pct'), '%')}")
    lines.append("")
    if h.get('worst'):
        lines.append("Lowest-scoring devices:")
        for dev in h['worst'][:5]:
            lines.append(f"  - {dev['device_name']}: {dev['score']}/100 "
                         f"({dev['critical']} crit, {dev['warning']} warn)")
        lines.append("")
    fws = (report.get('compliance') or {}).get('frameworks') or {}
    if fws:
        lines.append("Compliance:")
        for fw, rep in fws.items():
            pct = rep.get('score') if rep.get('score') is not None else 'N/A'
            lines.append(f"  - {fw.upper()}: {pct}% controls passing")
    return subject, "\n".join(lines)


def _maybe_send_scheduled_report():
    """Heartbeat hook: send the fleet report on its configured cron schedule.

    Mirrors _maybe_run_scheduled_backup's cheap-gate pattern. Config lives in
    config.json under `report_schedule` ({enabled, cron, recipients}). The
    once-per-minute claim is done under a file lock so concurrent heartbeats in
    the same matching minute don't each fire an email."""
    # v6.4.0 (perf): read-only shared config — this hook only reads (recipients
    # via _smtp_recipients_list), it never mutates config, so it never needs
    # load()'s per-request deepcopy on the common (feature-off) path.
    cfg = A._config_ro() or {}
    rs = cfg.get('report_schedule') or {}
    if not rs.get('enabled'):
        return
    cron = rs.get('cron')
    if not cron or not A._valid_cron(cron):
        return
    now = int(A.time.time())
    current_minute = now // 60
    state_file = A.DATA_DIR / 'report_schedule_state.json'
    # v6.4.2: catch-up window (see _cron_due_since) — needs the previous claim,
    # so read it before the cron test rather than after.
    _prev = (A.load(state_file) or {}).get('last_fired_minute')
    if _prev is None:
        # v6.4.2: seed an unclaimed schedule to the current minute so its catch-up
        # window starts NOW. Without this a schedule the operator just configured
        # would fire for a window that closed before it existed.
        with A._LockedUpdate(state_file) as state:
            state.setdefault('last_fired_minute', current_minute - 1)
        _prev = current_minute - 1
    if not A._cron_due_since(cron, now, _prev):
        return
    # Claim the minute atomically; bail if another heartbeat already sent.
    with A._LockedUpdate(state_file) as state:
        if state.get('last_fired_minute') == current_minute:
            return
        state['last_fired_minute'] = current_minute
        state['last_run'] = now
    recipients = rs.get('recipients') or A._smtp_recipients_list(cfg)
    if not recipients:
        return
    try:
        report = A._build_fleet_report()
        subject, body = A._render_report_email(report)
    except Exception as e:
        # A build failure is a real bug (bad data/template), not a transient
        # one -- retrying with backoff wouldn't help; it'll fail identically
        # at the next cron fire same as before this job-queue integration.
        A.sys.stderr.write(f'[remotepower] scheduled report build failed: {e}\n')
        return
    # v6.4.2: keep what we are about to send. This is the artifact an auditor
    # asks for by date, and it was computed and discarded.
    _archive_report(report, 'schedule')
    try:
        A.smtp_notifier.send_email(cfg, recipients, subject, body,
                                   html_body=A.smtp_notifier.brand_html(cfg, subject, body))
        A._log_email('fleet_report', recipients, 'ok', '')
    except A.smtp_notifier.SmtpError as e:
        A._log_email('fleet_report', recipients, 'error', str(e))
        # v6.1.1 (#2): genuinely transient (SMTP hiccup) -- retry with
        # backoff instead of waiting for the next cron fire, which can be
        # days away for a weekly/monthly schedule.
        A.enqueue_job('send_report_email',
                      {'recipients': recipients, 'subject': subject, 'body': body})
    except Exception as e:
        A.sys.stderr.write(f'[remotepower] scheduled report failed: {e}\n')
        A.enqueue_job('send_report_email',
                      {'recipients': recipients, 'subject': subject, 'body': body})


def handle_report_schedule_get():
    """GET /api/report/schedule — current scheduled-report config + last run."""
    A.require_auth()
    cfg = A.load(A.CONFIG_FILE) or {}
    rs = dict(cfg.get('report_schedule') or {})
    state_file = A.DATA_DIR / 'report_schedule_state.json'
    state = A.load(state_file) if A.backend_exists(state_file) else {}
    A.respond(200, {
        'enabled':    bool(rs.get('enabled')),
        'cron':       rs.get('cron', ''),
        'recipients': rs.get('recipients') or [],
        'last_run':   state.get('last_run') or 0,
    })


def handle_report_schedule_set():
    """PUT /api/report/schedule — configure the scheduled report. Admin-only."""
    actor = A.require_admin_auth()
    if A.method() != 'PUT':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.ReportScheduleSetRequest)
    enabled = bool(body.get('enabled'))
    cron = str(body.get('cron', '')).strip()
    if enabled and not A._valid_cron(cron):
        A.respond(400, {'error': 'invalid cron expression (5 fields: min hour dom month dow)'})
    raw_recips = body.get('recipients') or []
    if not isinstance(raw_recips, list):
        A.respond(400, {'error': 'recipients must be a list'})
    recipients = [A._sanitize_str(r, 254) for r in raw_recips
                  if isinstance(r, str) and '@' in r][:50]
    with A._LockedUpdate(A.CONFIG_FILE) as cfg:
        cfg['report_schedule'] = {
            'enabled':    enabled,
            'cron':       cron,
            'recipients': recipients,
        }
    A.audit_log(actor, 'report_schedule_set',
                f'enabled={enabled} cron="{cron}" recipients={len(recipients)}')
    A.respond(200, {'ok': True, 'enabled': enabled, 'cron': cron,
                    'recipients': recipients})


# ─── v3.14.0: custom report builder — saved report definitions ───────────────
MAX_REPORT_DEFS = 30


def _clean_report_def(body):
    """Validate a report definition payload → cleaned dict (or None)."""
    if not isinstance(body, dict):
        return None
    name = A._sanitize_str(str(body.get('name', '')), 64).strip()
    if not name:
        return None
    sections = [s for s in (body.get('sections') or []) if s in _ALL_REPORT_SECTIONS]
    fmt = str(body.get('format', 'json')).lower()
    if fmt not in ('json', 'csv'):
        fmt = 'json'
    cron = A._sanitize_str(str(body.get('cron', '')), 64).strip()
    enabled = bool(body.get('enabled'))
    if enabled and cron and not A._valid_cron(cron):
        return 'badcron'
    recipients = [A._sanitize_str(r, 254) for r in (body.get('recipients') or [])
                  if isinstance(r, str) and '@' in r][:50]
    # v6.1.2 (#41): webhook destination ids. This is a WHITELIST — a key that
    # isn't listed here never reaches the stored definition, so the Settings
    # toggle would appear to save and then quietly do nothing.
    destinations = [A._sanitize_str(str(x), 32) for x in (body.get('destinations') or [])
                    if isinstance(x, (str, int))][:20]
    # v6.4.2: scope a scheduled report to ONE SITE (= one customer, per
    # docs/sites.md). The schema had no site field, so the scheduler could only
    # ever send the whole-fleet report — an MSP with 12 customer sites, per-site
    # billing and per-site RBAC already configured could not say "email Acme
    # their monthly report on the 1st". Their only options were to hand-download
    # a JSON blob per customer per month, or to send all 12 customers the whole
    # fleet's numbers, which leaks every other customer's device counts and CVE
    # totals. Empty = whole fleet, exactly as before.
    site = A._sanitize_str(str(body.get('site', '')), 64).strip()
    if site and not isinstance((A.load(A.SITES_FILE) or {}).get(site), dict):
        return 'badsite'
    return {
        'id':         A._sanitize_str(str(body.get('id', '')), 16) or A.secrets.token_hex(6),
        'name':       name,
        'sections':   sections or list(_REPORT_SECTIONS),
        'format':     fmt,
        'cron':       cron,
        'enabled':    enabled,
        'recipients': recipients,
        'destinations': destinations,
        'site':       site,
    }


def handle_report_defs_list():
    """GET /api/report/definitions — saved custom report definitions."""
    A.require_auth()
    cfg = A.load(A.CONFIG_FILE) or {}
    A.respond(200, {'definitions': cfg.get('report_definitions') or [],
                    'available_sections': list(_REPORT_SECTIONS),
                    'opt_in_sections': list(_REPORT_OPT_IN_SECTIONS)})


def handle_report_defs_save():
    """POST /api/report/definitions — create/update a report definition. Admin."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    cleaned = A._clean_report_def(A.get_json_body())
    if cleaned == 'badcron':
        A.respond(400, {'error': 'invalid cron expression'})
    if cleaned == 'badsite':
        # A silently-dropped site would schedule a WHOLE-FLEET report to a
        # customer's account manager — the exact leak this field exists to stop.
        A.respond(400, {'error': 'unknown site'})
    if not cleaned:
        A.respond(400, {'error': 'name is required'})
    with A._LockedUpdate(A.CONFIG_FILE) as cfg:
        defs = cfg.get('report_definitions') or []
        defs = [d for d in defs if d.get('id') != cleaned['id']]
        defs.append(cleaned)
        if len(defs) > MAX_REPORT_DEFS:
            A.respond(400, {'error': f'too many report definitions (max {MAX_REPORT_DEFS})'})
        cfg['report_definitions'] = defs
    A.audit_log(actor, 'report_def_save', f"name={cleaned['name']} sections={len(cleaned['sections'])}")
    A.respond(200, {'ok': True, 'definition': cleaned})


def handle_report_def_delete(def_id):
    """DELETE /api/report/definitions/<id> — remove a report definition. Admin."""
    actor = A.require_admin_auth()
    if A.method() != 'DELETE':
        A.respond(405, {'error': 'Method not allowed'})
    found = False
    with A._LockedUpdate(A.CONFIG_FILE) as cfg:
        defs = cfg.get('report_definitions') or []
        new = [d for d in defs if d.get('id') != def_id]
        found = len(new) != len(defs)
        cfg['report_definitions'] = new
    if not found:
        A.respond(404, {'error': 'definition not found'})
    A.audit_log(actor, 'report_def_delete', f'id={def_id}')
    A.respond(200, {'ok': True})


def _maybe_send_report_definitions():
    """Heartbeat hook: send each enabled custom report on its own cron. Shares
    the once-per-minute claim pattern, keyed per definition id."""
    # v6.4.0 (perf): read-only shared config on the not-due path (no report
    # definitions on most installs → this returns before any mutation).
    cfg = A._config_ro() or {}
    defs = cfg.get('report_definitions') or []
    if not defs:
        return
    now = int(A.time.time())
    current_minute = now // 60
    state_file = A.DATA_DIR / 'report_schedule_state.json'
    _prev_claims = A.load(state_file) or {}
    for d in defs:
        if not d.get('enabled') or not d.get('cron') or not A._valid_cron(d['cron']):
            continue
        claim_key = 'def_' + str(d.get('id'))
        _prev = _prev_claims.get(claim_key)
        if _prev is None:
            # v6.4.2: seed on first sight — see _maybe_send_scheduled_report.
            with A._LockedUpdate(state_file) as state:
                state.setdefault(claim_key, current_minute - 1)
            _prev = current_minute - 1
        # v6.4.2: catch-up window (see _cron_due_since).
        if not A._cron_due_since(d['cron'], now, _prev):
            continue
        with A._LockedUpdate(state_file) as state:
            if state.get(claim_key) == current_minute:
                continue
            state[claim_key] = current_minute
        # v6.1.2 (#41): a report can go to webhook DESTINATIONS instead of (or as
        # well as) email. Homelabs rarely run SMTP but always have ntfy/Discord —
        # so an email-only report is, for most of them, a report they never see.
        dest_ids = d.get('destinations') or []
        recipients = d.get('recipients') or ([] if dest_ids else A._smtp_recipients_list(cfg))
        if not recipients and not dest_ids:
            continue
        try:
            # v6.4.2: honour the definition's site scope. `_build_fleet_report`
            # has taken site_id since the per-site download shipped; the
            # scheduler simply never passed it.
            _site = (d.get('site') or '').strip()
            report = A._filter_report_sections(
                A._build_fleet_report(site_id=_site) if _site
                else A._build_fleet_report(), d.get('sections'))
            # v6.4.2: the narrative. The person who needs a report most is the
            # one who never logs in — and every artifact that left the box was
            # uninterpreted numbers, even though the model that writes the
            # covering paragraph was already sitting behind an in-app button.
            _attach_report_summary(report, d.get('sections'))
            subject, body = A._render_report_email(report)
            subject = f"[{d.get('name')}] " + subject
            _archive_report(report, 'definition', name=d.get('name', ''),
                            site=_site)
        except Exception as e:
            A.sys.stderr.write(f"[remotepower] custom report '{d.get('name')}' "
                               f"build failed: {e}\n")
            continue
        # v6.4.2: attach the report itself. A definition saved with format=csv
        # still emailed only the plain-text summary — the operator scheduled an
        # artifact and received a preview of it. The plain-text body STAYS (it is
        # the readable preview); the attachment is the thing they asked for.
        #
        # Built here rather than through enqueue_job on purpose: job payloads are
        # JSON-serialised and raw bytes would blow up. This sweep does not use
        # the job queue, and this keeps it that way.
        _atts = None
        try:
            _slug = A.re.sub(r'[^a-z0-9]+', '-',
                             str(d.get('name') or 'report').lower()).strip('-') or 'report'
            _stamp = A.time.strftime('%Y%m%d')
            if (d.get('format') or 'json') == 'csv':
                _atts = [(f'{_slug}-{_stamp}.csv', 'text/csv',
                          _fleet_report_csv_bytes(report))]
            else:
                _atts = [(f'{_slug}-{_stamp}.json', 'application/json',
                          A.json.dumps(report, indent=2, default=str).encode())]
        except Exception as _e:
            # A broken attachment must not cost the operator the whole report.
            A.sys.stderr.write(f"[remotepower] report attachment build failed: {_e}\n")
            _atts = None
        if recipients:
            try:
                A.smtp_notifier.send_email(cfg, recipients, subject, body,
                                           html_body=A.smtp_notifier.brand_html(cfg, subject, body),
                                           attachments=_atts)
                A._log_email('fleet_report', recipients, 'ok', d.get('name', ''))
            except A.smtp_notifier.SmtpError as e:
                A._log_email('fleet_report', recipients, 'error', str(e))
            except Exception as e:
                A.sys.stderr.write(f"[remotepower] custom report '{d.get('name')}' "
                                   f"email failed: {e}\n")
        # Each destination is delivered independently: one broken webhook must not
        # stop the others, nor the email that already went out.
        for dest in A._webhook_destinations_by_id(cfg, dest_ids):
            try:
                A._dispatch_one_webhook('scheduled_report', dest, {}, body, subject, 3,
                                        allow_digest=False)
            except Exception as e:
                A._log_webhook('scheduled_report', dest.get('url', '?'), 'error',
                               f'report delivery failed: {type(e).__name__}: {str(e)[:120]}')
