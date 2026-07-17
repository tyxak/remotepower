"""RemotePower — OpenSCAP (auditor-grade CIS/STIG/PCI-DSS) compliance:
scan queue, agent result intake, full HTML-report download, and the fleet
overview.

The lightweight CIS baseline scores what every heartbeat already reports; this
is the auditor-grade complement. The operator queues a scan (a profile like
'cis' / 'stig' / 'pci-dss'); the agent runs `oscap xccdf eval` against its SSG
datastream and POSTs a compact result (score, pass/fail tallies, failed rule
ids). oscap runs on the endpoint, so there is no new server dependency, and it
degrades gracefully when oscap / SCAP content is absent. Storage (scap.json):
  {dev_id: {available, profile, score, pass, fail, counts, failed_rules, ts}}

A bound-module carve-out following the dmarc_handlers / rack_ipam_handlers
pattern: api.py execs a PRIVATE instance, binds its own ``globals()`` here (every
api service reached as ``A.<name>`` — a dynamic lookup that keeps the suite's
monkeypatching working), then re-imports the names back so routes resolve
unchanged. The _SCAP_PROFILES constant + SCAP_FILE / SCAP_REPORTS_DIR /
DEVICES_FILE stay in api.py, read here via A. The heartbeat-side force_scap_scan
flag handling also stays in api.py (it isn't a handler).
"""
import re
import sys
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


def handle_scap_scan():
    """POST /api/scap/scan — queue an OpenSCAP scan on the target device(s).
    Body: {device_id|device_ids|group|tag, profile}. Sets a one-shot flag the
    agent reads on its next heartbeat. Auth: 'upgrade' permission (a privileged
    fleet action), scoped."""
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.ScapScanRequest)
    ids = A._resolve_targets(body)
    if not ids:
        A.respond(400, {'error': 'No valid device targets'})
    actor = A.require_perm('patch', ids)
    profile = A._sanitize_str(body.get('profile', 'cis'), 80) or 'cis'
    with A._LockedUpdate(A.DEVICES_FILE) as devices:
        for did in ids:
            dev = devices.get(did)
            if dev:
                dev['force_scap_scan'] = True
                dev['scap_profile'] = profile
    A.audit_log(actor, 'scap_scan', f'targets={len(ids)} profile={profile}')
    A.respond(200, {'ok': True, 'queued': len(ids), 'profile': profile})


def handle_scap_report():
    """POST /api/scap/report — agent submits an OpenSCAP scan result.
    Authenticated by device_id + token (like /api/packages)."""
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.ScapReportRequest)
    dev_id = str(body.get('device_id', '')).strip()
    dev_token = str(body.get('token', '')).strip()
    if not A._validate_id(dev_id):
        A.respond(403, {'error': 'Unauthorized device'})
    devices = A.load(A.DEVICES_FILE)
    dev = devices.get(dev_id)
    if not dev or not A._device_token_ok(dev, dev_token):
        A.respond(403, {'error': 'Unauthorized device'})
    rec = {
        'ts': int(time.time()),
        'profile': A._sanitize_str(body.get('profile', ''), 80),
        'available': bool(body.get('available')),
        'reason': A._sanitize_str(body.get('reason', ''), 200),
        'datastream': A._sanitize_str(body.get('datastream', ''), 120),
    }
    # v3.4.2: the profiles this host's datastream actually offers, so the UI can
    # present only the ones that exist for the fleet's OSes (Debian SSG has no
    # cis/pci-dss/ospp — those ship in RHEL's scap-security-guide).
    aprofs = body.get('available_profiles')
    if isinstance(aprofs, list):
        rec['available_profiles'] = [A._sanitize_str(str(p), 80) for p in aprofs[:40] if p]
    if rec['available']:
        sc = body.get('score')
        rec['score'] = round(float(sc), 1) if isinstance(sc, (int, float)) else None
        counts = body.get('counts') if isinstance(body.get('counts'), dict) else {}
        rec['counts'] = {k: int(v) for k, v in counts.items()
                         if isinstance(v, int) and 0 <= v <= 100000}
        rec['pass'] = rec['counts'].get('pass', 0)
        rec['fail'] = rec['counts'].get('fail', 0)
        rec['failed_rules'] = []
        for r in (body.get('failed_rules') or [])[:200]:
            if isinstance(r, dict):
                rec['failed_rules'].append({
                    'id': A._sanitize_str(r.get('id', ''), 200),
                    'severity': A._sanitize_str(r.get('severity', 'unknown'), 16),
                })
    # v3.4.2: store the full HTML report (gzipped, base64 over the wire) so the
    # operator can download it. Kept on disk (one file per device, overwritten by
    # the latest scan), not in scap.json — it's large. Best-effort.
    rec['has_report'] = False
    gz_b64 = body.get('report_html_gz')
    if rec.get('available') and isinstance(gz_b64, str) and gz_b64:
        try:
            import base64 as _b64
            raw_gz = _b64.b64decode(gz_b64, validate=True)
            if 0 < len(raw_gz) <= 30 * 1024 * 1024:
                A.SCAP_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
                # dev_id is validated [A-Za-z0-9_-]; safe as a filename.
                (A.SCAP_REPORTS_DIR / f'{dev_id}.html.gz').write_bytes(raw_gz)
                rec['has_report'] = True
                rec['report_ts'] = rec['ts']
                rb = body.get('report_bytes')
                if isinstance(rb, int) and rb > 0:
                    rec['report_bytes'] = rb
        except Exception as e:
            sys.stderr.write(f'[remotepower] scap report store failed {dev_id}: {e}\n')
    with A._LockedUpdate(A.SCAP_FILE) as store:
        store[dev_id] = rec
    A.respond(200, {'ok': True})


def handle_scap_report_download(dev_id):
    """GET /api/scap/<dev_id>/report — download the full OpenSCAP/usg HTML report
    for one device's latest scan. Auth: require_auth + device scope. Serves the
    stored gzip, decompressed, as text/html."""
    A.require_auth()
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'invalid device id'}); return
    A._scope_block_device(dev_id)   # v3.5.0 RBAC v2: per-device read scope
    path = A.SCAP_REPORTS_DIR / f'{dev_id}.html.gz'
    if not path.exists():
        A.respond(404, {'error': 'no report on file for this device'}); return
    try:
        import gzip as _gz
        html = _gz.decompress(path.read_bytes())
    except Exception as e:
        A.respond(500, {'error': f'report read failed: {e}'}); return
    devices = A.load(A.DEVICES_FILE) or {}
    name = (devices.get(dev_id) or {}).get('name', dev_id)
    safe = re.sub(r'[^A-Za-z0-9_.-]', '_', str(name))
    print("Status: 200 OK")
    print("Content-Type: text/html; charset=utf-8")
    print(f"Content-Length: {len(html)}")
    print(f'Content-Disposition: inline; filename="scap-report-{safe}.html"')
    print("Cache-Control: no-store")
    print("X-Content-Type-Options: nosniff")
    # v3.13.0 hardening: this HTML is supplied verbatim by the (device-token-
    # authenticated) agent. Don't rely solely on the global nginx CSP — emit a
    # self-contained sandboxed CSP so a compromised agent can't land stored XSS
    # in the operator's session even if the upstream policy is ever loosened.
    # OpenSCAP/usg reports are static tables with inline CSS, so they still
    # render; only scripts/forms/same-origin access are neutralised.
    print("Content-Security-Policy: default-src 'none'; img-src 'self' data:; "
          "style-src 'unsafe-inline'; font-src data:; sandbox;")
    print("X-Frame-Options: DENY")
    print()
    sys.stdout.flush()
    sys.stdout.buffer.write(html)
    sys.stdout.buffer.flush()
    sys.exit(0)


def handle_scap_overview():
    """GET /api/scap — latest OpenSCAP result per (in-scope) device + summary."""
    A.require_auth()
    scope = A._caller_scope()
    # _scope_filter_devices folds in tenant isolation (a tenant admin has
    # scope=None but must not see other tenants' SCAP results). The
    # _device_in_scope checks below then just re-confirm role scope.
    devices = A._scope_filter_devices(A.load(A.DEVICES_FILE) or {})
    store = A.load(A.SCAP_FILE) or {}
    rows = []
    for did, rec in store.items():
        dev = devices.get(did)
        if not dev:
            continue
        if scope is not None and not A._device_in_scope(scope, dev):
            continue
        row = {
            'device_id': did, 'name': dev.get('name', did),
            'group': dev.get('group', ''),
            **{k: rec.get(k) for k in ('ts', 'profile', 'available', 'reason',
                                       'score', 'pass', 'fail', 'datastream')},
            'failed_top': (rec.get('failed_rules') or [])[:20],
            'has_report': bool(rec.get('has_report')),
            'report_bytes': rec.get('report_bytes'),
        }
        # Defensive: an older agent reports available=True with score 0 / pass 0 /
        # fail 0 when a profile evaluated no applicable rules (e.g. the Debian SSG
        # 'standard' profile). A 0% there is meaningless — present it as
        # not-applicable so the table doesn't show a scary 0%. Newer agents
        # already send available=False with a reason.
        if row.get('available') and not (row.get('pass') or 0) and not (row.get('fail') or 0):
            row['available'] = False
            row['score'] = None
            row['reason'] = row.get('reason') or (
                f"profile '{row.get('profile') or '?'}' evaluated no applicable rules "
                f"on this host")
        rows.append(row)
    rows.sort(key=lambda r: (r.get('score') if isinstance(r.get('score'), (int, float)) else 999))
    scored = [r['score'] for r in rows if isinstance(r.get('score'), (int, float))]
    # Offer profiles that are actually supported across the (in-scope) fleet:
    # the union of what each host reported its datastream contains. Until any
    # host has reported (first scan), fall back to the built-in superset so the
    # dropdown isn't empty. This stops operators picking pci-dss/cis on a
    # Debian-only fleet where those profiles don't exist.
    supported = set()
    for did, rec in store.items():
        dev = devices.get(did)
        if not dev or (scope is not None and not A._device_in_scope(scope, dev)):
            continue
        for p in (rec.get('available_profiles') or []):
            supported.add(p)
    profiles = sorted(supported) if supported else list(A._SCAP_PROFILES)
    A.respond(200, {
        'devices': rows,
        'profiles': profiles,
        'all_profiles': list(A._SCAP_PROFILES),
        'avg_score': round(sum(scored) / len(scored), 1) if scored else None,
        'scanned': len(rows),
    })
