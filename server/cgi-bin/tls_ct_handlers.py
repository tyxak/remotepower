"""RemotePower — TLS/DANE expiry monitor + certificate-transparency (crt.sh)
watch: watchlist CRUD, the synchronous + cadence probe paths, edge-triggered
expiry alerting, and the CT-log new-certificate watch.

A bound-module carve-out of api.py's request-coupled TLS/CT handlers, following
the tickets_handlers / cmdb_handlers / vpn_handlers pattern:

  - api.py execs a PRIVATE instance and binds its own ``globals()`` here, so
    every api service is reached as ``A.<name>`` — a DYNAMIC attribute lookup,
    which keeps the test suite's monkeypatching of api._ct_fetch_domain /
    api._ssrf_safe_opener / api.respond working, and resolves identically under
    the CGI (__main__) and imported-module (wsgi.py/scheduler.py) models.
  - api.py then from-imports every public + private name back into its own
    globals, so the route tables, the main() _safe() cadence calls, and
    scheduler.py's CADENCE tuple keep resolving the names unchanged.
  - Calls BETWEEN these functions ALSO go through ``A.`` — the CT tests patch
    api._ct_fetch_domain and expect run_ct_watch_if_due to see it, and
    _ct_fetch_domain reads a patched api._ssrf_safe_opener.

Constants (TLS_TARGETS_FILE, TLS_*, CT_*, MAX_TLS_TARGETS) stay in api.py and
are read here through A. Pure probe/parse logic still lives in the tls_monitor
sibling (imported directly).
"""
import json
import secrets
import sys
import time
import urllib.parse
import urllib.request

import tls_monitor


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


def _tls_targets() -> dict:
    """Load the TLS watchlist."""
    s = A.load(A.TLS_TARGETS_FILE)
    return s if isinstance(s, dict) else {}


def _tls_results() -> dict:
    """Load the last-probe results store."""
    s = A.load(A.TLS_RESULTS_FILE)
    return s if isinstance(s, dict) else {}


def handle_tls_list() -> None:
    """``GET /api/tls/targets`` — list watchlist + last results.

    Joins the watchlist with the last probe result for each entry so
    the UI can render in one round-trip.
    """
    A.require_auth()
    targets = A._tls_targets()
    results = A._tls_results()
    out = []
    for tid, t in targets.items():
        if not isinstance(t, dict):
            continue
        r = results.get(tid) or {}
        _gc = A._config_ro()
        warn = int(t.get('warn_days', _gc.get('tls_warn_days', A.TLS_DEFAULT_WARN_DAYS)))
        crit = int(t.get('crit_days', _gc.get('tls_crit_days', A.TLS_DEFAULT_CRIT_DAYS)))
        out.append({
            'id':              tid,
            'host':            t.get('host', ''),
            'port':            int(t.get('port', 443)),
            'label':           t.get('label', ''),
            'warn_days':       warn,
            'crit_days':       crit,
            # v1.11.2: connect override + DANE config + DANE result fields
            'connect_address': t.get('connect_address', ''),
            'dane_check':      bool(t.get('dane_check', False)),
            # v1.11.3: STARTTLS protocol selection
            'starttls':        t.get('starttls', 'none'),
            'last_check':      r.get('checked_at', 0),
            'expires_at':      r.get('expires_at', 0),
            'days_left':       tls_monitor.days_until_expiry(r) if r else 0,
            'status':          tls_monitor.status_for(r, warn, crit) if r else 'unknown',
            'addresses':       r.get('addresses', []),
            'issuer':          r.get('issuer', ''),
            'subject':         r.get('subject', ''),
            'san':             r.get('san', []),
            'hostname_match':  r.get('hostname_match'),
            'dns_error':       r.get('dns_error', ''),
            'tls_error':       r.get('tls_error', ''),
            'verify_error':    r.get('verify_error', ''),
            'dane_status':     r.get('dane_status', 'not_checked'),
            'dane_records':    r.get('dane_records', []),
            'dane_error':      r.get('dane_error', ''),
        })
    out.sort(key=lambda x: (x['status'] != 'critical',
                            x['status'] != 'warning',
                            (x['host'] or '').lower()))
    A.respond(200, out)


def handle_tls_add() -> None:
    """``POST /api/tls/targets`` — add a watchlist entry. Admin only.

    Body: ``{host, port?, label?, warn_days?, crit_days?}``.
    """
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A.get_json_body()
    parsed = tls_monitor.parse_target(body)
    if parsed is None:
        A.respond(400, {'error': 'invalid target — host required, port 1-65535'})
    # v4.6.0 (SECURITY): SSRF pre-flight — a TLS target (and its optional
    # connect_address DNS override) must not point at loopback / link-local /
    # cloud-metadata. RFC1918 LAN is allowed (internal cert monitoring is valid).
    for _h in (parsed.get('host'), parsed.get('connect_address')):
        if not _h:
            continue
        try:
            if A._url_targets_local_or_meta(urllib.parse.urlparse('https://' + str(_h)),
                                            allow_loopback=False):
                A.respond(400, {'error': 'target host is not allowed (loopback or '
                                'link-local/metadata address)'})
        except ValueError:
            A.respond(400, {'error': 'invalid target host'})
    targets = A._tls_targets()
    if len(targets) >= A.MAX_TLS_TARGETS:
        A.respond(400, {'error': f'max {A.MAX_TLS_TARGETS} TLS targets'})
    new_id = 'tls_' + secrets.token_hex(6)
    targets[new_id] = parsed
    A.save(A.TLS_TARGETS_FILE, targets)
    A.audit_log(actor, 'tls_target_add',
                detail=f'host={parsed["host"]}:{parsed["port"]}')
    A.respond(200, {'ok': True, 'id': new_id})


def handle_tls_internal_webhook() -> None:
    """``POST /api/internal/tls-webhook`` — called by remotepower-tls-check cron.

    Only accepts requests from loopback. Fires a tls_expiry webhook with
    the cert/DANE details supplied by the cron script.
    """
    remote = A._env('REMOTE_ADDR', '')
    hdr    = A._env('HTTP_X_REMOTEPOWER_INTERNAL', '')
    if remote not in ('127.0.0.1', '::1') or not hdr:
        A.respond(403, {'error': 'forbidden'})
    body = A.get_json_obj()
    host     = A._sanitize_str(body.get('host', ''), 253)
    port     = int(body.get('port', 443)) if str(body.get('port', 443)).isdigit() else 443
    days_left= body.get('days_left', 0)
    severity = body.get('severity', 'warning')
    if not host:
        A.respond(400, {'error': 'host required'})
    A.fire_webhook('tls_expiry', {
        'host':      host,
        'port':      port,
        'days_left': days_left,
        'severity':  severity,
    })
    A.respond(200, {'ok': True})


def handle_tls_update(target_id: str) -> None:
    """``PUT /api/tls/targets/{id}`` — edit an existing target.

    v3.3.0: same validation as POST; id stays the same so previous
    scan results stay attached. last_check / status / days_left are
    preserved so the edit doesn't reset the row to "never scanned".
    """
    actor = A.require_admin_auth()
    if A.method() != 'PUT':
        A.respond(405, {'error': 'Method not allowed'})
    if not target_id.startswith('tls_'):
        A.respond(404, {'error': 'target not found'})
    body = A.get_json_body()
    parsed = tls_monitor.parse_target(body)
    if parsed is None:
        A.respond(400, {'error': 'invalid target — host required, port 1-65535'})
    with A._LockedUpdate(A.TLS_TARGETS_FILE) as targets:
        if target_id not in targets:
            A.respond(404, {'error': 'target not found'})
        existing = targets[target_id]
        # Preserve scan-result fields the operator can't edit.
        for k in ('last_check', 'status', 'days_left', 'expires_at',
                  'issuer', 'tls_error', 'dns_error',
                  'dane_status', 'tls_chain'):
            if k in existing and k not in parsed:
                parsed[k] = existing[k]
        targets[target_id] = parsed
    A.audit_log(actor, 'tls_target_update',
                detail=f'id={target_id} host={parsed["host"]}:{parsed["port"]}')
    A.respond(200, {'ok': True, 'id': target_id})


def handle_tls_delete(target_id: str) -> None:
    """``DELETE /api/tls/targets/{id}`` — remove from watchlist."""
    actor = A.require_admin_auth()
    if not target_id.startswith('tls_'):
        A.respond(404, {'error': 'target not found'})
    targets = A._tls_targets()
    if target_id not in targets:
        A.respond(404, {'error': 'target not found'})
    host = targets[target_id].get('host', '?')
    del targets[target_id]
    A.save(A.TLS_TARGETS_FILE, targets)
    # Also clean the result if present
    results = A._tls_results()
    results.pop(target_id, None)
    A.save(A.TLS_RESULTS_FILE, results)
    A.audit_log(actor, 'tls_target_delete', detail=f'host={host}')
    A.respond(200, {'ok': True})


def handle_tls_scan() -> None:
    """``POST /api/tls/scan`` — probe all targets now (synchronous).

    This is intentionally synchronous so the UI can render the fresh
    results immediately. The cron runner uses the same code path. Each
    probe has a hard 5+5s timeout, so even with 200 targets the worst
    case is ~30 minutes; in practice it's seconds.

    Admin only because probing makes outbound network requests from
    the server, and someone with viewer access shouldn't be able to
    trigger 200 outbound connections.
    """
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    targets = A._tls_targets()
    results = tls_monitor.probe_all(targets)
    A.save(A.TLS_RESULTS_FILE, results)
    A.audit_log(actor, 'tls_scan', detail=f'targets={len(targets)}')
    A.respond(200, {'ok': True, 'scanned': len(results)})


def _tls_expiry_crossings(target, prev, cur):
    """Edge-triggered ``tls_expiry`` payloads for one target: fired only when a
    probe CROSSES the target's warn/crit threshold (or DANE flips ok→fail), so a
    cert that sits at 10 days doesn't re-alert on every sweep. Mirrors the logic
    the ``remotepower-tls-check`` cron runner has always used, but honours the
    per-target ``warn_days``/``crit_days`` instead of that script's fixed 30/7."""
    _gc = A._config_ro()
    warn = int(target.get('warn_days', _gc.get('tls_warn_days', A.TLS_DEFAULT_WARN_DAYS)))
    crit = int(target.get('crit_days', _gc.get('tls_crit_days', A.TLS_DEFAULT_CRIT_DAYS)))
    days      = tls_monitor.days_until_expiry(cur)
    prev_days = tls_monitor.days_until_expiry(prev) if prev else 9999
    host = target.get('host', '?')
    port = int(target.get('port', 443))
    out = []
    if prev_days > crit >= days:
        out.append({'host': host, 'port': port, 'days_left': days,
                    'severity': 'critical'})
    elif prev_days > warn >= days:
        out.append({'host': host, 'port': port, 'days_left': days,
                    'severity': 'warning'})
    dane_ok_prev = (prev or {}).get('dane_status', 'ok') in ('ok', 'not_checked', None, '')
    dane_ok_now  = cur.get('dane_status', 'ok') in ('ok', 'not_checked', None, '')
    if dane_ok_prev and not dane_ok_now:
        out.append({'host': host, 'port': port, 'days_left': days,
                    'severity': 'warning'})
    return out


def run_tls_scan_if_due():
    """Periodic TLS/DANE expiry re-probe so the watchlist is a real monitor.

    Historically this cadence lived ONLY in the optional ``remotepower-tls-check``
    cron (which the installer merely suggests, and which reads the watchlist as a
    raw file — invisible rows under the SQLite/Postgres backends), so unless an
    operator hand-installed the cron on a JSON-backend box, scheduled scans never
    ran. Now the server owns the schedule like every other monitor: per-target
    cadence (oldest ``checked_at`` first, skip younger than TLS_SCAN_INTERVAL),
    bounded per run + wall-clock budget so a big watchlist never bursts or blocks
    a heartbeat. Cheap when nothing is due. Webhooks fire edge-triggered after
    the save (never under a lock)."""
    targets = A._tls_targets()
    if not targets:
        return
    results = A._tls_results()
    now = int(time.time())
    order = sorted(
        ((tid, t) for tid, t in targets.items() if isinstance(t, dict) and t.get('host')),
        key=lambda kv: (results.get(kv[0]) or {}).get('checked_at', 0))
    pending, scanned = [], 0
    start = time.monotonic()
    for tid, t in order:
        prev = results.get(tid) or {}
        if now - int(prev.get('checked_at', 0) or 0) < A.TLS_SCAN_INTERVAL:
            break               # oldest-first: everything after this is younger
        if scanned >= A.TLS_MAX_PER_RUN or time.monotonic() - start > A.TLS_RUN_BUDGET:
            break
        try:
            cur = tls_monitor.probe_all({tid: t}).get(tid)
        except Exception as e:
            sys.stderr.write(f'[remotepower] tls probe failed {t.get("host")}: {e}\n')
            continue
        if not cur:
            continue
        scanned += 1
        results[tid] = cur
        pending.extend(('tls_expiry', p) for p in A._tls_expiry_crossings(t, prev, cur))
    if not scanned:
        return
    # Drop results for deleted targets so the store can't grow unbounded.
    results = {tid: r for tid, r in results.items() if tid in targets}
    A.save(A.TLS_RESULTS_FILE, results)
    for ev, payload in pending:
        A.fire_webhook(ev, payload)


# ─── W1-17: certificate-transparency watch (crt.sh) ─────────────────────────
def _ct_fetch_domain(domain):
    """Query crt.sh for certificates covering ``domain``. Returns a list of
    {id, serial, issuer, cn, not_before}. Raises on transport/parse errors —
    the caller counts failures for the per-domain circuit breaker."""
    url = 'https://crt.sh/?output=json&q=' + urllib.parse.quote(domain)
    opener = A._ssrf_safe_opener(allow_loopback=False, no_redirect=True,
                                 ssl_ctx=A._get_ssl_context())
    req = urllib.request.Request(
        url, headers={'User-Agent': f'RemotePower/{A.SERVER_VERSION}'})
    with opener.open(req, timeout=A.CT_HTTP_TIMEOUT) as resp:
        rows = json.loads(resp.read(4 * 1024 * 1024).decode('utf-8', 'replace'))
    out = []
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict):
            continue
        out.append({
            'id':         str(r.get('id', '')),
            'serial':     str(r.get('serial_number', ''))[:64],
            'issuer':     str(r.get('issuer_name', ''))[:200],
            'cn':         str(r.get('common_name') or r.get('name_value') or '')[:200],
            'not_before': str(r.get('not_before', ''))[:32],
        })
    return out


def run_ct_watch_if_due():
    """W1-17: periodic CT-log sweep over ``ct_watch_domains`` (config; empty =
    off). Same bounded-cadence shape as run_tls_scan_if_due: oldest-first,
    per-run cap + wall-clock budget, cheap `_config_ro()` read on the not-due
    path. crt.sh is notoriously slow, so a domain that fails CT_FAIL_BACKOFF
    times in a row is circuit-broken for 24h. The first successful poll per
    domain baselines silently; afterwards each unseen cert id raises
    ct_new_certificate (capped per run — a bulk reissue isn't 200 alerts).
    Webhooks fire AFTER the save, never under a lock."""
    domains = A._config_ro().get('ct_watch_domains') or []
    if not domains:
        return
    state = A.load(A.CT_WATCH_FILE) or {}
    now = int(time.time())
    order = sorted(domains, key=lambda d: (state.get(d) or {}).get('last_check', 0))
    pending, scanned = [], 0
    start = time.monotonic()
    for domain in order:
        st = state.get(domain) or {}
        last = int(st.get('last_check', 0) or 0)
        if now - last < A.CT_SCAN_INTERVAL:
            break               # oldest-first: everything after this is younger
        if int(st.get('fail_streak', 0) or 0) >= A.CT_FAIL_BACKOFF \
                and now - last < A.CT_BACKOFF_SECONDS:
            continue            # circuit-broken — retry tomorrow
        if scanned >= A.CT_MAX_PER_RUN or time.monotonic() - start > A.CT_RUN_BUDGET:
            break
        scanned += 1
        try:
            certs = A._ct_fetch_domain(domain)
        except Exception as e:
            st['fail_streak'] = int(st.get('fail_streak', 0) or 0) + 1
            st['last_check'] = now
            state[domain] = st
            sys.stderr.write(f'[remotepower] ct watch failed {domain}: {e}\n')
            continue
        seen = st.get('seen') or {}
        baselined = bool(st.get('baselined'))
        for c in certs:
            key = c['id'] or (c['serial'] + '|' + c['issuer'])
            if not key or key in seen:
                continue
            seen[key] = now
            if baselined and len(pending) < A.CT_MAX_EVENTS_PER_RUN:
                pending.append({'domain': domain, 'issuer': c['issuer'],
                                'cn': c['cn'], 'serial': c['serial'],
                                'not_before': c['not_before']})
        if len(seen) > A.CT_MAX_SEEN:
            for k in sorted(seen, key=seen.get)[:len(seen) - A.CT_MAX_SEEN]:
                seen.pop(k, None)
        state[domain] = {'seen': seen, 'baselined': True,
                         'last_check': now, 'fail_streak': 0}
    if not scanned:
        return
    # Drop state for domains removed from the watchlist (store stays bounded).
    state = {d: s for d, s in state.items() if d in domains}
    A.save(A.CT_WATCH_FILE, state)
    for p in pending:
        A.fire_webhook('ct_new_certificate', p)
