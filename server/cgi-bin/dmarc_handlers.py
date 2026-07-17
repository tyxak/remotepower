"""RemotePower — DMARC/SPF/DKIM posture watch + DMARC aggregate-report (RUA)
ingestion: watchlist CRUD, the synchronous re-scan path, the IMAP RUA-report
poll (cadence + on-demand), and the ingested-reports view.

A bound-module carve-out of api.py's request-coupled DMARC handlers, following
the tls_ct_handlers / vpn_handlers / cmdb_handlers pattern:

  - api.py execs a PRIVATE instance and binds its own ``globals()`` here, so
    every api service is reached as ``A.<name>`` — a DYNAMIC attribute lookup,
    which keeps the test suite's monkeypatching of api.respond / api.save /
    api._fetch_dmarc_reports working, and resolves identically under the CGI
    (__main__) and imported-module (wsgi.py/scheduler.py) models.
  - api.py then from-imports every public + private name back into its own
    globals, so the route tables, the main() _safe() cadence calls, and
    scheduler.py's CADENCE tuple keep resolving the names unchanged.
  - Calls BETWEEN these functions ALSO go through ``A.`` — a test that patches
    api._fetch_dmarc_reports expects run_dmarc_imap_if_due to see the patch.

Constants (DMARC_TARGETS_FILE / DMARC_RESULTS_FILE / DMARC_REPORTS_FILE /
CONFIG_FILE / MAX_DMARC_TARGETS) stay in api.py and are read here through A.
Pure DNS/parse logic still lives in the dmarc_monitor sibling (imported
directly, like tls_ct_handlers → tls_monitor).
"""
import re
import secrets
import sys
import time

import dmarc_monitor


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


def _dmarc_targets() -> dict:
    s = A.load(A.DMARC_TARGETS_FILE)
    return s if isinstance(s, dict) else {}


def _dmarc_results() -> dict:
    s = A.load(A.DMARC_RESULTS_FILE)
    return s if isinstance(s, dict) else {}


def handle_dmarc_list() -> None:
    """``GET /api/dmarc/targets`` — domains + last posture result in one round-trip."""
    A.require_auth()
    targets = A._dmarc_targets()
    results = A._dmarc_results()
    out = []
    for tid, t in targets.items():
        if not isinstance(t, dict):
            continue
        r = results.get(tid) or {}
        out.append({
            'id':            tid,
            'domain':        t.get('domain', ''),
            'dkim_selector': t.get('dkim_selector', ''),
            'label':         t.get('label', ''),
            'status':        r.get('status', 'unknown'),
            'reasons':       r.get('reasons', []),
            'dmarc':         r.get('dmarc', {}),
            'spf':           r.get('spf', {}),
            'dkim':          r.get('dkim', {}),
            'errors':        r.get('errors', {}),
            'checked_at':    r.get('checked_at', 0),
        })
    rank = {'fail': 0, 'weak': 1, 'unknown': 2, 'ok': 3}
    out.sort(key=lambda x: (rank.get(x['status'], 2), x['domain']))
    A.respond(200, out)


def handle_dmarc_add() -> None:
    """``POST /api/dmarc/targets`` — add a domain to the watchlist. Admin only."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    parsed = dmarc_monitor.parse_target(A.get_json_body())
    if parsed is None:
        A.respond(400, {'error': 'invalid — a valid domain is required'})
    targets = A._dmarc_targets()
    if len(targets) >= A.MAX_DMARC_TARGETS:
        A.respond(400, {'error': f'max {A.MAX_DMARC_TARGETS} DMARC domains'})
    new_id = 'dmarc_' + secrets.token_hex(6)
    targets[new_id] = parsed
    A.save(A.DMARC_TARGETS_FILE, targets)
    A.audit_log(actor, 'dmarc_target_add', detail=f'domain={parsed["domain"]}')
    A.respond(200, {'ok': True, 'id': new_id})


def handle_dmarc_delete(target_id: str) -> None:
    """``DELETE /api/dmarc/targets/{id}`` — remove a domain. Admin only."""
    actor = A.require_admin_auth()
    if not target_id.startswith('dmarc_'):
        A.respond(404, {'error': 'target not found'})
    targets = A._dmarc_targets()
    if target_id not in targets:
        A.respond(404, {'error': 'target not found'})
    domain = targets[target_id].get('domain', '?')
    del targets[target_id]
    A.save(A.DMARC_TARGETS_FILE, targets)
    results = A._dmarc_results()
    results.pop(target_id, None)
    A.save(A.DMARC_RESULTS_FILE, results)
    A.audit_log(actor, 'dmarc_target_delete', detail=f'domain={domain}')
    A.respond(200, {'ok': True})


def handle_dmarc_scan() -> None:
    """``POST /api/dmarc/scan`` — re-check every domain now (synchronous; DNS is
    fast). Admin only because it makes outbound DNS queries from the server."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    targets = A._dmarc_targets()
    results = A._dmarc_results()
    for tid, t in targets.items():
        if not isinstance(t, dict):
            continue
        try:
            results[tid] = dmarc_monitor.check_domain(
                t.get('domain', ''), t.get('dkim_selector', ''),
                int(A._config_ro().get('dmarc_pct_min', 100)))
        except Exception as e:
            sys.stderr.write(f'[remotepower] dmarc check failed {t.get("domain")}: {e}\n')
    A.save(A.DMARC_RESULTS_FILE, results)
    A.audit_log(actor, 'dmarc_scan', detail=f'domains={len(targets)}')
    A.respond(200, {'ok': True, 'scanned': len(targets)})


# ── DMARC aggregate-report (RUA) ingestion via IMAP + mailbox monitor ────────
# The IMAP creds are admin-configured; the report XML is SEMI-UNTRUSTED (anyone
# can email the RUA address), so the parse is DOCTYPE/ENTITY-guarded and the
# decompression is capped in dmarc_monitor. The password is stored under the
# `password` key so _scrub_config_secrets auto-redacts it from /api/config.

def _dmarc_imap_cfg() -> dict:
    c = (A.load(A.CONFIG_FILE) or {}).get('dmarc_imap')
    return c if isinstance(c, dict) else {}


def _dmarc_reports_state() -> dict:
    s = A.load(A.DMARC_REPORTS_FILE)
    return s if isinstance(s, dict) else {}


def _accumulate_dmarc_report(rep, reports, sources, seen_ids) -> bool:
    """Fold one parsed aggregate report into the running list + per-source
    pass/fail tallies. Skips a report_id already ingested. Returns True if new."""
    m = rep['meta']
    rid = m.get('report_id') or ''
    if rid and rid in seen_ids:
        return False
    if rid:
        seen_ids.add(rid)
    reports.append({
        'org_name': m.get('org_name', ''), 'domain': m.get('domain', ''),
        'report_id': rid, 'policy': m.get('policy', ''),
        'date_begin': m.get('date_begin', 0), 'date_end': m.get('date_end', 0),
        'summary': rep.get('summary', {}), 'received_at': int(time.time()),
    })
    now = int(time.time())
    for r in rep.get('records', []):
        ip = r.get('source_ip') or ''
        if not ip:
            continue
        src = sources.setdefault(ip, {'pass': 0, 'fail': 0, 'domains': [], 'last_seen': 0})
        src['pass' if r.get('pass') else 'fail'] += r.get('count', 0)
        src['last_seen'] = now
        hf = r.get('header_from') or ''
        if hf and hf not in src.get('domains', []):
            src['domains'] = (src.get('domains', []) + [hf])[:10]
    return True


def _fetch_dmarc_reports() -> dict:
    """Connect to the configured IMAP mailbox, ingest NEW RUA reports, and record
    mailbox health. Never raises — failures land in the stored mailbox status."""
    import imaplib
    import email as _email
    import ssl as _ssl
    c = A._dmarc_imap_cfg()
    state = A._dmarc_reports_state()
    mb = {'checked_at': int(time.time()), 'error': '', 'messages': 0, 'unseen': 0}
    if not c.get('enabled') or not c.get('host'):
        state['mailbox'] = {**mb, 'error': 'IMAP not configured'}
        A.save(A.DMARC_REPORTS_FILE, state)
        return {'ok': False, 'error': 'IMAP not configured', 'ingested': 0}
    reports = state.get('reports') or []
    sources = state.get('sources') or {}
    seen_ids = {r.get('report_id') for r in reports if isinstance(r, dict)}
    use_ssl = c.get('use_ssl', True) is not False
    verify_tls = c.get('verify_tls', True) is not False
    host = str(c.get('host'))[:255]
    port = int(c.get('port') or (993 if use_ssl else 143))
    folder = str(c.get('folder') or 'INBOX')[:128]
    last_uid = int(state.get('last_uid') or 0)
    ingested = 0
    M = None
    try:
        _ctx = _ssl.create_default_context()
        if not verify_tls:
            # operator opted out — internal / self-signed IMAP cert (e.g. a
            # Dovecot box with a private CA). Skips hostname + chain verification.
            _ctx.check_hostname = False
            _ctx.verify_mode = _ssl.CERT_NONE
        M = (imaplib.IMAP4_SSL(host, port, ssl_context=_ctx, timeout=20)
             if use_ssl else imaplib.IMAP4(host, port, timeout=20))
        M.login(str(c.get('username') or ''), str(c.get('password') or ''))
        M.select(folder, readonly=False)
        try:
            typ, sd = M.status(folder, '(MESSAGES UNSEEN)')
            if typ == 'OK' and sd and sd[0]:
                txt = sd[0].decode('utf-8', 'replace')
                _mm = re.search(r'MESSAGES\s+(\d+)', txt)
                _uu = re.search(r'UNSEEN\s+(\d+)', txt)
                mb['messages'] = int(_mm.group(1)) if _mm else 0
                mb['unseen'] = int(_uu.group(1)) if _uu else 0
        except Exception:
            pass
        typ, data = M.uid('search', None, 'ALL')
        uids = [int(x) for x in data[0].split() if x.isdigit()] if (typ == 'OK' and data and data[0]) else []
        for uid in [u for u in sorted(uids) if u > last_uid][:300]:
            try:
                typ, md = M.uid('fetch', str(uid), '(RFC822)')
                raw = next((it[1] for it in (md or []) if isinstance(it, tuple) and len(it) == 2), None)
                if raw:
                    for part in _email.message_from_bytes(raw).walk():
                        fn = (part.get_filename() or '').lower()
                        if not (fn.endswith('.gz') or fn.endswith('.zip') or fn.endswith('.xml')):
                            continue
                        payload = part.get_payload(decode=True)
                        if not payload:
                            continue
                        rep = dmarc_monitor.parse_aggregate_report(
                            dmarc_monitor.extract_report_xml(payload, fn))
                        if rep and A._accumulate_dmarc_report(rep, reports, sources, seen_ids):
                            ingested += 1
            except Exception as e:
                sys.stderr.write(f'[remotepower] dmarc report uid {uid} failed: {e}\n')
            last_uid = max(last_uid, uid)
    except Exception as e:
        mb['error'] = str(e)[:160]
    finally:
        try:
            if M is not None:
                M.logout()
        except Exception:
            pass
    state.update({'reports': reports[-300:], 'sources': sources, 'mailbox': mb,
                  'last_uid': last_uid, 'last_fetch': int(time.time()),
                  'updated': int(time.time())})
    A.save(A.DMARC_REPORTS_FILE, state)
    return {'ok': not mb['error'], 'ingested': ingested, 'mailbox': mb}


def run_dmarc_imap_if_due() -> None:
    """Periodic RUA-report poll (modeled on the integrations cadence). Cheap when
    disabled / not due."""
    c = A._dmarc_imap_cfg()
    if not c.get('enabled') or not c.get('host'):
        return
    s = A._dmarc_reports_state()
    if int(time.time()) - int(s.get('last_fetch', 0) or 0) < max(300, int(c.get('interval', 900) or 900)):
        return
    try:
        A._fetch_dmarc_reports()
    except Exception as e:
        sys.stderr.write(f'[remotepower] dmarc imap poll failed: {e}\n')


def handle_dmarc_reports() -> None:
    """``GET /api/dmarc/reports`` — ingested RUA reports + per-source tallies +
    mailbox status."""
    A.require_auth()
    s = A._dmarc_reports_state()
    reports = sorted((s.get('reports') or []),
                     key=lambda r: r.get('received_at', 0), reverse=True)[:100]
    src = s.get('sources') or {}
    sources = sorted(([{'ip': ip, **v} for ip, v in src.items() if isinstance(v, dict)]),
                     key=lambda x: x.get('fail', 0) + x.get('pass', 0), reverse=True)[:200]
    A.respond(200, {'reports': reports, 'sources': sources,
                    'mailbox': s.get('mailbox') or {}, 'updated': s.get('updated', 0)})


def handle_dmarc_fetch() -> None:
    """``POST /api/dmarc/fetch`` — pull new RUA reports from IMAP now. Admin only."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    res = A._fetch_dmarc_reports()
    A.audit_log(actor, 'dmarc_fetch',
                detail=f"ingested={res.get('ingested', 0)} err={res.get('error') or 'none'}")
    A.respond(200, res)


def handle_dmarc_imap_get() -> None:
    """``GET /api/dmarc/imap`` — IMAP config, password redacted. Admin only."""
    A.require_admin_auth()
    c = A._dmarc_imap_cfg()
    A.respond(200, {
        'enabled':  bool(c.get('enabled')),
        'host':     c.get('host', ''),
        'port':     int(c.get('port') or 993),
        'username': c.get('username', ''),
        'folder':   c.get('folder', 'INBOX'),
        'use_ssl':  c.get('use_ssl', True) is not False,
        'verify_tls': c.get('verify_tls', True) is not False,
        'interval': int(c.get('interval', 900) or 900),
        'password_set': bool(c.get('password')),
    })


def handle_dmarc_imap_save() -> None:
    """``POST /api/dmarc/imap`` — save IMAP config (admin). A blank password keeps
    the stored one."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.DmarcImapSaveRequest)
    host = A._no_ctrl(A._sanitize_str(body.get('host', ''), 255)).strip()
    try:
        port = int(body.get('port') or 993)
    except (TypeError, ValueError):
        port = 993
    if not (1 <= port <= 65535):
        A.respond(400, {'error': 'port must be 1-65535'})
    try:
        interval = max(300, int(body.get('interval', 900) or 900))
    except (TypeError, ValueError):
        interval = 900
    with A._LockedUpdate(A.CONFIG_FILE) as cfg:
        cur = cfg.get('dmarc_imap') if isinstance(cfg.get('dmarc_imap'), dict) else {}
        new_pw = body.get('password')
        cfg['dmarc_imap'] = {
            'enabled':  bool(body.get('enabled')),
            'host':     host, 'port': port,
            'username': A._no_ctrl(A._sanitize_str(body.get('username', ''), 255)),
            'folder':   A._no_ctrl(A._sanitize_str(body.get('folder', 'INBOX') or 'INBOX', 128)),
            'use_ssl':  body.get('use_ssl', True) is not False,
            'verify_tls': body.get('verify_tls', True) is not False,
            'interval': interval,
            'password': (str(new_pw)[:512] if new_pw else cur.get('password', '')),
        }
    A.audit_log(actor, 'dmarc_imap_save', detail=f'host={host} enabled={bool(body.get("enabled"))}')
    A.respond(200, {'ok': True})


def handle_dmarc_clear() -> None:
    """``DELETE /api/dmarc/reports`` — wipe ingested RUA reports, per-source
    tallies and mailbox state, and reset the IMAP UID cursor so a later fetch
    re-ingests from scratch. Admin only. The IMAP *config* is left untouched."""
    actor = A.require_admin_auth()
    if A.method() != 'DELETE':
        A.respond(405, {'error': 'Method not allowed'})
    A.save(A.DMARC_REPORTS_FILE, {})
    A.audit_log(actor, 'dmarc_reports_clear',
                detail='cleared ingested DMARC reports + sources + mailbox state')
    A.respond(200, {'ok': True})
