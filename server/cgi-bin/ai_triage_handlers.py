"""RemotePower — hail-mary log sweep + agentic alert triage (v6.3.1)

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

Two features live here:

1. **Hail-mary log sweep** — the operator asks a host for a bounded, one-shot
   sweep of its recent `/var/log` tails (`force_log_sweep` heartbeat flag →
   the agent's `collect_log_sweep()`), the result is secret-redacted at ingest
   and stored (latest sweep per device, `LOG_SWEEP_FILE`), and an AI pass
   (`log_sweep_rca` prompt) turns it into a root-cause read. The sweep +
   diagnosis are EXPLICIT operator actions: like the mitigate flow (and unlike
   ambient AI context, which honours `ai.privacy.send_journal`), clicking
   "Diagnose from logs" is the consent to send the redacted excerpt to the
   configured AI provider — the UI says so next to the button.

2. **Agentic alert triage** — a bounded investigate loop for one alert. The
   model is offered a fixed menu of read-only, server-side evidence tools
   (journal tail, log search, open alerts, recent commands, latest sweep, …)
   and must answer each round with strict JSON: either one tool call or a
   final verdict. At most `_TRIAGE_MAX_STEPS` tool calls, every tool result
   clipped, every tool scoped to the alert's device. The transcript + verdict
   are stored on the alert (`ai_triage`) so the inbox can render the evidence
   trail. The model NEVER executes anything — tools are pure reads; acting on
   the verdict goes through the existing approval-gated paths.
"""

import json
import re
import time

# ── tuning constants (storage keys live in api.py) ───────────────────────────
_SWEEP_MAX_FILES          = 48           # files kept per stored sweep
_SWEEP_MAX_LINES_PER_FILE = 400          # lines kept per file at ingest
_SWEEP_MAX_LINE_CHARS     = 1024         # per-line clip at ingest
_SWEEP_MAX_STORE_BYTES    = 320 * 1024   # total stored text budget per device
_SWEEP_AI_MAX_CHARS       = 48 * 1024    # excerpt budget handed to the model

_TRIAGE_MAX_STEPS         = 4            # tool calls per triage run
_TRIAGE_TOOL_CLIP         = 4000         # chars per tool result in transcript
_TRIAGE_MAX_STORE         = 8192         # stored verdict-field clip
_SWEEP_STALE_FOR_TOOL_S   = 30 * 60      # older than this → the triage tool
                                         # auto-requests a fresh sweep


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


# ── secret redaction (applied at ingest — stored copy is already clean) ──────
# Substring-matched key names, mirroring the RAG corpus rule: an exact set
# misses `api_key`/`passphrase`/… so match loosely and redact the VALUE.
_REDACT_KV = re.compile(
    r'(?i)\b([\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|'
    r'passphrase|private[_-]?key|client[_-]?secret|access[_-]?key|community|'
    r'credential|auth)[\w.-]*)\s*([=:])\s*("[^"]{1,256}"|\'[^\']{1,256}\'|\S{1,256})')
_REDACT_BEARER = re.compile(r'(?i)\b(bearer|basic)\s+[A-Za-z0-9+/._~=-]{8,}')
_REDACT_URLCRED = re.compile(r'://([^/\s:@]{1,64}):([^/\s@]{1,128})@')
# v6.3.1: multi-line PEM private-key block markers (handled at ingest, since a
# block spans lines and has no key= prefix the per-line scrubber keys on).
_PEM_BEGIN_RX = re.compile(r'-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----')
_PEM_END_RX = re.compile(r'-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----')


def _redact_log_line(line):
    """Scrub obvious credential material from one log line. Not a guarantee —
    a defense-in-depth pass so a `password=…` that an app logged never reaches
    the store or the AI provider."""
    # Bearer/Basic first: `Authorization: Bearer <tok>` would otherwise have
    # the KV pass consume "Bearer" as the value and leave the token behind.
    line = _REDACT_BEARER.sub(r'\1 [REDACTED]', line)
    line = _REDACT_KV.sub(r'\1\2[REDACTED]', line)
    line = _REDACT_URLCRED.sub(r'://\1:[REDACTED]@', line)
    return line


# ── ingest (called from the heartbeat handler when `log_sweep` is in the body)
def _ingest_log_sweep(dev_id, sweep):
    """Validate/cap/redact an agent's hail-mary sweep and store it as the
    device's latest sweep. Caps are enforced server-side too — the agent's own
    limits are not trusted."""
    if not isinstance(sweep, dict):
        return
    files_in = sweep.get('files')
    if not isinstance(files_in, list):
        files_in = []
    files, total = [], 0
    for f in files_in[:_SWEEP_MAX_FILES]:
        if not isinstance(f, dict):
            continue
        path = str(f.get('path', ''))[:512]
        lines_in = f.get('lines')
        if not path or not isinstance(lines_in, list):
            continue
        lines = []
        # v6.3.1: a PEM private-key block spans many lines with no `key=` prefix,
        # so the per-line KV scrubber can't catch it — collapse any BEGIN…END
        # PRIVATE KEY run to a single redaction marker before per-line scrubbing.
        in_pem = False
        for ln in lines_in[-_SWEEP_MAX_LINES_PER_FILE:]:
            raw = str(ln)[:_SWEEP_MAX_LINE_CHARS]
            if _PEM_BEGIN_RX.search(raw):
                in_pem = True
                ln = '[REDACTED PRIVATE KEY BLOCK]'
            elif in_pem:
                if _PEM_END_RX.search(raw):
                    in_pem = False
                continue          # drop the body + END line entirely
            else:
                ln = A._redact_log_line(raw)
            total += len(ln) + 1
            if total > _SWEEP_MAX_STORE_BYTES:
                break
            lines.append(ln)
        try:
            files.append({
                'path':      path,
                'mtime':     int(f.get('mtime') or 0),
                'size':      int(f.get('size') or 0),
                'score':     round(float(f.get('score') or 0.0), 2),
                'truncated': bool(f.get('truncated')),
                'lines':     lines,
            })
        except (TypeError, ValueError, OverflowError):
            continue
        if total > _SWEEP_MAX_STORE_BYTES:
            break
    try:
        scanned = int(sweep.get('scanned') or 0)
        skipped = int(sweep.get('skipped') or 0)
    except (TypeError, ValueError):
        scanned = skipped = 0
    rec = {
        'ts':          int(time.time()),
        'files':       files,
        'file_count':  len(files),
        'scanned':     scanned,
        'skipped':     skipped,
        'total_bytes': total,
        'note':        str(sweep.get('note', ''))[:256],
    }
    with A._LockedUpdate(A.LOG_SWEEP_FILE) as store:
        prev = store.get(dev_id) or {}
        # Keep the request stamp so the UI can tell "this sweep answers my
        # click" from a stale one; keep the last AI diagnosis until a new one
        # replaces it (the UI compares ai.sweep_ts to ts to grey it out).
        if prev.get('requested_at'):
            rec['requested_at'] = prev['requested_at']
        if prev.get('ai'):
            rec['ai'] = prev['ai']
        store[dev_id] = rec


# ── handlers: hail-mary sweep ────────────────────────────────────────────────
def handle_log_sweep_run(dev_id):
    """POST /api/devices/<id>/log-sweep/run — one-shot hail-mary sweep request.
    Sets the per-device `force_log_sweep` flag; the next heartbeat response
    carries it, the agent sweeps /var/log and reports on the heartbeat after
    that. Admin-gated like the sibling scan-now endpoints (the sweep reads
    arbitrary recent log content off the host)."""
    A.require_admin_auth()
    if not A._validate_id(dev_id):
        A.respond(400, {'error': 'invalid device id'})
        return
    with A._LockedUpdate(A.DEVICES_FILE) as devices:
        dev = devices.get(dev_id)
        if dev is None:
            A.respond(404, {'error': 'device not found'})
            return
        dev['force_log_sweep'] = True
    with A._LockedUpdate(A.LOG_SWEEP_FILE) as store:
        rec = store.get(dev_id) or {}
        rec['requested_at'] = int(time.time())
        store[dev_id] = rec
    A.audit_log(A.current_username() or 'unknown', 'log_sweep_request',
                f'dev={dev_id}')
    A.respond(200, {'ok': True,
                    'message': 'Log sweep queued — the device reports within '
                               'the next poll or two.'})


def handle_log_sweep_get(dev_id):
    """GET /api/devices/<id>/log-sweep — the device's latest stored sweep
    (+ pending flag while a requested sweep hasn't landed yet)."""
    A.require_auth()
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'invalid device id'})
        return
    devices = A._load_ro(A.DEVICES_FILE) or {}
    if dev_id not in devices:
        A.respond(404, {'error': 'device not found'})
        return
    rec = (A.load(A.LOG_SWEEP_FILE) or {}).get(dev_id) or {}
    requested = int(rec.get('requested_at') or 0)
    swept = int(rec.get('ts') or 0)
    rec['pending'] = bool(requested and requested > swept)
    A.respond(200, rec)


def _sweep_excerpt(rec, budget=_SWEEP_AI_MAX_CHARS):
    """Flatten a stored sweep into the text block handed to the model.
    Highest-scored files first; hard character budget."""
    parts = []
    used = 0
    files = sorted(rec.get('files') or [], key=lambda f: -(f.get('score') or 0))
    for f in files:
        age_m = max(0, (int(rec.get('ts') or 0) - int(f.get('mtime') or 0)) // 60)
        head = (f"== {f.get('path')} (modified ~{age_m}m before sweep, "
                f"err-score {f.get('score', 0)}"
                f"{', truncated' if f.get('truncated') else ''}) ==")
        body = '\n'.join(f.get('lines') or [])
        chunk = head + '\n' + body + '\n\n'
        if used + len(chunk) > budget:
            room = budget - used - len(head) - 20
            if room > 200:
                parts.append(head + '\n' + body[-room:] + '\n[…clipped]\n')
            break
        parts.append(chunk)
        used += len(chunk)
    return ''.join(parts)


def handle_log_sweep_diagnose(dev_id):
    """POST /api/devices/<id>/log-sweep/diagnose — synchronous AI root-cause
    pass over the stored sweep (`log_sweep_rca` prompt). Write-role gated:
    triggers an AI-provider call (cost) + a store write."""
    actor = A.require_write_role('run AI log diagnosis')
    _allowed, _used, _cap = A._ai_rate_limit_check(actor, A._ai_cfg())  # v6.3.1 cost cap
    if not _allowed:
        A.respond(429, {'error': f'AI daily request cap reached ({_used}/{_cap})'})
        return
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'invalid device id'})
        return
    devices = A.load(A.DEVICES_FILE) or {}
    dev = devices.get(dev_id)
    if dev is None:
        A.respond(404, {'error': 'device not found'})
        return
    rec = (A.load(A.LOG_SWEEP_FILE) or {}).get(dev_id) or {}
    if not rec.get('files'):
        A.respond(400, {'error': 'no sweep collected yet — run a log sweep first'})
        return
    excerpt = A._sweep_excerpt(rec)
    os_info = dev.get('os')
    os_str = os_info.get('pretty', '') if isinstance(os_info, dict) else str(os_info or '')
    system_prompt = A._resolve_system_prompt('log_sweep_rca')
    user_prompt = (
        f"Host: {dev.get('name', dev_id)} ({os_str})\n"
        f"Sweep taken: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(rec.get('ts') or 0))} — "
        f"{rec.get('file_count', 0)} file(s) kept of {rec.get('scanned', 0)} scanned, "
        f"{rec.get('skipped', 0)} skipped.\n"
        "Secret-looking values are already redacted.\n\n"
        f"{excerpt}"
    )
    try:
        ai_result = A._call_ai_with_prompts(system_prompt, user_prompt, 'log_sweep_rca')
    except Exception as e:
        A.respond(500, {'error': f'AI call failed: {e}'})
        return
    if not ai_result.get('ok'):
        A.respond(502, {'error': ai_result.get('error') or 'AI provider returned no text'})
        return
    summary = (ai_result.get('text') or '')[:_TRIAGE_MAX_STORE]
    ai_rec = {'summary': summary, 'at': int(time.time()),
              'by': A.current_username() or 'unknown', 'sweep_ts': rec.get('ts')}
    with A._LockedUpdate(A.LOG_SWEEP_FILE) as store:
        cur = store.get(dev_id) or {}
        cur['ai'] = ai_rec
        store[dev_id] = cur
    A.audit_log(A.current_username() or 'unknown', 'log_sweep_diagnose',
                f'dev={dev_id} chars={len(excerpt)}')
    # Success respond OUTSIDE any try/except Exception (HTTPError would be
    # swallowed and rewritten to a 500 — the handle_server_self_update class).
    A.respond(200, {'ok': True, 'ai': ai_rec})


# ── agentic alert triage ─────────────────────────────────────────────────────
def _triage_tools(dev_id, dev, alert=None):
    """The read-only evidence menu. Every tool is scoped to the alert's device
    and returns a plain string (clipped by the loop). Adding a tool = one entry
    here + a line in _TRIAGE_TOOL_MENU below."""
    alert = alert or {}
    def _journal(args):
        try:
            n = min(int(args.get('lines') or 40), 80)
        except (TypeError, ValueError):
            n = 40
        lines = [str(l) for l in (dev.get('journal') or [])[-n:]]
        return '\n'.join(A._redact_log_line(l) for l in lines) or '(journal empty)'

    def _services(args):
        svcs = dev.get('services') or []
        if not svcs:
            return '(no watched services)'
        out = []
        for s in svcs[:40]:
            if isinstance(s, dict):
                out.append(f"{s.get('name', '?')}: {s.get('status', s.get('active', '?'))}")
            else:
                out.append(str(s))
        return '\n'.join(out)

    def _open_alerts(args):
        alerts = (A.load(A.ALERTS_FILE) or {}).get('alerts', [])
        rows = [a for a in alerts
                if a.get('device_id') == dev_id and not a.get('resolved_at')]
        return '\n'.join(
            f"[{a.get('severity', '?')}] {a.get('event', '?')} "
            f"({time.strftime('%m-%d %H:%M', time.gmtime(a.get('ts') or 0))}) id={a.get('id')}"
            for a in rows[-25:]) or '(no other open alerts)'

    def _recent_commands(args):
        outs = (A.load(A.CMD_OUTPUT_FILE) or {}).get(dev_id) or []
        parts = []
        for o in outs[-5:]:
            parts.append(f"$ {str(o.get('cmd', ''))[:200]}  (rc={o.get('rc')})\n"
                         f"{A._redact_log_line(str(o.get('output', ''))[:600])}")
        return '\n---\n'.join(parts) or '(no recent command output)'

    def _log_search(args):
        pat = str(args.get('pattern') or '')[:128]
        if not pat:
            return '(log_search needs a "pattern" arg)'
        try:
            rx = re.compile(pat, re.IGNORECASE)
        except re.error as e:
            return f'(invalid pattern: {e})'
        units = ((A.load(A.LOG_WATCH_FILE) or {}).get(dev_id) or {}).get('units') or {}
        hits = []
        for unit, entries in units.items():
            for e in entries:
                line = e.get('line', '')
                if rx.search(line):
                    hits.append(f"{unit}: {A._redact_log_line(line)[:300]}")
                    if len(hits) >= 40:
                        return '\n'.join(hits)
        return '\n'.join(hits) or '(no matches in the 6h log buffer)'

    def _request_fresh_sweep():
        """Self-provisioning evidence: set the one-shot force flag so the NEXT
        triage run (manual re-run, or the operator opening the drawer) has a
        fresh sweep to read. Never raises into the tool."""
        try:
            with A._LockedUpdate(A.DEVICES_FILE) as devices:
                if dev_id in devices:
                    devices[dev_id]['force_log_sweep'] = True
                else:
                    return False
            with A._LockedUpdate(A.LOG_SWEEP_FILE) as store:
                rec = store.get(dev_id) or {}
                rec['requested_at'] = int(time.time())
                store[dev_id] = rec
            return True
        except Exception:
            return False

    def _log_sweep(args):
        rec = (A.load(A.LOG_SWEEP_FILE) or {}).get(dev_id) or {}
        age_s = int(time.time()) - int(rec.get('ts') or 0)
        if not rec.get('files') or age_s > _SWEEP_STALE_FOR_TOOL_S:
            requested = _request_fresh_sweep()
            note = ('A fresh sweep has been requested from the agent — it '
                    'arrives within a heartbeat or two; a re-run of this '
                    'triage will be able to read it.' if requested else
                    'The operator can run one from the device drawer.')
            if not rec.get('files'):
                return f'(no hail-mary sweep stored. {note})'
            return (f"(STALE sweep from {age_s // 60}m ago — treat with care. "
                    f"{note})\n" + A._sweep_excerpt(rec, budget=6000))
        return (f"(sweep from {age_s // 60}m ago, {rec.get('file_count', 0)} files)\n"
                + A._sweep_excerpt(rec, budget=6000))

    def _cves(args):
        rec = (A.load(A.CVE_FINDINGS_FILE) or {}).get(dev_id) or {}
        findings = [f for f in (rec.get('findings') or [])
                    if isinstance(f, dict) and not f.get('ignored')]
        if not findings:
            return '(no open CVE findings for this host)'
        rank = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        top = sorted(findings, key=lambda f: rank.get(f.get('severity'), 9))[:20]
        lines = [f"{len(findings)} open finding(s); top by severity:"]
        for f in top:
            fx = f.get('fixed_version')
            lines.append(f"[{f.get('severity', '?')}] {f.get('vuln_id', '?')} "
                         f"{f.get('package', '?')}"
                         + (f" → fix in {fx}" if fx else " (no fix yet)"))
        return '\n'.join(lines)

    def _metrics_trend(args):
        # v6.3.1: read the CPU/mem/swap/disk roll-up series (min/avg/max per
        # bucket) — the resolution the model needs to see what actually happened
        # around the alert. Prefer the 5-min tier (incident zoom, ~8d); fall
        # back to hourly if the fine tier has no points yet.
        rec = A._entity_read_one(A.METRICS_ROLLUP_FILE, dev_id, {}) or {}
        for tier, label in (('fivemin', '5-min'), ('hourly', 'hourly')):
            pts = A._rollup_read_shape(rec.get(tier) or [])
            if not pts:
                continue
            lines = [f"CPU/mem/swap/disk % ({label} avg, last {min(20, len(pts))} buckets):"]
            for p in pts[-20:]:
                when = time.strftime('%m-%d %H:%M', time.gmtime(p.get('ts') or 0))
                cells = ' '.join(f"{k}={p[k]['avg']}(max {p[k]['max']})"
                                 for k in ('cpu', 'mem', 'swap', 'disk')
                                 if isinstance(p.get(k), dict))
                if cells:
                    lines.append(f"{when}: {cells}")
            if len(lines) > 1:
                return '\n'.join(lines)
        return '(no CPU/memory roll-up history for this host yet)'

    def _device_summary(args):
        si = dev.get('sysinfo') or {}
        return json.dumps({
            'name': dev.get('name'), 'os': dev.get('os'),
            'last_seen_s_ago': int(time.time()) - int(dev.get('last_seen') or 0),
            'cpu_percent': si.get('cpu_percent'), 'mem_percent': si.get('mem_percent'),
            'disk_percent': si.get('disk_percent'), 'uptime': si.get('uptime'),
            'failed_units': si.get('failed_units'),
        }, default=str)[:1500]

    def _prior_incidents(args):
        # v6.3.1: cross-fleet outcome memory — prior resolved incidents of the
        # same signature (same event/kind) in the SAME tenant, with the verdict
        # and what actually cleared them. This is what a single-host tool can
        # never offer: institutional memory across the whole fleet.
        event = alert.get('event') or ''
        kind = A.EVENT_KIND_MAP.get(event) if hasattr(A, 'EVENT_KIND_MAP') else ''
        tenant = A._device_tenant(dev)
        priors = _similar_incidents(event, kind, tenant,
                                    exclude_alert_id=alert.get('id'), limit=5)
        if not priors:
            return ('(no similar prior incidents in memory for this signature — '
                    'this may be the first of its kind on the fleet)')
        lines = [f'{len(priors)} similar prior incident(s), most relevant first:']
        for o in priors:
            when = time.strftime('%Y-%m-%d', time.gmtime(o.get('resolved_at') or 0))
            rate = {'up': ' [operator confirmed helpful]',
                    'down': ' [operator marked unhelpful]'}.get(o.get('rating'), '')
            lines.append(
                f"- {when} on {o.get('device_name') or o.get('device_id')}{rate}\n"
                f"  root cause: {o.get('root_cause', '')}\n"
                f"  recommended: {o.get('recommended_action', '') or '(none recorded)'}\n"
                f"  outcome: {o.get('resolution', '')}")
        return '\n'.join(lines)

    return {
        'device_summary':  _device_summary,
        'journal_tail':    _journal,
        'services':        _services,
        'open_alerts':     _open_alerts,
        'recent_commands': _recent_commands,
        'log_search':      _log_search,
        'log_sweep':       _log_sweep,
        'cves':            _cves,
        'metrics_trend':   _metrics_trend,
        'prior_incidents': _prior_incidents,
    }


_TRIAGE_TOOL_MENU = (
    "Available evidence tools (all read-only, all scoped to this host):\n"
    "- device_summary {} — OS, load, memory, disk, failed units, last-seen\n"
    "- journal_tail {\"lines\": 40} — recent journal entries (max 80)\n"
    "- services {} — watched service states\n"
    "- open_alerts {} — the host's other open alerts\n"
    "- recent_commands {} — last commands run on the host + output\n"
    "- log_search {\"pattern\": \"<regex>\"} — grep the 6h log buffer\n"
    "- log_sweep {} — latest hail-mary /var/log sweep excerpt (a stale/missing "
    "sweep auto-requests a fresh one for the next run)\n"
    "- cves {} — the host's open CVE findings, top by severity\n"
    "- metrics_trend {} — recent CPU/mem/swap/disk % (5-min & hourly avg/max) "
    "around the incident\n"
    "- prior_incidents {} — how the fleet resolved SIMILAR past incidents "
    "(same signature, same tenant): the verdict and what actually cleared it\n"
)


_ATTACK_ID_RX = re.compile(r'^T\d{4}(?:\.\d{3})?$')
_ATTACK_PROOFS = ('observed', 'inferred', 'theoretical')


def _clean_attack_techniques(raw):
    """Validate the model's MITRE ATT&CK tags. Keeps only well-formed technique
    ids (Txxxx / Txxxx.yyy) with a recognised proof label — the model can
    hallucinate ids, so a strict shape check is the honesty gate. Returns a
    list of {id, name, proof}; drops anything malformed; caps at 8."""
    if not isinstance(raw, list):
        return []
    out = []
    for t in raw:
        if not isinstance(t, dict):
            continue
        tid = str(t.get('id', '')).strip().upper()
        if not _ATTACK_ID_RX.match(tid):
            continue
        proof = str(t.get('proof', '')).strip().lower()
        if proof not in _ATTACK_PROOFS:
            proof = 'theoretical'   # never over-state; unknown → weakest
        out.append({'id': tid, 'name': str(t.get('name', ''))[:80], 'proof': proof})
        if len(out) >= 8:
            break
    return out


def _parse_triage_json(text):
    """Extract the first JSON object from a model reply (tolerates fences and
    prose around it). Returns a dict or None."""
    if not text:
        return None
    t = re.sub(r'^```(?:json)?\s*|\s*```$', '', text.strip(), flags=re.MULTILINE)
    dec = json.JSONDecoder()
    for m in re.finditer(r'\{', t):
        try:
            obj, _ = dec.raw_decode(t[m.start():])
            if isinstance(obj, dict):
                return obj
        except ValueError:
            continue
    return None


def _run_alert_triage(alert, dev_id, dev):
    """The bounded investigate loop. Returns {verdict, steps, rounds} — raises
    RuntimeError on provider failure so the handler can map it to a 502."""
    tools = A._triage_tools(dev_id, dev, alert)
    system_prompt = A._resolve_system_prompt('alert_triage')
    payload = {k: v for k, v in (alert.get('payload') or {}).items()
               if isinstance(v, (str, int, float, bool))}
    transcript = (
        f"ALERT under investigation:\n"
        f"  event: {alert.get('event')}\n"
        f"  severity: {alert.get('severity')}\n"
        f"  host: {dev.get('name', dev_id)}\n"
        f"  fired: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(alert.get('ts') or 0))}\n"
        f"  payload: {json.dumps(payload, default=str)[:1200]}\n\n"
        f"{_TRIAGE_TOOL_MENU}\n"
        f"You may call at most {_TRIAGE_MAX_STEPS} tools, then you MUST give a "
        f"verdict. Reply with EXACTLY ONE JSON object per turn.\n"
    )
    steps = []
    verdict = None
    rounds = 0
    for _round in range(_TRIAGE_MAX_STEPS + 1):
        last_round = _round == _TRIAGE_MAX_STEPS
        prompt = transcript + (
            '\nYour tool budget is EXHAUSTED — reply with your verdict JSON now.'
            if last_round else '\nYour JSON reply:')
        result = A._call_ai_with_prompts(system_prompt, prompt, 'alert_triage')
        rounds += 1
        if not result.get('ok'):
            raise RuntimeError(result.get('error') or 'AI provider returned no text')
        obj = A._parse_triage_json(result.get('text') or '')
        if not obj:
            transcript += ('\n[system] Your last reply was not parseable JSON. '
                           'Reply with exactly one JSON object.\n')
            continue
        if obj.get('action') == 'tool' and not last_round:
            name = str(obj.get('tool') or '')
            args = obj.get('args') if isinstance(obj.get('args'), dict) else {}
            fn = tools.get(name)
            if fn is None:
                out = f'(unknown tool {name!r} — pick one from the menu)'
            else:
                try:
                    out = str(fn(args))[:_TRIAGE_TOOL_CLIP]
                except Exception as e:
                    out = f'(tool error: {e})'
            steps.append({'tool': name, 'args': args,
                          'why': str(obj.get('why', ''))[:300],
                          'result_chars': len(out)})
            transcript += (f'\n[tool call] {name} {json.dumps(args, default=str)[:300]}\n'
                           f'[tool result]\n{out}\n')
            continue
        # A verdict (or a tool request past the budget — read its fields as one).
        ev = obj.get('evidence')
        verdict = {
            'root_cause':         str(obj.get('root_cause', ''))[:_TRIAGE_MAX_STORE],
            'confidence':         str(obj.get('confidence', ''))[:16],
            'evidence':           [str(e)[:400] for e in ev][:10] if isinstance(ev, list) else [],
            'recommended_action': str(obj.get('recommended_action', ''))[:2000],
            'attack_techniques':  _clean_attack_techniques(obj.get('attack_techniques')),
        }
        break
    if verdict is None:
        verdict = {'root_cause': '', 'confidence': '',
                   'evidence': [], 'recommended_action': '',
                   'error': 'model never produced a parseable verdict'}
    return {'verdict': verdict, 'steps': steps, 'rounds': rounds}


def handle_alert_ai_triage(alert_id):
    """POST /api/alerts/<id>/ai-triage — run the bounded agentic triage loop
    for one alert and store the verdict + evidence trail on the alert record.
    Write-role gated (multiple AI-provider calls). Cross-tenant / out-of-scope
    alert ids 404 (via the caller-visibility filter) so existence isn't
    revealed."""
    actor = A.require_write_role('run AI alert triage')
    # v6.3.1: count a triage run against the per-user daily AI cap (one run =
    # one request, even though it makes several provider calls) — the loop is a
    # cost amplifier and was previously uncapped.
    _allowed, _used, _cap = A._ai_rate_limit_check(actor, A._ai_cfg())
    if not _allowed:
        A.respond(429, {'error': f'AI daily request cap reached ({_used}/{_cap})'})
        return
    all_alerts = (A.load(A.ALERTS_FILE) or {}).get('alerts', [])
    visible = A._filter_alerts_for_caller(all_alerts)
    alert = next((a for a in visible if a.get('id') == alert_id), None)
    if alert is None:
        A.respond(404, {'error': 'alert not found'})
        return
    dev_id = alert.get('device_id') or ''
    dev = (A.load(A.DEVICES_FILE) or {}).get(dev_id) or {}
    try:
        triage = A._run_alert_triage(alert, dev_id, dev)
    except RuntimeError as e:
        A.respond(502, {'error': str(e)})
        return
    except Exception as e:
        A.respond(500, {'error': f'triage failed: {e}'})
        return
    triage['at'] = int(time.time())
    triage['by'] = A.current_username() or 'unknown'
    found = False
    with A._LockedUpdate(A.ALERTS_FILE) as store:
        for a in store.get('alerts', []):
            if a.get('id') == alert_id:
                a['ai_triage'] = triage
                found = True
                break
    if not found:
        # The alert was pruned between the read and the write — still return
        # the triage so the operator sees the work, but flag it unattached.
        triage['stored'] = False
    A.audit_log(triage['by'], 'alert_ai_triage',
                f'id={alert_id} rounds={triage.get("rounds")}')
    A.respond(200, {'ok': True, 'ai_triage': triage})


def handle_alert_triage_feedback(alert_id):
    """POST /api/alerts/<id>/ai-triage/feedback {helpful: bool, note?} — the
    operator rates a stored verdict. This is the feedback loop's write side:
    the aggregate (up/down counts) surfaces in /api/ai/stats, and a rated-down
    verdict is the strongest tuning signal there is."""
    actor = A.require_write_role('rate AI triage')
    body = A.get_json_obj()
    helpful = bool(body.get('helpful'))
    note = A._sanitize_str(str(body.get('note', '')), 300)
    # v6.3.1: gate on the SAME visibility the triage read path uses (RBAC role
    # scope + tenant), not tenant alone — a same-tenant but out-of-scope writer
    # shouldn't be able to rate an alert they can't see.
    _visible = {a.get('id') for a in A._filter_alerts_for_caller(
        (A.load(A.ALERTS_FILE) or {}).get('alerts', []))}
    if alert_id not in _visible:
        A.respond(404, {'error': 'alert not found'})
        return
    found = False
    with A._LockedUpdate(A.ALERTS_FILE) as store:
        for a in store.get('alerts', []):
            if a.get('id') == alert_id:
                if not A._alert_tenant_visible(a):
                    A.respond(404, {'error': 'alert not found'})
                    return
                if not isinstance(a.get('ai_triage'), dict):
                    A.respond(400, {'error': 'no triage stored on this alert'})
                    return
                a['ai_triage']['feedback'] = {
                    'helpful': helpful, 'note': note,
                    'by': actor, 'at': int(time.time()),
                }
                found = True
                break
    if not found:
        A.respond(404, {'error': 'alert not found'})
        return
    A.audit_log(actor, 'alert_triage_feedback',
                f'id={alert_id} helpful={helpful}')
    A.respond(200, {'ok': True})


# ── auto-triage cadence (tiered autonomy — OFF by default) ───────────────────
_AUTO_TRIAGE_MIN_INTERVAL_S = 120     # between cadence attempts
_AUTO_TRIAGE_LOOKBACK_S = 24 * 3600   # only alerts fired in the last day
_SEV_RANK = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}


def run_ai_triage_if_due():
    """Cadence sweep: when `ai.auto_triage.enabled`, pick ONE recent, open,
    untriaged alert (severity ≥ the configured floor) and run the same bounded
    investigate loop the Triage button uses, storing the verdict as by='auto'.
    Hard limits: one alert per tick, a per-day run cap, and the loop's own
    4-tool budget. System context — no caller scoping (it triages every
    tenant's alerts; the verdict is only readable by callers who can already
    see the alert). Provider latency note: with the out-of-band scheduler this
    runs fully off the request path; without it, the tick that picks an alert
    pays the AI calls in-request — which is why the feature ships OFF."""
    # v6.3.1 (hardening): NEVER run the multi-call investigate loop on the
    # request path. When the out-of-band scheduler is active it owns the
    # cadence and the request path skips every sweep; without it, this loop
    # would stall whatever request (a heartbeat!) trips the gate for the full
    # AI latency. So auto-triage only runs under the scheduler.
    if not A._external_scheduler_active():
        return
    cfg = A._ai_cfg()
    at = cfg.get('auto_triage') or {}
    if not (cfg.get('enabled') and at.get('enabled')):
        return
    now = int(time.time())
    cap = int(at.get('daily_cap') or 20)
    today = time.strftime('%Y-%m-%d', time.gmtime(now))
    # v6.3.1 (hardening): the read-check-stamp of the cadence state must be
    # atomic, or two workers both pass the interval gate and double-spend AI
    # calls on the same alert. Take the lock, re-check, stamp, release — THEN
    # do the slow AI work outside the lock.
    with A._LockedUpdate(A.AI_TRIAGE_STATE_FILE) as state:
        if now - int(state.get('last_run') or 0) < _AUTO_TRIAGE_MIN_INTERVAL_S:
            return
        count = int(state.get('count') or 0) if state.get('day') == today else 0
        if count >= cap:
            return
        # Stamp BEFORE the slow work so a provider hang can't re-enter this run.
        state.update({'last_run': now, 'day': today, 'count': count})
    floor = _SEV_RANK.get(str(at.get('min_severity') or 'high'), 1)
    alerts = (A.load(A.ALERTS_FILE) or {}).get('alerts', [])
    candidates = [
        a for a in alerts
        if not a.get('resolved_at')
        and not a.get('ai_triage')
        and a.get('device_id')
        and _SEV_RANK.get(a.get('severity'), 9) <= floor
        and int(a.get('ts') or 0) >= now - _AUTO_TRIAGE_LOOKBACK_S
    ]
    if not candidates:
        return
    # v6.3.1 (hardening): pick by SEVERITY first, then OLDEST — the previous
    # newest-first (LIFO) pick starved the backlog during sustained alerting
    # (older un-triaged alerts were perpetually superseded and, against the
    # daily cap, never triaged). Most-severe, longest-waiting drains first.
    alert = min(candidates, key=lambda a: (_SEV_RANK.get(a.get('severity'), 9),
                                           int(a.get('ts') or 0)))
    dev_id = alert['device_id']
    dev = (A.load(A.DEVICES_FILE) or {}).get(dev_id) or {}

    def _bump_count():
        # Locked RMW — the counter is mutated on a separate path from the
        # last_run stamp, so re-read under the lock rather than writing a stale
        # snapshot (which would clobber a concurrent tick's count).
        with A._LockedUpdate(A.AI_TRIAGE_STATE_FILE) as st:
            if st.get('day') != today:
                st['day'], st['count'] = today, 0
            st['count'] = int(st.get('count') or 0) + 1

    try:
        triage = A._run_alert_triage(alert, dev_id, dev)
    except Exception as exc:
        # Provider down / misconfigured — count the attempt (it spent calls)
        # and let the next tick try a fresh alert rather than looping on this.
        _bump_count()
        raise RuntimeError(f'auto-triage of {alert.get("id")} failed: {exc}') from exc
    triage['at'] = int(time.time())
    triage['by'] = 'auto'
    with A._LockedUpdate(A.ALERTS_FILE) as store:
        for a in store.get('alerts', []):
            if a.get('id') == alert.get('id'):
                a['ai_triage'] = triage
                break
    _bump_count()
    A.audit_log('auto', 'alert_ai_triage',
                f'id={alert.get("id")} rounds={triage.get("rounds")} (auto)')


# ── v6.3.1: cross-fleet incident outcome memory ──────────────────────────────
# The compounding half of agentic triage. A single-host tool can't do this;
# RemotePower watches the WHOLE fleet, so every resolved+triaged incident is a
# data point the NEXT triage can learn from. We harvest resolved alerts that
# carry an AI verdict into a durable, tenant-tagged outcome store (it outlives
# the alert, which is pruned after alerts_retention_days), and expose the most
# similar priors to the investigate loop as a new read-only evidence tool —
# "we saw this exact signature before; here's the verdict and what actually
# cleared it." Retrieval is tenant-scoped; the memory never crosses tenants.

_INCIDENT_MEMORY_MAX = 1000        # outcomes retained (ring, newest kept)
_INCIDENT_SEEN_MAX = 4000          # captured alert-ids remembered (dedup ring)
_INCIDENT_MEMORY_INTERVAL_S = 300  # cadence: harvest at most every 5 min


def _incident_resolution(alert):
    """How the alert cleared, for the outcome record. 'auto' when an auto-resolve
    recover event closed it (resolved_by unset/system); otherwise the operator
    name. Best-effort — purely descriptive."""
    rb = alert.get('resolved_by')
    if not rb or rb in ('system', 'auto', ''):
        return 'auto-resolved (recover event)'
    return f'resolved by {rb}'


def _capture_incident_outcome(alert, dev):
    """Build one outcome record from a resolved, AI-triaged alert. Returns the
    dict, or None if the alert isn't a capture candidate. Pure — the caller
    persists + dedups."""
    tri = alert.get('ai_triage')
    if not isinstance(tri, dict) or not alert.get('resolved_at'):
        return None
    verdict = tri.get('verdict') if isinstance(tri.get('verdict'), dict) else {}
    root = str(verdict.get('root_cause') or '').strip()
    if not root:
        return None                      # nothing worth remembering
    fb = tri.get('feedback') if isinstance(tri.get('feedback'), dict) else {}
    rating = None
    if 'helpful' in fb:
        rating = 'up' if fb.get('helpful') else 'down'
    return {
        'alert_id': alert.get('id'),
        'event': alert.get('event') or '',
        'kind': A.EVENT_KIND_MAP.get(alert.get('event')) if hasattr(A, 'EVENT_KIND_MAP') else '',
        'severity': alert.get('severity') or '',
        'tenant': A._device_tenant(dev),
        'device_id': alert.get('device_id') or '',
        'device_name': alert.get('device_name') or dev.get('name') or '',
        'root_cause': root[:600],
        'recommended_action': str(verdict.get('recommended_action') or '')[:600],
        'confidence': str(verdict.get('confidence') or '')[:24],
        'resolution': _incident_resolution(alert),
        'resolved_at': int(alert.get('resolved_at') or 0),
        'rating': rating,
        'captured_at': int(time.time()),
    }


def run_incident_memory_if_due():
    """Cadence: harvest resolved+triaged alerts into the durable outcome memory
    (idempotent via a seen-id ring), so the knowledge survives alert pruning.
    Cheap: a read-gate before the lock, then one locked append. No AI calls."""
    now = int(time.time())
    mem = A.load(A.INCIDENT_MEMORY_FILE) or {}
    if (now - int(mem.get('last_run') or 0)) < _INCIDENT_MEMORY_INTERVAL_S:
        return
    alerts = (A.load(A.ALERTS_FILE) or {}).get('alerts', [])
    seen = set(mem.get('seen') or [])
    fresh = [a for a in alerts
             if a.get('resolved_at') and isinstance(a.get('ai_triage'), dict)
             and a.get('id') not in seen]
    devices = A.load(A.DEVICES_FILE) or {}
    new_outcomes = []
    new_ids = []
    for a in fresh:
        dev = devices.get(a.get('device_id')) or {}
        oc = _capture_incident_outcome(a, dev)
        new_ids.append(a.get('id'))       # mark seen even if not worth storing
        if oc:
            new_outcomes.append(oc)
    with A._LockedUpdate(A.INCIDENT_MEMORY_FILE) as store:
        outcomes = store.get('outcomes') if isinstance(store.get('outcomes'), list) else []
        outcomes.extend(new_outcomes)
        store['outcomes'] = outcomes[-_INCIDENT_MEMORY_MAX:]
        seen_list = store.get('seen') if isinstance(store.get('seen'), list) else []
        # keep the seen-ring in step with what's still capturable (bounded)
        seen_list.extend(i for i in new_ids if i)
        store['seen'] = seen_list[-_INCIDENT_SEEN_MAX:]
        store['last_run'] = now


def _similar_incidents(event, kind, tenant, exclude_alert_id=None, limit=5):
    """Retrieve prior resolved incidents most similar to (event, kind) within the
    SAME tenant. Rank: a thumbs-up verdict first (proven-useful), then recency.
    Same-event matches rank above same-kind-only matches. Pure read."""
    mem = A.load(A.INCIDENT_MEMORY_FILE) or {}
    outcomes = mem.get('outcomes') if isinstance(mem.get('outcomes'), list) else []
    scored = []
    for o in outcomes:
        if not isinstance(o, dict):
            continue
        if o.get('tenant') != tenant:
            continue                      # tenant isolation — never cross
        if exclude_alert_id and o.get('alert_id') == exclude_alert_id:
            continue
        same_event = o.get('event') == event and event
        same_kind = kind and o.get('kind') == kind
        if not (same_event or same_kind):
            continue
        rank = (0 if same_event else 1,
                0 if o.get('rating') == 'up' else (2 if o.get('rating') == 'down' else 1),
                -int(o.get('resolved_at') or 0))
        scored.append((rank, o))
    scored.sort(key=lambda x: x[0])
    return [o for _r, o in scored[:max(1, min(limit, 20))]]


def handle_ai_incident_memory():
    """GET /api/ai/incident-memory — recent resolved-incident outcomes visible to
    the caller's tenant (most recent first). Read-only situational memory; the
    same data the triage `prior_incidents` tool draws on. A superadmin (or
    tenancy off) sees every outcome; a tenant-scoped caller sees only their own
    tenant's (the standard _tenant_gate pattern)."""
    A.require_auth()
    gate = A._tenant_gate()          # None = superadmin / tenancy off = see all
    mem = A.load(A.INCIDENT_MEMORY_FILE) or {}
    outcomes = [o for o in (mem.get('outcomes') or [])
                if isinstance(o, dict) and (gate is None or o.get('tenant') == gate)]
    outcomes.sort(key=lambda o: int(o.get('resolved_at') or 0), reverse=True)
    A.respond(200, {'outcomes': outcomes[:100], 'count': len(outcomes)})
