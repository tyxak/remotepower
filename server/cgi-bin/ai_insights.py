"""On-demand AI insight helpers: fleet anomaly detection, cron builder,
runbook suggestions, and CMDB doc drafts.

v3.4.0. Everything here is pure: prompt builders return (system, messages)
tuples and response parsers turn model text into structured data. The api.py
handlers own the actual ai_provider.chat() call (and its config, redaction,
rate limiting), so this module unit-tests without a network or a provider.

The one piece of real logic is next_cron_runs() — a small stdlib evaluator
for standard 5-field cron expressions, used to validate and preview what the
AI cron builder produced.
"""

import json
import re
import datetime as _dt

# ── JSON extraction ──────────────────────────────────────────────────────────
def extract_json(text):
    """Best-effort: pull the first JSON object/array out of a model reply.

    Models wrap JSON in prose or ```json fences despite instructions; we strip
    fences then scan for the first balanced {...} or [...]. Returns the parsed
    value or None."""
    if not text:
        return None
    t = text.strip()
    t = re.sub(r'^```(?:json)?\s*', '', t)
    t = re.sub(r'\s*```$', '', t)
    try:
        return json.loads(t)
    except Exception:
        pass
    for opener, closer in (('{', '}'), ('[', ']')):
        start = t.find(opener)
        if start < 0:
            continue
        depth = 0
        for i in range(start, len(t)):
            if t[i] == opener:
                depth += 1
            elif t[i] == closer:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(t[start:i + 1])
                    except Exception:
                        break
    return None


# ── #10: AI cron builder ──────────────────────────────────────────────────────
CRON_SYSTEM = (
    "You convert a plain-English schedule description into a standard 5-field "
    "cron expression (minute hour day-of-month month day-of-week). Reply with "
    "ONLY a JSON object: {\"cron\": \"<expr>\", \"explanation\": \"<one "
    "sentence>\"}. Use */n, ranges and lists where natural. Assume the "
    "server's local timezone. If the request is ambiguous or not a schedule, "
    "set cron to \"\" and explain why."
)


def cron_prompt(description):
    return CRON_SYSTEM, [{'role': 'user', 'content': str(description)[:500]}]


def parse_cron_response(text):
    """-> {cron, explanation, valid, error}. Validates the field count/ranges."""
    data = extract_json(text) or {}
    cron = str(data.get('cron', '')).strip()
    explanation = str(data.get('explanation', '')).strip()
    if not cron:
        return {'cron': '', 'explanation': explanation or 'Could not derive a schedule.',
                'valid': False, 'error': 'no expression'}
    ok, err = validate_cron(cron)
    return {'cron': cron, 'explanation': explanation, 'valid': ok,
            'error': '' if ok else err}


_CRON_BOUNDS = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 6)]


def _parse_field(field, lo, hi):
    """Expand one cron field to a set of ints. Raises ValueError on bad input."""
    values = set()
    for part in field.split(','):
        step = 1
        if '/' in part:
            part, step_s = part.split('/', 1)
            step = int(step_s)
            if step < 1:
                raise ValueError('step must be >= 1')
        if part in ('*', ''):
            start, end = lo, hi
        elif '-' in part:
            a, b = part.split('-', 1)
            start, end = int(a), int(b)
        else:
            start = end = int(part)
        if start < lo or end > hi or start > end:
            raise ValueError(f'value out of range {lo}-{hi}')
        values.update(range(start, end + 1, step))
    return values


def validate_cron(expr):
    """Validate a standard 5-field cron expression. -> (ok, error)."""
    fields = expr.split()
    if len(fields) != 5:
        return False, 'expected 5 fields'
    try:
        for field, (lo, hi) in zip(fields, _CRON_BOUNDS):
            if not _parse_field(field, lo, hi):
                return False, 'empty field'
    except ValueError as e:
        return False, str(e)
    return True, ''


def next_cron_runs(expr, n=5, now=None):
    """Return the next `n` datetimes a 5-field cron expression fires.

    Minute-resolution forward scan, capped at ~4 years so an impossible
    expression (e.g. Feb 30) terminates instead of looping forever."""
    ok, err = validate_cron(expr)
    if not ok:
        raise ValueError(err)
    fields = expr.split()
    minutes = _parse_field(fields[0], 0, 59)
    hours   = _parse_field(fields[1], 0, 23)
    doms    = _parse_field(fields[2], 1, 31)
    months  = _parse_field(fields[3], 1, 12)
    dows    = _parse_field(fields[4], 0, 6)   # 0 = Sunday
    dom_restricted = fields[2] != '*'
    dow_restricted = fields[4] != '*'

    if now is None:
        now = _dt.datetime.now()
    t = now.replace(second=0, microsecond=0) + _dt.timedelta(minutes=1)

    out = []
    limit = 366 * 4 * 24 * 60
    steps = 0
    while len(out) < n and steps < limit:
        steps += 1
        if t.month in months and t.hour in hours and t.minute in minutes:
            # Cron quirk: when both DOM and DOW are restricted, a match on
            # *either* fires. When only one is restricted, that one must match.
            dom_ok = t.day in doms
            dow_ok = (t.weekday() + 1) % 7 in dows   # Python Mon=0 -> cron Sun=0
            if dom_restricted and dow_restricted:
                day_ok = dom_ok or dow_ok
            elif dom_restricted:
                day_ok = dom_ok
            elif dow_restricted:
                day_ok = dow_ok
            else:
                day_ok = True
            if day_ok:
                out.append(t)
        t += _dt.timedelta(minutes=1)
    return out


# ── #9: fleet anomaly detection ────────────────────────────────────────────────
ANOMALY_SYSTEM = (
    "You are an SRE reviewing a fleet snapshot. Identify genuine anomalies: "
    "hosts that stand out (resource spikes, offline, failed units, pending "
    "reboots, disks nearly full, suspicious ports). Ignore healthy hosts. "
    "Reply with ONLY a JSON array, most severe first; each item: "
    "{\"device\": \"<name>\", \"severity\": \"high|medium|low\", "
    "\"finding\": \"<short>\", \"why\": \"<one sentence>\"}. Empty array if "
    "nothing stands out."
)


def anomaly_prompt(fleet_summary):
    """fleet_summary: a compact text/JSON block the caller assembled."""
    return ANOMALY_SYSTEM, [{'role': 'user', 'content': str(fleet_summary)[:24000]}]


def parse_anomaly_response(text):
    data = extract_json(text)
    if not isinstance(data, list):
        return []
    out = []
    for item in data[:50]:
        if not isinstance(item, dict):
            continue
        sev = str(item.get('severity', 'low')).lower()
        if sev not in ('high', 'medium', 'low'):
            sev = 'low'
        out.append({
            'device':   str(item.get('device', ''))[:128],
            'severity': sev,
            'finding':  str(item.get('finding', ''))[:200],
            'why':      str(item.get('why', ''))[:400],
        })
    order = {'high': 0, 'medium': 1, 'low': 2}
    out.sort(key=lambda a: order.get(a['severity'], 3))
    return out


# ── #3: runbook suggestions ─────────────────────────────────────────────────
RUNBOOK_SYSTEM = (
    "You are a senior operator. Given an alert/issue and any retrieved "
    "context from this organization's own runbooks and docs, write a concise, "
    "actionable runbook to investigate and resolve it. Prefer the "
    "organization's own conventions when context is provided; otherwise give "
    "sound general Linux/ops steps. Use short numbered steps with exact "
    "commands. Note when a step is potentially destructive."
)


def runbook_prompt(trigger, retrieved_context=''):
    user = f"Issue:\n{trigger}\n"
    if retrieved_context:
        user += f"\nRetrieved context from our runbooks/docs:\n{retrieved_context}\n"
    user += "\nWrite the runbook."
    return RUNBOOK_SYSTEM, [{'role': 'user', 'content': user[:24000]}]


# ── #11: CMDB documentation drafts ───────────────────────────────────────────
DOCDRAFT_SYSTEM = (
    "You write infrastructure documentation (a CMDB asset page) from observed "
    "system state. Produce clean Markdown with sections: Overview, Hardware, "
    "Operating System & Kernel, Services & Open Ports, Containers, "
    "Notes/Risks. Be factual and concise — only state what the data supports. "
    "If a section has no data, write '_No data collected._'. This is a draft "
    "for a human to review and edit."
)


def docdraft_prompt(device_name, observed_state):
    user = (f"Device: {device_name}\n\nObserved state (JSON):\n"
            f"{observed_state}\n\nWrite the asset documentation in Markdown.")
    return DOCDRAFT_SYSTEM, [{'role': 'user', 'content': user[:24000]}]
