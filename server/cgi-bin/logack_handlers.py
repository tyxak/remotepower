"""RemotePower — log-alert acknowledgements ("clear this line, not the rule")

A log rule matches a CLASS of lines, so one routine message re-fires its alert
forever. Snoozing brings it back; deleting the rule goes blind. What an
operator actually wants is: *this exact message is understood — stop paging me
about it, but still page me about a new one.*

An acknowledgement stores the SIGNATURE of a matched line (see logsig.py: the
line with timestamps/pids/ids folded out). At fire time the matched lines are
filtered through the acks; if what remains is under the rule's threshold, the
alert does not fire at all. A genuinely different error has a different
signature and comes straight through.

Bound-module carve-out following the tls_ct_handlers / dmarc_handlers pattern:
api.py execs a private instance and binds its own ``globals()``, so every api
service is reached as ``A.<name>`` (a DYNAMIC lookup, which keeps the suite's
monkeypatching of api.respond / api.save working and resolves identically under
the __main__ and imported-module models). Calls BETWEEN these functions also go
through ``A.`` so a test that patches one is seen by its caller.
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


import re as _re
import time

import logsig

# v6.4.0 (field bug): the dashboard Needs-Attention "Clear line" button escapes
# the matched line with the frontend's escAttr(), which encodes " ' & < > ` \
# and newlines as literal `\xNN` sequences. The browser does NOT decode those
# when the attribute is read back (they're a JS-string escape, not an HTML
# entity), so the line arrived here with `\x22` where it had a real quote — and
# a signature computed on that mangled text can NEVER match the real line the
# rule keeps matching (dockerd logs are full of `"`), so the clear silently
# never took. Decode it back before signing. No-op for the Alerts-inbox path
# (escHtml → real chars, no `\xNN`), and safe for a literal `\xNN` in a real
# line (escAttr escapes the backslash → `\x5c`, so it round-trips).
_ATTR_ESC_RE = _re.compile(r'\\x([0-9a-fA-F]{2})')


def _unescape_attr(s):
    return _ATTR_ESC_RE.sub(lambda m: chr(int(m.group(1), 16)), s or '')

MAX_LOG_ACKS = 2000          # bounded store; oldest-first eviction
ACK_EXPIRY_MAX_DAYS = 365


# ── read side (used by the hot fire path — keep it cheap) ────────────────────
def _log_acks():
    """{key: entry} of live acknowledgements, expired ones dropped.

    Read through _load_ro: the fire path calls this per heartbeat and must not
    pay a deepcopy of the whole store. Callers MUST NOT mutate the result.
    """
    store = (A._load_ro(A.LOG_ACKS_FILE) or {}).get('acks') or {}
    if not isinstance(store, dict):
        return {}
    now = int(time.time())
    return {k: v for k, v in store.items()
            if isinstance(v, dict) and not (v.get('until') and v['until'] < now)}


def _ack_hit(acks, device_id, unit, sig):
    """The ack covering this line, or None. Checks the specific (device, unit)
    scope first, then the wider fleet-wide / any-unit forms."""
    if not sig:
        return None
    for did, u in ((device_id, unit), (device_id, ''), ('', unit), ('', '')):
        e = acks.get(logsig.ack_key(did, u, sig))
        if e:
            return e
    return None


def filter_acked_lines(device_id, unit, lines):
    """(kept, suppressed_count) — drop matched lines an operator has cleared.

    The suppressed count is returned rather than thrown away so the alert (and
    the rule's row on the Logs page) can say "3 hits, 2 cleared" instead of
    silently under-reporting, which would look like a broken rule.
    """
    if not lines:
        return list(lines or []), 0
    acks = A._log_acks()
    if not acks:
        return list(lines), 0
    kept, hits = [], 0
    for ln in lines:
        if A._ack_hit(acks, device_id, unit, logsig.signature(ln)):
            hits += 1
        else:
            kept.append(ln)
    if hits:
        A._bump_ack_hits(device_id, unit, lines)
    return kept, hits


def rule_acked(device_id, unit, pattern):
    """True if the operator silenced this whole RULE on this unit/host.

    Checked before a rule is evaluated, so a silenced rule costs nothing and
    fires nothing. Distinct from a line acknowledgement: this hides future
    DIFFERENT messages too, which is why the UI labels it separately.
    """
    key = logsig.rule_key(pattern)
    if not key:
        return False
    return A._ack_hit(A._log_acks(), device_id, unit, key) is not None


def _bump_ack_hits(device_id, unit, lines):
    """Record that acks are still catching traffic, so the management view can
    show which ones are doing work and which have gone stale (a line cleared a
    year ago that never recurred is a candidate for cleanup).

    Best-effort and non-blocking: this is bookkeeping on the heartbeat path and
    must never fail a heartbeat or wait on a contended lock.
    """
    try:
        with A._LockedUpdate(A.LOG_ACKS_FILE, non_blocking=True) as store:
            acks = store.setdefault('acks', {})
            now = int(time.time())
            for ln in lines:
                sig = logsig.signature(ln)
                if not sig:
                    continue
                for did, u in ((device_id, unit), (device_id, ''), ('', unit), ('', '')):
                    e = acks.get(logsig.ack_key(did, u, sig))
                    if isinstance(e, dict):
                        e['hits'] = int(e.get('hits', 0) or 0) + 1
                        e['last_hit'] = now
                        break
    except Exception:
        pass


# ── handlers ─────────────────────────────────────────────────────────────────
def handle_log_acks_list():
    """GET /api/logs/acks — every live acknowledgement the caller can see.

    Scoped through _scope_filter_devices; fleet-wide acks (no device) are
    visible to anyone who can read logs, since that is what they affect.
    """
    A.require_auth()
    devs = A._scope_filter_devices(A.load(A.DEVICES_FILE) or {})
    names = {d: (v.get('name') or d) for d, v in devs.items() if isinstance(v, dict)}
    out = []
    for key, e in (A._log_acks() or {}).items():
        did = str(e.get('device_id') or '')
        if did and did not in names:
            continue                       # another tenant's / out-of-scope host
        out.append({
            'key': key, 'device_id': did,
            'device': names.get(did, '') if did else 'whole fleet',
            'unit': e.get('unit') or 'any unit',
            'sample': e.get('sample') or '', 'norm': e.get('norm') or '',
            'kind': e.get('kind') or 'line', 'pattern': e.get('pattern') or '',
            'note': e.get('note') or '', 'by': e.get('by') or '',
            'ts': int(e.get('ts', 0) or 0), 'until': int(e.get('until', 0) or 0),
            'hits': int(e.get('hits', 0) or 0),
            'last_hit': int(e.get('last_hit', 0) or 0),
        })
    out.sort(key=lambda x: x['ts'], reverse=True)
    A.respond(200, {'acks': out, 'max': MAX_LOG_ACKS})


def handle_log_ack_add():
    """POST /api/logs/ack {line, device_id, unit, scope, note, days} — clear one
    matched log line for good (or for `days`).

    `line` is the raw matched text; the signature is derived server-side, so a
    client can never post a signature to silence something it never saw.
    """
    actor = A.require_write_role('manage log rules')
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A.get_json_obj()
    line = _unescape_attr(str(body.get('line', ''))[:2000])
    # Two shapes. A LINE acknowledgement is precise: this exact message, a new
    # one still fires. A RULE acknowledgement is the coarse escape for an alert
    # that captured no line — it silences the whole pattern on that unit, so it
    # is only offered where the precise option genuinely cannot be built.
    rule_pattern = _unescape_attr(str(body.get('pattern', ''))[:500])
    sig = logsig.signature(line) if line else logsig.rule_key(rule_pattern)
    if not sig:
        A.respond(400, {'error': 'line or pattern is required'})
    did = A._sanitize_str(str(body.get('device_id', '')), 64).strip()
    unit = A._sanitize_str(str(body.get('unit', '')), 128).strip()
    # 'fleet' widens the ack to every host; 'anyunit' keeps the host, any unit.
    scope = str(body.get('scope', 'device')).strip().lower()
    if scope == 'fleet':
        did = ''
    elif scope == 'anyunit':
        unit = ''
    if did:
        A._scope_block_device(did)        # 403s a device the caller can't see
    elif not A._resolve_role(A._caller_role()).get('admin'):
        # A fleet-wide silence is a fleet-wide decision.
        A.respond(403, {'error': 'a fleet-wide acknowledgement requires an admin'})
    try:
        days = int(body.get('days') or 0)
    except (TypeError, ValueError):
        days = 0
    days = max(0, min(ACK_EXPIRY_MAX_DAYS, days))
    now = int(time.time())
    entry = {
        'device_id': did, 'unit': unit, 'sig': sig,
        'kind': 'line' if line else 'rule',
        'pattern': rule_pattern if not line else '',
        'sample': line[:300] if line else f'whole rule: {rule_pattern}'[:300],
        'norm': logsig.normalize(line) if line else f'every line matching {rule_pattern}'[:300],
        'note': A._sanitize_str(str(body.get('note', '')), 200),
        'by': actor, 'ts': now, 'until': now + days * 86400 if days else 0,
        'hits': 0, 'last_hit': 0,
    }
    key = logsig.ack_key(did, unit, sig)
    with A._LockedUpdate(A.LOG_ACKS_FILE) as store:
        acks = store.setdefault('acks', {})
        acks[key] = entry
        if len(acks) > MAX_LOG_ACKS:
            for k in sorted(acks, key=lambda k: int((acks[k] or {}).get('ts', 0) or 0)
                            )[:len(acks) - MAX_LOG_ACKS]:
                acks.pop(k, None)
    A.audit_log(actor, 'log_ack_add', f'device={did or "*"} unit={unit or "*"} sig={sig}')
    # Close what is already open for this line, so acknowledging it clears the
    # board instead of leaving behind the very row that prompted it.
    resolved = A._resolve_log_alerts_for_signature(did, unit, sig, actor)
    A.respond(200, {'ok': True, 'key': key, 'norm': entry['norm'],
                    'resolved': resolved})


def handle_log_ack_delete():
    """POST /api/logs/ack/delete {key} — un-mute; the line alerts again."""
    actor = A.require_write_role('manage log rules')
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    key = A._sanitize_str(str(A.get_json_obj().get('key', '')), 200).strip()
    if not key:
        A.respond(400, {'error': 'key is required'})
    did = key.split('|', 1)[0]
    if did and did != '*':
        A._scope_block_device(did)
    elif not A._resolve_role(A._caller_role()).get('admin'):
        A.respond(403, {'error': 'a fleet-wide acknowledgement requires an admin'})
    with A._LockedUpdate(A.LOG_ACKS_FILE) as store:
        if not (store.get('acks') or {}).pop(key, None):
            A.respond(404, {'error': 'acknowledgement not found'})
    A.audit_log(actor, 'log_ack_delete', f'key={key}')
    A.respond(200, {'ok': True})


def _resolve_log_alerts_for_signature(device_id, unit, sig, actor):
    """Resolve open log_alert rows whose captured evidence matches this
    signature. Returns how many were closed.

    Without this, clearing a line leaves the alert that prompted it sitting in
    the inbox — the operator would have to acknowledge the same thing twice,
    which is exactly the friction this feature exists to remove.
    """
    n = 0
    now = int(time.time())
    try:
        with A._LockedUpdate(A.ALERTS_FILE) as store:
            for a in store.get('alerts') or []:
                if not isinstance(a, dict) or a.get('event') != 'log_alert':
                    continue
                if a.get('resolved_at'):
                    continue
                p = a.get('payload') or {}
                if device_id and str(a.get('device_id') or '') != device_id:
                    continue
                if unit and str(p.get('unit') or '') != unit:
                    continue
                samples = p.get('sample') or []
                if isinstance(samples, str):
                    samples = [samples]
                if not any(logsig.signature(s) == sig for s in samples):
                    continue
                a['resolved_at'] = now
                a['resolved_by'] = actor
                a['resolution'] = 'acknowledged — log line cleared'
                n += 1
    except Exception:
        return n
    return n
