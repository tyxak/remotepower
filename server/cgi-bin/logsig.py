"""RemotePower — log-line signatures.

A log rule like ``err|warn|critical|FATAL`` matches a CLASS of lines, so the
same routine message re-fires the alert forever. The operator's only escapes
were "snooze it" (comes back) or "delete the rule" (goes blind). Neither is
what they mean, which is: *I have seen THIS line, stop telling me about it —
but still tell me about a new one.*

That needs a stable identity for "this line", which is what a signature is: the
line with its varying parts (timestamps, pids, ids, addresses, sizes, durations)
folded out, hashed. Two occurrences of the same message a day apart share a
signature; a genuinely different error does not.

Pure functions, no api imports — unit-testable and importable from anywhere.
"""

import hashlib
import re

# Deliberately ordered: the most specific shapes first, so a UUID isn't first
# chewed up into "a run of hex digits" and an IP isn't reduced to numbers.
_SUBS = (
    # ISO-8601 / syslog timestamps at any position
    (re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?'), '<ts>'),
    (re.compile(r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b'), '<ts>'),
    (re.compile(r'\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b'), '<ts>'),
    # UUIDs
    (re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
                r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'), '<uuid>'),
    # IPv4 (+ optional port) and the obvious IPv6 shapes
    (re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b'), '<ip>'),
    (re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b'), '<ip>'),
    # process ids in the classic `name[1234]:` prefix, and bare pid= forms
    (re.compile(r'\[\d+\]'), '[<pid>]'),
    (re.compile(r'\b(pid|ppid|tid|uid|gid|port|fd)=\d+', re.I), r'\1=<n>'),
    # long hex runs (hashes, request ids, memory addresses)
    (re.compile(r'\b(?:0x)?[0-9a-fA-F]{8,}\b'), '<hex>'),
    # byte sizes / durations / percentages, then any remaining number
    (re.compile(r'\b\d+(?:\.\d+)?\s?(?:[KMGT]i?B|bytes?|ms|s|m|h)\b', re.I), '<qty>'),
    (re.compile(r'\b\d+(?:\.\d+)?%'), '<pct>'),
    (re.compile(r'\b\d+(?:\.\d+)?\b'), '<n>'),
)

_WS = re.compile(r'\s+')
# `2026-07-22T15:46:37+02:00 host unit[123]: real message` — the journal prefix
# repeats on every line and carries no meaning for identity.
_SYSLOG_PREFIX = re.compile(
    r'^<ts>\s+\S+\s+[\w.@\-]+(?:\[<pid>\])?:\s*')


def normalize(line):
    """Fold a log line down to its invariant shape. Returns a string, safe to
    show an operator — it IS the human explanation of what got muted."""
    s = str(line or '')[:1000]
    for rx, rep in _SUBS:
        s = rx.sub(rep, s)
    s = _WS.sub(' ', s).strip()
    s = _SYSLOG_PREFIX.sub('', s, count=1)
    return s[:300]


def signature(line):
    """Stable short id for a log line's *shape*. Empty string for an empty line
    so a blank never silences anything."""
    norm = normalize(line)
    if not norm:
        return ''
    return hashlib.sha256(norm.encode('utf-8', 'replace')).hexdigest()[:16]


def ack_key(device_id, unit, sig):
    """Storage key for one acknowledgement.

    Scope is per (device, unit, signature) so muting noise on one host's
    php-fpm does not blind the same message on another host — that would be a
    fleet-wide silence nobody asked for. A deliberately fleet-wide ack passes
    an empty device_id.
    """
    return f'{device_id or "*"}|{unit or "*"}|{sig}'
