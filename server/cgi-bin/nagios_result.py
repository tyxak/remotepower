"""RemotePower — read the result of a monitoring plugin that follows the Nagios plugin convention.

A custom monitoring script can ask to be read as a plugin. Its exit code is then its state, and the first
line of its output is ``TEXT | perfdata``:

    exit code   state
    0           ok
    1           warning
    2           critical
    3 or other  unknown      (a script the agent could not run or that timed out is unknown too)

    DISK WARNING - free space: / 4012 MB (18%) | /=17988MB;19000;20000;0;22000 inodes=41%;80;90

That makes the thousands of existing plugins (``check_disk``, ``check_procs``, ``check_http``, an NRPE command,
a Sensu or Icinga check) runnable as they are. A script that does not ask keeps the older reading: exit 0 is
ok, anything else is a failure.

Pure and stdlib-only: no storage, no request context. Written from the convention's public description, which
fixes the exit codes and the ``'label'=value[UOM];warn;crit;min;max`` shape of performance data.
"""

import math

# The two ways a script's exit code is read.
MODE_EXIT = "exit"
MODE_NAGIOS = "nagios"
MODES = (MODE_EXIT, MODE_NAGIOS)

STATES = ("ok", "warning", "critical", "unknown")

MAX_PERF_ENTRIES = 20
MAX_LABEL = 64
MAX_THRESHOLD = 24
MAX_UOM = 12
MAX_TEXT = 240
# A value this large is a counter that wrapped or a mistake; 1e18 is far above any real reading and keeps the
# float arithmetic downstream (charts, Prometheus) well away from overflow.
MAX_ABS_VALUE = 1e18


def clean_mode(value):
    """The mode to store for what a client sent: ``nagios`` or the default ``exit``."""
    return MODE_NAGIOS if str(value or "").strip().lower() == MODE_NAGIOS else MODE_EXIT


def state_for(rc, mode):
    """The state a script's exit code means under ``mode``.

    Under ``exit`` there are two states, ok and critical, which is what the Checks page showed for a failing
    script before plugins were read this way. Under ``nagios`` the four states of the convention."""
    if isinstance(rc, bool) or not isinstance(rc, int):
        return "unknown" if mode == MODE_NAGIOS else "critical"
    if mode == MODE_NAGIOS:
        return {0: "ok", 1: "warning", 2: "critical"}.get(rc, "unknown")
    return "ok" if rc == 0 else "critical"


def stored_state(row):
    """The state a stored result row is in. A row written before states existed has only ``ok``, and a row edited by
    hand can hold anything, so the stored value counts only when it is one of the four words."""
    st = row.get("state") if isinstance(row, dict) else None
    if isinstance(st, str) and st in STATES:
        return st
    return "ok" if isinstance(row, dict) and row.get("ok") else "critical"


def _number(text):
    """A finite float from text, or None. ``U`` (unknown) and anything unreadable are None."""
    try:
        v = float(text)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(v) or abs(v) > MAX_ABS_VALUE:
        return None
    return v


def _tokens(perf):
    """Split performance data into its ``label=value;...`` items. Items are separated by spaces, except inside a
    label in single quotes (``'free space'=12MB``), where a doubled quote stands for one quote."""
    out, cur, quoted, i, n = [], [], False, 0, len(perf)
    while i < n:
        c = perf[i]
        if quoted:
            if c == "'":
                if i + 1 < n and perf[i + 1] == "'":
                    cur.append("'")
                    i += 2
                    continue
                quoted = False
            else:
                cur.append(c)
        elif c == "'" and not cur:
            quoted = True
        elif c in " \t":
            if cur:
                out.append("".join(cur))
                cur = []
        else:
            cur.append(c)
        i += 1
    if cur:
        out.append("".join(cur))
    return out


def _split_value(text):
    """``12.5MB`` -> (12.5, 'MB'); ``U`` -> (None, ''); unreadable -> (None, None)."""
    t = text.strip()
    if t == "U":
        return None, ""
    j = len(t)
    while j > 0 and not (t[j - 1].isdigit() or t[j - 1] == "."):
        j -= 1
    num, uom = t[:j], t[j:]
    v = _number(num)
    if v is None:
        return None, None
    return v, uom[:MAX_UOM]


def parse_perfdata(perf):
    """The performance data of one plugin result as a list of ``{label, value, uom, warn, crit, min, max}``.

    ``warn`` and ``crit`` keep the plugin's own range text (``10:20``, ``~:5``, ``@3``), because that is how a
    person reads them. ``value``, ``min`` and ``max`` are numbers or None. An item that cannot be read is left
    out, and at most MAX_PERF_ENTRIES are kept."""
    out = []
    # the labels are text from the host, so every cut below keeps the stored row small
    for tok in _tokens(str(perf or "")):
        label, eq, rest = tok.partition("=")
        label = label.strip()
        if not eq or not label:
            continue
        parts = rest.split(";")
        value, uom = _split_value(parts[0])
        if uom is None:
            continue
        entry = {
            "label": label[:MAX_LABEL],
            "value": value,
            "uom": uom,
            "warn": parts[1][:MAX_THRESHOLD] if len(parts) > 1 else "",
            "crit": parts[2][:MAX_THRESHOLD] if len(parts) > 2 else "",
            "min": _number(parts[3]) if len(parts) > 3 and parts[3] else None,
            "max": _number(parts[4]) if len(parts) > 4 and parts[4] else None,
        }
        out.append(entry)
        if len(out) >= MAX_PERF_ENTRIES:
            break
    return out


def parse_output(text):
    """Split a plugin's output into ``(status_text, perf)``.

    The status text is the first line before its ``|``. Performance data is whatever follows a ``|``, on the
    first line and on the lines after it (the convention lets long output carry more)."""
    lines = str(text or "").replace("\r", "").split("\n")
    status, perf_parts = "", []
    seen_first = False
    for ln in lines:
        head, bar, tail = ln.partition("|")
        if not seen_first:
            if not head.strip() and not bar:
                continue
            status = head.strip()[:MAX_TEXT]
            seen_first = True
        if bar:
            perf_parts.append(tail)
    return status, parse_perfdata(" ".join(perf_parts))
