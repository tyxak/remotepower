"""RemotePower — business services: the pure part.

A business service is a name for something people depend on ("Checkout", "Office network", "Mail") and the
things it is made of: hosts, monitors, systemd units, containers, the result of a custom script, or another
business service. A rule says how the parts add up:

    all   every part has to be up (a chain: the web server AND the database AND the cache)
    any   one part is enough (redundancy: either of two load balancers)
    min   at least N parts have to be up (a quorum: two of three database nodes)

The state of a service is one of ok, unknown, warning, critical. A part that is down but not needed makes the
service *warning* (degraded), not critical, so a redundant pair that lost one member shows what it is.

Pure and stdlib-only: no storage, no request context, so every rule here is tested without a server. Where the
state of each part comes from (devices, monitors, services, containers, scripts) is the handlers' business.
"""

# worst last: a comparison of two states is a comparison of these numbers
RANK = {"ok": 0, "unknown": 1, "warning": 2, "critical": 3}
STATES = tuple(sorted(RANK, key=lambda k: RANK[k]))

RULE_ALL, RULE_ANY, RULE_MIN = "all", "any", "min"
RULES = (RULE_ALL, RULE_ANY, RULE_MIN)

KIND_HOST, KIND_MONITOR, KIND_UNIT, KIND_CONTAINER, KIND_SCRIPT, KIND_SERVICE = (
    "host",
    "monitor",
    "unit",
    "container",
    "script",
    "service",
)
KINDS = (KIND_HOST, KIND_MONITOR, KIND_UNIT, KIND_CONTAINER, KIND_SCRIPT, KIND_SERVICE)

MAX_MEMBERS = 50
MAX_SERVICES = 100
MAX_NAME = 80
MAX_DESC = 256
MAX_FIELD = 128
# How a nested service may go: a service of services of services is read, but a chain this long is a mistake
MAX_DEPTH = 5

# What each kind of part is identified by. A host-bound part carries the host's id, so the handlers can hide a
# service from a caller who cannot see one of its hosts.
_FIELDS = {
    KIND_HOST: ("device_id",),
    KIND_MONITOR: ("label",),
    KIND_UNIT: ("device_id", "unit"),
    KIND_CONTAINER: ("device_id", "name"),
    KIND_SCRIPT: ("device_id", "script_id"),
    KIND_SERVICE: ("service_id",),
}


def worst(states):
    """The worst of some states; ``unknown`` for none."""
    worst_state = None
    for s in states:
        if (
            isinstance(s, str)
            and s in RANK
            and (worst_state is None or RANK[s] > RANK[worst_state])
        ):
            worst_state = s
    return worst_state or "unknown"


def clean_rule(raw):
    """A rule as it is stored: ``{"type": "all"}``, ``{"type": "any"}`` or ``{"type": "min", "min": N}``.
    Anything unreadable is the strictest rule, ``all``."""
    if not isinstance(raw, dict):
        return {"type": RULE_ALL}
    t = raw.get("type")
    if t == RULE_ANY:
        return {"type": RULE_ANY}
    if t == RULE_MIN:
        n = raw.get("min")
        if (
            isinstance(n, bool)
            or not isinstance(n, (int, float))
            or n != n
            or n in (float("inf"), float("-inf"))
        ):
            n = 1
        return {"type": RULE_MIN, "min": max(1, min(MAX_MEMBERS, int(n)))}
    return {"type": RULE_ALL}


def evaluate(rule, states):
    """The state of a service whose parts are in ``states``, under ``rule``."""
    states = [s if isinstance(s, str) and s in RANK else "unknown" for s in states]
    if not states:
        return "unknown"
    total = len(states)
    up = sum(1 for s in states if s == "ok")
    r = clean_rule(rule)
    if up == total:
        return "ok"
    if r["type"] == RULE_ANY:
        return "warning" if up >= 1 else worst(states)
    if r["type"] == RULE_MIN:
        need = min(r["min"], total)
        if up >= need:
            return "warning"
        return "critical" if "critical" in states else worst(states)
    return worst(states)


def clean_member(raw):
    """A part as it is stored, or None when it cannot be read. Only the fields of its kind are kept."""
    if not isinstance(raw, dict):
        return None
    kind = raw.get("kind")
    if kind not in _FIELDS:
        return None
    out = {"kind": kind}
    for f in _FIELDS[kind]:
        v = raw.get(f)
        if not isinstance(v, str):
            return None
        v = "".join(ch for ch in v if ch >= " " and ch != "\x7f").strip()
        if not v or len(v) > MAX_FIELD:
            return None
        out[f] = v
    return out


def clean_members(raw):
    """The readable parts of a list, without repeats, at most MAX_MEMBERS."""
    out, seen = [], set()
    for item in raw if isinstance(raw, list) else []:
        m = clean_member(item)
        if m is None:
            continue
        key = member_key(m)
        if key in seen:
            continue
        seen.add(key)
        out.append(m)
        if len(out) >= MAX_MEMBERS:
            break
    return out


def member_key(m):
    """A stable text for a part, to tell two apart and to key a state on."""
    return "|".join([m["kind"]] + [m[f] for f in _FIELDS[m["kind"]]])


def device_ids(members):
    """The ids of the hosts that the parts of a service sit on."""
    out = []
    for m in members:
        d = m.get("device_id")
        if d and d not in out:
            out.append(d)
    return out


def find_cycle(services):
    """The first cycle among services that contain services, as a list of ids that starts and ends on the same id,
    or None. ``services`` maps an id to its list of parts."""
    color, stack = {}, []

    def dfs(sid):
        color[sid] = 1
        stack.append(sid)
        for m in services.get(sid) or []:
            if m.get("kind") != KIND_SERVICE:
                continue
            nxt = m.get("service_id")
            if nxt not in services:
                continue
            if color.get(nxt) == 1:
                return stack[stack.index(nxt) :] + [nxt]
            if color.get(nxt) is None:
                found = dfs(nxt)
                if found:
                    return found
        stack.pop()
        color[sid] = 2
        return None

    for sid in services:
        if color.get(sid) is None:
            found = dfs(sid)
            if found:
                return found
    return None


def depth(services, sid, _seen=None):
    """How many levels of services below ``sid`` there are, counting itself as 1. A cycle counts as MAX_DEPTH + 1."""
    seen = _seen or set()
    if sid in seen:
        return MAX_DEPTH + 1
    seen = seen | {sid}
    below = [
        depth(services, m["service_id"], seen)
        for m in services.get(sid) or []
        if m.get("kind") == KIND_SERVICE and m.get("service_id") in services
    ]
    return 1 + (max(below) if below else 0)


def availability(transitions, now, window, current):
    """The share of the last ``window`` seconds a service was not critical, as a percent, or None when nothing is
    known for that window.

    ``transitions`` is a list of ``{"ts": t, "state": s}`` in time order: the state the service moved to at t.
    ``current`` is the state it is in now. A degraded service is up, because it still serves; critical is down;
    unknown is left out (it is not known to be up or down)."""
    start = now - window
    pts = [
        (t["ts"], t["state"])
        for t in transitions
        if isinstance(t, dict) and isinstance(t.get("ts"), (int, float)) and t.get("state") in RANK
    ]
    pts.sort(key=lambda p: p[0])
    # the state at the start of the window is the last transition before it
    state_at_start = None
    for ts, st in pts:
        if ts <= start:
            state_at_start = st
        else:
            break
    segs, cursor, cur = [], start, state_at_start
    for ts, st in pts:
        if ts <= start:
            continue
        if ts >= now:
            break
        if cur is not None:
            segs.append((cursor, ts, cur))
        cursor, cur = ts, st
    if cur is None and not segs:
        cur = current if current in RANK else None
        if cur is None:
            return None
        # nothing recorded in the window: the state it is in now is the best guess for all of it
        cursor = start
    if cur is not None:
        segs.append((cursor, now, cur))
    known = [(a, b, s) for a, b, s in segs if s != "unknown" and b > a]
    total = sum(b - a for a, b, _s in known)
    if total <= 0:
        return None
    up = sum(b - a for a, b, s in known if s != "critical")
    return round(100.0 * up / total, 2)
