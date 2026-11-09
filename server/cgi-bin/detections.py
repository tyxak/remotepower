"""RemotePower: detections (8.0.0): behaviour read from what the agents already report.

A signature exists only after someone has seen the threat. These rules look at what a host DOES, so a zero-day, a freshly weaponised exploit or a tool nobody has named yet
shows by its effect: a shell holding a connection to the Internet, a database reaching out to an address it never used, a new open port that a stranger is already
connected to, a way back in followed by a new destination, an address a host called that Threat Intel marks as bad later. Nothing here collects anything. The rules read
the Traffic samples (the Linux agent's `ss` sample and the addresses a host has used), the fleet events (a new SSH key, a new open port, a burst of failed logins, a login
from a new source) and what Threat Intel knows about an address.

Pure functions: no file, no clock, no network. `detections_handlers` gathers one host's context, calls `evaluate`, and raises an alert for each finding that is not already
one. A rule that cannot be evaluated (a missing record, a row of the wrong kind) finds nothing; a detection must never fail the sweep that carries it.
"""

from __future__ import annotations

from typing import Any, Callable

import traffic as T

HOUR = 3600
DAY = 86400
MAX_PER_HOST = 5  # findings one host shows, and raises in one sweep, the worst first
EVENT_LOOKBACK_S = DAY  # how far back the sweep reads a host's events
KEEP_S = 7 * DAY  # how long a raised finding is remembered; no repeat interval is longer
EVIDENCE_KEYS = 12  # facts kept with a stored finding
TEXT_MAX = 120  # characters kept of a text fact

# What a program name means. A shell, or a network tool, that itself holds an established connection to the Internet is what a reverse shell looks like. The names are the
# process names `ss` reports (the kernel's `comm`), lower case.
SHELLS = frozenset({"bash", "sh", "dash", "zsh", "ash", "ksh", "csh", "tcsh", "fish"})
NET_TOOLS = frozenset(
    {"nc", "ncat", "netcat", "socat", "telnet"}
)  # busybox is left out: a container's wget and its health checks run under that name
# Programs that answer other programs and have no business starting a connection of their own to an address they never used: databases, caches, mail storage and the SSH
# server (a forwarded port is the one routine reason, and it is rare). Web servers, PHP, DNS and FTP are left out: OCSP lookups, upstream calls, recursion and active-mode
# data connections all start connections to new addresses every week.
SERVICES = frozenset(
    {
        "mysqld",
        "mariadbd",
        "postgres",
        "mongod",
        "mongos",
        "redis-server",
        "redis-sentinel",
        "memcached",
        "dovecot",
        "sshd",
    }
)
# Programs that fetch updates and the time. They reach a new mirror or a new CDN address most days, so they do not count as "a new destination" after a way back in.
ROUTINE = frozenset(
    {
        "apt",
        "apt-get",
        "http",
        "https",
        "dnf",
        "yum",
        "zypper",
        "pacman",
        "snapd",
        "packagekitd",
        "fwupd",
        "chronyd",
        "ntpd",
        "systemd-timesyn",
        "unattended-upgr",
        "flatpak",
    }
)
# What a person leaves behind to come back: a new SSH key, an account with no password, a changed firewall.
PERSISTENCE_EVENTS = frozenset({"ssh_key_added", "empty_password_account", "firewall_changed"})
OPEN_PORT_EVENTS = frozenset({"new_port_detected", "port_exposed_world"})
LOGIN_EVENTS = frozenset({"brute_force_detected", "login_new_source"})
EVENT_NAMES = (
    PERSISTENCE_EVENTS | OPEN_PORT_EVENTS | LOGIN_EVENTS
)  # the fleet events the sweep reads for a host

# id -> title, why it matters, the severity it raises at most, what it reads, and {parameter: (default, lowest, highest, label)}
RULES: dict[str, dict[str, Any]] = {
    "interpreter_egress": {
        "title": "A shell or network tool talks to the Internet",
        "why": "A shell, nc or socat holding a connection of its own to a public address is how a reverse shell looks, whatever the exploit that started it.",
        "severity": "high",
        "needs": ("Traffic",),
        "params": {},
    },
    "service_new_destination": {
        "title": "A database or SSH server connects to a new address",
        "why": "A database, a cache or the SSH server calling an address the host never used, after its first hour, is what a stolen credential or a webshell does first.",
        "severity": "medium",
        "needs": ("Traffic",),
        "params": {},
    },
    "known_bad_contact": {
        "title": "A host calls an address Threat Intel marks as bad",
        "why": "An address can turn bad after a host used it. This looks again at every address a host called and tells you when one now scores high or has attacked you.",
        "severity": "high",
        "needs": ("Traffic", "Threat Intel"),
        "params": {
            "min_score": (75, 1, 100, "Lowest score that counts"),
            "days": (14, 1, 90, "Days an attack counts"),
        },
    },
    "persistence_then_egress": {
        "title": "A way back in, then a new destination",
        "why": "A new SSH key, an account with no password or a changed firewall, followed soon by a first connection to a new address, is what a takeover looks like.",
        "severity": "high",
        "needs": ("Traffic", "Events"),
        "params": {"hours": (2, 1, 24, "Hours between the two")},
    },
    "bruteforce_then_login": {
        "title": "Password guessing, then a login from a new address",
        "why": "A burst of failed logins followed by a first login from a new address may be the guess that worked. The same address in both is the strongest sign.",
        "severity": "critical",
        "needs": ("Events",),
        "params": {"hours": (1, 1, 24, "Hours between the two")},
    },
    "exposed_port_in_use": {
        "title": "A new open port is already used from the Internet",
        "why": "A port that was not open before and already has a public address connected to it is a service somebody started and somebody else found.",
        "severity": "medium",
        "needs": ("Traffic", "Events"),
        "params": {"hours": (6, 1, 48, "Hours after the port opened")},
    },
}
ORDER = tuple(RULES)
RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def settings(stored: Any) -> dict[str, dict[str, Any]]:
    """Each rule's `enabled` and parameters: what the administrator stored, held to the allowed range, over the defaults. A value that is not a whole number in range (or a
    flag that is not a boolean) is the default, and an unknown rule or parameter is dropped, so a damaged config can never switch a rule's meaning.
    """
    stored = stored if isinstance(stored, dict) else {}
    out: dict[str, dict[str, Any]] = {}
    for rid, spec in RULES.items():
        mine = stored.get(rid) if isinstance(stored.get(rid), dict) else {}
        row: dict[str, Any] = {
            "enabled": mine.get("enabled") if isinstance(mine.get("enabled"), bool) else True
        }
        for name, (dflt, lo, hi, _label) in spec["params"].items():
            v = mine.get(name)
            row[name] = (
                v if isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi else dflt
            )
        out[rid] = row
    return out


def clean_update(raw: Any) -> tuple[dict[str, dict[str, Any]], str]:
    """What an administrator may change: ({rule: {enabled?, parameter?}}, error). Refuses an unknown rule or parameter, a value out of range and a flag that is not true or
    false, naming the first one; nothing is kept from a refused document."""
    if not isinstance(raw, dict) or not raw:
        return {}, "rules must be an object of rule ids"
    out: dict[str, dict[str, Any]] = {}
    for rid, body in raw.items():
        if rid not in RULES:
            return {}, f"unknown rule: {str(rid)[:60]}"
        if not isinstance(body, dict) or not body:
            return {}, f"{rid}: give enabled or a parameter"
        row: dict[str, Any] = {}
        for name, v in body.items():
            if name == "enabled":
                if not isinstance(v, bool):
                    return {}, f"{rid}.enabled must be true or false"
                row[name] = v
            elif name in RULES[rid]["params"]:
                _d, lo, hi, _label = RULES[rid]["params"][name]
                if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
                    return {}, f"{rid}.{name} must be a whole number from {lo} to {hi}"
                row[name] = v
            else:
                return {}, f"{rid}: unknown setting {str(name)[:60]}"
        out[rid] = row
    return out, ""


def merged(stored: Any, update: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """The settings document after `update` (from clean_update) is applied: every rule's full row, so a saved document never depends on a default that moves later."""
    now = settings(stored)
    for rid, row in update.items():
        now[rid].update(row)
    return now


def catalog(stored: Any) -> list[dict[str, Any]]:
    """The rules as the page lists them: id, title, why, severity, what it reads, whether it is on and each parameter with its value, default and limits."""
    now = settings(stored)
    return [
        {
            "id": rid,
            "title": RULES[rid]["title"],
            "why": RULES[rid]["why"],
            "severity": RULES[rid]["severity"],
            "needs": list(RULES[rid]["needs"]),
            "enabled": now[rid]["enabled"],
            "params": [
                {
                    "name": name,
                    "label": label,
                    "value": now[rid][name],
                    "default": dflt,
                    "min": lo,
                    "max": hi,
                }
                for name, (dflt, lo, hi, label) in RULES[rid]["params"].items()
            ],
        }
        for rid in ORDER
    ]


# ── helpers ──────────────────────────────────────────────────────────────────


def _prog(name: Any) -> str:
    """The program name as `ss` gave it, lower case, without a path."""
    s = str(name or "").strip().lower()
    return s.rsplit("/", 1)[-1].split(" ", 1)[0]


def _public(ip: Any) -> bool:
    return T.scope_of(ip) == "public"


def _num(v: Any) -> float | None:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and v == v else None


def _int(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _dict(v: Any) -> dict[str, Any]:
    """`v` when it is a map, else an empty one: a stored record can hold anything, and a call such as ctx.get() cannot be narrowed by isinstance in place."""
    return v if isinstance(v, dict) else {}


def _where(ctx: dict[str, Any]) -> str:
    host = _dict(ctx.get("host"))
    return str(host.get("name") or host.get("id") or "the host")


def _rows(ctx: dict[str, Any], direction: str | None = None) -> list[dict[str, Any]]:
    rows = [
        r for r in (ctx.get("rows") or []) if isinstance(r, dict) and isinstance(r.get("ip"), str)
    ]
    return [r for r in rows if direction is None or r.get("d") == direction]


def _events(ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """The host's events that are usable: a name, a whole-number time and the payload as a map."""
    out = []
    for e in ctx.get("events") or []:
        if (
            not isinstance(e, dict)
            or not isinstance(e.get("event"), str)
            or _int(e.get("ts")) is None
        ):
            continue
        out.append({"event": e["event"], "ts": e["ts"], "payload": _dict(e.get("payload"))})
    return out


def _recent(ctx: dict[str, Any], names: frozenset[str], hours: int) -> list[dict[str, Any]]:
    now = _int(ctx.get("now")) or 0
    return sorted(
        (e for e in _events(ctx) if e["event"] in names and 0 <= now - e["ts"] <= hours * HOUR),
        key=lambda e: e["ts"],
    )


def _finding(
    rule: str,
    ctx: dict[str, Any],
    subject: str,
    severity: str,
    detail: str,
    repeat_s: int,
    **extra: Any,
) -> dict[str, Any]:
    """One finding. `key` names it for good (the same thing found again has the same key); `repeat_s` is how long after it was raised it may be raised again."""
    host = _dict(ctx.get("host"))
    out = {
        "rule": rule,
        "key": f"{rule}:{host.get('id', '')}:{subject}"[:200],
        "severity": severity,
        "detail": detail[:300],
        "repeat_s": min(repeat_s, KEEP_S),
    }
    out.update({k: v for k, v in extra.items() if v not in (None, "")})
    return out


# ── the rules ────────────────────────────────────────────────────────────────


def interpreter_egress(ctx: dict[str, Any], p: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for r in _rows(ctx, "out"):
        if not _public(r["ip"]):
            continue
        prog = _prog(r.get("proc"))
        sev = "high" if prog in SHELLS else "medium" if prog in NET_TOOLS else ""
        if sev:
            out.append(
                _finding(
                    "interpreter_egress",
                    ctx,
                    f"{prog}|{r['ip']}",
                    sev,
                    f"{prog} on {_where(ctx)} is connected to {r['ip']}:{r.get('port')}",
                    6 * HOUR,
                    ip=r["ip"],
                    port=r.get("port"),
                    process=prog,
                    evidence={
                        "connections": r.get("n"),
                        "sent": r.get("tx"),
                        "received": r.get("rx"),
                    },
                )
            )
    return out


def service_new_destination(ctx: dict[str, Any], p: dict[str, Any]) -> list[dict[str, Any]]:
    rec, now, out = ctx.get("rec"), _int(ctx.get("now")) or 0, []
    for r in _rows(ctx, "out"):
        prog = _prog(r.get("proc"))
        if prog not in SERVICES or not _public(r["ip"]) or not T.is_new(rec, r["ip"], now):
            continue
        out.append(
            _finding(
                "service_new_destination",
                ctx,
                f"{prog}|{r['ip']}",
                "medium",
                f"{prog} on {_where(ctx)} connected to {r['ip']}:{r.get('port')}, an address the host never used before",
                DAY,
                ip=r["ip"],
                port=r.get("port"),
                process=prog,
                evidence={
                    "sent": r.get("tx"),
                    "received": r.get("rx"),
                    "first_used": _int(_dict(_dict(rec).get("seen")).get(r["ip"])),
                },
            )
        )
    return out


def _bad(
    intel: dict[str, Any], ip: str, min_score: int, horizon: int
) -> tuple[bool, str, dict[str, Any]]:
    """(is it bad, why in words, the evidence) for one address, from the Threat Intel entry {score, last}: a score at or over the line, or an attack on this installation after
    `horizon`."""
    v = _dict(intel.get(ip))
    score, last = _num(v.get("score")), _int(v.get("last"))
    scored = score is not None and score >= min_score
    attacked = last is not None and last >= horizon
    why = []
    if scored and score is not None:
        why.append(f"scores {int(score)} at Threat Intel")
    if attacked:
        why.append("has attacked this installation lately")
    return (scored or attacked), " and ".join(why), {"score": score, "attacked": attacked}


def known_bad_contact(ctx: dict[str, Any], p: dict[str, Any]) -> list[dict[str, Any]]:
    """Two looks at the addresses a host CALLED (outbound only: a server is visited by scanners all day, and the brute-force alerts already name them). The rows connected now
    are high; an address the host used earlier, that has since been marked, is medium."""
    now = _int(ctx.get("now")) or 0
    intel = _dict(ctx.get("intel"))
    seen_out = _dict(_dict(ctx.get("rec")).get("seen_out"))
    horizon = now - p["days"] * DAY
    out, live = [], set()
    for r in _rows(ctx, "out"):
        ip = r["ip"]
        live.add(ip)
        bad, why, ev = _bad(intel, ip, p["min_score"], horizon) if _public(ip) else (False, "", {})
        if bad:
            out.append(
                _finding(
                    "known_bad_contact",
                    ctx,
                    ip,
                    "high",
                    f"{_where(ctx)} is connected to {ip}, which {why}",
                    6 * HOUR,
                    ip=ip,
                    port=r.get("port"),
                    process=_prog(r.get("proc")),
                    evidence={**ev, "connected": True},
                )
            )
    for ip, first in sorted(seen_out.items()):
        if ip in live or not isinstance(ip, str) or _int(first) is None or not _public(ip):
            continue
        bad, why, ev = _bad(intel, ip, p["min_score"], horizon)
        if bad:
            days = max(0, (now - first) // DAY)
            out.append(
                _finding(
                    "known_bad_contact",
                    ctx,
                    ip,
                    "medium",
                    f"{_where(ctx)} first called {ip} {days} day{'s' if days != 1 else ''} ago; the address {why}",
                    7 * DAY,
                    ip=ip,
                    evidence={**ev, "connected": False, "first_used": first},
                )
            )
    return out


def persistence_then_egress(ctx: dict[str, Any], p: dict[str, Any]) -> list[dict[str, Any]]:
    rec, now = ctx.get("rec"), _int(ctx.get("now")) or 0
    events = _recent(ctx, PERSISTENCE_EVENTS, p["hours"])
    seen = _dict(_dict(rec).get("seen"))
    out: list[dict[str, Any]] = []
    if not events:
        return out
    for r in _rows(ctx, "out"):
        ip, prog = r["ip"], _prog(r.get("proc"))
        first = _int(seen.get(ip))
        if prog in ROUTINE or first is None or not _public(ip) or not T.is_new(rec, ip, now):
            continue
        e = next(
            (e for e in events if 0 <= first - e["ts"] <= p["hours"] * HOUR), None
        )  # the first way back in that came shortly before the first use of the address
        if e is None:
            continue
        out.append(
            _finding(
                "persistence_then_egress",
                ctx,
                f"{e['event']}|{e['ts']}|{ip}",
                "high",
                f"{e['event'].replace('_', ' ')} on {_where(ctx)}, then a first connection to {ip}:{r.get('port')} by {prog or 'a program'}",
                10**9,
                ip=ip,
                port=r.get("port"),
                process=prog,
                evidence={"event": e["event"], "event_at": e["ts"], "first_used": first},
            )
        )
    return out


def bruteforce_then_login(ctx: dict[str, Any], p: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    window = p["hours"] * HOUR
    evs = _events(ctx)
    brutes = [e for e in evs if e["event"] == "brute_force_detected"]
    for lg in sorted((e for e in evs if e["event"] == "login_new_source"), key=lambda e: e["ts"]):
        lp = lg["payload"]
        before = [b for b in brutes if 0 <= lg["ts"] - b["ts"] <= window]
        if not before:
            continue
        src = str(lp.get("source") or "")
        match = next(
            (b for b in before if src and b["payload"].get("source_ip") == src), None
        )  # the strongest sign: the address that guessed is the address that got in
        bp = (match or max(before, key=lambda e: e["ts"]))["payload"]
        user = str(lp.get("user") or "")
        what = "The address that guessed passwords on" if match else "A burst of failed logins on"
        out.append(
            _finding(
                "bruteforce_then_login",
                ctx,
                f"{src}|{lg['ts']}",
                "critical" if match else "high",
                f"{what} {_where(ctx)} was followed by a first login from {src or 'a new address'}{' as ' + user if user else ''}",
                10**9,
                ip=src,
                evidence={
                    "failed_logins": bp.get("count"),
                    "guessed_from": bp.get("source_ip"),
                    "same_address": match is not None,
                    "login_at": lg["ts"],
                    "user": user,
                },
            )
        )
    return out


def exposed_port_in_use(ctx: dict[str, Any], p: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    ports: dict[int, dict[str, Any]] = {}
    for e in _recent(ctx, OPEN_PORT_EVENTS, p["hours"]):
        port = _int(e["payload"].get("port"))
        if port is not None and port not in ports:
            ports[port] = e
    if not ports:
        return out
    seen = _dict(_dict(ctx.get("rec")).get("seen"))
    for r in _rows(ctx, "in"):
        port = _int(r.get("port"))
        opened = ports.get(port) if port is not None else None
        if opened is not None and _public(r["ip"]):
            out.append(
                _finding(
                    "exposed_port_in_use",
                    ctx,
                    f"{port}|{r['ip']}",
                    "medium",
                    f"port {port} opened on {_where(ctx)} and {r['ip']} is already connected to it",
                    6 * HOUR,
                    ip=r["ip"],
                    port=port,
                    process=_prog(r.get("proc")),
                    evidence={
                        "event": opened["event"],
                        "event_at": opened["ts"],
                        "connections": r.get("n"),
                        "first_used": _int(seen.get(r["ip"])),
                    },
                )
            )
    return out


_RULE_FUNCS: dict[str, Callable[[dict[str, Any], dict[str, Any]], list[dict[str, Any]]]] = {
    "interpreter_egress": interpreter_egress,
    "service_new_destination": service_new_destination,
    "known_bad_contact": known_bad_contact,
    "persistence_then_egress": persistence_then_egress,
    "bruteforce_then_login": bruteforce_then_login,
    "exposed_port_in_use": exposed_port_in_use,
}


def evaluate(
    ctx: dict[str, Any],
    rules: dict[str, dict[str, Any]] | None = None,
    errors: list[tuple[str, str]] | None = None,
) -> list[dict[str, Any]]:
    """What the enabled rules find for one host: [finding], the most severe first, a key only once. Not cut: the caller shows and raises at most MAX_PER_HOST, and it removes
    what was raised lately first, so a host with more findings than that still reaches the later ones. A rule that raises is skipped and the others run; when the caller passes
    a list, (rule id, what it raised) is added to it, so the caller can say that a rule failed instead of the rule failing in silence.
    """
    rules = rules if rules is not None else settings(None)
    found: list[dict[str, Any]] = []
    for rid in ORDER:
        p = rules.get(rid)
        if not isinstance(p, dict) or not p.get("enabled"):
            continue
        try:
            found.extend(_RULE_FUNCS[rid](ctx, p))
        except Exception as e:
            if errors is not None:
                errors.append((rid, f"{type(e).__name__}: {str(e)[:100]}"))
            continue
    out, keys = [], set()
    for f in sorted(found, key=lambda f: (RANK.get(f["severity"], 9), f["key"])):
        if f["key"] not in keys:
            keys.add(f["key"])
            out.append(f)
    return out


def compact(f: dict[str, Any]) -> dict[str, Any]:
    """A finding as it is stored and shown: the facts a person reads, the text cut and no repeat interval."""
    out = {
        k: f[k] for k in ("rule", "key", "severity", "detail", "ip", "port", "process") if k in f
    }
    ev = f.get("evidence")
    if isinstance(ev, dict):
        out["evidence"] = {
            str(k)[:40]: (
                v if v is None or isinstance(v, (int, float, bool)) else str(v)[:TEXT_MAX]
            )
            for k, v in list(ev.items())[:EVIDENCE_KEYS]
        }
    return out


def remember(
    alerted: Any, raised: list[dict[str, Any]], now: int, cap: int = 100
) -> dict[str, int]:
    """The `alerted` map after these findings were raised: {key: time}. What is older than KEEP_S is forgotten, and at most `cap` keys are kept, the newest."""
    kept = {
        k: v
        for k, v in _dict(alerted).items()
        if isinstance(k, str) and _int(v) is not None and 0 <= now - v <= KEEP_S
    }
    for f in raised:
        kept[f["key"]] = now
    if len(kept) > cap:
        kept = dict(sorted(kept.items(), key=lambda kv: kv[1])[-cap:])
    return kept


def is_due(alerted: Any, finding: dict[str, Any], now: int) -> bool:
    """True when the finding was never raised, or was raised more than its repeat interval ago."""
    at = _int(_dict(alerted).get(finding["key"]))
    return at is None or now - at >= finding["repeat_s"] or at > now
