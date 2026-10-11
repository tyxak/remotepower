"""Edge evidence — what Cloudflare and the edge honeypot say about an address.

Two feeds the SERVER reads from api.cloudflare.com, with a read-only token:

  * Cloudflare's firewall events (GraphQL `firewallEventsAdaptiveGroups`, or the
    zone's single events from `firewallEventsAdaptive` when its plan has no
    grouped view): who was refused at the edge, by which mechanism. Only
    mechanisms that mean "this request looked like an attack" count. A country
    or ASN rule, the security level, an IP access rule (a ban somebody else
    already decided, often from fail2ban or the honeypot itself) and a
    challenge that a person may have solved are policy, not evidence, and are
    dropped here.
  * The honeypot Worker's log (Workers Observability): every trap hit that a
    visitor with no business there made, with the Worker's own decision.

This module is the pure half: request building, response parsing, and the
reduction to `threat_evidence` summaries. It never opens a socket. The caller
(edge_intel_handlers.py) passes the HTTP in, as ip_intel does.

What it keeps: the address, a count, a mechanism or trap kind, and a time. What
it never keeps: paths, query strings, user agents, host names and notes. Those
are typed by the attacker, and a report is public. A rule's description is the
operator's own text; it is read here only to pick a class and is never copied.
"""

import calendar
import json
import re
import time

import threat_evidence

CF_API = "https://api.cloudflare.com/client/v4"
CF_GRAPHQL = CF_API + "/graphql"

# Cloudflare's firewall event `source`, lower-cased, to the mechanism that counts.
# Anything not listed is not evidence of an attack on us.
_CF_SOURCES = {
    "waf": "waf",  # managed rules (legacy name)
    "firewallmanaged": "waf",  # managed rules
    "managed": "waf",
    "firewallcustom": "custom",  # the operator's own custom rule
    "firewallrules": "custom",
    "ratelimit": "ratelimit",
    "l7ddos": "ddos",
    "botfight": "bot",
    "botmanagement": "bot",
    "bic": "bot",  # Browser Integrity Check
    "uablock": "ua",
}
# Mechanisms whose refusals count towards "refused N times" like a WAF's. The two
# below are weaker signals (a monitor or a script with an odd header trips them),
# so they only count through the hostile-request total.
_CF_WEAK = ("bot", "ua")

# Actions that are a refusal. A challenge is not: a person solves it, and the
# operator's own geo and bot challenges would otherwise be reported as attacks.
_CF_REFUSALS = ("block", "connectionclose", "forceconnectionclose")

# Actions that are neither a refusal nor a challenge a person was given: a request
# that was allowed or skipped, and what became of a challenge. The event read asks
# Cloudflare to leave them out, so a busy site's allowed traffic cannot fill the
# one page of events that a read is capped at. The names are the ones cf-sniffcat
# filters on against the same API.
_NOT_EVENTS = (
    "allow",
    "skip",
    "challenge_solved",
    "challenge_failed",
    "challenge_bypassed",
    "jschallenge_solved",
    "jschallenge_failed",
    "jschallenge_bypassed",
    "managed_challenge_skipped",
    "managed_challenge_non_interactive_solved",
    "managed_challenge_interactive_solved",
    "managed_challenge_bypassed",
)

# What the operator wrote in a custom rule's description, to a class. Used only
# to choose a class; the text is never copied anywhere.
_RULE_WORDS = tuple(
    (cls, re.compile(rx))
    for cls, rx in (
        ("sqli", r"\bsql|sqli|injection"),
        ("xss", r"\bxss\b|cross-?site"),
        ("traversal", r"travers|\blfi\b|\brfi\b"),
        ("rce", r"\brce\b|remote code|command exec|webshell|log4"),
        ("flood", r"\brate\b|rate-?limit|flood|\bdos\b"),
        ("scanner", r"scanner|\bscan\b|nikto|nmap|vulnerab"),
        (
            "probe",
            r"probe|sensitive|backup|dump|wp-|wordpress|xmlrpc|admin|phpmyadmin|adminer|"
            r"disclosure|dotfile|\.env|\.git|enumerat|unusual|method|private host|fw_private",
        ),
    )
)
_LIST_REF_RE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")
_HEX32 = re.compile(r"[0-9a-f]{32}")

# The Worker's own decision, from its `action` field.
_TRAP_DECIDED = ("banned", "already-banned", "already-blocked-elsewhere")
_TRAP_SKIPPED = ("allowlisted", "shared-egress")
# The Worker's kind to the vocabulary's. oddclient, selftest, wpauthed, js_beacon
# and canary_mail are logged to be read and are not evidence of an attack.
_TRAP_TOKEN = {
    "bait": "bait",
    "robots": "robots",
    "login": "login",
    "private": "private",
    "impostor": "impostor",
    "wpprobe": "wpprobe",
    "wpenum": "wpenum",
    "mazeentry": "mazeentry",
    "maze": "maze",
    "mazeloot": "mazeloot",
    "gitdump": "gitdump",
    "canary_use": "canary",
    "decoy": "decoy",
    "decoy_login": "decoylogin",
}

MAX_ROWS = 10000
MAX_EVENTS = 2500  # single events one zone's read carries, as cf-sniffcat's default
TRAP_LINES = 1000  # log lines one Worker's read carries
MAX_ZONES = 50
MAX_WORKERS = 3
_WORKER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}")


def valid_id(value):
    """A Cloudflare account or zone id: 32 lower-case hex digits."""
    return isinstance(value, str) and bool(_HEX32.fullmatch(value))


def valid_worker(name):
    return isinstance(name, str) and bool(_WORKER_RE.fullmatch(name))


def _short(v, n=160):
    if v is None:
        return ""
    return "".join(ch for ch in str(v) if ch.isprintable())[:n]


def _int(v):
    try:
        return max(0, int(v))
    except (TypeError, ValueError, OverflowError):
        return 0


def _headers(token):
    return {
        "Authorization": "Bearer " + token,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


# ── requests ───────────────────────────────────────────────────────────────────


def zones_request(token, account_id="", page=1):
    q = f"?per_page={MAX_ZONES}&page={int(page)}&status=active"
    if valid_id(account_id):
        q += "&account.id=" + account_id
    return {"method": "GET", "url": f"{CF_API}/zones{q}", "headers": _headers(token), "body": None}


def rules_request(token, zone_id):
    """The zone's custom-rules entrypoint: each rule's id, description, action
    and expression. The expression is read for one thing: whether it names an IP
    list."""
    if not valid_id(zone_id):
        raise ValueError("invalid zone id")
    url = f"{CF_API}/zones/{zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint"
    return {"method": "GET", "url": url, "headers": _headers(token), "body": None}


def firewall_request(token, zone_ids, since, until, limit=MAX_ROWS):
    """One GraphQL request for every zone: groups of (address, action, source,
    rule) with a count. Grouped on purpose: the response carries no path and no
    user agent, so nothing the attacker typed is ever fetched.

    Every value is written into the query as a literal rather than passed as a
    typed variable. They are all ours and all validated here (32 hex digits, an
    ISO time we formatted, an integer), so nothing can be injected, and the
    request does not depend on the names of GraphQL's scalar types."""
    zones = [z for z in zone_ids if valid_id(z)][:MAX_ZONES]
    if not zones:
        raise ValueError("no zone id")
    tags = ", ".join('"%s"' % z for z in zones)
    n = max(1, min(MAX_ROWS, int(limit)))
    query = (
        "query { viewer { zones(filter: {zoneTag_in: [%s]}) { zoneTag"
        " firewallEventsAdaptiveGroups(limit: %d, orderBy: [count_DESC],"
        ' filter: {datetime_geq: "%s", datetime_lt: "%s"}) {'
        " count dimensions { clientIP action source ruleId } } } } }"
        % (tags, n, _iso(since), _iso(until))
    )
    return {
        "method": "POST",
        "url": CF_GRAPHQL,
        "headers": _headers(token),
        "body": json.dumps({"query": query}).encode(),
        "max_bytes": 4_000_000,
        "timeout": 25,
    }


def events_request(token, zone_ids, since, until, limit=MAX_EVENTS):
    """The same facts as firewall_request, read one event at a time from
    `firewallEventsAdaptive`. A Free zone is refused the grouped dataset and can
    read this one, which is the dataset cf-sniffcat reads on the same zones.

    Four fields are asked for and no others, so the response carries no path, query
    string, host or user agent here either. Events that were allowed, skipped or
    answered by a person are left out by the query (`_NOT_EVENTS`); the rest are
    grouped by the parser."""
    zones = [z for z in zone_ids if valid_id(z)][:MAX_ZONES]
    if not zones:
        raise ValueError("no zone id")
    if len(zones) == 1:
        which = 'zoneTag: "%s"' % zones[0]
    else:
        which = "zoneTag_in: [%s]" % ", ".join('"%s"' % z for z in zones)
    n = max(1, min(MAX_EVENTS, int(limit)))
    skip = ", ".join('{action_neq: "%s"}' % a for a in _NOT_EVENTS)
    query = (
        "query { viewer { zones(filter: {%s}) { zoneTag"
        " firewallEventsAdaptive(limit: %d, orderBy: [datetime_DESC],"
        ' filter: {datetime_geq: "%s", datetime_lt: "%s", AND: [%s]}) {'
        " clientIP action source ruleId } } } }" % (which, n, _iso(since), _iso(until), skip)
    )
    return {
        "method": "POST",
        "url": CF_GRAPHQL,
        "headers": _headers(token),
        "body": json.dumps({"query": query}).encode(),
        "max_bytes": 4_000_000,
        "timeout": 25,
    }


def trap_request(token, account_id, worker, since_ms, until_ms, limit=TRAP_LINES):
    """The honeypot Worker's `trap hit` log lines in a window, from Workers
    Observability. One Worker per request; the filter shape is the one the
    operator's own report scripts already use against this API."""
    if not valid_id(account_id):
        raise ValueError("invalid account id")
    if not valid_worker(worker):
        raise ValueError("invalid worker name")
    filters = [
        {"key": "$metadata.service", "operation": "eq", "type": "string", "value": worker},
        {"key": "msg", "operation": "eq", "type": "string", "value": "trap hit"},
    ]
    body = {
        "queryId": "rp-edge",
        "view": "events",
        "limit": max(1, min(2000, int(limit))),
        "timeframe": {"from": int(since_ms), "to": int(until_ms)},
        "parameters": {"datasets": ["cloudflare-workers"], "filters": filters},
    }
    return {
        "method": "POST",
        "url": f"{CF_API}/accounts/{account_id}/workers/observability/telemetry/query",
        "headers": _headers(token),
        "body": json.dumps(body).encode(),
        "max_bytes": 4_000_000,
        "timeout": 25,
    }


def _iso(epoch):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(epoch)))


# ── responses ──────────────────────────────────────────────────────────────────


_POINTER_RE = re.compile(r"\s*Refer to this page for more details.*$", re.S)


def _cf_error(status, body):
    """{'ok': False, 'error', 'auth' | 'dataset'} for a REST or GraphQL failure.
    The provider's sentence is shown to the operator, so it is cut and stripped
    of control characters, never trusted as markup; its closing pointer to a
    documentation page is dropped, because the page shows text and not a link.

    'dataset' is Cloudflare saying a zone has no access to a GraphQL field. That
    sentence names the ZONE, not the token, and it is what a missing Analytics
    permission and a plan without the dataset both produce, so it is kept apart
    from 'auth' and never worded as one of the two."""
    msg = ""
    if isinstance(body, dict):
        errs = body.get("errors")
        if isinstance(errs, list) and errs and isinstance(errs[0], dict):
            msg = _short(_POINTER_RE.sub("", str(errs[0].get("message") or "")), 200)
            code = str(errs[0].get("code") or (errs[0].get("extensions") or {}).get("code") or "")
            path = errs[0].get("path")
            if "does not have access to the path" in msg.lower() or (
                code == "authz" and isinstance(path, list) and len(path) >= 3
            ):
                return {"ok": False, "dataset": True, "error": msg or "this zone cannot read that dataset"}
            if (
                code in ("authz", "10000", "9109")
                or "authoriz" in msg.lower()
                or "permission" in msg.lower()
            ):
                return {"ok": False, "auth": True, "error": msg or "the token cannot read this"}
    if status in (401, 403):
        return {
            "ok": False,
            "auth": True,
            "error": msg or "the token was refused (HTTP %d)" % status,
        }
    if status == 0:
        return {"ok": False, "error": msg or "unreachable"}
    if status == 429:
        return {"ok": False, "error": "rate limited by Cloudflare"}
    return {"ok": False, "error": msg or f"HTTP {status}"}


def parse_zones(status, body):
    if status != 200 or not isinstance(body, dict) or body.get("success") is False:
        return _cf_error(status, body)
    out = []
    for z in body.get("result") or []:
        if isinstance(z, dict) and valid_id(z.get("id")):
            out.append({"id": z["id"], "name": _short(z.get("name"), 80)})
    return {"ok": True, "zones": out[:MAX_ZONES]}


def rule_class(description):
    """The class a custom rule's description points at, or None."""
    d = str(description or "").lower()
    for cls, rx in _RULE_WORDS:
        if rx.search(d):
            return cls
    return None


def parse_rules(status, body):
    """{'ok': True, 'rules': {rule_id: {'d': short description, 'c': class or '',
    'k': True when its expression names an IP list}}}. A zone with no custom
    rules answers 404, which is an empty answer, not a failure."""
    if status == 404:
        return {"ok": True, "rules": {}}
    if status != 200 or not isinstance(body, dict) or body.get("success") is False:
        return _cf_error(status, body)
    rules = (
        ((body.get("result") or {}).get("rules")) if isinstance(body.get("result"), dict) else None
    )
    out = {}
    for r in rules or []:
        if not isinstance(r, dict) or not _HEX32.fullmatch(str(r.get("id") or "")):
            continue
        out[r["id"]] = {
            "d": _short(r.get("description"), 60),
            "c": rule_class(r.get("description")) or "",
            "k": bool(_LIST_REF_RE.search(str(r.get("expression") or ""))),
        }
        if len(out) >= 200:
            break
    return {"ok": True, "rules": out}


def parse_firewall(status, body):
    """{'ok': True, 'rows': [{zone, ip, action, source, rule, count}], 'truncated'}.
    GraphQL answers HTTP 200 with an `errors` list for a refused field, so the
    list is read as well as the status."""
    if not isinstance(body, dict) or body.get("errors") or status != 200:
        return _cf_error(status, body)
    zones = ((body.get("data") or {}).get("viewer") or {}).get("zones")
    rows, truncated = [], False
    for z in zones or []:
        if not isinstance(z, dict):
            continue
        groups = z.get("firewallEventsAdaptiveGroups") or []
        if len(groups) >= MAX_ROWS:
            truncated = True
        for g in groups:
            d = g.get("dimensions") if isinstance(g, dict) else None
            if not isinstance(d, dict):
                continue
            rows.append(
                {
                    "zone": str(z.get("zoneTag") or ""),
                    "ip": str(d.get("clientIP") or ""),
                    "action": str(d.get("action") or "").lower(),
                    "source": str(d.get("source") or "").lower(),
                    "rule": str(d.get("ruleId") or ""),
                    "count": _int(g.get("count")),
                }
            )
    return {"ok": True, "rows": rows, "truncated": truncated}


def parse_events(status, body, limit=MAX_EVENTS):
    """The rows parse_firewall returns, built from single events: one per address,
    action, source and rule, with the number of events behind it. `limit` is what
    the request asked for per zone; a zone that came back full is flagged."""
    if not isinstance(body, dict) or body.get("errors") or status != 200:
        return _cf_error(status, body)
    zones = ((body.get("data") or {}).get("viewer") or {}).get("zones")
    rows, truncated = [], False
    for z in zones or []:
        if not isinstance(z, dict):
            continue
        events = z.get("firewallEventsAdaptive") or []
        if len(events) >= limit:
            truncated = True
        seen = {}
        for e in events:
            if not isinstance(e, dict):
                continue
            key = (
                str(e.get("clientIP") or ""),
                str(e.get("action") or "").lower(),
                str(e.get("source") or "").lower(),
                str(e.get("ruleId") or ""),
            )
            seen[key] = seen.get(key, 0) + 1
        for (ip, action, source, rule), n in seen.items():
            rows.append(
                {
                    "zone": str(z.get("zoneTag") or ""),
                    "ip": ip,
                    "action": action,
                    "source": source,
                    "rule": rule,
                    "count": n,
                }
            )
    return {"ok": True, "rows": rows, "truncated": truncated}


def _log_object(event):
    """The fields of one log line. Workers Logs wraps what the Worker printed
    under a few different keys depending on the view, and a printed JSON object
    may arrive as a string, so every known wrapper is merged in."""
    if isinstance(event, str):
        try:
            event = json.loads(event)
        except ValueError:
            return {}
    if not isinstance(event, dict):
        return {}
    merged = dict(event)
    for key in ("$data", "data", "source", "$workers"):
        v = event.get(key)
        if isinstance(v, str):
            try:
                v = json.loads(v)
            except ValueError:
                v = None
        if isinstance(v, dict):
            merged.update(v)
    return merged


def parse_trap(status, body, limit=TRAP_LINES):
    """{'ok': True, 'hits': [{kind, ip, action, at}], 'truncated': bool}. A read that
    came back with as many lines as it asked for is flagged, because the Worker may
    have logged more than that in the window."""
    if status != 200 or not isinstance(body, dict) or body.get("success") is False:
        return _cf_error(status, body)
    res = body.get("result")
    events = res.get("events") if isinstance(res, dict) else res
    if isinstance(events, dict):
        events = events.get("events") or events.get("logs")
    if not isinstance(events, list):
        events = (res.get("logs") if isinstance(res, dict) else None) or []
    hits = []
    for e in events:
        o = _log_object(e)
        if str(o.get("msg") or "") != "trap hit":
            continue
        meta = o.get("$metadata") if isinstance(o.get("$metadata"), dict) else {}
        hits.append(
            {
                "kind": str(o.get("kind") or "").lower()[:24],
                "ip": str(o.get("ip") or "")[:64],
                "action": str(o.get("action") or "").lower()[:40],
                "at": (
                    _epoch(o.get("at"))
                    or _epoch(o.get("timestamp"))
                    or _epoch(meta.get("timestamp"))
                ),
            }
        )
    return {"ok": True, "hits": hits, "truncated": len(events) >= limit}


def _epoch(value):
    """Epoch seconds from an ISO string or a number of seconds or milliseconds."""
    if value in (None, ""):
        return 0
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        v = float(value)
        return int(v / 1000) if v > 1e11 else int(v)
    s = str(value).strip()
    m = re.fullmatch(r"(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:\.\d+)?(?:Z|\+00:00)?", s)
    if not m:
        return 0
    try:
        return calendar.timegm(tuple(int(x) for x in m.groups()) + (0, 0, 0))
    except (ValueError, OverflowError):
        return 0


# ── reduction to evidence ──────────────────────────────────────────────────────


def cf_events(rows, rules=None, now=None, since=None, until=None, include_carriers=False):
    """(events, stats). `rows` come from parse_firewall; `rules` is
    {zone_id: {rule_id: {...}}} from parse_rules, or None when it could not be
    read (a rule is then taken as it is). `stats` counts what was dropped and
    why, with keys from a fixed list, so the page can say it."""
    now = int(now or time.time())
    rules = rules or {}
    stats = {"rows": len(rows), "kept": 0, "ignored": {}}
    per_ip = {}

    def drop(why, n=1):
        stats["ignored"][why] = stats["ignored"].get(why, 0) + n

    for r in rows:
        n = _int(r.get("count"))
        if not n:
            continue
        action, source = r.get("action", ""), r.get("source", "")
        if action not in _CF_REFUSALS:
            drop("not_a_refusal", n)
            continue
        kind = _CF_SOURCES.get(source)
        if not kind:
            drop("not_an_attack_source", n)
            continue
        ip = threat_evidence.public_ip(r.get("ip"))
        if not ip:
            drop("not_public", n)
            continue
        if threat_evidence.infra_reason(ip):
            drop("cloudflare_address", n)
            continue
        rule = (rules.get(r.get("zone")) or {}).get(r.get("rule")) or {}
        if rule.get("k") and not include_carriers:
            # A rule that also blocks an IP list refuses addresses for being on a
            # community blocklist, which is not something they did to us.
            drop("list_rule", n)
            continue
        token, fam_count = None, 0 if kind in _CF_WEAK else n
        cls = rule.get("c") if kind == "custom" else ""
        if cls in ("sqli", "xss", "traversal", "rce", "probe", "scanner", "flood"):
            token = "req:" + cls
        else:
            token = "cf:" + kind
        e = per_ip.setdefault(ip, {"ip": ip, "src": {}, "tok": {"cf": {}}, "blk": 0})
        e["tok"]["cf"][token] = e["tok"]["cf"].get(token, 0) + n
        if fam_count:
            e["src"]["cf"] = e["src"].get("cf", 0) + fam_count
        e["blk"] += n
        stats["kept"] += n
    first = int(since or now - 600)
    last = int(until or now)
    out = []
    for e in per_ip.values():
        e["first"], e["last"] = first, last
        ev = threat_evidence.normalize_event(e, now=now, families=threat_evidence.EDGE_SOURCES)
        if ev is not None:
            out.append(ev)
    return out, stats


def trap_events(hits, now=None):
    """(events, stats). One summary per address: hits per trap kind, and the
    Worker's decision when it banned the address. Each log line is one hit. The
    Worker samples the lines of a source it can never ban, so a flood is
    undercounted here, never overstated."""
    now = int(now or time.time())
    stats = {"hits": len(hits), "kept": 0, "ignored": {}}
    per_ip = {}

    def drop(why):
        stats["ignored"][why] = stats["ignored"].get(why, 0) + 1

    for h in hits:
        action = h.get("action", "")
        if action in _TRAP_SKIPPED:
            drop("own_or_shared_address")
            continue
        token = _TRAP_TOKEN.get(h.get("kind", ""))
        if not token:
            drop("not_evidence")
            continue
        ip = threat_evidence.public_ip(h.get("ip"))
        if not ip:
            drop("not_public")
            continue
        if threat_evidence.infra_reason(ip):
            drop("cloudflare_address")
            continue
        e = per_ip.setdefault(
            ip, {"ip": ip, "src": {"trap": 0}, "tok": {"trap": {}}, "trp": 0, "first": 0, "last": 0}
        )
        t = "trap:" + token
        e["tok"]["trap"][t] = e["tok"]["trap"].get(t, 0) + 1
        e["src"]["trap"] += 1
        if action in _TRAP_DECIDED:
            e["trp"] += 1
        at = int(h.get("at") or 0)
        if at:
            e["first"] = at if not e["first"] else min(e["first"], at)
            e["last"] = max(e["last"], at)
        stats["kept"] += 1
    out = []
    for e in per_ip.values():
        e["first"] = e["first"] or now
        e["last"] = e["last"] or now
        ev = threat_evidence.normalize_event(e, now=now, families=threat_evidence.EDGE_SOURCES)
        if ev is not None:
            out.append(ev)
    return out, stats
