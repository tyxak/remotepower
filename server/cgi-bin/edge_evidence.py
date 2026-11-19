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

What it keeps: the address, a count, a mechanism or trap kind, and a time. From
8.0.1 it also keeps up to three SAMPLES per address, when the operator's samples
setting is on: the method and the path of a request the edge refused or the
honeypot answered, each rebuilt by threat_evidence.normalize_sample (a short safe
alphabet, no query string), as a host's sensor sends them. What it never keeps:
query strings, user agents, host names and notes. Those are typed by the attacker,
and a report is public. A rule's description is the operator's own text; it is
read here only to pick a class and is never copied.
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
# to choose a class; the text is never copied anywhere. The first rule that matches
# wins, so the order is part of the table:
#   * an attack by name comes first, and "sql" has to be followed by "injection" (or be
#     "sqli"): a rule that lists the files it blocks says ".sql", and that read as SQL
#     injection until 8.0.1. "command injection" and "code injection" are code execution;
#     any other "... injection" names no class. No other word was added to an attack's row:
#     a word like "exploit" in a rule about files would file a request for /.env as remote
#     code execution, and take it out from under an ignore list that held it back as probing;
#   * the private-host rule comes before the admin one, because its description says who
#     may pass ("non-admin");
#   * user enumeration comes before WordPress, because it names /wp-json/;
#   * `probe` is last: a rule that only says it blocks probes.
_RULE_WORDS = tuple(
    (cls, re.compile(rx))
    for cls, rx in (
        ("sqli", r"sqli|sql[ _-]?injection"),
        ("xss", r"\bxss\b|cross-?site"),
        ("traversal", r"travers|\blfi\b|\brfi\b"),
        ("rce", r"\brce\b|remote code|command exec|webshell|log4|(?:command|code)[ _-]?injection"),
        ("flood", r"\brate\b|rate-?limit|flood|\bdos\b"),
        ("scanner", r"scanner|\bscan\b|nikto|nmap|vulnerab"),
        ("host_recon", r"private host|fw_private|internal host"),
        ("user_enum", r"enumerat"),
        ("wordpress", r"wp-|wordpress|xmlrpc"),
        (
            "config_probe",
            r"sensitive|backup|dump|dotfile|\.env|\.git|\.sql|\.bak|credential|secret",
        ),
        ("admin_probe", r"admin|adminer|\bpma\b|cpanel"),
        ("method_probe", r"unusual|\bmethods?\b"),
        # "disclosure" stays general: a rule against version disclosure blocks a readme, not a key
        ("probe", r"probe|probing|disclosure"),
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
# What a single-event read asks for beyond the four fields a refusal is counted by, when the
# operator's samples setting is on: where the request went, when, and how. Cloudflare's own
# tutorial for this dataset shows the first two; the method's name is not on a page that was
# read, so the caller asks in tiers and settles for the first one Cloudflare accepts.
EVENT_EXTRA_TIERS = (
    ("clientRequestPath", "datetime", "clientRequestHTTPMethodName"),
    ("clientRequestPath", "datetime"),
    (),
)
_EVENT_EXTRAS = frozenset(EVENT_EXTRA_TIERS[0])
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


def events_request(token, zone_ids, since, until, limit=MAX_EVENTS, extra=()):
    """The same facts as firewall_request, read one event at a time from
    `firewallEventsAdaptive`. A Free zone is refused the grouped dataset and can
    read this one, which is the dataset cf-sniffcat reads on the same zones.

    Four fields are asked for, plus the ones in `extra` (one of EVENT_EXTRA_TIERS:
    the path, the time and the method, for samples). The response never carries a
    query string, a host or a user agent: none of those is ever asked for. Events
    that were allowed, skipped or answered by a person are left out by the query
    (`_NOT_EVENTS`); the rest are grouped by the parser."""
    zones = [z for z in zone_ids if valid_id(z)][:MAX_ZONES]
    if not zones:
        raise ValueError("no zone id")
    if len(zones) == 1:
        which = 'zoneTag: "%s"' % zones[0]
    else:
        which = "zoneTag_in: [%s]" % ", ".join('"%s"' % z for z in zones)
    n = max(1, min(MAX_EVENTS, int(limit)))
    skip = ", ".join('{action_neq: "%s"}' % a for a in _NOT_EVENTS)
    # only names from the fixed list reach the query, in the list's own order
    more = "".join(" " + f for f in EVENT_EXTRA_TIERS[0] if f in extra and f in _EVENT_EXTRAS)
    query = (
        "query { viewer { zones(filter: {%s}) { zoneTag"
        " firewallEventsAdaptive(limit: %d, orderBy: [datetime_DESC],"
        ' filter: {datetime_geq: "%s", datetime_lt: "%s", AND: [%s]}) {'
        " clientIP action source ruleId%s } } } }"
        % (which, n, _iso(since), _iso(until), skip, more)
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
    from 'auth' and never worded as one of the two.

    'query' is Cloudflare answering that it will not run the query as written: an
    error list on an answer that is not a refusal of the token, a rate limit or a
    failure on its side. A read that asked for more fields than the four it needs
    asks again for fewer when it sees this (EVENT_EXTRA_TIERS)."""
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
                return {
                    "ok": False,
                    "dataset": True,
                    "error": msg or "this zone cannot read that dataset",
                }
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
    if msg and status < 500:
        return {"ok": False, "query": True, "error": msg}
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
    the request asked for per zone; a zone that came back full is flagged.

    When the read asked for them (EVENT_EXTRA_TIERS) a row also carries `first` and
    `last`, the times of its earliest and latest event, and `smp`, up to
    threat_evidence.MAX_SAMPLES requests as {'m', 'p', 't'}. The path and the method
    are kept as Cloudflare sent them, cut to a length; they are the visitor's text
    and nothing here reads them. threat_evidence.normalize_sample rebuilds each one
    before it is stored."""
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
            g = seen.setdefault(key, {"n": 0, "first": 0, "last": 0, "smp": []})
            g["n"] += 1
            at = _epoch(e.get("datetime"))
            if at:
                g["first"] = at if not g["first"] else min(g["first"], at)
                g["last"] = max(g["last"], at)
            path = e.get("clientRequestPath")
            if isinstance(path, str) and path and len(g["smp"]) < threat_evidence.MAX_SAMPLES * 4:
                g["smp"].append(
                    {
                        "m": str(e.get("clientRequestHTTPMethodName") or "").upper()[:10],
                        "p": path[:2048],
                        "t": at,
                    }
                )
        for (ip, action, source, rule), g in seen.items():
            row = {
                "zone": str(z.get("zoneTag") or ""),
                "ip": ip,
                "action": action,
                "source": source,
                "rule": rule,
                "count": g["n"],
            }
            if g["first"]:
                row["first"], row["last"] = g["first"], g["last"]
            if g["smp"]:
                row["smp"] = g["smp"]
            rows.append(row)
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


_WORD_RE = re.compile(r"[a-z][a-z-]{0,23}")
_HOST_RE = re.compile(r"[a-z0-9][a-z0-9.-]{0,99}")


def _word(value):
    """One of the short lower-case words a browser sends in a Sec-Fetch header, or ''. The header is the visitor's text."""
    s = str(value or "").strip().lower()
    return s if _WORD_RE.fullmatch(s) else ""


def _host(value):
    """A host name in the form the Worker wrote it (lower case, no port), or ''. The visitor's text, read to be compared and kept nowhere."""
    s = str(value or "").strip().lower()
    return s if _HOST_RE.fullmatch(s) else ""


def parse_trap(status, body, limit=TRAP_LINES):
    """{'ok': True, 'hits': [{kind, ip, action, at, method, path, host, v, sfs, sfm, sfd, ref, org}], 'truncated': bool}.
    A read that came back with as many lines as it asked for is flagged, because the
    Worker may have logged more than that in the window. `method` and `path` are the
    visitor's text, cut to a length and read by nothing here; they become a sample
    only through threat_evidence.normalize_sample.

    From script version 2 the Worker also writes how the request was made: `sfs`, `sfm` and `sfd` are the Sec-Fetch-Site, -Mode
    and -Dest words a browser sends, `ref` and `org` the host names of the Referer and the Origin, and `v` is the version. They are
    read by page_caused() and kept nowhere. A line without `v` is from an older script, and nothing in it says whether a page made
    the request."""
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
                "method": str(o.get("method") or "").upper()[:10],
                "path": str(o.get("path") or "")[:2048],
                "host": _host(o.get("host")),
                "v": min(99, _int(o.get("v"))),
                "sfs": _word(o.get("sfs")),
                "sfm": _word(o.get("sfm")),
                "sfd": _word(o.get("sfd")),
                "ref": _host(o.get("ref")),
                "org": _host(o.get("org")),
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


def _keep_samples(e, family, found):
    """Add `found` ({'m', 'p', 't'} as a reader made them) to an address's samples under
    `family`. A few more than the vocabulary keeps are held here, so a repeated path does
    not crowd the others out; normalize_event rebuilds each one and keeps the first three."""
    smp = e.setdefault("smp", [])
    for f in found:
        if len(smp) >= threat_evidence.MAX_SAMPLES * 4:
            break
        # a time that was not read is left out (None), so the sample is stamped with the read's own time
        smp.append(
            {
                "f": family,
                "m": f.get("m") or "",
                "p": f.get("p") or "",
                "c": 0,
                "t": f.get("t") or None,
            }
        )


def cf_events(
    rows, rules=None, now=None, since=None, until=None, include_carriers=False, samples=False
):
    """(events, stats). `rows` come from parse_firewall or parse_events; `rules` is
    {zone_id: {rule_id: {...}}} from parse_rules, or None when it could not be
    read (a rule is then taken as it is). `stats` counts what was dropped and
    why, with keys from a fixed list, so the page can say it.

    A custom rule the operator described gets the class its description points at
    (rule_class); any other refusal is named by its mechanism. Rows read one event at
    a time carry the events' own times, which become the address's first and last
    sighting; a grouped read has only the window it asked for. `samples` (the
    operator's setting) keeps what the rows hold of the requests themselves."""
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
        fam_count = 0 if kind in _CF_WEAK else n
        cls = rule.get("c") if kind == "custom" else ""
        token = (threat_evidence.req_token(cls) if cls else None) or ("cf:" + kind)
        e = per_ip.setdefault(
            ip, {"ip": ip, "src": {}, "tok": {"cf": {}}, "blk": 0, "first": 0, "last": 0}
        )
        e["tok"]["cf"][token] = e["tok"]["cf"].get(token, 0) + n
        if fam_count:
            e["src"]["cf"] = e["src"].get("cf", 0) + fam_count
        e["blk"] += n
        at_first, at_last = _int(r.get("first")), _int(r.get("last"))
        if at_first and at_last:
            e["first"] = at_first if not e["first"] else min(e["first"], at_first)
            e["last"] = max(e["last"], at_last)
        if samples and isinstance(r.get("smp"), list):
            _keep_samples(e, "cf", [f for f in r["smp"] if isinstance(f, dict)])
        stats["kept"] += n
    first = int(since or now - 600)
    last = int(until or now)
    out = []
    for e in per_ip.values():
        # the events' own times when the read carried them, else the window that was asked for
        e["first"], e["last"] = (e["first"] or first), (e["last"] or last)
        ev = threat_evidence.normalize_event(e, now=now, families=threat_evidence.EDGE_SOURCES)
        if ev is not None:
            out.append(ev)
    return out, stats


# The traps that a visitor does not walk into by accident: a credential the Worker planted being used, and a sign-in
# to a decoy service. With the operator's setting on, one hit on either is a decision of its own.
PLANTED_TOKENS = ("canary", "decoylogin")

# A bait path is a file that should never be public (.env, .git, a SQL dump), so a request that the visitor's own
# tool made for one is a decision, and not one attempt of ten. The WordPress traps (debug log, wp-includes, the user
# list) sit on sites that are not WordPress, so they count too. So do a decoy host name (only DNS brute force finds
# it) and the fake .git (only a dumper walks it). The word is "made": a page can make a visitor's browser ask for any
# of them (an image tag is enough), so a request that a page caused is set aside (page_caused) and a line from a
# script that does not say how the request was made is one attempt like a login hit (see trap_events).
BAIT_TOKENS = ("bait", "wpprobe", "wpenum", "decoy", "gitdump")

# The first script whose lines say how the request was made (docs/honeypot-worker.md, docs/honeypot-traps.md).
SCRIPT_VERSION = 2


def page_caused(h):
    """True when a page, and not the visitor, made the browser send this request, so the visitor did not choose to ask for the path.

    A browser sends Sec-Fetch-Site, -Mode and -Dest on every request it makes, and a page cannot remove or change them. A request
    typed into the address bar says `none`, a navigation or a form post inside the site says `same-origin` with `navigate` and
    `document`, and a tool says nothing. Everything else was made for a page: a request from another site or another subdomain, an
    image, a script, a frame, a fetch(). A browser too old to send the headers names the page in its Referer or its Origin, and
    a host other than the trap's own is a page of somebody else's. A tool that writes these headers itself can have its requests
    set aside by doing so, which costs it the report and nothing else."""
    site, mode, dest = h.get("sfs") or "", h.get("sfm") or "", h.get("sfd") or ""
    if site in ("cross-site", "same-site"):
        return True
    if mode not in ("", "navigate") or dest not in ("", "document"):
        return True
    if site == "same-origin" and not (mode == "navigate" and dest == "document"):
        return True
    own = h.get("host") or ""
    return any(h.get(k) and h.get(k) != own for k in ("ref", "org"))


def trap_events(hits, now=None, decided_tokens=(), samples=False):
    """(events, stats). One summary per address: hits per trap kind, and the
    Worker's decision when it banned the address. Each log line is one hit. The
    Worker samples the lines of a source it can never ban, so a flood is
    undercounted here, never overstated.

    `decided_tokens` are trap kinds that count as decided on a single hit, banned
    or not (see PLANTED_TOKENS); the default is the Worker's own word only. They
    count only on a line from a script that says how the request was made
    (SCRIPT_VERSION): a line that does not is one attempt, because nothing in it
    tells a visitor's own request from one that a page caused. A request that a
    page caused (page_caused) is not a hit at all, whatever the Worker did with it.
    `samples` (the operator's setting) keeps the method and path the Worker logged
    with a hit, as up to three samples per address.

    stats['older'] counts the kept lines from a script that does not say how the
    request was made, so the page can tell the operator to replace it."""
    now = int(now or time.time())
    stats = {"hits": len(hits), "kept": 0, "ignored": {}, "older": 0}
    per_ip = {}

    def drop(why):
        stats["ignored"][why] = stats["ignored"].get(why, 0) + 1

    for h in hits:
        action = h.get("action", "")
        if action in _TRAP_SKIPPED:
            drop("own_or_shared_address")
            continue
        vouched = _int(h.get("v")) >= SCRIPT_VERSION
        if vouched and page_caused(h):
            drop("page_request")
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
        if action in _TRAP_DECIDED or (vouched and token in decided_tokens):
            e["trp"] += 1
        if not vouched:
            stats["older"] += 1
        at = int(h.get("at") or 0)
        if at:
            e["first"] = at if not e["first"] else min(e["first"], at)
            e["last"] = max(e["last"], at)
        if samples and h.get("path"):
            _keep_samples(e, "trap", [{"m": h.get("method"), "p": h.get("path"), "t": at}])
        stats["kept"] += 1
    out = []
    for e in per_ip.values():
        e["first"] = e["first"] or now
        e["last"] = e["last"] or now
        ev = threat_evidence.normalize_event(e, now=now, families=threat_evidence.EDGE_SOURCES)
        if ev is not None:
            out.append(ev)
    return out, stats
