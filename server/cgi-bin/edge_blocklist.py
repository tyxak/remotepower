"""Edge blocklist: keep one Cloudflare IP list up to date.

What cf-waf did for the operator, inside RemotePower. RemotePower builds one list of
addresses from the sources the operator picks and makes an account list in Cloudflare
match it, so the rules that already say `ip.src in $name` keep working and nothing
else changes. RemotePower writes the list and nothing else: the rules that use it
stay the operator's.

Sources, in the order they win when the list is full:

  always      the operator's own entries
  own         what RemotePower itself found: addresses it reported, or that scored
              high, and were seen lately
  abuseipdb   AbuseIPDB's blacklist
  sniffcat    SniffCat's blacklist

This module is the pure half: request building, response parsing, and the choice of
what goes in the list. It never opens a socket; the caller passes the HTTP in, as
ip_intel and edge_evidence do.

What it will not do, whatever a source says: put an address in the list that the
operator's never-block list, allow-list, fleet, recent logins or Cloudflare itself
covers; put in a private or reserved address; put in a range wider than /16 (IPv4) or
/32 (IPv6); or let a sync that would empty or halve the list through unasked.
"""

import ipaddress
import json
import re
import urllib.parse

import edge_evidence
import ip_intel
import threat_evidence

CF_API = "https://api.cloudflare.com/client/v4"

NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,49}")
MARKER = "Managed by RemotePower"
PLAN_CAP = 10000  # custom list items on Free, Pro and Business; one pool for every list
PER_PAGE = 500
MAX_PAGES = 40
MAX_ALWAYS = 1000
MIN_V4_PREFIX = 16
MIN_V6_PREFIX = 32
_CLOUDFLARE_NETS = tuple(ipaddress.ip_network(c) for c in threat_evidence.CLOUDFLARE_RANGES)

SOURCES = ("always", "own", "abuseipdb", "sniffcat")
CALLS_PER_DAY = 4  # one blacklist download per source and read; AbuseIPDB's base tier allows five
STALE_SOURCE_S = 3 * 86400  # a source that did not answer is read from its last copy this long
SHRINK_FLOOR = 0.5
SHRINK_MIN_ITEMS = 200
OWN_SCORE_DEFAULT = 75


# ── spelling ───────────────────────────────────────────────────────────────────


def valid_name(name):
    """Cloudflare's rule for a list name: lower-case letters, digits and underscores."""
    return isinstance(name, str) and bool(NAME_RE.fullmatch(name))


def canonical(value):
    """The one spelling of an address or network, or None. A host route is the bare
    address, and an IPv6 address is the compressed form, so a list read back from
    Cloudflare compares equal to what was sent."""
    try:
        net = ipaddress.ip_network(str(value or "").strip(), strict=False)
    except ValueError:
        return None
    if net.prefixlen == net.max_prefixlen:
        return str(net.network_address)
    return str(net)


def _network(canon):
    return ipaddress.ip_network(canon, strict=False)


def is_public(canon):
    """True for a globally routable address or network."""
    net = _network(canon)
    if net.prefixlen == net.max_prefixlen:
        return ip_intel.is_public(str(net.network_address))
    return bool(net.is_global) and not net.is_multicast


def too_wide(canon):
    net = _network(canon)
    return net.prefixlen < (MIN_V4_PREFIX if net.version == 4 else MIN_V6_PREFIX)


def clean_entries(raw, limit=MAX_ALWAYS):
    """(entries, error) for addresses and networks typed one per line or separated
    by commas. `#` starts a comment. The error names the first entry that is not
    acceptable, so the page can say which."""
    items = raw if isinstance(raw, list) else str(raw or "").replace(",", "\n").splitlines()
    out, seen = [], set()
    for it in items:
        text = str(it).split("#", 1)[0].strip()
        if not text:
            continue
        c = canonical(text)
        if not c:
            return [], f"Not an address or network: {text[:60]}"
        if not is_public(c):
            return [], f"Not a public address: {text[:60]}"
        if too_wide(c):
            return [], (f"Too wide: {text[:60]} (the widest allowed is /{MIN_V4_PREFIX} for IPv4 "
                        f"and /{MIN_V6_PREFIX} for IPv6)")
        if c not in seen:
            seen.add(c)
            out.append(c)
        if len(out) >= limit:
            break
    return out, ""


def protected_reason(canon, protected):
    """Why this entry must stay out of the list, or ''. `protected` holds the
    networks of the RemotePower server, the fleet, the operator's allow-list and
    the never-block list. A range that overlaps one of them is kept out whole."""
    net = _network(canon)
    if net.prefixlen == net.max_prefixlen:
        return ip_intel.never_block_reason(str(net.network_address), protected)
    if not is_public(canon):
        return "not a public address"
    for c in _CLOUDFLARE_NETS:
        if c.version == net.version and c.overlaps(net):
            return "a Cloudflare edge address"
    for p in protected or []:
        if p.version == net.version and p.overlaps(net):
            return "on the never-block list"
    return ""


# ── the sources ────────────────────────────────────────────────────────────────


def _detail(body):
    if isinstance(body, dict):
        for k in ("message", "error", "detail"):
            v = body.get(k)
            if isinstance(v, str) and v:
                return "".join(ch for ch in v if ch.isprintable())[:120]
        errs = body.get("errors")
        if isinstance(errs, list) and errs and isinstance(errs[0], dict):
            return "".join(ch for ch in str(errs[0].get("detail") or errs[0].get("message") or "")
                           if ch.isprintable())[:120]
    return ""


def _source_error(status, body, who):
    d = _detail(body)
    if status == 0:
        return {"ok": False, "error": "unreachable"}
    if status == 429:
        return {"ok": False, "rate_limited": True, "error": f"{who} says the daily limit is used up"}
    if status == 401:
        return {"ok": False, "error": f"{who} rejected the API key"}
    if status == 403:
        if "quota" in d.lower():
            return {"ok": False, "no_quota": True, "error": f"{who} has no blacklist quota for this key"}
        return {"ok": False, "error": f"{who} refused the request (HTTP 403)" + (f": {d}" if d else "")}
    return {"ok": False, "error": d or f"{who} answered HTTP {status}"}


def abuseipdb_request(key, confidence, limit):
    """GET /blacklist. `confidenceMinimum` is a subscriber feature on AbuseIPDB's
    base tier, which answers with its own floor instead of an error; `limit` is
    capped by the plan the same quiet way."""
    q = urllib.parse.urlencode(
        {"confidenceMinimum": max(25, min(100, int(confidence))), "limit": max(1, min(500000, int(limit)))}
    )
    return {
        "method": "GET",
        "url": f"{ip_intel.ABUSEIPDB_BASE}/blacklist?{q}",
        "headers": {"Key": key, "Accept": "application/json"},
        "body": None,
        "timeout": 40,
        "max_bytes": 8_000_000,
    }


def abuseipdb_parse(status, body):
    if status != 200 or not isinstance(body, dict):
        return _source_error(status, body, "AbuseIPDB")
    rows = body.get("data")
    if not isinstance(rows, list):
        return {"ok": False, "error": "AbuseIPDB's answer was not a list"}
    return {"ok": True, "ips": _addresses(r.get("ipAddress") for r in rows if isinstance(r, dict))}


def sniffcat_request(key, confidence, limit):
    """GET /blacklist as JSON. `confidenceMin` is required and runs 30 to 100;
    `limit` runs 10 to 100,000."""
    q = urllib.parse.urlencode(
        {"type": "json", "confidenceMin": max(30, min(100, int(confidence))),
         "limit": max(10, min(100000, int(limit)))}
    )
    return {
        "method": "GET",
        "url": f"{ip_intel.SNIFFCAT_BASE}/blacklist?{q}",
        "headers": {"X-Secret-Token": key, "Accept": "application/json"},
        "body": None,
        "timeout": 40,
        "max_bytes": 8_000_000,
    }


def sniffcat_parse(status, body):
    if status != 200 or not isinstance(body, dict) or body.get("success") is False:
        return _source_error(status, body, "SniffCat")
    rows = body.get("reports")
    if not isinstance(rows, list):
        return {"ok": False, "error": "SniffCat's answer was not a list"}
    return {"ok": True, "ips": _addresses(r.get("ip") for r in rows if isinstance(r, dict))}


def _addresses(values):
    """Canonical public addresses and networks, in the order given, without repeats.
    A blacklist is a list of single addresses; anything else is dropped here and
    never counted as one."""
    out, seen = [], set()
    for v in values:
        c = canonical(v)
        if c and c not in seen and is_public(c) and not too_wide(c):
            seen.add(c)
            out.append(c)
    return out


# ── the choice ─────────────────────────────────────────────────────────────────


def own_candidates(attackers, now, min_score, days, reported_counts=True):
    """Addresses RemotePower itself found, strongest first: reported to a service
    (it had enough evidence to say so in public) or scored `min_score` or more, and
    seen within `days`. `attackers` is the Threat intel store's address record."""
    cutoff = int(now) - max(1, int(days)) * 86400
    out = []
    for ip, att in (attackers or {}).items():
        if not isinstance(att, dict) or int(att.get("last_seen") or 0) < cutoff:
            continue
        verdict = att.get("verdict") if isinstance(att.get("verdict"), dict) else {}
        score = int(verdict.get("score") or 0)
        if verdict.get("whitelisted"):
            continue
        reported = bool(att.get("reported")) and reported_counts
        if not (reported or score >= int(min_score)):
            continue
        c = canonical(ip)
        if c:
            out.append((c, score, int(att.get("last_seen") or 0)))
    out.sort(key=lambda r: (-r[1], -r[2], r[0]))
    return [r[0] for r in out]


def build(always, own, abuse, sniff, capacity, protected):
    """The list to make: {'items': [(entry, source)], 'kept': {source: n}, 'offered':
    {source: n}, 'trimmed': n, 'dropped': {'protected': n}}. Each source is taken in
    its own order, in the order of SOURCES; an entry is kept once, under the first
    source that offered it; nothing is added past `capacity`."""
    capacity = max(0, int(capacity))
    items, seen = [], set()
    kept = {s: 0 for s in SOURCES}
    offered = {s: 0 for s in SOURCES}
    dropped = {"protected": 0}
    trimmed = 0
    for source, entries in (("always", always), ("own", own), ("abuseipdb", abuse), ("sniffcat", sniff)):
        for e in entries or []:
            c = canonical(e)
            if not c or c in seen:
                continue
            if protected_reason(c, protected):
                dropped["protected"] += 1
                continue
            seen.add(c)
            offered[source] += 1
            if len(items) >= capacity:
                trimmed += 1
                continue
            items.append((c, source))
            kept[source] += 1
    return {"items": items, "kept": kept, "offered": offered, "trimmed": trimmed, "dropped": dropped}


def diff(current, desired):
    """(added, removed) as sorted lists, for two collections of canonical entries."""
    cur, want = set(current), set(desired)
    return sorted(want - cur), sorted(cur - want)


def hold_reason(current_n, desired_n):
    """Why a sync must not run unasked, or ''. A source that failed quietly, a key
    that lapsed or a typo in a threshold all look like "the list should be much
    smaller"; none of them should empty a list that rules depend on."""
    if current_n > 0 and desired_n == 0:
        return "Nothing would be left in the list."
    if current_n >= SHRINK_MIN_ITEMS and desired_n < current_n * SHRINK_FLOOR:
        return "The list would shrink by more than half."
    return ""


def capacity_for(setting, lists, own_id):
    """How many entries the list may hold: the operator's ceiling less what the
    account's other lists use. Custom list items are one pool across every IP list,
    and a hostname or ASN list has a pool of its own."""
    used = 0
    for lst in lists or []:
        if lst.get("id") != own_id and lst.get("kind") in ("ip", "redirect"):
            used += int(lst.get("num_items") or 0)
    return max(0, int(setting) - used)


def description(version, sources):
    names = ", ".join(sources) if sources else "none"
    return (f"{MARKER} v{version}. Sources: {names}. "
            "Do not edit manually: changes are overwritten on the next sync.")[:300]


def managed(desc):
    return isinstance(desc, str) and desc.startswith(MARKER)


# ── Cloudflare's lists ─────────────────────────────────────────────────────────


def _headers(token):
    return {
        "Authorization": "Bearer " + token,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _ids(account, *rest):
    """Every id that reaches a URL is 32 hex digits. A missing one is an invalid
    one: None must not become the text "None" in a path."""
    if not edge_evidence.valid_id(account):
        raise ValueError("invalid account id")
    for r in rest:
        if not edge_evidence.valid_id(r):
            raise ValueError("invalid id")


def lists_request(token, account):
    _ids(account)
    return {"method": "GET", "url": f"{CF_API}/accounts/{account}/rules/lists", "headers": _headers(token),
            "body": None}


def items_request(token, account, list_id, cursor=""):
    _ids(account, list_id)
    q = {"per_page": PER_PAGE}
    if cursor:
        q["cursor"] = str(cursor)[:200]
    return {"method": "GET",
            "url": f"{CF_API}/accounts/{account}/rules/lists/{list_id}/items?{urllib.parse.urlencode(q)}",
            "headers": _headers(token), "body": None, "timeout": 25, "max_bytes": 4_000_000}


def create_request(token, account, name, desc):
    _ids(account)
    if not valid_name(name):
        raise ValueError("invalid list name")
    return {"method": "POST", "url": f"{CF_API}/accounts/{account}/rules/lists", "headers": _headers(token),
            "body": json.dumps({"name": name, "kind": "ip", "description": desc[:500]}).encode()}


def describe_request(token, account, list_id, desc):
    _ids(account, list_id)
    return {"method": "PUT", "url": f"{CF_API}/accounts/{account}/rules/lists/{list_id}",
            "headers": _headers(token), "body": json.dumps({"description": desc[:500]}).encode()}


def replace_request(token, account, list_id, entries):
    """PUT the whole list. Cloudflare answers at once with an operation id, removes
    every existing item and adds these; only one such operation can be pending for
    an account at a time."""
    _ids(account, list_id)
    body = [{"ip": e, "comment": f"RemotePower: {src}"} for e, src in entries]
    return {"method": "PUT", "url": f"{CF_API}/accounts/{account}/rules/lists/{list_id}/items",
            "headers": _headers(token), "body": json.dumps(body).encode(), "timeout": 40,
            "max_bytes": 1_000_000}


def operation_request(token, account, operation_id):
    _ids(account, operation_id)
    return {"method": "GET",
            "url": f"{CF_API}/accounts/{account}/rules/lists/bulk_operations/{operation_id}",
            "headers": _headers(token), "body": None}


def _failed(status, body):
    res = edge_evidence._cf_error(status, body)
    if isinstance(body, dict) and isinstance(body.get("errors"), list) and body["errors"]:
        first = body["errors"][0] if isinstance(body["errors"][0], dict) else {}
        code = str(first.get("code") or "")
        msg = str(first.get("message") or "").lower()
        if code == "10019" or "limit" in msg and "list" in msg:
            res["list_limit"] = True
        if "in progress" in msg or "pending" in msg:
            res["busy"] = True
    return res


def _ok(status, body):
    return status == 200 and isinstance(body, dict) and body.get("success") is not False


def parse_lists(status, body):
    if not _ok(status, body):
        return _failed(status, body)
    out = []
    for r in body.get("result") or []:
        if isinstance(r, dict) and edge_evidence.valid_id(r.get("id")):
            out.append({
                "id": r["id"],
                "name": str(r.get("name") or "")[:60],
                "kind": str(r.get("kind") or ""),
                "description": str(r.get("description") or "")[:500],
                "num_items": int(r.get("num_items") or 0),
            })
    return {"ok": True, "lists": out}


def parse_items(status, body):
    if not _ok(status, body):
        return _failed(status, body)
    ips = []
    for r in body.get("result") or []:
        if isinstance(r, dict):
            c = canonical(r.get("ip"))
            if c:
                ips.append(c)
    info = body.get("result_info") if isinstance(body.get("result_info"), dict) else {}
    cursors = info.get("cursors") if isinstance(info.get("cursors"), dict) else {}
    return {"ok": True, "ips": ips, "cursor": str(cursors.get("after") or "")}


def parse_created(status, body):
    if not _ok(status, body):
        return _failed(status, body)
    res = body.get("result")
    if isinstance(res, dict) and edge_evidence.valid_id(res.get("id")):
        return {"ok": True, "id": res["id"]}
    return {"ok": False, "error": "Cloudflare did not return the new list"}


def parse_done(status, body):
    return {"ok": True} if _ok(status, body) else _failed(status, body)


def parse_replace(status, body):
    if not _ok(status, body):
        return _failed(status, body)
    res = body.get("result")
    op = res.get("operation_id") if isinstance(res, dict) else None
    if edge_evidence.valid_id(op):
        return {"ok": True, "operation_id": op}
    return {"ok": False, "error": "Cloudflare did not return an operation id"}


def parse_operation(status, body):
    """{'ok': True, 'state': 'pending'|'running'|'completed'|'failed', 'error'}."""
    if not _ok(status, body):
        return _failed(status, body)
    res = body.get("result") if isinstance(body.get("result"), dict) else {}
    state = str(res.get("status") or "").lower()
    if state not in ("pending", "running", "completed", "failed"):
        state = "pending"
    return {"ok": True, "state": state, "error": "".join(
        ch for ch in str(res.get("error") or "") if ch.isprintable())[:160]}
