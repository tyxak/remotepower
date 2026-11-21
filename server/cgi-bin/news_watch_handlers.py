"""RemotePower — Security news watch: feeds of security news that raise an alert, and start a scan, when an item reports a critical flaw (8.0.2)

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

Constants stay in api.py and are read here through A. The reading of a feed and the rules for "critical" and "relevant" are pure logic in a sibling module (`news_watch`).

What this module does. The settings (on or off, the feeds, which critical items count, what happens when one does) are kept in the settings document under
`news_watch`; what has been read (the ids already seen for each feed, the last read, the critical items found) is kept in `news_watch.json`. Every EVERY_S seconds the
sweep claims the slot, and a detached process reads each feed once through the SSRF-safe opener. Then, under the lock of the store, it records what is new and decides: an
item counts when it is critical and, with the scope "relevant", names software some host has installed. A counting item raises an alert of event `security_news_critical`,
and with the action "scan" the first one in SCAN_GAP_S starts a scan of every host, taking the scan slot the way the button does. The alerts go out after the store was saved,
so a failed save cannot send one twice. Everything is off until an operator switches it on. An operator can clear the red ! of an item (`handle_news_watch_clear`): the item
keeps its place in the list and stops counting for the mark of the sidebar and the tab.
"""

import hashlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import news_watch as N


class _ApiNamespace:
    __slots__ = ("_g",)

    def __init__(self, g):
        self._g = g

    def __getattr__(self, name):
        try:
            return self._g[name]
        except KeyError:
            raise AttributeError(f"api namespace has no {name!r}") from None


A = None


def bind(api_globals):
    """Called once by api.py right after importing this module, with
    api's ``globals()``."""
    global A
    A = _ApiNamespace(api_globals)


EVERY_S = 1800  # seconds between two reads of the feeds; the feeds themselves change about once an hour
SCAN_GAP_S = 6 * 3600  # at most one scan started by the watch in this time, whatever the feeds say
MAX_ALERTS_PER_RUN = 5  # alerts one read raises; a critical item beyond it is listed and says so
MANUAL_GAP_S = 60  # "Check now" is refused when the feeds were read less than this long ago
FEED_FAIL_STREAK = 6  # reads of one feed that fail in a row before an alert says so: three hours at the cadence of EVERY_S
FETCH_TIMEOUT_S = 10  # for each step of a connection
FETCH_DEADLINE_S = 25  # for the whole of one feed, so a server that sends a byte at a time cannot hold the read
RUN_BUDGET_S = 45  # for all the feeds of one read; a feed past it is read next time
MAX_SOFTWARE = 8  # names of software shown for one item
MAX_CLEAR_IDS = 100  # ids read from one "clear" request; the list holds N.MAX_LISTED items, so more could never match


# ── who is asking ────────────────────────────────────────────────────────────


def _is_operator():
    """An administrator, and on a multi-tenant install only the platform operator. The feeds, the scan and the software names an item matches
    all describe the whole installation, so they are not a tenant's to read or change."""
    try:
        return bool(A._caller_is_admin()) and (not A._tenancy_enforced() or A._caller_is_superadmin())
    except Exception:
        return False


# ── reading a feed ───────────────────────────────────────────────────────────


def _fetch(url):
    """The bytes of a feed, at most MAX_FEED_BYTES, read through the opener that checks the address each connection really reaches.

    A redirect is followed (the feed of The Hacker News answers from another host), and every hop is checked again at connect time. The read
    is made in blocks against a deadline: a timeout counts the wait for one block, so a server that sends a byte every few seconds would
    otherwise hold the read for as long as it liked."""
    parts = urllib.parse.urlsplit(url)
    if A._url_targets_local_or_meta(parts, allow_loopback=False):
        raise ValueError("this address is a loopback, link-local or unspecified address, which a feed is not read from")
    opener = A._ssrf_safe_opener(allow_loopback=False, ssl_ctx=A._get_ssl_context(), no_redirect=False, enforce_ip=True)
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": f"RemotePower/{A.SERVER_VERSION}",
            "Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.9, */*;q=0.5",
        },
    )
    deadline = time.monotonic() + FETCH_DEADLINE_S
    chunks, size = [], 0
    with opener.open(req, timeout=FETCH_TIMEOUT_S) as resp:
        while True:
            block = resp.read1(65536)
            if not block:
                break
            size += len(block)
            if size > N.MAX_FEED_BYTES:
                raise ValueError(f"the feed is larger than {N.MAX_FEED_BYTES // 1_000_000} MB")
            if time.monotonic() > deadline:
                raise TimeoutError("the feed took too long to arrive")
            chunks.append(block)
    return b"".join(chunks)


def _feed_key(url):
    """What an alert about one feed is told apart by: a short hash of its address. Two feeds can have the same name, and the address itself stays out of the alert."""
    return "feed:" + hashlib.sha256(str(url).encode("utf-8", "replace")).hexdigest()[:12]


def _feed_event(kind, url, rec, streak=0):
    """(event, payload) for a feed that keeps failing (`failing`), is read again (`recovered`) or stopped being watched (`removed`, which closes the same alert).
    The payload names the feed by its title or else its host, and says what the page says; the address is not in it."""
    rec = rec if isinstance(rec, dict) else {}
    label = (str(rec.get("title") or "")[:120] or urllib.parse.urlsplit(str(url)).hostname or "a feed")
    if kind == "failing":
        err = N._clean(str(rec.get("last_error") or ""), 160) or "no answer"
        return "security_news_feed_failing", {"label": label, "dest": _feed_key(url), "detail": f"{label} could not be read {streak} times in a row. The last answer: {err}"[:300]}
    detail = "This feed is no longer watched." if kind == "removed" else f"{label} is read again."
    return "security_news_feed_recovered", {"label": label, "dest": _feed_key(url), "detail": detail}


def _fire_feed_events(events):
    """Raise the alerts about feeds, after the store is saved: what is fired here is never sent twice, and a failure to send is said and not raised."""
    for event, payload in events:
        try:
            A.fire_webhook(event, payload)
        except Exception as ex:
            sys.stderr.write(f"[remotepower] news watch: the alert about a feed could not be raised: {type(ex).__name__}: {ex}\n")


def _close_feed_alerts(urls):
    """Close the open alert of every feed in `urls` (None: of every feed), for a feed that stopped being watched: removed from the list, or the whole watch switched off. A read-only
    look first, so that a settings change with nothing open costs nothing."""
    try:
        st = _store_dict((A._load_ro(A.NEWS_WATCH_FILE) or {}) if A.backend_exists(A.NEWS_WATCH_FILE) else {})
        fst = st.get("feeds") if isinstance(st.get("feeds"), dict) else {}
        if not any(isinstance(r, dict) and r.get("fail_alerted") is True and (urls is None or u in urls) for u, r in fst.items()):
            return
        events = []
        with A._LockedUpdate(A.NEWS_WATCH_FILE) as doc:
            fst = doc.get("feeds") if isinstance(doc.get("feeds"), dict) else {}
            for u, r in fst.items():
                if isinstance(r, dict) and r.get("fail_alerted") is True and (urls is None or u in urls):
                    r["fail_alerted"] = False
                    events.append(_feed_event("removed", u, r))
        _fire_feed_events(events)
    except Exception as e:
        sys.stderr.write(f"[remotepower] news watch: the alerts about feeds could not be closed: {type(e).__name__}\n")


def _why(e):
    """A short sentence for a failed read: what the page shows next to the feed. Never more than 160 characters, and no markup."""
    if isinstance(e, urllib.error.HTTPError):
        text = f"the server answered HTTP {e.code}"
    elif isinstance(e, urllib.error.URLError):
        text = f"could not connect ({e.reason})"
    elif isinstance(e, (TimeoutError, OSError)) and "timed out" in str(e).lower():
        text = "the server did not answer in time"
    elif isinstance(e, (ValueError, TimeoutError, OSError)):
        text = str(e) or type(e).__name__
    else:
        text = type(e).__name__
    return N._clean(text, 160) or "failed"


# ── the poll ─────────────────────────────────────────────────────────────────


def _store_dict(value):
    return value if isinstance(value, dict) else {}


def _detail(it, names, scan, running=()):
    """The sentence an alert carries: why the item counts as critical, the CVE ids it names, whether it names software that runs on the hosts or is only installed,
    and what the watch did about it."""
    texts = {
        "critical": "called critical",
        "zero_day": "zero-day",
        "exploited": "reported as exploited",
        "unauth_exec": "code execution without signing in",
        "kev": "a CVE on the CISA known-exploited list",
    }
    parts = []
    for r in it["reasons"]:
        if r == "cvss":
            parts.append(f"CVSS {it['cvss']:g}" if isinstance(it.get("cvss"), float) else "CVSS 9 or more")
        elif r in texts:
            parts.append(texts[r])
    text = ", ".join(parts)
    if it["cves"]:
        text += "; " + ", ".join(it["cves"][:3])
    if running:
        text += ". It names software that runs on your hosts: " + ", ".join(running[:MAX_SOFTWARE]) + "."
    elif names:
        text += ". It names software installed on your hosts."
    else:
        text += ". It is not matched to software on your hosts."
    if scan == "started":
        text += " A scan of all hosts was started."
    return text[:300]


def poll_once(now=None, fetch=None):
    """Read every feed once, record what is new, raise the alerts and start the scan. Returns what happened, for "Check now".

    The feeds are read first, outside any lock. Then the store is updated under its lock, and what is new is decided from the store as it is
    there, so two reads that overlap cannot both find the same item new. The scan is started and the alerts are raised after the lock is
    released, in that order, so an alert can say that a scan was started."""
    now = int(now if now is not None else time.time())
    fetch = fetch or _fetch
    cfg = N.settings(A._config_ro().get("news_watch"))
    feeds = cfg["feeds"]
    try:
        kev = set(A._kev_epss()[0])
    except Exception:
        kev = set()
    started = time.monotonic()
    read = {}
    for url in feeds:
        if time.monotonic() - started > RUN_BUDGET_S:
            read[url] = ("error", "not read this time: the other feeds took too long")
            continue
        try:
            read[url] = ("ok", N.parse_feed(fetch(url)))
        except Exception as e:
            read[url] = ("error", _why(e))
            if isinstance(e, urllib.error.HTTPError):
                e.close()  # the error is also the open response, and nothing reads it

    fleet = []  # what the hosts have and run, built once, and only when an item needs it
    running_of = {}  # item id -> the software it names that runs on some host, for the alert's sentence

    def names_for(text):
        if not fleet:
            try:
                containers = A._load_ro(A.CONTAINERS_FILE) if A.backend_exists(A.CONTAINERS_FILE) else {}
                fleet.append(N.fleet_software(A._load_ro(A.PACKAGES_FILE) or {}, A._load_ro(A.DEVICES_FILE) or {}, containers, now, cfg["words"]))
            except Exception as e:
                sys.stderr.write(f"[remotepower] news watch: what the hosts have could not be read: {type(e).__name__}\n")
                fleet.append({"installed": set(), "running": {}})
        names, running = N.mentions(text, fleet[0])
        return names[:MAX_SOFTWARE], running[:MAX_SOFTWARE]

    alerts, scan_wanted, summary = [], False, {"feeds": len(feeds), "failed": 0, "new_critical": 0, "alerts": 0, "scan": None}
    feed_events = []  # the alerts about the feeds themselves, raised after the store is saved
    with A._LockedUpdate(A.NEWS_WATCH_FILE) as st:
        fst = st.get("feeds")
        if not isinstance(fst, dict):
            fst = st["feeds"] = {}
        for gone in [k for k in fst if k not in feeds]:
            if _store_dict(fst.get(gone)).get("fail_alerted") is True:
                feed_events.append(_feed_event("removed", gone, _store_dict(fst.get(gone))))      # its alert is closed with it
            fst.pop(gone)  # a feed taken out of the list loses its record
        listed = [i for i in (st.get("items") if isinstance(st.get("items"), list) else []) if isinstance(i, dict)]
        have = {i.get("id") for i in listed}
        fresh_items = []
        for url in feeds:
            kind, got = read[url]
            prev = _store_dict(fst.get(url))
            if kind == "error":
                prev["last_try"] = now
                prev["last_error"] = got
                streak = prev.get("fail_streak")
                prev["fail_streak"] = streak + 1 if isinstance(streak, int) and not isinstance(streak, bool) else 1
                if prev["fail_streak"] >= FEED_FAIL_STREAK and prev.get("fail_alerted") is not True:
                    prev["fail_alerted"] = True      # once, on the transition: the next read that works clears it and raises the recovery
                    feed_events.append(_feed_event("failing", url, prev, prev["fail_streak"]))
                fst[url] = prev
                summary["failed"] += 1
                continue
            was_baselined = prev.get("baselined") is True
            rec, new = N.process(prev, got["items"], now, kev, cfg["critical_words"])
            rec.update(title=got["title"] or str(prev.get("title") or ""), last_try=now, last_ok=now, last_error="", fail_streak=0, last_new=len(new))
            if prev.get("fail_alerted") is True:
                feed_events.append(_feed_event("recovered", url, rec))
            rec["fail_alerted"] = False
            rec["last_critical"] = sum(1 for it in new if it["critical"])
            fst[url] = rec
            label = rec["title"] or urllib.parse.urlsplit(url).hostname or ""
            for it in new:
                if not it["critical"] or it["id"] in have:
                    continue
                have.add(it["id"])
                names, running_of[it["id"]] = names_for(it["text"])
                entry = {
                    "id": it["id"], "feed": label[:120], "title": it["title"], "link": it["link"], "published": it["published"],
                    "seen_at": now, "reasons": it["reasons"], "cves": it["cves"], "cvss": it["cvss"], "software": names,
                }
                counts = cfg["scope"] == "all" or (cfg["scope"] == "relevant" and names) or (cfg["scope"] == "running" and running_of[it["id"]])
                if not it["fresh"]:
                    entry["outcome"] = "baseline" if not was_baselined else "stale"
                elif cfg["action"] == "list" or not counts:
                    entry["outcome"] = "listed"
                elif len(alerts) >= MAX_ALERTS_PER_RUN:
                    entry["outcome"] = "over_limit"
                else:
                    entry["outcome"] = "alerted"
                    alerts.append(entry)
                fresh_items.append(entry)
        summary["new_critical"] = len(fresh_items)
        if alerts and cfg["action"] == "scan":
            last_scan = st.get("last_scan_at")
            if isinstance(last_scan, int) and not isinstance(last_scan, bool) and 0 <= now - last_scan < SCAN_GAP_S:
                for e in alerts:
                    e["outcome"] = "scan_waiting"
                summary["scan"] = "waiting"
            else:
                scan_wanted = True
                st["last_scan_at"] = now
                for e in alerts:
                    e["outcome"] = "scanned"
        st["items"] = (fresh_items + listed)[: N.MAX_LISTED]
        st["last_run"] = now
    # the store is saved: what follows may be retried by nobody, and is never sent twice
    scan_state = summary["scan"]
    if scan_wanted:
        try:
            scan_state, hosts = A.cve_handlers_mod.queue_fleet_scan("news-watch")
        except Exception as e:
            sys.stderr.write(f"[remotepower] news watch: the scan could not be started: {type(e).__name__}: {e}\n")
            scan_state, hosts = "error", 0
        summary["scan"] = scan_state
        if scan_state != "started":
            _mark_scan_refused([e["id"] for e in alerts])
        else:
            try:
                A.audit_log("news-watch", "news_watch_scan", f"hosts={hosts} items={len(alerts)}")
            except Exception:
                pass
    _fire_feed_events(feed_events)
    for e in alerts:
        payload = {
            "title": e["title"], "url": e["link"], "source": e["feed"], "severity": "high" if e["software"] else "medium",
            "detail": _detail(e, e["software"], scan_state if scan_wanted else None, running_of.get(e["id"], ())),
        }
        try:
            A.fire_webhook("security_news_critical", payload)
            summary["alerts"] += 1
        except Exception as ex:
            sys.stderr.write(f"[remotepower] news watch: the alert could not be raised: {type(ex).__name__}: {ex}\n")
    return summary


def _mark_scan_refused(ids):
    """The scan was wanted and not started (one was already running, no host has a package list): the items say so instead of 'scan started'.
    The time of the last scan is put back, so the next critical item may try again."""
    try:
        with A._LockedUpdate(A.NEWS_WATCH_FILE) as st:
            for i in st.get("items") if isinstance(st.get("items"), list) else []:
                if isinstance(i, dict) and i.get("id") in ids and i.get("outcome") == "scanned":
                    i["outcome"] = "scan_refused"
            st.pop("last_scan_at", None)
    except Exception as e:
        sys.stderr.write(f"[remotepower] news watch: the scan note could not be saved: {type(e).__name__}\n")


def run_news_watch_if_due():
    """Cadence sweep: every EVERY_S seconds, read the feeds. Cheap when the watch is off or it is not due: one read of the settings document.

    The slot is claimed under the lock of the settings document, with the time looked at again inside it, so two requests that both find it
    due start one read. The read itself runs in a detached process (it fetches over the network, which must never hold a request)."""
    cfg = A._config_ro()
    watch = N.settings(cfg.get("news_watch"))
    if not watch["enabled"] or not watch["feeds"]:
        return
    now = int(time.time())

    def recent(c):
        last = c.get("last_news_watch_run")
        return isinstance(last, (int, float)) and not isinstance(last, bool) and 0 <= now - last < EVERY_S

    if recent(cfg):
        return
    with A._LockedUpdate(A.CONFIG_FILE) as cfg_w:
        if recent(cfg_w):
            return
        cfg_w["last_news_watch_run"] = now
    A._run_detached(poll_once)


# ── the page ─────────────────────────────────────────────────────────────────


def _num(v):
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _running_now(now):
    """{word: {'hosts', 'world'}} for what the hosts run as they are now (news_watch.running_software). Never raises: no answer is nothing running."""
    try:
        containers = A._load_ro(A.CONTAINERS_FILE) if A.backend_exists(A.CONTAINERS_FILE) else {}
        return N.running_software(A._load_ro(A.DEVICES_FILE) or {}, containers, now)
    except Exception as e:
        sys.stderr.write(f"[remotepower] news watch: what runs on the hosts could not be read: {type(e).__name__}\n")
        return {}


def _public_item(i, running, extra=()):
    """One critical item as the page reads it: every field of the right kind and no other.

    The software it names is read against the hosts as they are now, not as they were when the item was found: `running` lists what runs on some host (with how many
    hosts, and whether a socket of it listens to the Internet), `software` the rest. A word that is neither software people write about nor something that runs (the first
    word of an everyday package name, which an earlier version stored) is not shown."""
    reasons = [r for r in i.get("reasons") or [] if r in N.REASONS] if isinstance(i.get("reasons"), list) else []
    cves = [c for c in i.get("cves") or [] if isinstance(c, str)][: N.MAX_CVES] if isinstance(i.get("cves"), list) else []
    soft = [s for s in i.get("software") or [] if isinstance(s, str)][:MAX_SOFTWARE] if isinstance(i.get("software"), list) else []
    kept = [t for t in soft if t in N.KNOWN_SOFTWARE or t in extra or t in running]
    cvss = i.get("cvss")
    return {
        "id": str(i.get("id") or "")[:32],
        "feed": str(i.get("feed") or "")[:120],
        "title": str(i.get("title") or "")[: N.TITLE_LEN],
        "link": N._link(str(i.get("link") or "")),
        "published": _num(i.get("published")),
        "seen_at": _num(i.get("seen_at")),
        "reasons": reasons,
        "cves": cves,
        "cvss": float(cvss) if isinstance(cvss, (int, float)) and not isinstance(cvss, bool) and cvss == cvss else None,
        "software": [t for t in kept if t not in running],
        "running": [{"name": t, "hosts": running[t]["hosts"], "world": running[t]["world"]} for t in kept if t in running],
        "outcome": i.get("outcome") if i.get("outcome") in N.OUTCOMES else "listed",
        "cleared_at": _num(i.get("cleared_at")),
    }


def _attention_of(items, now):
    """(how many, the newest seen_at) of the items, as _public_item makes them, that the mark counts: found in the last MAX_AGE_S seconds, more than a record made when a feed was
    first read or an item too old to act on, naming software that runs on a host, and not cleared by an operator."""
    n, newest = 0, None
    for i in items:
        at = i["seen_at"]
        if not i["running"] or i["cleared_at"] is not None or i["outcome"] in ("baseline", "stale") or at is None or now - at > N.MAX_AGE_S:
            continue
        n += 1
        newest = at if newest is None or at > newest else newest
    return n, newest


def attention(now):
    """(how many, the newest seen_at) for the mark of the Security news tab and of its entry in the sidebar: (0, None) when the watch is off or nothing needs a look. The
    sidebar's poll asks for it for the platform operator only, and the page remembers, in its own browser, the newest one it has shown. Never raises."""
    try:
        cfg = N.settings(A._config_ro().get("news_watch"))
        if not cfg["enabled"]:
            return 0, None
        st = _store_dict((A._load_ro(A.NEWS_WATCH_FILE) or {}) if A.backend_exists(A.NEWS_WATCH_FILE) else {})
        listed = [i for i in (st.get("items") if isinstance(st.get("items"), list) else []) if isinstance(i, dict)]
        running = _running_now(now) if listed else {}
        if not running:
            return 0, None
        extra = set(cfg["words"])
        return _attention_of([_public_item(i, running, extra) for i in listed], now)
    except Exception as e:
        sys.stderr.write(f"[remotepower] news watch: the mark could not be worked out: {type(e).__name__}\n")
        return 0, None


def _view(now):
    """The whole page for an operator: the settings, how each feed fared at its last read, and the critical items found."""
    cfg = N.settings(A._config_ro().get("news_watch"))
    st = (A._load_ro(A.NEWS_WATCH_FILE) or {}) if A.backend_exists(A.NEWS_WATCH_FILE) else {}
    st = _store_dict(st)
    fst = _store_dict(st.get("feeds"))
    status = []
    for url in cfg["feeds"]:
        r = _store_dict(fst.get(url))
        err = r.get("last_error")
        status.append(
            {
                "url": url,
                "title": str(r.get("title") or "")[:120],
                "last_ok": _num(r.get("last_ok")),
                "last_try": _num(r.get("last_try")),
                "last_error": N._clean(err, 160) if isinstance(err, str) else "",
                "fail_streak": _num(r.get("fail_streak")) or 0,
                "baselined": r.get("baselined") is True,
                "last_new": _num(r.get("last_new")) or 0,
                "last_critical": _num(r.get("last_critical")) or 0,
            }
        )
    running = _running_now(now)
    extra = set(cfg["words"])
    items = [_public_item(i, running, extra) for i in (st.get("items") if isinstance(st.get("items"), list) else []) if isinstance(i, dict)]
    items = items[: N.MAX_LISTED]
    needs_a_look, attention_at = _attention_of(items, now)
    return {
        "editable": True,
        "now": now,
        "enabled": cfg["enabled"],
        "feeds": cfg["feeds"],
        "scope": cfg["scope"],
        "action": cfg["action"],
        "words": cfg["words"],
        "critical_words": cfg["critical_words"],
        "max_words": N.MAX_WORDS,
        "every": EVERY_S,
        "scan_gap": SCAN_GAP_S,
        "max_feeds": N.MAX_FEEDS,
        "last_run": _num(st.get("last_run")),
        "last_scan_at": _num(st.get("last_scan_at")),
        "status": status,
        "items": items,
        "needs_a_look": needs_a_look,
        "attention_at": attention_at,
    }


def handle_news_watch_get():
    """GET /api/news-watch -- the settings, the state of each feed and the critical items found (8.0.2). Any signed-in role may ask, and only the platform operator is
    answered with anything: the software an item names comes from every host of the installation, so a tenant's administrator or a viewer reads {editable: false} and the
    page leaves the card out."""
    A.require_auth()
    if A.method() != "GET":
        A.respond(405, {"error": "Method not allowed"})
    if not _is_operator():
        A.respond(200, {"editable": False})
    A.respond(200, _view(int(time.time())))


def handle_news_watch_config_set():
    """POST /api/news-watch/config {enabled?, feeds?, scope?, action?, words?} -- change the settings of the news watch (8.0.2). The platform operator's, since the feeds are read by
    the server and a scan covers every host. A field that is not in the body is left as it is; a body with one value that is not valid is refused whole, naming it. Switching
    the watch on, or changing the feeds, makes the next sweep read at once."""
    actor = A.require_admin_auth()
    if A.method() != "POST":
        A.respond(405, {"error": "Method not allowed"})
    body = A._read_valid(A.request_models.NewsWatchConfigRequest)
    A._require_platform_operator("The security news settings")
    update, err = N.clean_update(body)
    if err:
        A.respond(400, {"error": err})
    with A._LockedUpdate(A.CONFIG_FILE) as cfg:
        before = N.settings(cfg.get("news_watch"))
        after = dict(before)
        after.update(update or {})
        cfg["news_watch"] = after
        if after["enabled"] and (not before["enabled"] or after["feeds"] != before["feeds"]):
            cfg.pop("last_news_watch_run", None)
    hosts = ",".join(sorted({urllib.parse.urlsplit(u).hostname or "" for u in after["feeds"]}))
    if not after["enabled"]:
        _close_feed_alerts(None)      # a watch that is off reports nothing, so a feed alert left open would stay for ever
    elif before["feeds"] != after["feeds"]:
        _close_feed_alerts(set(before["feeds"]) - set(after["feeds"]))
    A.audit_log(actor, "news_watch_config", f"enabled={after['enabled']} scope={after['scope']} action={after['action']} words={len(after['words'])} critical_words={len(after['critical_words'])} feeds={hosts}"[:300])
    A.respond(200, dict(_view(int(time.time())), ok=True))


def handle_news_watch_clear():
    """POST /api/news-watch/clear {ids?: [id, ...], all?: true, undo?: true} -- clear the red ! of items, or with `undo` bring it back (8.0.2). The platform operator's.

    An item shows a ! while it names software that runs on a host. Clearing says "seen": the item stays in the list with what runs on the hosts, loses its !, and no longer counts
    for the mark of the sidebar and the tab. The time is kept on the item in the store, so a clear holds for every browser and every operator account. Only an item that shows a ! now
    is cleared, for the ids as for `all`: an item that names software no host runs has no ! to clear, and the ! it gets when a host starts running that software is news. A body that
    names nothing, or whose `all` is anything but true, is refused. The answer is the page and how many items were cleared: an id that is not listed, or already cleared, clears none.

    `undo: true` turns the same body round: the ids, or `all`, name cleared items, and each of them loses the time it was cleared at. The ! is back for every browser and every operator
    account in the state it had before the clear, which is also what the mark of the sidebar and the tab goes by: a browser that had not shown the item yet is told again, and one that had
    shown it before it was cleared is not. An item that is not cleared is left as it is. The answer is the page and how many items were brought back (`restored`)."""
    actor = A.require_admin_auth()
    if A.method() != "POST":
        A.respond(405, {"error": "Method not allowed"})
    body = A._read_valid(A.request_models.NewsWatchClearRequest)
    A._require_platform_operator("The security news settings")
    raw = body.get("ids")
    ids = {x for x in (raw if isinstance(raw, list) else [])[:MAX_CLEAR_IDS] if isinstance(x, str) and x}
    everything = body.get("all") is True
    restoring = body.get("undo") is True
    if not ids and not everything:
        A.respond(400, {"error": "Say which items to bring back" if restoring else "Say which items to clear"})
    now = int(time.time())
    if restoring:
        restored = 0
        with A._LockedUpdate(A.NEWS_WATCH_FILE) as st:
            for i in st.get("items") if isinstance(st.get("items"), list) else []:
                if not isinstance(i, dict) or _num(i.get("cleared_at")) is None:
                    continue
                if everything or i.get("id") in ids:
                    del i["cleared_at"]
                    restored += 1
        if restored:
            A.audit_log(actor, "news_watch_unclear", f"items={restored}")
        A._invalidate_load_cache(A.NEWS_WATCH_FILE)
        A.respond(200, dict(_view(now), ok=True, restored=restored))
    running = _running_now(now)
    extra = set(N.settings(A._config_ro().get("news_watch"))["words"])
    cleared = 0
    with A._LockedUpdate(A.NEWS_WATCH_FILE) as st:
        for i in st.get("items") if isinstance(st.get("items"), list) else []:
            if not isinstance(i, dict) or _num(i.get("cleared_at")) is not None:
                continue
            if (everything or i.get("id") in ids) and _public_item(i, running, extra)["running"]:
                i["cleared_at"] = now
                cleared += 1
    if cleared:
        A.audit_log(actor, "news_watch_clear", f"items={cleared}")
    A._invalidate_load_cache(A.NEWS_WATCH_FILE)
    A.respond(200, dict(_view(now), ok=True, cleared=cleared))


def handle_news_watch_run():
    """POST /api/news-watch/run -- read the feeds now (8.0.2). The platform operator's. It does what the sweep does: what is new is recorded, and what counts raises its alert and
    may start the scan. Refused with 429 when the feeds were read less than MANUAL_GAP_S seconds ago, and with 409 while the watch is off. The answer is the page and what
    the read found."""
    A.require_admin_auth()
    if A.method() != "POST":
        A.respond(405, {"error": "Method not allowed"})
    A._require_platform_operator("The security news settings")
    cfg = N.settings(A._config_ro().get("news_watch"))
    if not cfg["enabled"] or not cfg["feeds"]:
        A.respond(409, {"error": "The news watch is off, or has no feed"})
    now = int(time.time())
    st = (A._load_ro(A.NEWS_WATCH_FILE) or {}) if A.backend_exists(A.NEWS_WATCH_FILE) else {}
    last = _store_dict(st).get("last_run")
    if isinstance(last, int) and not isinstance(last, bool) and 0 <= now - last < MANUAL_GAP_S:
        A.respond(429, {"error": "The feeds were read a moment ago. Try again shortly.", "retry_after_seconds": MANUAL_GAP_S - (now - last)})
    A._invalidate_load_cache(A.NEWS_WATCH_FILE)
    result = poll_once(now)
    A._invalidate_load_cache(A.NEWS_WATCH_FILE)
    A.respond(200, dict(_view(int(time.time())), ok=True, result=result))
