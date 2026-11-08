"""RemotePower integrations — poll popular homelab software and surface health.

Design: each connector is a PURE function ``health(inst, c) -> dict`` of an
instance-config dict and an HTTP client. ``api.py`` owns the SSRF-safe HTTP
client, the poll cadence, history and alerting; this module is just the
per-product API clients + parsers, so every connector is trivially unit-tested
with a fake client (no network).

A connector returns::

    {'status': 'ok'|'warning'|'critical'|'unknown',
     'detail': '<short human line>',
     'metrics': {<k>: <number/str>, ...},   # optional, shown in the drawer
     'version': '<remote version>'}          # optional

The instance-config dict (stored per-integration in the server config) carries:
    id, type, label, url, enabled, verify_tls, and a small set of credential
    fields named so the config-secret scrubber redacts them automatically
    ('secret', plus non-secret 'username'/'slug').
"""

import base64
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse

from textfmt import plural

OK = "ok"
WARN = "warning"
CRIT = "critical"
UNKNOWN = "unknown"

# Field kinds the Settings UI knows how to render.
TEXT = "text"
PASSWORD = "password"
TEXTAREA = "textarea"  # v7.4.3: several lines (the Prometheus connectors' values)


class IntegrationError(Exception):
    """Any failure reaching/parsing a target — caught by the poller → 'critical'."""


# What a failed connection says to an operator. A URLError carries the real
# cause in .reason; the exception's class name and errno are for a developer.
_NAME_FAILURES = (
    "name or service not known",
    "nodename nor servname",
    "temporary failure in name resolution",
    "no address associated",
    "getaddrinfo failed",
)


def network_error_reason(e: BaseException):
    """Why a call over the network failed, in words an operator can act on, or None for an exception that is not a
    recognised network failure (a bug, a bad value, a message somebody wrote for a person). urllib wraps nearly every
    failure in URLError, so `type(e).__name__` says "URLError" for a DNS failure, a refused connection and a timeout alike.
    """
    if isinstance(e, urllib.error.HTTPError):
        return "it answered HTTP %d" % e.code
    reason = getattr(e, "reason", None)
    cause = reason if isinstance(reason, BaseException) else e
    raw = str(reason if reason is not None else e).strip()
    text = raw.lower()
    if isinstance(cause, socket.gaierror) or any(s in text for s in _NAME_FAILURES):
        return "the host name does not resolve"
    if isinstance(cause, ConnectionRefusedError) or "connection refused" in text:
        return "the connection was refused"
    if isinstance(cause, TimeoutError) or "timed out" in text:
        return "it did not answer in time"
    if isinstance(cause, ssl.SSLCertVerificationError) or "certificate verify failed" in text:
        return "its certificate was not accepted"
    if isinstance(cause, ssl.SSLError):
        return "the TLS handshake failed"
    if isinstance(cause, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)) or (
        "reset by peer" in text
    ):
        return "the connection was dropped"
    if "network is unreachable" in text or "no route to host" in text:
        return "the network is unreachable"
    return None


def describe_network_error(e: BaseException) -> str:
    """Why a target could not be reached, in words an operator can act on."""
    reason = network_error_reason(e)
    if reason:
        return reason
    r = getattr(e, "reason", None)
    return str(r if r is not None else e).strip()[:120] or "the request failed"


def explain_failure(e: BaseException, limit: int = 200) -> str:
    """The text of a 502 for a failed call to another system: a network failure in words, anything else as the exception said it.
    A 502 used to carry `URLError: <urlopen error [Errno -2] Name or service not known>`."""
    return (network_error_reason(e) or str(e))[:limit]


# v6.4.2: the transport's per-response read budget, declared HERE so the cap and
# the message that explains hitting it cannot drift apart (api.py's
# _SSRFIntegrationClient reads it). 2 MB is generous for an API response and
# still bounds a hostile or misconfigured endpoint.
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class Resp:
    __slots__ = ("status", "text", "headers", "truncated")

    def __init__(self, status, text, headers=None, truncated=False):
        self.status = int(status)
        self.text = text or ""
        self.headers = headers or {}
        # v6.4.2: the transport read a bounded number of bytes and there was
        # more. Without this the operator gets "invalid JSON" for a response
        # that was perfectly valid until we cut it in half.
        self.truncated = bool(truncated)

    @property
    def ok(self):
        return 200 <= self.status < 300

    def _content_type(self):
        for k, v in (self.headers or {}).items():
            if str(k).lower() == "content-type":
                return str(v).lower()
        return ""

    def _why_not_json(self):
        """The most specific true statement we can make about a body that would
        not parse.

        v6.4.2: this used to be the single string "invalid JSON (HTTP 200)" for
        every cause, which is the one thing the operator cannot act on — it
        describes our parser's opinion rather than what the server sent. Each
        branch below is a distinct real-world cause with a distinct fix."""
        if self.truncated:
            return (
                f"response too large to parse (over {MAX_RESPONSE_BYTES // (1024 * 1024)} MB) "
                "— ask the endpoint for fewer fields"
            )
        body = self.text.strip()
        if not body:
            return f"HTTP {self.status} with an empty body"
        ctype = self._content_type()
        head = body[:200].lower()
        if head.startswith(("<!doctype", "<html", "<?xml")) or "text/html" in ctype:
            return (
                f"HTTP {self.status} returned HTML, not JSON — check the URL points at "
                "the app root, and that a login page or WAF is not intercepting it"
            )
        # A JSON document with junk in front of it: PHP notices, a BOM, or debug
        # output from a plugin. The document itself is usually fine.
        if _find_json_start(body) > 0:
            return (
                f"HTTP {self.status} sent output before its JSON (a PHP notice or "
                "debug output?) and the remainder did not parse either"
            )
        return f"invalid JSON (HTTP {self.status})"

    def json(self):
        try:
            return json.loads(self.text)
        except Exception:
            pass
        # v6.4.2: salvage a JSON document that has junk in front of it. A
        # WordPress install whose theme or plugin emits a PHP notice prepends it
        # to every REST response; the JSON after it is valid and the site is
        # healthy. Refusing to parse it turns somebody else's cosmetic warning
        # into "your monitoring is broken". Bounded: only a short prefix, and
        # only when the remainder parses cleanly on its own.
        start = _find_json_start(self.text)
        if 0 < start <= _MAX_JSON_PREFIX_JUNK:
            try:
                return json.loads(self.text[start:])
            except Exception:
                pass
        raise IntegrationError(self._why_not_json())


# How much leading junk we will step over to find the real document. Generous
# enough for a stack of PHP notices, small enough that we are not scanning an
# HTML page hunting for a stray brace.
_MAX_JSON_PREFIX_JUNK = 4096


def _find_json_start(text):
    """Index of the first plausible JSON document start, or 0/-1.

    Returns 0 when the body already starts with one (nothing to skip) and -1
    when there is no `{`/`[` at all."""
    if not text:
        return -1
    stripped = text.lstrip("﻿ \t\r\n")
    lead = len(text) - len(stripped)
    if stripped[:1] in ("{", "["):
        return lead if lead else 0
    for i, ch in enumerate(text):
        if ch in "{[":
            return i
    return -1


class HTTPClient:
    """Abstract SSRF-safe client. api.py implements ``request``; tests fake it.

    Convenience helpers (get/post_form/post_json/get_json) are built on the one
    abstract ``request`` so every connector and every test share the same surface.
    """

    def __init__(self, base):
        self.base = (base or "").rstrip("/")

    # --- the one thing subclasses must implement -------------------------------
    def request(self, method, path, headers=None, params=None, body=None):
        raise NotImplementedError

    # --- conveniences ----------------------------------------------------------
    def _full(self, path, params=None):
        # SECURITY: never accept an absolute URL as `path` — it would bypass
        # `self.base` and the SSRF pre-flight's host binding (the _vcloud_base
        # class). Callers pass provider-relative paths only.
        if path.startswith(("http://", "https://")):
            raise ValueError("absolute URL is not allowed as a request path")
        url = self.base + (path if path.startswith("/") else "/" + path)
        if params:
            sep = "&" if "?" in url else "?"
            url = url + sep + urllib.parse.urlencode(params)
        return url

    def get(self, path, headers=None, params=None):
        return self.request("GET", path, headers=headers, params=params)

    def post_form(self, path, fields, headers=None):
        h = {"Content-Type": "application/x-www-form-urlencoded"}
        h.update(headers or {})
        body = urllib.parse.urlencode(fields or {}).encode()
        return self.request("POST", path, headers=h, body=body)

    def post_json(self, path, obj, headers=None):
        h = {"Content-Type": "application/json"}
        h.update(headers or {})
        body = json.dumps(obj).encode()
        return self.request("POST", path, headers=h, body=body)

    def get_json(self, path, headers=None, params=None):
        r = self.get(path, headers=headers, params=params)
        if not r.ok:
            raise IntegrationError(f"HTTP {r.status} from {path}")
        return r.json()


# ── connector registry ────────────────────────────────────────────────────────
CONNECTORS: dict = {}


def _register(
    type_, label, category, fields, notes="", version="", author="", homepage="", default_url=""
):
    """Decorator registering a connector + its UI metadata.

    version/author/homepage (v6.1.1) are optional display metadata so the
    connector-repository panel has something to show beyond a bare type/label —
    built-ins leave them blank (they're versioned with the product itself);
    third-party connectors.d/ plugins are expected to set them."""

    def deco(fn):
        CONNECTORS[type_] = {
            "type": type_,
            "label": label,
            "category": category,
            "fields": fields,
            "notes": notes,
            "version": version,
            "author": author,
            "homepage": homepage,
            "default_url": default_url,
            "health": fn,
        }
        return fn

    return deco


def _field(key, label, kind=PASSWORD, optional=False, placeholder=""):
    return {
        "key": key,
        "label": label,
        "kind": kind,
        "optional": optional,
        "placeholder": placeholder,
    }


PLUGIN_CONNECTORS: set = set()  # type_ids registered by a connectors.d/ plugin


def load_plugins(plugin_dir=None):
    """v5.8.0 (B5.1): import every ``*.py`` under ``connectors.d/`` so third-party
    connector files self-register via the same ``@_register`` decorator the
    built-ins use. Returns the list of loaded filenames.

    SECURITY: this executes arbitrary Python as the web user, exactly like the
    rest of cgi-bin. The directory MUST therefore be root-owned and only writable
    by the operator (same as cgi-bin) — there is NO UI upload path;
    plugins are filesystem-only. A plugin that raises on import is logged and
    skipped so one bad file can't take the whole feature down."""
    import glob
    import importlib.util
    import os
    import sys

    if plugin_dir is None:
        plugin_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "connectors.d")
    loaded = []
    if not os.path.isdir(plugin_dir):
        return loaded
    before = set(CONNECTORS)
    for path in sorted(glob.glob(os.path.join(plugin_dir, "*.py"))):
        base = os.path.basename(path)
        modname = "rp_connector_" + os.path.splitext(base)[0]
        try:
            spec = importlib.util.spec_from_file_location(modname, path)
            if spec is None or spec.loader is None:
                continue
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            loaded.append(base)
        except Exception as e:  # a bad plugin must not break the feature
            sys.stderr.write(
                f"[remotepower] connector plugin {base} failed to load: "
                f"{e.__class__.__name__}: {e}\n"
            )
    PLUGIN_CONNECTORS.update(set(CONNECTORS) - before)
    return loaded


def list_connectors():
    """UI-facing catalog (no health fns), sorted by category then label."""
    out = []
    for c in CONNECTORS.values():
        out.append(
            {
                "type": c["type"],
                "label": c["label"],
                "category": c["category"],
                "fields": c["fields"],
                "notes": c["notes"],
                "version": c.get("version") or "",
                "author": c.get("author") or "",
                "homepage": c.get("homepage") or "",
                "default_url": c.get("default_url") or "",
                "plugin": c["type"] in PLUGIN_CONNECTORS,
            }
        )
    out.sort(key=lambda c: (c["category"], c["label"]))
    return out


def poll_instance(inst, client):
    """Run one integration instance's health() and normalize the result.

    Never raises — any error becomes a 'critical' result with the message, so the
    caller's alert/transition logic always gets a usable dict."""
    spec = CONNECTORS.get(inst.get("type"))
    if not spec:
        return {"status": UNKNOWN, "detail": f"unknown type {inst.get('type')}", "metrics": {}}
    try:
        res = spec["health"](inst, client) or {}
    except IntegrationError as e:
        return {"status": CRIT, "detail": str(e)[:200], "metrics": {}}
    except Exception as e:  # defensive: a parser bug must not crash the poll loop
        return {"status": CRIT, "detail": f"{e.__class__.__name__}: {e}"[:200], "metrics": {}}
    res.setdefault("status", UNKNOWN)
    res.setdefault("detail", "")
    res.setdefault("metrics", {})
    res["detail"] = str(res["detail"])[:200]
    return res


# ── small parse helpers ────────────────────────────────────────────────────────
def _num(x, default=0):
    try:
        return float(x)
    except (TypeError, ValueError):
        return default


def _pct(part, whole):
    whole = _num(whole)
    return round(100.0 * _num(part) / whole, 1) if whole else 0.0


def _hdr_token(inst, header, prefix=""):
    return {header: prefix + (inst.get("secret") or "")}


# ══════════════════════════════════════════════════════════════════════════════
# WAVE A — highest appeal
# ══════════════════════════════════════════════════════════════════════════════


def pihole_logout(c, sid):
    """End a Pi-hole v6 session: DELETE /api/auth, answered 204 (docs.pi-hole.net/api/auth). Pi-hole holds at most webserver.api.max_sessions of them (16 by
    default) and may deny a new login when they are all taken; a session that is left behind lives for webserver.session.timeout (1800 s by default), and the
    documentation asks clients to log out when they are done. A poll every minute that never did used the seats up, and the web login of whoever runs the Pi-hole
    with them. Best effort: what was read is worth more than the logout, so nothing here raises."""
    if not sid:
        return False
    try:
        return bool(c.request("DELETE", "/api/auth", headers={"X-FTL-SID": sid}).ok)
    except Exception:
        return False


@_register(
    "pihole",
    "Pi-hole",
    "dns",
    [_field("secret", "App password", PASSWORD)],
    notes="Pi-hole v6 API (app password under Settings → Web interface / API).",
)
def _pihole(inst, c):
    # v6: authenticate for a session ID, read, and give the session back (8.0.0: it used to stay until Pi-hole timed it out).
    sid = ""
    try:
        auth = c.post_json("/api/auth", {"password": inst.get("secret") or ""}).json()
        sid = (((auth or {}).get("session") or {}).get("sid")) or ""
    except IntegrationError:
        sid = ""
    h = {"X-FTL-SID": sid} if sid else {}
    try:
        return _pihole_read(c, h)
    finally:
        pihole_logout(c, sid)


def _pihole_read(c, h):
    s = c.get_json("/api/stats/summary", headers=h)
    q = s.get("queries") or {}
    g = s.get("gravity") or {}
    total = q.get("total", 0)
    blocked_pct = q.get("percent_blocked", _pct(q.get("blocked"), total))
    ver = ""
    try:
        v = c.get_json("/api/info/version", headers=h)
        ver = (((v.get("version") or {}).get("core") or {}).get("local") or {}).get(
            "version", ""
        ) or ""
    except IntegrationError:
        pass
    # v6.1.2: what is actually being blocked. "23% blocked" is a number; "your TV
    # phoned home 4,000 times" is the thing you'd act on. Best-effort — a failure
    # here must NOT fail the health check, which is the connector's real job.
    top_blocked, top_clients = [], []
    try:
        td = c.get_json("/api/stats/top_domains?blocked=true&count=10", headers=h)
        top_blocked = [
            {"name": str(d.get("domain", "")), "count": int(_num(d.get("count")))}
            for d in (td.get("domains") or [])
            if d.get("domain")
        ][:10]
    except (IntegrationError, AttributeError, TypeError, ValueError):
        pass
    try:
        tc = c.get_json("/api/stats/top_clients?count=10", headers=h)
        top_clients = [
            {"name": str(d.get("name") or d.get("ip") or ""), "count": int(_num(d.get("count")))}
            for d in (tc.get("clients") or [])
            if d.get("name") or d.get("ip")
        ][:10]
    except (IntegrationError, AttributeError, TypeError, ValueError):
        pass
    return {
        "status": OK,
        "version": ver,
        "detail": f"{int(_num(total))} queries today, {round(_num(blocked_pct),1)}% blocked",
        "metrics": {
            "queries_today": total,
            "blocked_pct": blocked_pct,
            "domains_blocked": g.get("domains_being_blocked", 0),
        },
        "top_blocked": top_blocked,
        "top_clients": top_clients,
    }


@_register(
    "adguard",
    "AdGuard Home",
    "dns",
    [_field("username", "Username", TEXT), _field("secret", "Password", PASSWORD)],
    notes="Uses HTTP Basic auth against the AdGuard Home admin API.",
)
def _adguard(inst, c):
    import base64

    auth = base64.b64encode(f"{inst.get('username','')}:{inst.get('secret','')}".encode()).decode()
    h = {"Authorization": "Basic " + auth}
    st = c.get_json("/control/status", headers=h)
    running = st.get("running", True)
    prot = st.get("protection_enabled", True)
    ver = st.get("version", "")
    queries = blocked = 0
    top_blocked, top_clients = [], []
    try:
        stats = c.get_json("/control/stats", headers=h)
        queries = stats.get("num_dns_queries", 0)
        blocked = stats.get("num_blocked_filtering", 0)
        # v6.1.2: AdGuard already returns the top lists in the SAME response we
        # fetch for the counters, so this costs no extra request. Shape is a list
        # of single-pair dicts: [{"tracker.example": 42}, …].
        top_blocked = _adguard_top(stats.get("top_blocked_domains"))
        top_clients = _adguard_top(stats.get("top_clients"))
    except IntegrationError:
        pass
    if not running:
        return {
            "status": CRIT,
            "detail": "DNS server not running",
            "version": ver,
            "metrics": {},
            "top_blocked": [],
            "top_clients": [],
        }
    status = OK if prot else WARN
    detail = f"{int(_num(queries))} queries, {_pct(blocked, queries)}% blocked"
    if not prot:
        detail = "protection DISABLED · " + detail
    return {
        "status": status,
        "version": ver,
        "detail": detail,
        "metrics": {"queries": queries, "blocked": blocked, "protection": prot},
        "top_blocked": top_blocked,
        "top_clients": top_clients,
    }


def _adguard_top(raw):
    """AdGuard's top-N lists are [{"name": count}, …] — one pair per dict, not a
    list of {name, count} objects. Normalise to the latter so the Pi-hole and
    AdGuard panels can share one renderer."""
    out = []
    for item in (raw or [])[:10]:
        if not isinstance(item, dict):
            continue
        for name, count in item.items():
            out.append({"name": str(name), "count": int(_num(count))})
            break  # exactly one pair per entry by AdGuard's contract
    return out


@_register(
    "truenas",
    "TrueNAS",
    "storage",
    [_field("secret", "API key", PASSWORD)],
    notes="TrueNAS CORE/SCALE REST API v2.0 with an API key (Bearer).",
)
def _truenas(inst, c):
    h = _hdr_token(inst, "Authorization", "Bearer ")
    first = c.get("/api/v2.0/system/info", headers=h)
    # 8.0.0: the newest TrueNAS releases (26) no longer have the REST API this connector speaks; they answer 404 at /api/v2.0, and "HTTP 404" told nobody why. The replacement is a
    # JSON-RPC 2.0 API over a WebSocket (/api/current), which this connector does not speak yet.
    if first.status in (404, 410):
        raise IntegrationError(
            "no REST API at /api/v2.0: TrueNAS 26 removed it, and its WebSocket API is not supported by this connector yet. On an earlier release, check the address"
        )
    if first.status in (401, 403):
        raise IntegrationError(f"unauthorized (HTTP {first.status}) — check the API key")
    if not first.ok:
        raise IntegrationError(f"/api/v2.0/system/info answered HTTP {first.status}")
    info = first.json()
    ver = info.get("version", "") if isinstance(info, dict) else ""
    pools = c.get_json("/api/v2.0/pool", headers=h)
    bad = [
        p.get("name", "?")
        for p in (pools or [])
        if str(p.get("status", "")).upper() not in ("ONLINE", "HEALTHY")
    ]
    crit = warn = 0
    try:
        for a in c.get_json("/api/v2.0/alert/list", headers=h) or []:
            if a.get("dismissed"):
                continue
            lvl = str(a.get("level", "")).upper()
            if lvl in ("CRITICAL", "ALERT", "EMERGENCY"):
                crit += 1
            elif lvl in ("WARNING", "ERROR"):
                warn += 1
    except IntegrationError:
        pass
    status = OK
    if bad or crit:
        status = CRIT
    elif warn:
        status = WARN
    detail = f"{len(pools or [])} pools" + (f", DEGRADED: {', '.join(bad)}" if bad else " healthy")
    if crit or warn:
        detail += f" · {crit} crit / {warn} warn alerts"
    return {
        "status": status,
        "version": ver,
        "detail": detail,
        "metrics": {
            "pools": len(pools or []),
            "pools_bad": len(bad),
            "alerts_crit": crit,
            "alerts_warn": warn,
        },
    }


@_register(
    "unifi",
    "UniFi Network",
    "network",
    [
        _field("secret", "API key (or the password, with a username)", PASSWORD),
        _field("username", "Username (only for the older login)", TEXT, optional=True),
        _field("slug", "Site (default: default)", TEXT, optional=True),
    ],
    notes="UniFi Network through its Integration API (8.0.0): an API key made under Integrations in the Network application, sent as X-API-KEY, on a UniFi OS console "
    "(UDM, UDR, Cloud Gateway, Cloud Key) or a Network application from 9.0. Lists the adopted devices and goes critical when one is offline, interrupted or isolated. "
    "With a Username, the older login (classic /api/login of a self-hosted controller) is used instead; UniFi OS consoles do not answer it.",
)
def _unifi(inst, c):
    site = inst.get("slug") or "default"
    if inst.get("username"):
        return _unifi_login(inst, c, site)
    return _unifi_integration(inst, c, site)


def _unifi_login(inst, c, site):
    """The older way: a cookie login on a self-hosted controller, and the health of its subsystems."""
    c.post_json(
        "/api/login",
        {
            "username": inst.get("username", ""),
            "password": inst.get("secret", ""),
            "remember": True,
        },
    )
    health = c.get_json(f"/api/s/{site}/stat/health")
    subs = (health or {}).get("data") or []
    bad = [s.get("subsystem", "?") for s in subs if str(s.get("status", "ok")).lower() != "ok"]
    status = CRIT if bad else OK
    detail = f"{len(subs)} subsystems OK" if not bad else f"degraded: {', '.join(bad)}"
    return {
        "status": status,
        "detail": detail,
        "metrics": {"subsystems": len(subs), "subsystems_bad": len(bad)},
    }


# The Integration API (UniFi Network 9.0 and later): every path is under /proxy/network/integration, lists are pages {offset, limit, count, totalCount, data} with a limit of at
# most 200, a site is {id (a UUID), internalReference (the older name, "default" on a single-site install), name}, and an adopted device carries `state`, `firmwareUpdatable` and
# `supported`. Read from the vendor's own OpenAPI file for 10.4.57 (developer.ui.com/network/v10.4.57/openapi.json) on 2026-11-08, and the first two answers against a capture of a
# 10.6.109 console.
_UNIFI_BASE = "/proxy/network/integration/v1"
_UNIFI_DOWN = ("OFFLINE", "CONNECTION_INTERRUPTED", "ISOLATED")
_UNIFI_PAGE = 200
_UNIFI_PAGES = 5  # 1,000 devices: past that the answer says it counted the first thousand
_UNIFI_ID = re.compile(
    r"^[0-9A-Za-z-]{8,64}$"
)  # a site id is a UUID: what this lets through needs no quoting in a path, and nothing else gets that far


def _unifi_page(c, path, h, limit=_UNIFI_PAGE):
    """One page of a list: (rows, totalCount). A body that is not a page is an error, not an empty list."""
    r = c.get(f"{path}?offset=0&limit={int(limit)}", headers=h)
    return _unifi_rows(r, path)


def _unifi_rows(r, path):
    if r.status in (401, 403):
        raise IntegrationError(
            f"unauthorized (HTTP {r.status}) — check the API key (Network application → Integrations)"
        )
    if not r.ok:
        raise IntegrationError(
            f"{path} answered HTTP {r.status} — is this a UniFi OS console or a Network application from 9.0?"
        )
    body = r.json()
    rows = body.get("data") if isinstance(body, dict) else None
    if not isinstance(rows, list):
        raise IntegrationError(f"{path} did not answer a page")
    total = body.get("totalCount")
    total = (
        int(total)
        if isinstance(total, (int, float)) and not isinstance(total, bool) and 0 <= total < 10**9
        else len(rows)
    )
    return [x for x in rows if isinstance(x, dict)], total


def _unifi_integration(inst, c, site):
    h = _hdr_token(inst, "X-API-KEY", "")
    info = c.get(f"{_UNIFI_BASE}/info", headers=h)
    if info.status in (401, 403):
        raise IntegrationError(
            f"unauthorized (HTTP {info.status}) — check the API key (Network application → Integrations)"
        )
    if not info.ok:
        raise IntegrationError(
            f"/info answered HTTP {info.status} — is this a UniFi OS console or a Network application from 9.0?"
        )
    body = info.json()
    ver = str(body.get("applicationVersion") or "") if isinstance(body, dict) else ""
    sites, _ = _unifi_page(c, f"{_UNIFI_BASE}/sites", h)
    chosen = next((x for x in sites if x.get("internalReference") == site), None)
    if chosen is None and not inst.get("slug") and len(sites) == 1:
        chosen = sites[0]
    if chosen is None:
        known = (
            ", ".join(sorted(str(x.get("internalReference") or "?") for x in sites)[:6]) or "none"
        )
        raise IntegrationError(f"site {site!r} not found (the console has: {known})")
    sid = str(chosen.get("id") or "")
    if not _UNIFI_ID.match(sid):
        raise IntegrationError("the console named a site with an id that is not one")
    devices, total = [], 0
    for page in range(_UNIFI_PAGES):
        r = c.get(
            f"{_UNIFI_BASE}/sites/{sid}/devices?offset={page * _UNIFI_PAGE}&limit={_UNIFI_PAGE}",
            headers=h,
        )
        rows, total = _unifi_rows(r, f"{_UNIFI_BASE}/sites/<site>/devices")
        devices += rows
        if not rows or len(devices) >= total:
            break
    down = [d for d in devices if str(d.get("state") or "") in _UNIFI_DOWN]
    odd = [d for d in devices if str(d.get("state") or "") == "U5G_INCORRECT_TOPOLOGY"]
    updates = sum(
        1 for d in devices if d.get("firmwareUpdatable") is True and d.get("supported") is not False
    )
    clients = None
    try:
        _rows, clients = _unifi_page(c, f"{_UNIFI_BASE}/sites/{sid}/clients", h, limit=1)
    except IntegrationError:
        pass  # the client count is a nicety: the devices are the health
    names = ", ".join(str(d.get("name") or d.get("macAddress") or "?")[:40] for d in down[:3])
    if down:
        status, detail = CRIT, f"{len(down)} of {len(devices)} devices down: {names}" + (
            " …" if len(down) > 3 else ""
        )
    elif odd:
        status, detail = (
            WARN,
            f"{plural(len(odd), 'device', 'devices')} with an incorrect topology (U5G)",
        )
    else:
        status, detail = OK, f"{len(devices)} devices online" if devices else "no adopted devices"
    if total > len(devices):
        detail += f" · counted the first {len(devices)} of {total}"
    if updates:
        detail += f" · {updates} firmware update{'s' if updates != 1 else ''} available"
    metrics = {"devices": len(devices), "devices_down": len(down), "firmware_updates": updates}
    if clients is not None:
        metrics["clients"] = clients
    out = {"status": status, "detail": detail, "metrics": metrics}
    if ver:
        out["version"] = ver
    return out


@_register(
    "homeassistant",
    "Home Assistant",
    "apps",
    [_field("secret", "Long-lived access token", PASSWORD)],
    notes="Home Assistant REST API with a long-lived access token (Bearer).",
)
def _homeassistant(inst, c):
    h = _hdr_token(inst, "Authorization", "Bearer ")
    api = c.get_json("/api/", headers=h)
    if "API running" not in json.dumps(api):
        raise IntegrationError("API did not report running")
    ver = ""
    try:
        ver = c.get_json("/api/config", headers=h).get("version", "")
    except IntegrationError:
        pass
    total = unavailable = 0
    try:
        for s in c.get_json("/api/states", headers=h) or []:
            total += 1
            if s.get("state") in ("unavailable", "unknown"):
                unavailable += 1
    except IntegrationError:
        pass
    status = WARN if unavailable else OK
    return {
        "status": status,
        "version": ver,
        "detail": f"{total} entities, {unavailable} unavailable",
        "metrics": {"entities": total, "unavailable": unavailable},
    }


# ══════════════════════════════════════════════════════════════════════════════
# WAVE B — virtualization / infra
# ══════════════════════════════════════════════════════════════════════════════


@_register(
    "pbs",
    "Proxmox Backup Server",
    "backup",
    [
        _field("username", "Token ID (user@realm!name)", TEXT),
        _field("secret", "Token secret", PASSWORD),
    ],
    notes="PBS API token. Authorization: PBSAPIToken=<id>:<secret>. Datastore fill, a datastore that cannot be read or is not mounted, bad chunks after garbage "
    "collection, and the tasks that failed in the last 24 hours. PBS shows a token only its own user's tasks unless that user has Sys.Audit on /system/tasks: "
    "without it the failed-task count leaves out the scheduled backup, verify and prune jobs.",
)
def _pbs(inst, c):
    h = {"Authorization": f"PBSAPIToken={inst.get('username','')}:{inst.get('secret','')}"}
    usage = c.get_json("/api2/json/status/datastore-usage", headers=h)
    stores = (usage or {}).get("data") or []
    worst = 0.0
    worst_name = ""
    now = time.time()
    # v6.3.0: per-datastore breakdown so the Backups page can render a tidy table
    # (name, fill %, total/avail). Robust to a store missing any size field.
    _GB = 1024.0**3
    datastores = []
    broken, unmounted, corrupt = [], [], []
    for s in stores:
        name = s.get("store", "?")
        used = _pct(s.get("used"), s.get("total"))
        if used > worst:
            worst, worst_name = used, name
        _total = _num(s.get("total"))
        _avail = _num(s.get("avail"))
        ds = {
            "name": name,
            "used_pct": round(used, 1),
            "total_gb": round(_total / _GB, 1) if _total else 0,
            "avail_gb": round(_avail / _GB, 1) if _avail > 0 else 0,
        }
        # PBS reports a rolling dedup factor in the usage history when available.
        _dedup = s.get("deduplication-factor") or s.get("dedup")
        if isinstance(_dedup, (int, float)) and _dedup > 0:
            ds["dedup"] = round(float(_dedup), 2)
        # estimated-full-date (unix ts) → surface how long until the store fills. PBS says an estimate in the past means that usage is declining or not
        # changing (8.0.0: a date that has gone by was shown as the day the store fills), so only a date to come is a forecast.
        _eff = s.get("estimated-full-date")
        if isinstance(_eff, (int, float)) and not isinstance(_eff, bool) and _eff > now:
            ds["full_eta"] = int(_eff)
        # 8.0.0: PBS answers `error` when it cannot look a datastore up, and avail -1 ("-1 on error"); both used to read as a store with nothing used in it.
        err = s.get("error")
        if isinstance(err, str) and err.strip():
            ds["error"] = err.strip()[:200]
        elif s.get("avail") is not None and _avail < 0:
            ds["error"] = "the datastore could not be read"
        if ds.get("error"):
            broken.append(name)
        # mount-status is mounted | notmounted | nonremovable: a removable datastore that is not mounted is not a fault of the server, but backups cannot land
        if s.get("mount-status") == "notmounted":
            ds["mounted"] = False
            unmounted.append(name)
        # chunks still marked .bad after garbage collection: some snapshot still refers to data that verification found damaged
        gc = s.get("gc-status")
        bad = int(_num(gc.get("still-bad"))) if isinstance(gc, dict) else 0
        if bad > 0:
            ds["bad_chunks"] = bad
            corrupt.append(name)
        datastores.append(ds)
    status = OK
    if worst >= 90 or broken:
        status = CRIT
    elif worst >= 80 or unmounted or corrupt:
        status = WARN
    ver = ""
    try:
        ver = ((c.get_json("/api2/json/version", headers=h) or {}).get("data") or {}).get(
            "version", ""
        )
    except IntegrationError:
        pass
    detail = f"{len(stores)} datastores, fullest {worst_name} {round(worst,1)}%"
    if broken:
        detail += f"; cannot read {', '.join(broken[:3])}"
    if unmounted:
        detail += f"; not mounted: {', '.join(unmounted[:3])}"
    if corrupt:
        detail += f"; bad chunks in {', '.join(corrupt[:3])}"
    metrics = {"datastores": len(stores), "fullest_pct": worst}
    failed = _pbs_failed_tasks(c, h, now)
    if failed is not None:
        metrics["tasks_failed_24h"] = failed["count"]
        if failed["count"]:
            status = status if status != OK else WARN
            detail += f"; {failed['count']} failed {'task' if failed['count'] == 1 else 'tasks'} in 24 h ({failed['kinds']})"
    return {
        "status": status,
        "version": ver,
        "detail": detail,
        "metrics": metrics,
        "datastores": datastores,
    }


def _pbs_failed_tasks(c, h, now):
    """The tasks that ended in an error in the last 24 hours, counted and named by kind (GET /api2/json/nodes/localhost/tasks?errors=1&since=...), or None
    when the token cannot read them. PBS shows a user only their own tasks unless the user has Sys.Audit on /system/tasks, so a token without it sees none of
    the scheduled backup, verify and prune jobs: the connector says what it counted, and the notes say what the token needs.
    """
    try:
        rows = (
            c.get_json(
                "/api2/json/nodes/localhost/tasks",
                headers=h,
                params={"errors": 1, "since": int(now) - 86400, "limit": 100},
            )
            or {}
        ).get("data")
        if not isinstance(rows, list):
            return None
        kinds = {}
        for t in rows:
            if isinstance(t, dict):
                k = str(t.get("worker_type") or "task")[:40]
                kinds[k] = kinds.get(k, 0) + 1
        top = sorted(kinds.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
        return {"count": sum(kinds.values()), "kinds": ", ".join(f"{n} {k}" for k, n in top)}
    except (IntegrationError, AttributeError, TypeError, ValueError):
        return None


@_register(
    "kubernetes",
    "Kubernetes / k3s",
    "orchestration",
    [_field("secret", "ServiceAccount token", PASSWORD)],
    notes="Reads nodes + pods with a read-only ServiceAccount Bearer token. Self-signed API: turn off Verify TLS.",
)
def _kubernetes(inst, c):
    h = _hdr_token(inst, "Authorization", "Bearer ")
    nodes = c.get_json("/api/v1/nodes", headers=h)
    not_ready = []
    for n in (nodes or {}).get("items", []):
        ready = next(
            (
                cd
                for cd in (n.get("status", {}).get("conditions") or [])
                if cd.get("type") == "Ready"
            ),
            None,
        )
        if not ready or ready.get("status") != "True":
            not_ready.append(n.get("metadata", {}).get("name", "?"))
    crash = pending = running = 0
    try:
        for p in (c.get_json("/api/v1/pods", headers=h) or {}).get("items", []):
            phase = p.get("status", {}).get("phase")
            if phase == "Pending":
                pending += 1
            elif phase == "Running":
                running += 1
            for cs in p.get("status", {}).get("containerStatuses") or []:
                w = cs.get("state", {}).get("waiting") or {}
                if w.get("reason") in ("CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull"):
                    crash += 1
    except IntegrationError:
        pass
    status = OK
    if not_ready or crash:
        status = CRIT
    elif pending:
        status = WARN
    detail = f"{len((nodes or {}).get('items', []))} nodes"
    if not_ready:
        detail += f", NotReady: {', '.join(not_ready[:3])}"
    detail += (
        f" · {running} running"
        + (f", {crash} crashloop" if crash else "")
        + (f", {pending} pending" if pending else "")
    )
    return {
        "status": status,
        "detail": detail,
        "metrics": {
            "nodes_notready": len(not_ready),
            "pods_crashloop": crash,
            "pods_pending": pending,
        },
    }


@_register(
    "vcenter",
    "VMware vSphere / ESXi / vCenter",
    "virtualization",
    [_field("username", "Username", TEXT), _field("secret", "Password", PASSWORD)],
    notes="vCenter 7+ REST API (/api/session). Standalone ESXi exposes only SOAP — point at vCenter.",
)
def _vcenter(inst, c):
    import base64

    auth = base64.b64encode(f"{inst.get('username','')}:{inst.get('secret','')}".encode()).decode()
    sess = c.request("POST", "/api/session", headers={"Authorization": "Basic " + auth})
    if not sess.ok:
        raise IntegrationError(f"session failed (HTTP {sess.status})")
    token = (sess.text or "").strip().strip('"')
    h = {"vmware-api-session-id": token}
    hosts = c.get_json("/api/vcenter/host", headers=h)
    vms = []
    try:
        vms = c.get_json("/api/vcenter/vm", headers=h) or []
    except IntegrationError:
        pass
    down = [
        hh.get("name", "?")
        for hh in (hosts or [])
        if str(hh.get("connection_state", "CONNECTED")).upper() != "CONNECTED"
    ]
    status = CRIT if down else OK
    poweredon = sum(1 for v in vms if str(v.get("power_state", "")).upper() == "POWERED_ON")
    return {
        "status": status,
        "detail": f"{len(hosts or [])} hosts"
        + (f", disconnected: {', '.join(down)}" if down else "")
        + f" · {poweredon}/{len(vms)} VMs on",
        "metrics": {
            "hosts": len(hosts or []),
            "hosts_down": len(down),
            "vms": len(vms),
            "vms_on": poweredon,
        },
    }


@_register(
    "openshift",
    "Red Hat OpenShift",
    "virtualization",
    [_field("secret", "API token", PASSWORD)],
    notes="OpenShift exposes the Kubernetes API. Reads nodes + projects with a read-only oc/ServiceAccount Bearer token. Self-signed API: turn off Verify TLS.",
)
def _openshift(inst, c):
    h = _hdr_token(inst, "Authorization", "Bearer ")
    nodes = c.get_json("/api/v1/nodes", headers=h)
    not_ready = []
    for n in (nodes or {}).get("items", []):
        ready = next(
            (
                cd
                for cd in (n.get("status", {}).get("conditions") or [])
                if cd.get("type") == "Ready"
            ),
            None,
        )
        if not ready or ready.get("status") != "True":
            not_ready.append(n.get("metadata", {}).get("name", "?"))
    projects = 0
    try:
        projects = len(
            (c.get_json("/apis/project.openshift.io/v1/projects", headers=h) or {}).get("items", [])
        )
    except IntegrationError:
        pass
    status = CRIT if not_ready else OK
    n_nodes = len((nodes or {}).get("items", []))
    detail = f"{n_nodes} nodes, {projects} projects" + (
        f" · NotReady: {', '.join(not_ready[:3])}" if not_ready else ""
    )
    return {
        "status": status,
        "detail": detail,
        "metrics": {"nodes": n_nodes, "nodes_notready": len(not_ready), "projects": projects},
    }


@_register(
    "vcloud",
    "VMware Cloud Director",
    "virtualization",
    [_field("username", "Username (user@org)", TEXT), _field("secret", "Password", PASSWORD)],
    notes="Username as user@org (e.g. administrator@System). Reads vApp + VM counts via the /api session.",
)
def _vcloud(inst, c):
    import base64

    def _hget(headers, name):
        name = name.lower()
        for k, v in (headers or {}).items():
            if str(k).lower() == name:
                return v
        return None

    auth = base64.b64encode(f"{inst.get('username','')}:{inst.get('secret','')}".encode()).decode()
    accept = "application/*+json;version=37.0"
    sess = c.request(
        "POST", "/api/sessions", headers={"Authorization": "Basic " + auth, "Accept": accept}
    )
    if not sess.ok:
        raise IntegrationError(f"session failed (HTTP {sess.status})")
    token = _hget(sess.headers, "x-vmware-vcloud-access-token") or _hget(
        sess.headers, "x-vcloud-authorization"
    )
    if not token:
        raise IntegrationError("no vCloud session token returned")
    h = {"x-vcloud-authorization": token, "Accept": accept}
    vms = c.get_json("/api/query?type=vm&format=records&pageSize=1", headers=h) or {}
    vapps = c.get_json("/api/query?type=vApp&format=records&pageSize=1", headers=h) or {}
    try:
        n_vms = int(vms.get("total", 0) or 0)
        n_vapps = int(vapps.get("total", 0) or 0)
    except (TypeError, ValueError):
        n_vms = n_vapps = 0
    return {
        "status": OK,
        "detail": f"{n_vapps} vApps, {n_vms} VMs",
        "metrics": {"vapps": n_vapps, "vms": n_vms},
    }


@_register(
    "unraid",
    "Unraid",
    "storage",
    [_field("secret", "API key", PASSWORD)],
    notes="Unraid Connect GraphQL API (x-api-key). Best-effort — the API is newer/less stable.",
)
def _unraid(inst, c):
    q = {"query": "{ array { state capacity { disks { free used total } } } }"}
    data = c.post_json("/graphql", q, headers={"x-api-key": inst.get("secret", "")}).json()
    arr = ((data or {}).get("data") or {}).get("array") or {}
    state = str(arr.get("state", "UNKNOWN")).upper()
    status = OK if state == "STARTED" else (WARN if state else UNKNOWN)
    return {
        "status": status,
        "detail": f"array {state.lower() or 'unknown'}",
        "metrics": {"array_state": state},
    }


# ══════════════════════════════════════════════════════════════════════════════
# WAVE C — reverse proxy / certs
# ══════════════════════════════════════════════════════════════════════════════


@_register(
    "traefik",
    "Traefik",
    "proxy",
    [
        _field("username", "Username (if basic-auth)", TEXT, optional=True),
        _field("secret", "Password (if basic-auth)", PASSWORD, optional=True),
    ],
    notes="Traefik API (/api/overview). Add basic-auth creds only if the API is protected.",
)
def _traefik(inst, c):
    h = {}
    if inst.get("secret"):
        import base64

        h["Authorization"] = (
            "Basic "
            + base64.b64encode(
                f"{inst.get('username','')}:{inst.get('secret','')}".encode()
            ).decode()
        )
    ov = c.get_json("/api/overview", headers=h)
    routers = (ov or {}).get("http", {}).get("routers", {})
    errors = routers.get("errors", 0)
    warnings = routers.get("warnings", 0)
    status = CRIT if errors else (WARN if warnings else OK)
    ver = ""
    try:
        ver = (c.get_json("/api/version", headers=h) or {}).get("Version", "")
    except IntegrationError:
        pass
    return {
        "status": status,
        "version": ver,
        "detail": f"{routers.get('total', 0)} routers, {int(errors)} errors, {int(warnings)} warnings",
        "metrics": {"routers": routers.get("total", 0), "errors": errors, "warnings": warnings},
    }


@_register(
    "npm",
    "Nginx Proxy Manager",
    "proxy",
    [_field("username", "Email", TEXT), _field("secret", "Password", PASSWORD)],
    notes="Nginx Proxy Manager API — logs in for a token, checks proxy hosts + cert expiry.",
)
def _npm(inst, c):
    tok = (
        c.post_json(
            "/api/tokens", {"identity": inst.get("username", ""), "secret": inst.get("secret", "")}
        ).json()
        or {}
    ).get("token", "")
    if not tok:
        raise IntegrationError("login failed")
    h = {"Authorization": "Bearer " + tok}
    hosts = c.get_json("/api/nginx/proxy-hosts", headers=h) or []
    disabled = sum(1 for x in hosts if not x.get("enabled", True))
    expiring = 0
    try:
        import datetime

        now = datetime.datetime.utcnow()
        for cert in c.get_json("/api/nginx/certificates", headers=h) or []:
            exp = cert.get("expires_on")
            if exp:
                try:
                    d = datetime.datetime.fromisoformat(str(exp).replace("Z", "").split(".")[0])
                    if (d - now).days <= 14:
                        expiring += 1
                except ValueError:
                    pass
    except IntegrationError:
        pass
    status = WARN if (disabled or expiring) else OK
    return {
        "status": status,
        "detail": f"{len(hosts)} proxy hosts"
        + (f", {disabled} disabled" if disabled else "")
        + (f", {expiring} certs expiring<14d" if expiring else ""),
        "metrics": {"proxy_hosts": len(hosts), "disabled": disabled, "certs_expiring": expiring},
    }


@_register(
    "caddy",
    "Caddy",
    "proxy",
    [],
    notes="Caddy admin API (default :2019, usually localhost — must be reachable from the server).",
)
def _caddy(inst, c):
    cfg = c.get_json("/config/")
    if cfg is None:
        raise IntegrationError("empty admin config")
    fails = 0
    upstreams = 0
    try:
        for u in c.get_json("/reverse_proxy/upstreams") or []:
            upstreams += 1
            if int(u.get("num_requests", 0)) == 0 and int(u.get("fails", 0)) > 0:
                fails += 1
    except IntegrationError:
        pass
    status = WARN if fails else OK
    return {
        "status": status,
        "detail": f"admin API up, {upstreams} upstreams" + (f", {fails} failing" if fails else ""),
        "metrics": {"upstreams": upstreams, "upstreams_failing": fails},
    }


# ══════════════════════════════════════════════════════════════════════════════
# WAVE D — observability / status
# ══════════════════════════════════════════════════════════════════════════════


@_register(
    "uptimekuma",
    "Uptime Kuma",
    "observability",
    [_field("slug", "Status-page slug", TEXT)],
    notes="Reads a PUBLISHED Uptime Kuma status page (no API key). Set the page slug.",
)
def _uptimekuma(inst, c):
    slug = inst.get("slug") or "default"
    hb = c.get_json(f"/api/status-page/heartbeat/{slug}")
    beats = (hb or {}).get("heartbeatList") or {}
    total = down = 0
    for _mid, lst in beats.items():
        if not lst:
            continue
        total += 1
        if int((lst[-1] or {}).get("status", 1)) == 0:
            down += 1
    status = CRIT if down else OK
    return {
        "status": status,
        "detail": f"{total} monitors, {down} down",
        "metrics": {"monitors": total, "down": down},
    }


@_register(
    "netdata",
    "Netdata",
    "observability",
    [_field("secret", "API token (if protected)", PASSWORD, optional=True)],
    notes="Netdata /api/v1 — pulls active alarms (not all metrics).",
)
def _netdata(inst, c):
    h = _hdr_token(inst, "Authorization", "Bearer ") if inst.get("secret") else {}
    info = c.get_json("/api/v1/info", headers=h)
    ver = info.get("version", "")
    crit = warn = 0
    try:
        alarms = (c.get_json("/api/v1/alarms", headers=h) or {}).get("alarms") or {}
        for _name, a in alarms.items():
            st = str(a.get("status", "")).upper()
            if st == "CRITICAL":
                crit += 1
            elif st == "WARNING":
                warn += 1
    except IntegrationError:
        pass
    status = CRIT if crit else (WARN if warn else OK)
    return {
        "status": status,
        "version": ver,
        "detail": (
            f"{crit} critical, {warn} warning alarms" if (crit or warn) else "no active alarms"
        ),
        "metrics": {"alarms_critical": crit, "alarms_warning": warn},
    }


@_register(
    "grafana",
    "Grafana",
    "observability",
    [_field("secret", "API token", PASSWORD, optional=True)],
    notes="Grafana /api/health (DB reachability). A token is optional for that. With a token that may read alert instances, the alerts that are firing now are counted "
    "and named (/api/alertmanager/grafana/api/v2/alerts, active and not silenced or inhibited) and make the tile a warning.",
)
def _grafana(inst, c):
    h = _hdr_token(inst, "Authorization", "Bearer ") if inst.get("secret") else {}
    hp = c.get_json("/api/health", headers=h)
    db = str(hp.get("database", "")).lower()
    ver = hp.get("version", "")
    status = OK if db == "ok" else CRIT
    detail = f"database {db or 'unknown'}"
    metrics = {"database_ok": db == "ok"}
    # 8.0.0: the alert instances that are firing now. Grafana's alerting spec (pkg/services/ngalert/api/tooling/spec.json) gives the route, the three filters and the answer: a list
    # of {labels, status{state: unprocessed | active | suppressed}, ...}. Only `active` is firing, whatever the filters let through. A token that may not read them, or a Grafana
    # without the route (legacy alerting), leaves the answer as it was.
    if inst.get("secret"):
        try:
            r = c.get(
                "/api/alertmanager/grafana/api/v2/alerts",
                headers=h,
                params={"active": "true", "silenced": "false", "inhibited": "false"},
            )
        except IntegrationError:
            r = None  # the health call answered; this one got none (a timeout, a reset): the tile stays what the health call says
        firing = None
        names = []
        if r is None:
            pass
        elif r.ok:
            try:
                body = r.json()
            except (IntegrationError, ValueError):
                body = None
            if isinstance(body, list):
                live = [
                    a
                    for a in body
                    if isinstance(a, dict)
                    and isinstance(a.get("status"), dict)
                    and a["status"].get("state") == "active"
                ]
                firing = len(live)
                for a in live:
                    n = (
                        (a.get("labels") or {}).get("alertname")
                        if isinstance(a.get("labels"), dict)
                        else None
                    )
                    if isinstance(n, str) and n and n not in names:
                        names.append(n)
        elif r.status in (401, 403):
            detail += " · the token cannot read alert instances"
        if firing is not None:
            metrics["alerts_firing"] = firing
            if firing:
                shown = sorted(names)[:3]
                more = len(names) - len(shown)
                detail += f" · {firing} alert{'s' if firing != 1 else ''} firing"
                if shown:
                    detail += ": " + ", ".join(shown) + (f" +{more} more" if more > 0 else "")
                if status == OK:
                    status = WARN
            else:
                detail += " · no alerts firing"
    return {"status": status, "version": ver, "detail": detail, "metrics": metrics}


@_register(
    "remotepower",
    "RemotePower (peer instance)",
    "observability",
    [_field("secret", "API key (viewer role)", PASSWORD)],
    notes="Surfaces a PEER RemotePower instance's PUBLIC fleet health as a tile "
    "beside your homelab integrations. Set URL to the peer's base "
    "(https://peer.example.com) and paste a VIEWER-role API key generated on that "
    "instance (Settings → API keys). Read-only 'federation-lite': it calls "
    "GET /api/nav-counts (fleet vitals) plus the no-auth /api/public-info for the "
    "version — off-site homelab visibility, NOT federation (no shared identity or "
    "control).",
)
def _remotepower(inst, c):
    key = str(inst.get("secret") or "").strip()
    if not key:
        raise IntegrationError("a viewer-role API key from the peer instance is required")
    # RemotePower authenticates API keys via the X-Token header (its primary
    # scheme) and also accepts Authorization: Bearer; send both so the connector
    # works against any recent peer. get_json() raises IntegrationError on a
    # non-2xx (bad/expired key, no route, unreachable) → the poller marks the
    # tile CRITICAL, which is exactly the "unreachable/auth-failed" case.
    headers = {"X-Token": key, "Authorization": f"Bearer {key}"}
    nc = c.get_json("/api/nav-counts", headers=headers)
    if not isinstance(nc, dict):
        raise IntegrationError("unexpected /api/nav-counts response from peer")
    # nav-counts keys (peer side): fleet = offline monitored devices,
    # monitoring = monitors currently down, security = critical CVE findings,
    # site_health = {healthy, issues, failing}, alerts = {open, acknowledged, ...}.
    # Everything is parsed defensively (chained .get()) — no hard dependency on a
    # single key, since an older peer may omit some of them.
    offline = int(_num(nc.get("fleet")))
    monitors_down = int(_num(nc.get("monitoring")))
    alerts = nc.get("alerts")
    alerts_open = int(_num(alerts.get("open"))) if isinstance(alerts, dict) else 0
    sh = nc.get("site_health")
    # Default healthy=True so a peer that predates site_health isn't read as degraded.
    sh_healthy = bool(sh.get("healthy", True)) if isinstance(sh, dict) else True

    # Total device count isn't in nav-counts; the viewer-visible fleet/health
    # summary carries it. Best-effort — degrade gracefully if the peer lacks it.
    devices = None
    try:
        fh = c.get_json("/api/fleet/health", headers=headers)
        if isinstance(fh, dict) and fh.get("total_devices") is not None:
            devices = int(_num(fh.get("total_devices")))
    except IntegrationError:
        pass

    # Version from the no-auth public-info endpoint (cheap, best-effort).
    version = ""
    try:
        info = c.get_json("/api/public-info")
        if isinstance(info, dict):
            version = str(info.get("server_version") or "")
    except IntegrationError:
        pass

    # OK only when the peer is reachable AND reports itself healthy with a quiet
    # fleet; anything the peer flags (degraded control-plane / offline hosts /
    # open alerts / monitors down) → WARNING. Unreachable/auth failures already
    # raised above → CRITICAL via the poller.
    degraded = (not sh_healthy) or offline or alerts_open or monitors_down
    status = WARN if degraded else OK

    metrics = {"offline": offline, "alerts_open": alerts_open}
    if devices is not None:
        metrics["devices"] = devices

    parts = []
    if devices is not None:
        parts.append(f"{devices} device{'' if devices == 1 else 's'}")
    parts.append(f"{offline} offline")
    parts.append(f"{alerts_open} open alert{'' if alerts_open == 1 else 's'}")
    detail = ", ".join(parts)
    if not sh_healthy:
        detail += " — peer control-plane degraded"

    out = {"status": status, "detail": detail, "metrics": metrics}
    if version:
        out["version"] = version
    return out


# ══════════════════════════════════════════════════════════════════════════════
# WAVE E — apps people care about
# ══════════════════════════════════════════════════════════════════════════════


@_register(
    "jellyfin",
    "Jellyfin",
    "media",
    [_field("secret", "API key", PASSWORD)],
    notes="Jellyfin /System/Info with an API key (Authorization: MediaBrowser Token).",
)
def _jellyfin(inst, c):
    # Jellyfin 10.12 turned EnableLegacyAuthorization off by default, and with it
    # the X-Emby-Token / X-MediaBrowser-Token headers and the api_key parameter:
    # a key sent that way is ignored and every call answers 401. The
    # Authorization header with the MediaBrowser scheme is read with or without
    # that flag, and older releases read it too.
    token = str(inst.get("secret", "")).strip().replace('"', "")
    h = {"Authorization": f'MediaBrowser Token="{token}"'}
    r = c.get("/System/Info", headers=h)
    if r.status == 401:
        raise IntegrationError("HTTP 401 from /System/Info — Jellyfin rejected the API key")
    if not r.ok:
        raise IntegrationError(f"HTTP {r.status} from /System/Info")
    info = r.json()
    ver = info.get("Version", "")
    active = transcoding = 0
    try:
        for s in c.get_json("/Sessions", headers=h) or []:
            if s.get("NowPlayingItem"):
                active += 1
                if s.get("TranscodingInfo") or {}:
                    transcoding += 1
    except IntegrationError:
        pass
    return {
        "status": OK,
        "version": ver,
        "detail": f"up · {active} playing, {transcoding} transcoding",
        "metrics": {"sessions_active": active, "transcoding": transcoding},
    }


@_register(
    "plex",
    "Plex",
    "media",
    [_field("secret", "X-Plex-Token", PASSWORD)],
    notes="Plex Media Server token (X-Plex-Token).",
)
def _plex(inst, c):
    h = {"X-Plex-Token": inst.get("secret", ""), "Accept": "application/json"}
    ident = c.get_json("/identity", headers=h)
    ver = (ident.get("MediaContainer") or {}).get("version", "")
    active = 0
    try:
        sessions = c.get_json("/status/sessions", headers=h)
        active = int((sessions.get("MediaContainer") or {}).get("size", 0))
    except IntegrationError:
        pass
    return {
        "status": OK,
        "version": ver,
        "detail": f"up · {active} active sessions",
        "metrics": {"sessions_active": active},
    }


@_register(
    "nextcloud",
    "Nextcloud",
    "apps",
    [_field("username", "Admin user", TEXT), _field("secret", "Password / app password", PASSWORD)],
    notes="Nextcloud serverinfo API (admin or app password, Basic auth).",
)
def _nextcloud(inst, c):
    import base64

    auth = base64.b64encode(f"{inst.get('username','')}:{inst.get('secret','')}".encode()).decode()
    h = {"Authorization": "Basic " + auth, "OCS-APIRequest": "true", "Accept": "application/json"}
    info = c.get_json(
        "/ocs/v2.php/apps/serverinfo/api/v1/info", headers=h, params={"format": "json"}
    )
    data = ((info or {}).get("ocs") or {}).get("data") or {}
    nc = data.get("nextcloud") or {}
    system = nc.get("system") or {}
    ver = system.get("version", "")
    users = (nc.get("storage") or {}).get("num_users", 0)
    update_available = (
        bool(system.get("update", {}).get("available"))
        if isinstance(system.get("update"), dict)
        else False
    )
    status = WARN if update_available else OK
    return {
        "status": status,
        "version": ver,
        "detail": f"{int(_num(users))} users" + (" · update available" if update_available else ""),
        "metrics": {"users": users, "update_available": update_available},
    }


# ══════════════════════════════════════════════════════════════════════════════
# WAVE F — download & media-automation stack
# ══════════════════════════════════════════════════════════════════════════════


@_register(
    "sabnzbd",
    "SABnzbd",
    "download",
    [_field("secret", "API key", PASSWORD)],
    notes="SABnzbd API key (Config → General).",
)
def _sabnzbd(inst, c):
    q = c.get_json(
        "/api", params={"mode": "queue", "output": "json", "apikey": inst.get("secret", "")}
    )
    queue = (q or {}).get("queue") or {}
    slots = int(_num(queue.get("noofslots", 0)))
    speed = queue.get("speed", "0")
    paused = bool(queue.get("paused"))
    status = WARN if paused else OK
    return {
        "status": status,
        "version": queue.get("version", ""),
        "detail": f"{slots} in queue, {speed}B/s" + (" · PAUSED" if paused else ""),
        "metrics": {"queue": slots, "mb_left": queue.get("mbleft", 0), "paused": paused},
    }


@_register(
    "nzbget",
    "NZBGet",
    "download",
    [_field("username", "Username", TEXT), _field("secret", "Password", PASSWORD)],
    notes="NZBGet JSON-RPC with control username/password.",
)
def _nzbget(inst, c):
    import base64

    auth = base64.b64encode(f"{inst.get('username','')}:{inst.get('secret','')}".encode()).decode()
    r = c.post_json(
        "/jsonrpc",
        {"method": "status", "params": [], "id": 1},
        headers={"Authorization": "Basic " + auth},
    ).json()
    res = (r or {}).get("result") or {}
    rate = int(_num(res.get("DownloadRate", 0))) // 1024
    remaining = int(_num(res.get("RemainingSizeMB", 0)))
    standby = bool(res.get("ServerStandBy"))
    return {
        "status": OK,
        "version": res.get("Version", ""),
        "detail": f"{rate} KB/s, {remaining} MB remaining" + (" · idle" if standby else ""),
        "metrics": {"download_kbs": rate, "remaining_mb": remaining},
    }


@_register(
    "qbittorrent",
    "qBittorrent",
    "download",
    [_field("username", "Username", TEXT), _field("secret", "Password", PASSWORD)],
    notes="qBittorrent WebUI — logs in for a session cookie, reads transfer + torrents.",
)
def _qbittorrent(inst, c):
    login = c.post_form(
        "/api/v2/auth/login",
        {"username": inst.get("username", ""), "password": inst.get("secret", "")},
        headers={"Referer": c.base},
    )
    if not login.ok or "Ok" not in (login.text or "Ok"):
        if not login.ok:
            raise IntegrationError(f"login failed (HTTP {login.status})")
    info = c.get_json("/api/v2/transfer/info")
    conn = str(info.get("connection_status", "connected"))
    dl = int(_num(info.get("dl_info_speed", 0))) // 1024
    count = 0
    try:
        count = len(c.get_json("/api/v2/torrents/info") or [])
    except IntegrationError:
        pass
    status = WARN if conn == "disconnected" else OK
    return {
        "status": status,
        "detail": f"{count} torrents, {dl} KB/s, {conn}",
        "metrics": {"torrents": count, "download_kbs": dl, "connection": conn},
    }


@_register(
    "transmission",
    "Transmission",
    "download",
    [
        _field("username", "Username", TEXT, optional=True),
        _field("secret", "Password", PASSWORD, optional=True),
    ],
    notes="Transmission RPC (handles the 409 X-Transmission-Session-Id handshake).",
)
def _transmission(inst, c):
    h = {}
    if inst.get("username") or inst.get("secret"):
        import base64

        h["Authorization"] = (
            "Basic "
            + base64.b64encode(
                f"{inst.get('username','')}:{inst.get('secret','')}".encode()
            ).decode()
        )
    body = {"method": "session-stats"}
    r = c.post_json("/transmission/rpc", body, headers=h)
    if r.status == 409:
        sid = r.headers.get("X-Transmission-Session-Id") or r.headers.get(
            "x-transmission-session-id"
        )
        h["X-Transmission-Session-Id"] = sid or ""
        r = c.post_json("/transmission/rpc", body, headers=h)
    if not r.ok:
        raise IntegrationError(f"RPC failed (HTTP {r.status})")
    args = (r.json() or {}).get("arguments") or {}
    total = int(_num(args.get("torrentCount", 0)))
    active = int(_num(args.get("activeTorrentCount", 0)))
    dl = int(_num(args.get("downloadSpeed", 0))) // 1024
    return {
        "status": OK,
        "detail": f"{total} torrents, {active} active, {dl} KB/s",
        "metrics": {"torrents": total, "active": active, "download_kbs": dl},
    }


@_register(
    "deluge",
    "Deluge",
    "download",
    [_field("secret", "WebUI password", PASSWORD)],
    notes="Deluge Web JSON API — logs in for a session cookie.",
)
def _deluge(inst, c):
    auth = c.post_json(
        "/json", {"method": "auth.login", "params": [inst.get("secret", "")], "id": 1}
    ).json()
    if not (auth or {}).get("result"):
        raise IntegrationError("login failed")
    ui = c.post_json(
        "/json", {"method": "web.update_ui", "params": [["name", "state"], {}], "id": 2}
    ).json()
    res = (ui or {}).get("result") or {}
    torrents = res.get("torrents") or {}
    stats = res.get("stats") or {}
    dl = int(_num(stats.get("download_rate", 0))) // 1024
    return {
        "status": OK,
        "detail": f"{len(torrents)} torrents, {dl} KB/s",
        "metrics": {"torrents": len(torrents), "download_kbs": dl},
    }


@_register(
    "servarr",
    "Servarr (other *arr app)",
    "download",
    [_field("secret", "API key", PASSWORD)],
    notes="Generic *arr connector — auto-detects the API version (/api/v3 for "
    "Sonarr/Radarr, /api/v1 for Prowlarr/Lidarr/Readarr). The named entries "
    "(Sonarr, Radarr, …) use this same connector; pick one per instance.",
)
def _servarr(inst, c):
    h = {"X-Api-Key": inst.get("secret", "")}
    # *arr apps split across API versions: Sonarr/Radarr on /api/v3, but
    # Prowlarr/Lidarr/Readarr on /api/v1. Probe both for system/status.
    api = None
    st = {}
    last = 0
    for ver_path in ("v3", "v1"):
        r = c.get(f"/api/{ver_path}/system/status", headers=h)
        if r.ok:
            api, st = ver_path, (r.json() or {})
            break
        last = r.status
    if api is None:
        if last in (401, 403):
            raise IntegrationError(f"unauthorized (HTTP {last}) — check the API key")
        raise IntegrationError(
            f"system/status not reachable (HTTP {last or 404}) — check the URL + API key"
        )
    app = st.get("appName", "Servarr")
    ver = st.get("version", "")
    health = c.get_json(f"/api/{api}/health", headers=h) or []
    errors = [x.get("message", "") for x in health if str(x.get("type", "")).lower() == "error"]
    warnings = [x.get("message", "") for x in health if str(x.get("type", "")).lower() == "warning"]
    # 8.0.0: what the download client is stuck on. GET /api/<v>/queue/status (Sonarr and Radarr on v3, Lidarr and Readarr on v1; Prowlarr has no queue, so it answers 404) is
    # {totalCount, count, unknownCount, errors, warnings, unknownErrors, unknownWarnings}, where the last four say whether any queued item carries one. It is the signal the health list
    # does not give: a download that failed to import sits in the queue with the app itself reporting no problem. Asked quietly, so an app without the route, or an answer
    # that does not come, leaves the result as it was.
    queue, queue_read = {}, False
    try:
        qr = c.get(f"/api/{api}/queue/status", headers=h)
        if qr.ok:
            body = qr.json()
            if isinstance(body, dict):
                queue, queue_read = body, True
    except IntegrationError:
        pass
    q_total = queue.get("totalCount")
    q_total = (
        int(q_total)
        if isinstance(q_total, (int, float))
        and not isinstance(q_total, bool)
        and q_total == q_total
        and 0 <= q_total < 10**9
        else 0
    )
    q_err = bool(queue.get("errors") or queue.get("unknownErrors"))
    q_warn = bool(queue.get("warnings") or queue.get("unknownWarnings"))
    status = CRIT if errors else (WARN if (warnings or q_err or q_warn) else OK)
    detail = f"{app} {ver}"
    if errors:
        detail += f" · {len(errors)} error: {errors[0][:60]}"
    elif warnings:
        detail += f" · {len(warnings)} warning: {warnings[0][:60]}"
    else:
        detail += " · healthy"
    if q_total:
        detail += f" · {q_total} in queue"
    if q_err:
        detail += " · downloads with errors"
    elif q_warn:
        detail += " · downloads with warnings"
    metrics = {"app": app, "health_errors": len(errors), "health_warnings": len(warnings)}
    # an app with no queue (Prowlarr), or an answer that did not come, has no Queue chip rather than a zero
    if queue_read:
        metrics["queue_total"] = q_total
        metrics["queue_problems"] = 1 if (q_err or q_warn) else 0
    return {"status": status, "version": ver, "detail": detail, "metrics": metrics}


# Discoverability: list each *arr app by name in the Add dropdown. They all use
# the one _servarr connector above (which auto-detects /api/v3 vs /api/v1), so
# the user just picks "Sonarr" / "Radarr" / … instead of having to know it's
# "Servarr". One integration instance per app.
for _arr_type, _arr_label in (
    ("sonarr", "Sonarr"),
    ("radarr", "Radarr"),
    ("prowlarr", "Prowlarr"),
    ("lidarr", "Lidarr"),
    ("readarr", "Readarr"),
):
    _register(
        _arr_type,
        _arr_label,
        "download",
        [_field("secret", "API key", PASSWORD)],
        notes=f"{_arr_label} — health-check warnings/errors via its API "
        "(auto-detects /api/v1 vs /api/v3).",
    )(_servarr)


@_register(
    "bazarr",
    "Bazarr",
    "download",
    [_field("secret", "API key", PASSWORD)],
    notes="Bazarr subtitle manager (own /api, distinct from the *arr v3 API).",
)
def _bazarr(inst, c):
    h = {"X-Api-Key": inst.get("secret", "")}
    st = c.get_json("/api/system/status", headers=h)
    ver = ((st or {}).get("data") or {}).get("bazarr_version", "") or (st or {}).get(
        "bazarr_version", ""
    )
    issues = 0
    try:
        health = c.get_json("/api/system/health", headers=h)
        issues = len((health or {}).get("data") or [])
    except IntegrationError:
        pass
    status = WARN if issues else OK
    return {
        "status": status,
        "version": ver,
        "detail": "up" + (f" · {issues} health issues" if issues else ""),
        "metrics": {"health_issues": issues},
    }


@_register(
    "overseerr",
    "Overseerr / Jellyseerr",
    "request",
    [_field("secret", "API key", PASSWORD)],
    notes="Overseerr and its Jellyseerr fork share the same API (X-Api-Key).",
)
def _overseerr(inst, c):
    h = {"X-Api-Key": inst.get("secret", "")}
    st = c.get_json("/api/v1/status", headers=h)
    ver = st.get("version", "")
    update = bool(st.get("updateAvailable"))
    pending = 0
    try:
        pending = int(
            _num((c.get_json("/api/v1/request/count", headers=h) or {}).get("pending", 0))
        )
    except IntegrationError:
        pass
    status = WARN if update else OK
    return {
        "status": status,
        "version": ver,
        "detail": f"{pending} pending requests" + (" · update available" if update else ""),
        "metrics": {"pending_requests": pending, "update_available": update},
    }


# ══════════════════════════════════════════════════════════════════════════════
# WAVE G — self-hosted apps round-out
# ══════════════════════════════════════════════════════════════════════════════


@_register(
    "immich",
    "Immich",
    "media",
    [_field("secret", "API key", PASSWORD)],
    notes="Immich API key (Account Settings → API Keys), sent as x-api-key. Permissions the key needs: server.about and server.statistics; add server.storage for the "
    "disk fill (it sets the status: 80% warns, 90% is critical) and queue.read (job.read on a server before 2.4.0) for the number of failed jobs.",
)
def _immich(inst, c):
    h = {"x-api-key": inst.get("secret", "")}
    about = c.get_json("/api/server/about", headers=h) or {}
    ver = str(about.get("version", "") or "")
    stats = c.get_json("/api/server/statistics", headers=h) or {}
    photos = int(_num(stats.get("photos", 0)))
    videos = int(_num(stats.get("videos", 0)))
    usage_mb = int(_num(stats.get("usage", 0)) / (1024 * 1024))
    metrics = {"photos": photos, "videos": videos, "usage_mb": usage_mb}
    detail = f"{photos} photos, {videos} videos, {usage_mb} MB used"
    status = OK
    # 8.0.0: how full the disk under the library is (GET /api/server/storage, API key permission server.storage) and what the job queues hold
    # (GET /api/queues since 2.4.0, permission queue.read; GET /api/jobs, permission job.read, before that and still answering). Both are optional: a key
    # without the permission, or a server without the route, leaves the answer as it was.
    disk = _immich_disk(c, h)
    if disk is not None:
        metrics["disk_pct"] = disk
        detail += f" · disk {disk:g}% full"
        status = CRIT if disk >= 90 else WARN if disk >= 80 else OK
    jobs = _immich_jobs(c, h)
    if jobs is not None:
        metrics.update(
            jobs_failed=jobs["failed"], jobs_active=jobs["active"], jobs_waiting=jobs["waiting"]
        )
        if jobs["failed"]:
            detail += f" · {jobs['failed']} failed {'job' if jobs['failed'] == 1 else 'jobs'}"
    return {"status": status, "version": ver, "detail": detail, "metrics": metrics}


def _immich_disk(c, h):
    """The percentage of the disk under the library that is used, or None when the server does not say (no permission, no route, an answer without it)."""
    try:
        st = c.get_json("/api/server/storage", headers=h) or {}
        pct = st.get("diskUsagePercentage")
        if isinstance(pct, bool) or not isinstance(pct, (int, float)):
            pct = (
                _pct(st.get("diskUseRaw"), st.get("diskSizeRaw"))
                if _num(st.get("diskSizeRaw")) > 0
                else None
            )
        return None if pct is None else round(float(pct), 1)
    except (IntegrationError, AttributeError, TypeError, ValueError):
        return None


def _immich_jobs(c, h):
    """The jobs the server's queues hold, summed over the queues, or None. /api/queues (2.4.0 and later, an alpha API) answers a list of
    {name, isPaused, statistics: {active, waiting, failed, ...}}; /api/jobs (deprecated, and what older servers have) answers a map of
    queue name to {jobCounts: {...}, queueStatus: {...}}. The first is tried first and the second when it does not answer or answers something else.
    """

    def total(rows):
        out = {"active": 0, "waiting": 0, "failed": 0}
        for counts in rows:
            if not isinstance(counts, dict):
                raise TypeError("a queue without counts")
            for k in out:
                out[k] += int(_num(counts.get(k)))
        return out

    try:
        q = c.get_json("/api/queues", headers=h)
        if isinstance(q, list) and q:
            return total([(r or {}).get("statistics") for r in q])
    except (IntegrationError, AttributeError, TypeError, ValueError):
        pass
    try:
        j = c.get_json("/api/jobs", headers=h)
        if isinstance(j, dict) and j:
            return total([(r or {}).get("jobCounts") for r in j.values()])
    except (IntegrationError, AttributeError, TypeError, ValueError):
        pass
    return None


def _paperless_problems(st):
    """The problems GET /api/status/ names, as (status, text), worst first: the critical checks are written before the warnings, so the order needs no sort.

    Read from Paperless-ngx's own SystemStatusView: database.status and the tasks' redis, celery, index, classifier, sanity-check and LLM-index statuses are OK, WARNING or ERROR, each
    with an *_error. A WARNING of the classifier, the sanity check or the LLM index is what an install that has not run one yet says ("No classifier training tasks found"), so only
    their ERROR counts; a WARNING of celery is "no worker answers a ping", which does. A database, redis or celery that is in ERROR stops documents being consumed, so those are critical.
    """
    out = []
    if not isinstance(st, dict):
        return out
    db = st.get("database") if isinstance(st.get("database"), dict) else {}
    tasks = st.get("tasks") if isinstance(st.get("tasks"), dict) else {}

    def word(d, key):
        return str(d.get(key) or "").upper()

    def say(label, err):
        e = str(err or "").strip()
        return f"{label}: {e[:80]}" if e else label

    if word(db, "status") == "ERROR":
        out.append((CRIT, say("database", db.get("error"))))
    if word(tasks, "redis_status") == "ERROR":
        out.append((CRIT, say("redis", tasks.get("redis_error"))))
    if word(tasks, "celery_status") == "ERROR":
        out.append((CRIT, say("celery", tasks.get("celery_error"))))
    elif word(tasks, "celery_status") == "WARNING":
        out.append((WARN, "celery: no worker answers"))
    ms = db.get("migration_status") if isinstance(db.get("migration_status"), dict) else {}
    pending = (
        ms.get("unapplied_migrations") if isinstance(ms.get("unapplied_migrations"), list) else []
    )
    if pending:
        out.append(
            (WARN, f"{len(pending)} migration{'s' if len(pending) != 1 else ''} not applied")
        )
    for key, label in (
        ("index", "index"),
        ("classifier", "classifier"),
        ("sanity_check", "sanity check"),
        ("llmindex", "LLM index"),
    ):
        if word(tasks, key + "_status") == "ERROR":
            out.append((WARN, say(label, tasks.get(key + "_error"))))
    return out


@_register(
    "paperless",
    "Paperless-ngx",
    "apps",
    [_field("secret", "API token", PASSWORD)],
    notes="Paperless-ngx API token (profile → API auth token), sent as Authorization: Token. Counts come from /api/statistics/; health (database, redis, celery, "
    "index, classifier, sanity check) comes from /api/status/, which Paperless answers only to a staff or superuser account or one with the view_system_monitoring "
    "permission. Without that the counts still show and the detail says so.",
)
def _paperless(inst, c):
    h = _hdr_token(inst, "Authorization", "Token ")
    st = c.get_json("/api/statistics/", headers=h) or {}
    docs = int(_num(st.get("documents_total", 0)))
    inbox = int(_num(st.get("documents_inbox", 0)))
    out = {
        "status": OK,
        "detail": f"{docs} documents, {inbox} in inbox",
        "metrics": {"documents": docs, "inbox": inbox},
    }
    # 8.0.0: Paperless-ngx's own health, GET /api/status/. It answers a plain-text 403 to a user who is not staff or a superuser and does not hold
    # paperless.view_system_monitoring, and a release that has no such route a 404: neither is Paperless being unwell, so the counts stay and the detail says why health is missing.
    try:
        r = c.get("/api/status/", headers=h)
    except IntegrationError:
        return out  # the counts were read; the health call got no answer (a timeout, a reset): that is not Paperless being unwell
    if r.ok:
        try:
            body = r.json()
        except (
            IntegrationError,
            ValueError,
        ):  # a body that is not JSON: Resp.json() says so with an IntegrationError
            body = None
        if isinstance(body, dict):
            problems = _paperless_problems(body)
            out["metrics"]["problems"] = len(problems)
            if problems:
                out["status"] = CRIT if problems[0][0] == CRIT else WARN
                out["detail"] += " · " + "; ".join(text for _, text in problems)
    elif r.status in (401, 403):
        out["detail"] += " · health needs a staff user or the view_system_monitoring permission"
    elif r.status == 404:
        out["detail"] += " · this Paperless has no status endpoint"
    else:
        out["detail"] += f" · the status endpoint answered HTTP {r.status}"
    return out


@_register(
    "vaultwarden",
    "Vaultwarden",
    "apps",
    [],
    notes="Unauthenticated /alive liveness probe (+ /api/config for the server version). "
    "No credential needed.",
)
def _vaultwarden(inst, c):
    r = c.get("/alive")
    if not r.ok:
        raise IntegrationError(f"/alive returned HTTP {r.status}")
    ver = ""
    try:
        ver = str((c.get_json("/api/config") or {}).get("version", "") or "")
    except IntegrationError:
        pass
    return {"status": OK, "version": ver, "detail": "alive", "metrics": {"alive": True}}


@_register(
    "gitea",
    "Gitea / Forgejo",
    "apps",
    [_field("secret", "Access token (optional)", PASSWORD, optional=True)],
    notes="Gitea/Forgejo API (/api/v1). A token (Authorization: token …) is only "
    "needed for a private instance / to count private repos.",
)
def _gitea(inst, c):
    h = _hdr_token(inst, "Authorization", "token ") if inst.get("secret") else {}
    ver = str((c.get_json("/api/v1/version", headers=h) or {}).get("version", "") or "")
    repos = 0
    try:
        r = c.get("/api/v1/repos/search", headers=h, params={"limit": 1})
        if r.ok:
            body = r.json() or {}
            # The total lives in the X-Total-Count header (the body is one page);
            # fall back to body fields for older/forked servers.
            hdr = next(
                (v for k, v in (r.headers or {}).items() if str(k).lower() == "x-total-count"),
                None,
            )
            if hdr is not None:
                repos = int(_num(hdr))
            else:
                repos = int(_num(body.get("total_count", len(body.get("data") or []))))
    except IntegrationError:
        pass
    return {
        "status": OK,
        "version": ver,
        "detail": f"up · {repos} repositories",
        "metrics": {"repos": repos},
    }


@_register(
    "syncthing",
    "Syncthing",
    "apps",
    [_field("secret", "API key", PASSWORD)],
    notes="Syncthing REST API key (Actions → Settings → General), sent as X-API-Key.",
)
def _syncthing(inst, c):
    # Unauthenticated liveness first — distinguishes "down" from "bad key".
    health = c.get_json("/rest/noauth/health")
    if str((health or {}).get("status", "")).upper() != "OK":
        raise IntegrationError("health endpoint did not report OK")
    h = {"X-API-Key": inst.get("secret", "")}
    st = c.get_json("/rest/system/status", headers=h) or {}
    uptime = int(_num(st.get("uptime", 0)))
    conns = (c.get_json("/rest/system/connections", headers=h) or {}).get("connections") or {}
    connected = sum(1 for d in conns.values() if (d or {}).get("connected"))
    out = {
        "status": OK,
        "detail": f"{connected}/{len(conns)} devices connected, up {uptime // 3600}h",
        "metrics": {"devices_connected": connected, "devices": len(conns), "uptime_s": uptime},
    }
    # 8.0.0: Syncthing's own error list, GET /rest/system/error -> {"errors": [{"when", "message"}]} (the red banner of its page). Cheap, unlike /rest/db/status, which its
    # documentation calls an expensive call and which does not list its states. A release or a key that cannot read it leaves the answer as it was.
    try:
        body = c.get_json("/rest/system/error", headers=h)
    except IntegrationError:
        return out
    raw = body.get("errors") if isinstance(body, dict) else None
    errs = [
        e
        for e in (raw if isinstance(raw, list) else [])
        if isinstance(e, dict) and str(e.get("message") or "").strip()
    ]
    out["metrics"]["errors"] = len(errs)
    if errs:
        newest = max(errs, key=lambda e: str(e.get("when") or ""))
        out["status"] = WARN
        out[
            "detail"
        ] += f" · {len(errs)} error{'s' if len(errs) != 1 else ''}: {str(newest['message']).strip()[:100]}"
    return out


@_register(
    "frigate",
    "Frigate",
    "media",
    [],
    notes="Frigate /api/stats — camera count + detection FPS. Frigate's API is "
    "unauthenticated; front it with a trusted proxy if exposed.",
)
def _frigate(inst, c):
    stats = c.get_json("/api/stats") or {}
    cams = stats.get("cameras") or {}
    det = stats.get("detection_fps")
    if det is None:  # newer Frigate reports it per-camera only
        det = sum(_num((v or {}).get("detection_fps")) for v in cams.values())
    det = round(_num(det), 1)
    ver = str(((stats.get("service") or {}).get("version", "")) or "")
    return {
        "status": OK,
        "version": ver,
        "detail": f"{len(cams)} cameras, {det} detection FPS",
        "metrics": {"cameras": len(cams), "det_fps": det},
    }


@_register(
    "octoprint",
    "OctoPrint",
    "apps",
    [_field("secret", "API key", PASSWORD)],
    notes="OctoPrint API key (Settings → API), sent as X-Api-Key. A disconnected "
    "printer is a warning (OctoPrint itself is still up), not critical.",
)
def _octoprint(inst, c):
    h = {"X-Api-Key": inst.get("secret", "")}
    ver = c.get_json("/api/version", headers=h) or {}
    server = str(ver.get("server", "") or "")
    r = c.get("/api/printer", headers=h, params={"exclude": "temperature,sd"})
    if r.status == 409:  # OctoPrint is up but no printer is connected
        return {
            "status": WARN,
            "version": server,
            "detail": "printer disconnected",
            "metrics": {"printing": False, "operational": False},
        }
    if not r.ok:
        raise IntegrationError(f"HTTP {r.status} from /api/printer")
    flags = ((r.json() or {}).get("state") or {}).get("flags") or {}
    printing = bool(flags.get("printing"))
    operational = bool(flags.get("operational"))
    status = OK if operational else WARN
    detail = "printing" if printing else ("operational, idle" if operational else "not operational")
    return {
        "status": status,
        "version": server,
        "detail": detail,
        "metrics": {"printing": printing, "operational": operational},
    }


@_register(
    "esphome",
    "ESPHome (dashboard)",
    "apps",
    [
        _field("username", "User name (optional)", TEXT, optional=True),
        _field("secret", "Password (optional)", PASSWORD, optional=True),
    ],
    notes="ESPHome dashboard or ESPHome Device Builder (it replaced the built-in dashboard, which ESPHome has removed). Reads the node list (/devices) and which nodes "
    "answer (/ping): Device Builder keeps both routes for compatibility and its authors mark them deprecated. Out-of-date firmware is a warning; an offline node is "
    "counted and said, not alerted, because a node that sleeps is offline most of the time. User name and password only if the dashboard has them set (HTTP Basic).",
)
def _esphome(inst, c):
    h = {}
    if inst.get("secret"):
        h = {
            "Authorization": "Basic "
            + base64.b64encode(f"{inst.get('username', '')}:{inst.get('secret')}".encode()).decode()
        }
    data = c.get_json("/devices", headers=h)
    nodes = (data.get("configured") if isinstance(data, dict) else data) or []
    outdated = 0
    for n in nodes:
        dep = (n or {}).get("deployed_version")
        cur = (n or {}).get("current_version")
        if dep and cur and str(dep) != str(cur):
            outdated += 1
    # 8.0.0: GET /ping answers {<config>.yaml: true | false | null} for every configured node. A dashboard without it, or one that answers anything else, leaves this out.
    offline = None
    try:
        ping = c.get_json("/ping", headers=h)
        seen = [v for v in ping.values() if isinstance(v, bool)] if isinstance(ping, dict) else []
        if seen:
            offline = sum(1 for v in seen if v is False)
    except IntegrationError:
        pass
    status = WARN if outdated else OK
    detail = f"{len(nodes)} nodes"
    if offline:
        detail += f", {offline} offline"
    detail += f", {outdated} out of date" if outdated else ", all current"
    metrics = {"nodes": len(nodes), "outdated": outdated}
    if offline is not None:
        metrics["offline"] = offline
    return {"status": status, "detail": detail, "metrics": metrics}


@_register(
    "homebridge",
    "Homebridge",
    "apps",
    [_field("username", "Username", TEXT), _field("secret", "Password", PASSWORD)],
    notes="Homebridge UI (homebridge-config-ui-x) — logs in for a token, reads "
    "bridge status + plugin count.",
)
def _homebridge(inst, c):
    login = c.post_json(
        "/api/auth/login",
        {"username": inst.get("username", ""), "password": inst.get("secret", "")},
    )
    if not login.ok:
        raise IntegrationError(f"login failed (HTTP {login.status})")
    tok = str((login.json() or {}).get("access_token", "") or "")
    if not tok:
        raise IntegrationError("login returned no access token")
    h = {"Authorization": "Bearer " + tok}
    st = c.get_json("/api/status/homebridge", headers=h) or {}
    up = str(st.get("status", "")).lower() == "up"
    plugins = 0
    try:
        plugins = len(c.get_json("/api/plugins", headers=h) or [])
    except IntegrationError:
        pass
    return {
        "status": OK if up else WARN,
        "detail": f"bridge {st.get('status', 'unknown')}, {plugins} plugins",
        "metrics": {"up": up, "plugins": plugins},
    }


def _wp_ts(s):
    """Parse a Simple History GMT timestamp → epoch. 0 when unparseable (the UI
    renders that as '—' rather than 1970).

    v6.4.2: accept ISO-8601 as well as the MySQL-style 'YYYY-MM-DD HH:MM:SS'.
    WP core's REST layer serialises dates as '2026-07-23T09:15:00' and Simple
    History's own format has varied across majors — parsing only the space form
    meant every login silently timestamped 0, so the table showed '—' for all of
    them AND `logins_24h` was permanently 0. A metric that is always zero looks
    exactly like a quiet site."""
    import calendar
    import time as _time

    raw = str(s or "").strip()
    if not raw:
        return 0
    # Drop a trailing timezone marker — these are documented GMT either way, and
    # strptime cannot take '%z' consistently across the forms seen in the wild.
    if raw.endswith("Z"):
        raw = raw[:-1]
    raw = raw.replace("T", " ", 1)
    if "." in raw:  # fractional seconds
        raw = raw.split(".", 1)[0]
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return int(calendar.timegm(_time.strptime(raw, fmt)))
        except (TypeError, ValueError):
            continue
    return 0


# How many logins we keep. Bounds what a remote (possibly compromised) site can
# push into our state store; api.py's read-whitelist trims to 5 again for display.
_WP_LOGIN_CAP = 5
# How many log entries we scan per poll. The channel carries failed logins,
# logouts and password resets as well as successful ones, so a small page can
# contain no logins at all on a busy site — 25 was enough to show five rows and
# not enough to count a day.
_WP_EVENT_PAGE = 100


def _wp_login_event(e):
    """One Simple History event → {user, ip, ts} if it is a successful login,
    else None. Defensive about shape — the REST payload varies across Simple
    History major versions (context keys vs. top-level fields)."""
    if not isinstance(e, dict):
        return None
    ctx = e.get("context")
    if not isinstance(ctx, dict):
        ctx = {}
    key = str(ctx.get("_message_key") or e.get("message_key") or "")
    logger = str(e.get("logger") or "")
    if key != "user_logged_in" and not (
        logger == "SimpleUserLogger" and "logged in" in str(e.get("message") or "")
    ):
        return None
    idata = e.get("initiator_data")
    if not isinstance(idata, dict):
        idata = {}
    user = str(idata.get("user_login") or ctx.get("user_login") or "?")[:64]
    ip = ""
    ips = e.get("ip_addresses")
    if isinstance(ips, dict):
        for v in ips.values():
            if v:
                ip = str(v)
                break
    elif isinstance(ips, list) and ips:
        ip = str(ips[0])
    if not ip:
        ip = str(ctx.get("_server_remote_addr") or "")
    return {"user": user, "ip": ip[:64], "ts": _wp_ts(e.get("date_gmt") or e.get("date"))}


def _wp_rest_root(c):
    """The site's REST index as a dict — the one fetch every WordPress poll makes.

    Two things stop this being a plain GET, and both produced "invalid JSON" on
    sites that were perfectly healthy:

    - **`_fields` is not an optimisation, it is the fix.** The unfiltered index
      enumerates every registered route with its full schema; on a site with
      WooCommerce/Yoast/Elementor it runs to megabytes, past the transport's
      read budget. The body then arrived cut off mid-object and the operator was
      told their JSON was invalid. We read four keys, so we ask for four keys.
    - **Plain permalinks have no `/wp-json/` path at all** — the REST root is
      only reachable as `?rest_route=/`. That is a default on some installs, so
      "404" was a permanent and unexplained failure for those operators.
    """
    fields = {"_fields": "name,description,url,home,namespaces"}
    r = c.get("/wp-json/", params=fields)
    if r.status == 404:
        alt = c.get("/", params={"rest_route": "/", **fields})
        if alt.ok:
            r = alt
    if not r.ok:
        hint = ""
        if r.status in (401, 403):
            hint = (
                " — the REST API is refusing anonymous requests "
                "(a security plugin or host rule?)"
            )
        elif r.status == 404:
            hint = (
                " — no REST API at /wp-json/ or ?rest_route=/; check the URL "
                "is the site root and that the REST API is not disabled"
            )
        raise IntegrationError(f"HTTP {r.status} from the WordPress REST API{hint}")
    root = r.json()
    # `or {}` does NOT coerce a truthy non-dict: a bare JSON list or string
    # sailed through it and AttributeError'd on the next line, surfacing to the
    # operator as "AttributeError: 'list' object has no attribute 'get'".
    return root if isinstance(root, dict) else {}


@_register(
    "wordpress",
    "WordPress",
    "apps",
    [
        _field("username", "Username", TEXT, optional=True),
        _field("secret", "Application password", PASSWORD, optional=True),
    ],
    notes="Watches a WordPress site: REST reachability + site identity, and — "
    "with a username + Application password (Users → Profile → Application "
    "Passwords) — the last logins with timestamp and source IP via the free "
    "Simple History plugin's REST API (the server geo-enriches the IPs when a "
    "GeoIP database is configured in Settings → Security). Without Simple "
    "History the connector still monitors the site; the login list is just "
    "unavailable.",
)
def _wordpress(inst, c):
    root = _wp_rest_root(c)
    site = str(root.get("name") or "").strip()
    # A 200 that is JSON but carries none of the index's keys is not a WordPress
    # REST root — reporting it OK ("site up") would be a green tile for
    # something we never actually reached. Tested by PRESENCE, not truthiness:
    # a site with an empty title is perfectly legitimate and must stay green.
    if not any(k in root for k in ("name", "namespaces", "url", "home", "description")):
        return {
            "status": WARN,
            "detail": "reachable, but the response is not a WordPress REST index "
            "— check the URL points at the site root",
            "metrics": {},
        }
    h = {}
    user, pw = inst.get("username") or "", inst.get("secret") or ""
    authed = False
    if user and pw:
        # An Application password is generated with spaces for readability
        # ("abcd EFGH ijkl ..."); WordPress strips them before comparing, and an
        # operator who pastes it unchanged would otherwise be told, correctly but
        # uselessly, that their correct password was rejected.
        h["Authorization"] = (
            "Basic " + base64.b64encode(f"{user}:{pw.replace(' ', '')}".encode()).decode()
        )
        why = ""
        try:
            me_r = c.get("/wp-json/wp/v2/users/me", headers=h)
            if me_r.status in (401, 403):
                # Distinguish the two causes, because the fix is different and
                # "check the Application password" is actively wrong for the
                # second one. Many CGI/FastCGI hosts drop the Authorization
                # header before PHP ever sees it, so the credentials are never
                # presented at all — WordPress then reports "not logged in".
                code = ""
                try:
                    b = me_r.json()
                    code = str(b.get("code") or "") if isinstance(b, dict) else ""
                except IntegrationError:
                    code = ""
                why = (
                    " — credentials rejected (check the Application password, and "
                    "that the site is served over HTTPS)"
                    if code
                    in (
                        "incorrect_password",
                        "invalid_username",
                        "rest_application_password_disabled",
                    )
                    else " — the site did not accept the login (WordPress said "
                    f"{code or 'nothing specific'}). Some hosts strip the "
                    "Authorization header before PHP sees it; check that "
                    "Application Passwords are enabled and reaching the site"
                )
            elif me_r.ok:
                me = me_r.json()
                authed = bool(isinstance(me, dict) and me.get("id"))
                if not authed:
                    why = " — signed in but the site returned no user identity"
            else:
                why = f" — HTTP {me_r.status} from the users endpoint"
        except IntegrationError as e:
            why = f" — {e}"
        if not authed:
            return {
                "status": WARN,
                "detail": f"{site or 'site up'}{why}",
                "metrics": {},
                # Symmetric with the success return: a consumer that reads
                # recent_logins must see an empty list, not a missing key.
                "recent_logins": [],
            }
    logins = []
    logins_available = False
    logins_24h = 0
    page_full = False
    if authed:
        try:
            ev = c.get_json(
                "/wp-json/simple-history/v1/events",
                headers=h,
                params={"per_page": _WP_EVENT_PAGE, "loggers": "SimpleUserLogger"},
            )
            # Simple History has returned both a bare list and {data: [...]}
            # across its majors; tolerate either, and anything else means the
            # plugin is not there rather than that we should crash.
            rows = ev.get("data") if isinstance(ev, dict) else ev
            if isinstance(rows, list):
                logins_available = True
                import time as _t0

                _day_ago = int(_t0.time()) - 86400
                for row in rows:
                    le = _wp_login_event(row)
                    if not le:
                        continue
                    # Count EVERY login in the window, but only keep the newest
                    # few for display. The old loop broke out of the scan once
                    # it had five to show, so `logins_24h` was structurally
                    # incapable of exceeding 5 — on a site with real traffic the
                    # metric was a constant, and a constant is not a metric.
                    if le["ts"] >= _day_ago:
                        logins_24h += 1
                    if len(logins) < _WP_LOGIN_CAP:
                        logins.append(le)
                # The SimpleUserLogger channel carries failed logins, logouts and
                # password resets too, so a page of it can contain few or no
                # successful logins. Say when the window was full rather than
                # implying the count is complete.
                page_full = len(rows) >= _WP_EVENT_PAGE
        except IntegrationError:
            logins_available = False
    detail = site or "site up"
    if logins_available:
        detail += f" — {plural(len(logins), 'recent login', 'recent logins')}"
    elif authed:
        detail += " — login history unavailable (Simple History plugin not detected)"
    return {
        "status": OK,
        "detail": detail,
        "metrics": ({"logins_24h": logins_24h} if logins_available else {}),
        "recent_logins": logins,
        # Honest about the scan window: the count is "logins seen in the last
        # <page> log entries", which equals the true 24h count only when we
        # reached the end of that window.
        "logins_window_full": bool(page_full),
    }


# ── EDR / endpoint-protection connectors (v6.2.0) ─────────────────────────────
# These are read-only *posture* connectors, but they exist for a reason the other
# connectors don't have: besides their own health, each one reports the set of
# hosts it PROTECTS (`edr_hosts`). api.py cross-references that against the actual
# fleet to answer the only question that really matters — "which of my machines
# have no EDR on them at all?". A dashboard saying "EDR: healthy" while three
# servers are uncovered is worse than no dashboard, because it is reassuring.
#
# Each returns, in addition to the usual health keys:
#   edr_hosts: [{hostname, agent_version, last_seen, status}]   (capped)
# Hostname NORMALISATION is NOT done here — connectors stay dumb
# parsers; the matching rules live in one place server-side.
_EDR_HOST_CAP = 1000  # bounds the persisted blob on a big estate


def _edr_summary(hosts, total=None):
    """Shared health verdict: an EDR whose agents are falling off is a warning."""
    total = len(hosts) if total is None else int(_num(total, len(hosts)))
    active = sum(1 for h in hosts if h.get("status") == "active")
    stale = len(hosts) - active
    # An agent that stopped reporting is an agent that is not protecting anything.
    status = OK if stale == 0 else (WARN if active else CRIT)
    return {
        "status": status,
        "detail": (f"{active}/{total} endpoints protected" + (f", {stale} stale" if stale else "")),
        "metrics": {"agents_total": total, "agents_active": active, "agents_stale": stale},
        "edr_hosts": hosts[:_EDR_HOST_CAP],
    }


@_register(
    "wazuh",
    "Wazuh",
    "security",
    [_field("username", "API username", TEXT), _field("secret", "API password", PASSWORD)],
    notes="Wazuh manager API (default port 55000). Reports agent coverage for the "
    "EDR-coverage cross-reference.",
)
def _wazuh(inst, c):
    # Wazuh mints a short-lived JWT from basic auth, then wants it as a bearer.
    auth = base64.b64encode(f"{inst.get('username','')}:{inst.get('secret','')}".encode()).decode()
    tok = c.get_json("/security/user/authenticate", headers={"Authorization": "Basic " + auth})
    jwt = ((tok or {}).get("data") or {}).get("token") or ""
    if not jwt:
        raise IntegrationError("Wazuh did not return a token (bad credentials?)")
    h = {"Authorization": "Bearer " + jwt}
    d = c.get_json("/agents?limit=500&select=name,status,version,lastKeepAlive", headers=h)
    data = (d or {}).get("data") or {}
    items = data.get("affected_items") or []
    hosts = []
    for a in items:
        if not isinstance(a, dict):
            continue
        name = str(a.get("name") or "").strip()
        if not name or name.lower() == "wazuh-manager":
            continue  # the manager registers itself as agent 000 — not an endpoint
        hosts.append(
            {
                "hostname": name,
                "agent_version": str(a.get("version") or ""),
                "last_seen": str(a.get("lastKeepAlive") or ""),
                "status": "active" if str(a.get("status") or "").lower() == "active" else "stale",
            }
        )
    out = _edr_summary(hosts, data.get("total_affected_items"))
    return out


@_register(
    "crowdstrike",
    "CrowdStrike Falcon",
    "security",
    [_field("username", "Client ID", TEXT), _field("secret", "Client secret", PASSWORD)],
    notes="Falcon OAuth2 API (e.g. https://api.crowdstrike.com). Read-only: needs "
    "only the 'Hosts: Read' scope.",
)
def _crowdstrike(inst, c):
    # OAuth2 client-credentials. The token endpoint is on the SAME host as the
    # API, which is why this fits the SSRF-bound client at all (see the note on
    # Defender for Endpoint in docs — its token host differs, so it cannot).
    r = c.post_form(
        "/oauth2/token",
        {
            "client_id": inst.get("username") or "",
            "client_secret": inst.get("secret") or "",
        },
    )
    if not r.ok:
        raise IntegrationError(f"Falcon auth failed (HTTP {r.status})")
    token = (r.json() or {}).get("access_token") or ""
    if not token:
        raise IntegrationError("Falcon returned no access token")
    h = {"Authorization": "Bearer " + token}
    q = c.get_json("/devices/queries/devices/v1?limit=500", headers=h)
    ids = [str(i) for i in ((q or {}).get("resources") or []) if i]
    total = (((q or {}).get("meta") or {}).get("pagination") or {}).get("total", len(ids))
    hosts = []
    if ids:
        # Repeated ?ids= params — urlencode(dict) cannot express that, so build the
        # query explicitly. Still a provider-RELATIVE path (the client rejects an
        # absolute URL, which is what keeps the SSRF guard's host binding intact).
        qs = urllib.parse.urlencode([("ids", i) for i in ids[:_EDR_HOST_CAP]])
        e = c.get_json("/devices/entities/devices/v2?" + qs, headers=h)
        for a in (e or {}).get("resources") or []:
            if not isinstance(a, dict):
                continue
            name = str(a.get("hostname") or "").strip()
            if not name:
                continue
            hosts.append(
                {
                    "hostname": name,
                    "agent_version": str(a.get("agent_version") or ""),
                    "last_seen": str(a.get("last_seen") or ""),
                    # Falcon marks a sensor 'normal' when healthy; anything else
                    # (containment, reduced functionality) is not full protection.
                    # KNOWN LIMITATION: Falcon's `status` reflects containment
                    # state, not reporting freshness — a sensor that fell offline
                    # weeks ago can still read 'normal'. A last_seen-age staleness
                    # heuristic was considered but deferred: last_seen formats
                    # differ per provider and a wrong threshold would emit false
                    # CRITs on healthy estates. Coverage cross-ref in api.py
                    # (agent-not-seen) is the durable staleness signal instead.
                    "status": (
                        "active"
                        if str(a.get("status") or "").lower() in ("normal", "online", "")
                        else "stale"
                    ),
                }
            )
    return _edr_summary(hosts, total)


@_register(
    "sentinelone",
    "SentinelOne",
    "security",
    [_field("secret", "API token", PASSWORD)],
    notes="SentinelOne management console API token (Settings → Users → API token).",
)
def _sentinelone(inst, c):
    h = {"Authorization": "ApiToken " + (inst.get("secret") or "")}
    d = c.get_json("/web/api/v2.1/agents?limit=500", headers=h)
    items = (d or {}).get("data") or []
    total = ((d or {}).get("pagination") or {}).get("totalItems", len(items))
    hosts, infected = [], 0
    for a in items:
        if not isinstance(a, dict):
            continue
        name = str(a.get("computerName") or "").strip()
        if not name:
            continue
        if a.get("infected"):
            infected += 1
        hosts.append(
            {
                "hostname": name,
                "agent_version": str(a.get("agentVersion") or ""),
                "last_seen": str(a.get("lastActiveDate") or ""),
                "status": "active" if a.get("isActive") else "stale",
            }
        )
    out = _edr_summary(hosts, total)
    # An infected endpoint outranks a stale one: this is the alarm, not the tally.
    if infected:
        out["status"] = CRIT
        out["detail"] = (
            f"{plural(infected, 'infected endpoint', 'infected endpoints')}, " + out["detail"]
        )
    out["metrics"]["infected"] = infected
    return out


# ── 8.0.0: overlay networks and tunnels (Tailscale, Headscale, Cloudflare Tunnel) ──────────────────────────────────────────
# A tailnet or a tunnel is what carries the remote access to the hosts, so the health that matters is "can it still reach
# them": a key that has run out locks a host out of its tailnet, and a tunnel with no connection is a service nobody can open.
# A host that is only offline is NOT a warning here: phones and laptops come and go, and a standing amber tile is the one
# that gets ignored. The shapes below are the vendors' documented ones; every field is read defensively because a parser that
# trusts one of them turns a changed API into a traceback instead of a tile.
_OVERLAY_SOON_DAYS = 14  # a key that ends within this many days is a warning
_OVERLAY_SEEN_DAYS = 30  # an expired key only matters for a host that was seen this recently (old ones are abandoned)
_OVERLAY_ONLINE_S = 300  # a host seen this recently counts as online when the API has no live flag


def _iso_epoch(value):
    """Seconds since the epoch for an RFC 3339 timestamp ('2026-11-07T10:00:00Z', fractions and offsets allowed), or 0.
    The zero time Go prints for 'never' ('0001-01-01T00:00:00Z') is 0 too: it is not a date a key can expire on.
    """
    if not isinstance(value, str) or len(value) < 10:
        return 0
    s = value.strip()
    if s.startswith("0001-01-01"):
        return 0
    try:
        from datetime import datetime, timezone

        s = s.replace("Z", "+00:00").replace("z", "+00:00")
        # fromisoformat before 3.11 rejects more than six fraction digits; trim them
        s = re.sub(r"(\.\d{6})\d+", r"\1", s)
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except (ValueError, OverflowError):
        return 0


def _overlay_summary(rows, now=None):
    """Counts for a list of {name, online, last_seen, expires, no_expiry, update, authorized} rows, and the verdict."""
    now = int(now if now is not None else time.time())
    total = online = expiring = expired = updates = unapproved = 0
    for r in rows:
        total += 1
        seen = r.get("last_seen") or 0
        live = r.get("online")
        if live is None:
            live = bool(seen and now - seen <= _OVERLAY_ONLINE_S)
        online += 1 if live else 0
        exp = r.get("expires") or 0
        if exp and not r.get("no_expiry"):
            if exp <= now:
                if seen and now - seen <= _OVERLAY_SEEN_DAYS * 86400:
                    expired += 1
            elif exp - now <= _OVERLAY_SOON_DAYS * 86400:
                expiring += 1
        updates += 1 if r.get("update") else 0
        unapproved += 1 if r.get("authorized") is False else 0
    status = OK
    bits = ["%s, %d online" % (plural(total, "host", "hosts"), online)]
    if expired:
        status = CRIT
        bits.append("%d with a key that has run out" % expired)
    if expiring:
        status = status if status == CRIT else WARN
        bits.append("%d keys end within %d days" % (expiring, _OVERLAY_SOON_DAYS))
    if unapproved:
        status = status if status == CRIT else WARN
        bits.append("%d waiting for approval" % unapproved)
    return {
        "status": status,
        "detail": ", ".join(bits),
        "metrics": {
            "devices": total,
            "online": online,
            "offline": total - online,
            "keys_expiring": expiring,
            "keys_expired": expired,
            "updates": updates,
            "unapproved": unapproved,
        },
    }


@_register(
    "tailscale",
    "Tailscale",
    "network",
    [
        _field("secret", "API access token", PASSWORD),
        _field("slug", "Tailnet (blank = the token's own)", TEXT, optional=True),
    ],
    notes="Tailscale API. Reports the hosts of your tailnet, how many are online, and the keys that end soon or have run out. "
    "Create the token under Settings, Keys in the Tailscale admin console.",
    default_url="https://api.tailscale.com",
)
def _tailscale(inst, c):
    tailnet = urllib.parse.quote(str(inst.get("slug") or "-").strip() or "-", safe="")
    h = {"Authorization": "Bearer " + (inst.get("secret") or "")}
    d = c.get_json("/api/v2/tailnet/%s/devices" % tailnet, headers=h)
    items = (d or {}).get("devices") if isinstance(d, dict) else None
    rows = []
    for dev in items if isinstance(items, list) else []:
        if not isinstance(dev, dict) or dev.get("isExternal"):
            continue  # a host shared in from another tailnet is not this tailnet's to keep alive
        live = dev.get("connectedToControl")
        rows.append(
            {
                "online": live if isinstance(live, bool) else None,
                "last_seen": _iso_epoch(dev.get("lastSeen")),
                "expires": _iso_epoch(dev.get("expires")),
                "no_expiry": bool(dev.get("keyExpiryDisabled")),
                "update": bool(dev.get("updateAvailable")),
                "authorized": (
                    dev.get("authorized") if isinstance(dev.get("authorized"), bool) else None
                ),
            }
        )
    return _overlay_summary(rows)


@_register(
    "headscale",
    "Headscale",
    "network",
    [_field("secret", "API key", PASSWORD)],
    notes="Headscale API. Reports the nodes of your server, how many are online, and the keys that end soon or have run out. "
    "Create the key with `headscale apikeys create`.",
)
def _headscale(inst, c):
    h = {"Authorization": "Bearer " + (inst.get("secret") or "")}
    d = c.get_json("/api/v1/node", headers=h)
    items = (d or {}).get("nodes") if isinstance(d, dict) else None
    rows = []
    for n in items if isinstance(items, list) else []:
        if not isinstance(n, dict):
            continue
        live = n.get("online")
        exp = _iso_epoch(n.get("expiry"))
        rows.append(
            {
                "online": live if isinstance(live, bool) else None,
                "last_seen": _iso_epoch(n.get("lastSeen")),
                "expires": exp,
                "no_expiry": not exp,
            }
        )
    return _overlay_summary(rows)


@_register(
    "cloudflare_tunnel",
    "Cloudflare Tunnel",
    "network",
    [
        _field("secret", "API token", PASSWORD),
        _field("slug", "Account ID", TEXT),
    ],
    notes="Cloudflare API. Reports the tunnels of an account: healthy, degraded (some connections are missing) or down "
    "(none). The token needs the Cloudflare Tunnel read permission; the account ID is on the account's overview page.",
    default_url="https://api.cloudflare.com",
)
def _cloudflare_tunnel(inst, c):
    account = str(inst.get("slug") or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{32}", account):
        raise IntegrationError(
            "the account ID is the 32-character hex string on the account's overview page"
        )
    h = {"Authorization": "Bearer " + (inst.get("secret") or "")}
    d = c.get_json(
        "/client/v4/accounts/%s/cfd_tunnel" % account,
        headers=h,
        params={"is_deleted": "false", "per_page": 100},
    )
    if not isinstance(d, dict) or d.get("success") is False:
        errs = d.get("errors") if isinstance(d, dict) else None
        first = errs[0] if isinstance(errs, list) and errs and isinstance(errs[0], dict) else {}
        raise IntegrationError(
            "Cloudflare refused it: %s" % (str(first.get("message") or "no reason given")[:120])
        )
    items = d.get("result")
    counts = {"healthy": 0, "degraded": 0, "down": 0, "inactive": 0}
    conns = 0
    names_down = []
    for t in items if isinstance(items, list) else []:
        if not isinstance(t, dict):
            continue
        st = str(t.get("status") or "").lower()
        if st in counts:
            counts[st] += 1
        if st == "down" and len(names_down) < 3:
            names_down.append(str(t.get("name") or "")[:40])
        cl = t.get("connections")
        conns += len(cl) if isinstance(cl, list) else 0
    total = sum(counts.values())
    status = CRIT if counts["down"] else (WARN if counts["degraded"] else OK)
    bits = ["%s" % plural(total, "tunnel", "tunnels"), "%d healthy" % counts["healthy"]]
    if counts["degraded"]:
        bits.append("%d degraded" % counts["degraded"])
    if counts["down"]:
        bits.append(
            "%d down (%s)" % (counts["down"], ", ".join(n for n in names_down if n) or "unnamed")
        )
    return {
        "status": status,
        "detail": ", ".join(bits),
        "metrics": {
            "tunnels": total,
            "healthy": counts["healthy"],
            "degraded": counts["degraded"],
            "down": counts["down"],
            "inactive": counts["inactive"],
            "connections": conns,
        },
    }


# ── per-connector headline stat chips (for the rich tiles) ─────────────────────
# Map each connector type to a few (metric_key, label, kind) the UI shows as
# labeled chips. kinds: int (humanized 12.3k), pct (18%), num (small count),
# rate (KB/s, value already in KB/s), mb (123 MB), flag (yes/no), str. Surfaces
# the metrics the connectors ALREADY collect — no extra API calls.
_STATS: dict = {
    "custom_probe": [
        ("http_status", "HTTP", "num"),
    ],
    # v6.2.0 — EDR. "Protected" is the headline; "stale" is the one that bites.
    "wazuh": [
        ("agents_active", "Protected", "int"),
        ("agents_stale", "Stale", "int"),
    ],
    "crowdstrike": [
        ("agents_active", "Protected", "int"),
        ("agents_stale", "Stale", "int"),
    ],
    "sentinelone": [
        ("agents_active", "Protected", "int"),
        ("agents_stale", "Stale", "int"),
        ("infected", "Infected", "int"),
    ],
    "tailscale": [
        ("devices", "Hosts", "int"),
        ("online", "Online", "num"),
        ("keys_expiring", "Keys ending", "num"),
        ("keys_expired", "Keys expired", "num"),
    ],
    "headscale": [
        ("devices", "Nodes", "int"),
        ("online", "Online", "num"),
        ("keys_expiring", "Keys ending", "num"),
        ("keys_expired", "Keys expired", "num"),
    ],
    "cloudflare_tunnel": [
        ("tunnels", "Tunnels", "int"),
        ("healthy", "Healthy", "num"),
        ("degraded", "Degraded", "num"),
        ("down", "Down", "num"),
    ],
    "github": [
        ("repos", "Repos", "int"),
        ("open_issues", "Open issues", "int"),
    ],
    "wordpress": [
        ("logins_24h", "Logins 24h", "int"),
    ],
    "pihole": [
        ("queries_today", "Queries", "int"),
        ("blocked_pct", "Blocked", "pct"),
        ("domains_blocked", "Blocklist", "int"),
    ],
    "adguard": [
        ("queries", "Queries", "int"),
        ("blocked", "Blocked", "int"),
        ("protection", "Filtering", "flag"),
    ],
    "truenas": [
        ("pools", "Pools", "num"),
        ("pools_bad", "Degraded", "num"),
        ("alerts_crit", "Crit alerts", "num"),
        ("alerts_warn", "Warn alerts", "num"),
    ],
    "unifi": [
        ("devices", "Devices", "num"),
        ("devices_down", "Down", "num"),
        ("clients", "Clients", "num"),
        ("firmware_updates", "Updates", "num"),
        ("subsystems", "Subsystems", "num"),
        ("subsystems_bad", "Degraded", "num"),
    ],
    "homeassistant": [("entities", "Entities", "int"), ("unavailable", "Unavailable", "num")],
    "pbs": [
        ("datastores", "Datastores", "num"),
        ("fullest_pct", "Fullest", "pct"),
        ("tasks_failed_24h", "Failed 24h", "num"),
    ],
    "kubernetes": [
        ("nodes_notready", "Nodes down", "num"),
        ("pods_crashloop", "CrashLoop", "num"),
        ("pods_pending", "Pending", "num"),
    ],
    "vcenter": [
        ("hosts", "Hosts", "num"),
        ("vms_on", "VMs on", "num"),
        ("hosts_down", "Down", "num"),
    ],
    "openshift": [
        ("nodes", "Nodes", "num"),
        ("nodes_notready", "Nodes down", "num"),
        ("projects", "Projects", "num"),
    ],
    "vcloud": [("vapps", "vApps", "num"), ("vms", "VMs", "num")],
    "unraid": [("array_state", "Array", "str")],
    "traefik": [
        ("routers", "Routers", "num"),
        ("errors", "Errors", "num"),
        ("warnings", "Warnings", "num"),
    ],
    "npm": [("proxy_hosts", "Proxy hosts", "num"), ("certs_expiring", "Certs <14d", "num")],
    "caddy": [("upstreams", "Upstreams", "num"), ("upstreams_failing", "Failing", "num")],
    "uptimekuma": [("monitors", "Monitors", "num"), ("down", "Down", "num")],
    "netdata": [("alarms_critical", "Critical", "num"), ("alarms_warning", "Warning", "num")],
    "grafana": [("database_ok", "Database", "flag"), ("alerts_firing", "Firing", "int")],
    "remotepower": [
        ("devices", "Hosts", "int"),
        ("offline", "Offline", "num"),
        ("alerts_open", "Open alerts", "num"),
    ],
    "jellyfin": [("sessions_active", "Streaming", "num"), ("transcoding", "Transcode", "num")],
    "plex": [("sessions_active", "Streaming", "num")],
    "nextcloud": [("users", "Users", "int"), ("update_available", "Update", "flag")],
    "sabnzbd": [("queue", "Queue", "num"), ("mb_left", "Left", "mb"), ("paused", "Paused", "flag")],
    "nzbget": [("download_kbs", "Down", "rate"), ("remaining_mb", "Remaining", "mb")],
    "qbittorrent": [("torrents", "Torrents", "num"), ("download_kbs", "Down", "rate")],
    "transmission": [
        ("torrents", "Torrents", "num"),
        ("active", "Active", "num"),
        ("download_kbs", "Down", "rate"),
    ],
    "deluge": [("torrents", "Torrents", "num"), ("download_kbs", "Down", "rate")],
    "servarr": [
        ("health_errors", "Errors", "num"),
        ("health_warnings", "Warnings", "num"),
        ("queue_total", "Queue", "num"),
    ],
    "bazarr": [("health_issues", "Issues", "num")],
    "overseerr": [("pending_requests", "Pending", "num"), ("update_available", "Update", "flag")],
    "immich": [
        ("photos", "Photos", "int"),
        ("videos", "Videos", "int"),
        ("usage_mb", "Usage", "mb"),
        ("disk_pct", "Disk", "pct"),
        ("jobs_failed", "Failed jobs", "num"),
    ],
    "paperless": [
        ("documents", "Documents", "int"),
        ("inbox", "Inbox", "num"),
        ("problems", "Problems", "int"),
    ],
    "vaultwarden": [("alive", "Alive", "flag")],
    "gitea": [("repos", "Repos", "int")],
    "syncthing": [
        ("devices_connected", "Connected", "num"),
        ("devices", "Devices", "num"),
        ("errors", "Errors", "int"),
    ],
    "frigate": [("cameras", "Cameras", "num"), ("det_fps", "Detect FPS", "num")],
    "octoprint": [("printing", "Printing", "flag"), ("operational", "Operational", "flag")],
    "esphome": [
        ("nodes", "Nodes", "num"),
        ("outdated", "Outdated", "num"),
        ("offline", "Offline", "num"),
    ],
    "homebridge": [("up", "Bridge", "flag"), ("plugins", "Plugins", "num")],
}
# The named *arr connectors share the servarr stat chips.
for _arr in ("sonarr", "radarr", "prowlarr", "lidarr", "readarr"):
    _STATS[_arr] = _STATS["servarr"]


def _human(v):
    n = _num(v)
    if n >= 1_000_000:
        return f"{n / 1e6:.1f}M"
    if n >= 1000:
        return f"{n / 1e3:.1f}k"
    return str(int(n))


def _fmt_stat(kind, v):
    if kind == "pct":
        return f"{round(_num(v))}%"
    if kind == "int":
        return _human(v)
    if kind == "rate":  # v is KB/s; roll up to MB/s past 1000
        kb = _num(v)
        return f"{kb / 1024:.1f} MB/s" if kb >= 1000 else f"{int(kb)} KB/s"
    if kind == "mb":
        return f"{int(_num(v))} MB"
    if kind == "flag":
        return "yes" if v else "no"
    return str(v)


# ══════════════════════════════════════════════════════════════════════════════
# v5.1.0 — declarative plugin: a code-free custom HTTP health probe
# ══════════════════════════════════════════════════════════════════════════════
def _probe_compare(val, op, want):
    """Compare a JSON value against the operator's expectation. Pure + total."""
    if op == "contains":
        return str(want) in str(val)
    if op == "ne":
        return str(val) != str(want)
    if op in ("lt", "gt"):
        try:
            a, b = float(val), float(want)
        except (TypeError, ValueError):
            return False
        return a < b if op == "lt" else a > b
    return str(val) == str(want)  # default / "eq"


@_register(
    "custom_probe",
    "Custom HTTP probe",
    "custom",
    [
        _field("probe_path", "Health path (default /)", TEXT, optional=True, placeholder="/health"),
        _field(
            "probe_expect",
            "Expected HTTP status (blank = any 2xx)",
            TEXT,
            optional=True,
            placeholder="200",
        ),
        _field(
            "probe_json_field",
            "JSON field to check (dotted, optional)",
            TEXT,
            optional=True,
            placeholder="data.status",
        ),
        _field(
            "probe_json_op",
            "Compare: eq | ne | lt | gt | contains",
            TEXT,
            optional=True,
            placeholder="eq",
        ),
        _field("probe_json_value", "Expected value", TEXT, optional=True, placeholder="healthy"),
        _field("secret", "Bearer token (optional)", PASSWORD, optional=True),
    ],
    notes="Declarative HTTP health probe — NO code. Polls <url><path>, checks the "
    "status code and (optionally) one JSON field. SSRF-guarded like every "
    "connector; the token is stored as a scrubbed secret. Lets you monitor "
    "any HTTP service without forking.",
)
def _custom_probe(inst, c):
    path = (inst.get("probe_path") or "/").strip() or "/"
    headers = {}
    tok = inst.get("secret")
    if tok:
        headers["Authorization"] = "Bearer " + tok
    r = c.get(path, headers=headers)
    metrics = {"http_status": r.status}
    expect = str(inst.get("probe_expect") or "").strip()
    if expect:
        if not expect.isdigit() or int(expect) != r.status:
            return {
                "status": CRIT,
                "detail": f"HTTP {r.status} (expected {expect})",
                "metrics": metrics,
            }
    elif not r.ok:
        return {"status": CRIT, "detail": f"HTTP {r.status}", "metrics": metrics}
    field = str(inst.get("probe_json_field") or "").strip()
    if field:
        try:
            data = r.json()
        except Exception:
            return {
                "status": WARN,
                "detail": f"HTTP {r.status} but response is not JSON",
                "metrics": metrics,
            }
        val = data
        for part in field.split("."):
            if isinstance(val, dict) and part in val:
                val = val[part]
            else:
                return {
                    "status": WARN,
                    "detail": f"JSON field '{field}' not found",
                    "metrics": metrics,
                }
        op = (inst.get("probe_json_op") or "eq").strip().lower()
        want = inst.get("probe_json_value")
        if isinstance(val, (int, float, str, bool)):
            metrics[field] = val
        if not _probe_compare(val, op, want):
            return {
                "status": CRIT,
                "detail": f"{field}={val} fails ({op} {want})",
                "metrics": metrics,
            }
        return {"status": OK, "detail": f"HTTP {r.status}, {field}={val}", "metrics": metrics}
    return {"status": OK, "detail": f"HTTP {r.status}", "metrics": metrics}


# ══════════════════════════════════════════════════════════════════════════════
# v7.4.3 (#46) — Prometheus: a PromQL query against a server, or a scrape of an
# exporter's /metrics page. Both read named values, so the thresholds under
# "Alert on a metric", the host card and its trend treat them like any other
# connector's numbers.
# ══════════════════════════════════════════════════════════════════════════════
PROM_MAX_VALUES = 12  # the history keeps twelve numbers an instance (api._INTEG_NUMERIC_MAX)
# Connectors whose headline chips are every number they read, under the names the operator chose, so
# _STATS has nothing to list for them.
DYNAMIC_STATS = frozenset({"prometheus", "prometheus_exporter"})
_PROM_BUDGET_S = (
    20.0  # one poll asks for its values for this long at most; the rest wait for the next poll
)
_PROM_MAX_LINE = 500  # characters in one value line
_PROM_MAX_SAMPLES = 200_000  # sample lines read from one page
_PROM_MAX_LABELS = 64  # labels read from one sample
_PROM_MAX_LABEL_VALUE = 1024
_PROM_MAX_MATCHERS = 16
_PROM_LINE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_.:-]{0,63})\s*=(?![=~])\s*(\S.*)$")
_PROM_METRIC_RE = re.compile(r"^[A-Za-z_:][A-Za-z0-9_:]*$")
_PROM_NAME_AT = re.compile(r"[A-Za-z_:][A-Za-z0-9_:]*")
_PROM_LABEL_AT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_PROM_ESCAPES = {"n": "\n", "\\": "\\", '"': '"', "'": "'"}


def _prom_num(v):
    """A whole number as an int (a byte count reads better than 6200000000.0), anything else as it is."""
    return int(v) if v == int(v) and abs(v) < 1e15 else v


def parse_prom_lines(text, need_alias=True):
    """The value lines of a Prometheus instance: ``name = expression``, one to a line.

    Blank lines and lines that start with # are skipped. Returns ``[(line number, name or None,
    expression)]``. A line that cannot be used raises IntegrationError naming it: a value that is
    silently left out is one the operator believes is being read."""
    out = []
    for n, raw in enumerate(str(text or "").splitlines(), 1):
        line = "".join(
            ch for ch in raw if ch == "\t" or (ord(ch) >= 0x20 and ord(ch) != 0x7F)
        ).strip()
        if not line or line.startswith("#"):
            continue
        if len(line) > _PROM_MAX_LINE:
            raise IntegrationError(f"line {n} is longer than {_PROM_MAX_LINE} characters")
        m = _PROM_LINE_RE.match(line)
        if m:
            name, expr = m.group(1), m.group(2).strip()
        elif need_alias:
            raise IntegrationError(f"line {n}: write it as  name = expression")
        else:
            name, expr = None, line
        out.append((n, name, expr))
        if len(out) > PROM_MAX_VALUES:
            raise IntegrationError(
                f"at most {PROM_MAX_VALUES} values to an instance; add a second instance"
            )
    return out


def parse_query_lines(text):
    """The lines of a PromQL instance -> ``[(name, expression)]``, each name used once."""
    out, seen = [], set()
    for n, name, expr in parse_prom_lines(text, need_alias=True):
        if name in seen:
            raise IntegrationError(f"line {n}: the name {name} is used twice")
        seen.add(name)
        out.append((name, expr))
    return out


def parse_selector(expr):
    """``metric`` or ``metric{label="value", other!="x"}`` -> ``(metric, [(label, op, value)])``.

    Only = and != matchers. A page of samples is not searched with expressions, and a pattern the
    operator wrote is not run against text a remote host chose; the query form takes any PromQL."""
    s = str(expr).strip()
    brace = s.find("{")
    metric = (s if brace < 0 else s[:brace]).strip()
    if not _PROM_METRIC_RE.match(metric):
        raise IntegrationError(f"{metric[:40]!r} is not a metric name")
    if brace < 0:
        return metric, []
    if not s.endswith("}"):
        raise IntegrationError("a selector ends with }")
    body = s[brace + 1 : -1]
    matchers, i, n = [], 0, len(body)
    while True:
        while i < n and body[i] in " \t,":
            i += 1
        if i >= n:
            break
        m = _PROM_LABEL_AT.match(body, i)
        if not m:
            raise IntegrationError("a label name is expected inside { }")
        label, i = m.group(0), m.end()
        while i < n and body[i] in " \t":
            i += 1
        op = body[i : i + 2] if body[i : i + 2] in ("!=", "=~", "!~") else body[i : i + 1]
        if op in ("=~", "!~"):
            raise IntegrationError(
                "regular expression matchers are not supported on a scrape; use the query form"
            )
        if op not in ("=", "!="):
            raise IntegrationError(f"after {label} write = or !=")
        i += len(op)
        while i < n and body[i] in " \t":
            i += 1
        if i >= n or body[i] not in "\"'":
            raise IntegrationError(f"the value of {label} goes in quotes")
        quote = body[i]
        i += 1
        buf = []
        while i < n and body[i] != quote:
            if body[i] == "\\" and i + 1 < n:
                buf.append(_PROM_ESCAPES.get(body[i + 1], "\\" + body[i + 1]))
                i += 2
            else:
                buf.append(body[i])
                i += 1
        if i >= n:
            raise IntegrationError(f"the quote after {label} is not closed")
        i += 1
        matchers.append((label, op, "".join(buf)))
        if len(matchers) > _PROM_MAX_MATCHERS:
            raise IntegrationError(f"at most {_PROM_MAX_MATCHERS} matchers to a value")
    return metric, matchers


def parse_scrape_lines(text):
    """The lines of an exporter instance -> ``[(name, metric, matchers)]``. The name is the
    metric's own when the line does not give one, and each name is used once."""
    out, seen = [], set()
    for n, name, expr in parse_prom_lines(text, need_alias=False):
        try:
            metric, matchers = parse_selector(expr)
        except IntegrationError as e:
            raise IntegrationError(f"line {n}: {e}") from None
        name = name or metric
        if name in seen:
            raise IntegrationError(
                f"line {n}: the name {name} is used twice; give each value a name of its own"
            )
        seen.add(name)
        out.append((name, metric, matchers))
    return out


def _prom_page_labels(line, i):
    """The ``{...}`` block of a sample line starting at ``line[i]`` -> ``(labels, index after the })``,
    or None when it is malformed. Values are quoted with \\ escapes; bounded in count and length."""
    labels, n = {}, len(line)
    i += 1
    while True:
        while i < n and line[i] in " \t,":
            i += 1
        if i >= n:
            return None
        if line[i] == "}":
            return labels, i + 1
        m = _PROM_LABEL_AT.match(line, i)
        if not m or m.end() >= n or line[m.end()] != "=":
            return None
        name, j = m.group(0), m.end() + 1
        if j >= n or line[j] != '"':
            return None
        j += 1
        buf = []
        while j < n and line[j] != '"':
            if line[j] == "\\" and j + 1 < n:
                buf.append(_PROM_ESCAPES.get(line[j + 1], "\\" + line[j + 1]))
                j += 2
            else:
                buf.append(line[j])
                j += 1
        labels[name] = "".join(buf)[
            :_PROM_MAX_LABEL_VALUE
        ]  # a value that never closed ends the line: None below
        if len(labels) > _PROM_MAX_LABELS:
            return None
        i = j + 1


def iter_samples(text):
    """``(metric, labels, value)`` for each sample line of a Prometheus text page.

    Comments, lines that do not read and values that are not numbers are skipped; a timestamp
    after the value is ignored. Bounded: it stops after _PROM_MAX_SAMPLES lines."""
    count = 0
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line or line[0] == "#":
            continue
        count += 1
        if count > _PROM_MAX_SAMPLES:
            return
        m = _PROM_NAME_AT.match(line)
        if not m:
            continue
        metric, i, labels = m.group(0), m.end(), {}
        if i < len(line) and line[i] == "{":
            parsed = _prom_page_labels(line, i)
            if parsed is None:
                continue
            labels, i = parsed
        rest = line[i:].split(None, 1)
        if not rest:
            continue
        try:
            value = float(rest[0])
        except ValueError:
            continue
        yield metric, labels, value


def _prom_matches(labels, matchers):
    for label, op, want in matchers:
        if (labels.get(label, "") == want) != (op == "="):
            return False
    return True


def prom_query_value(doc):
    """``(value, None, series)`` or ``(None, why, series)`` from the answer of ``/api/v1/query``:
    the first sample of a vector, or a scalar. ``series`` is how many series answered."""
    data = doc.get("data") if isinstance(doc, dict) else None
    if not isinstance(data, dict):
        return None, "the answer has no data", 0
    kind, result = data.get("resultType"), data.get("result")
    if kind == "vector":
        if not isinstance(result, list) or not result:
            return None, "no data (the query returned nothing)", 0
        first = result[0]
        sample, series = (first.get("value") if isinstance(first, dict) else None), len(result)
    elif kind == "scalar":
        sample, series = result, 1
    elif kind == "matrix":
        return None, "a range, not a value; wrap it in a function such as avg_over_time()", 0
    else:
        return None, f"a {str(kind)[:20]} result is not a number", 0
    if not (isinstance(sample, list) and len(sample) == 2):
        return None, "the sample is not a [time, value] pair", series
    try:
        value = float(sample[1])
    except (TypeError, ValueError):
        return None, "the value is not a number", series
    if value != value or value in (float("inf"), float("-inf")):
        return None, f"the value is {str(sample[1])[:8]}", series
    return _prom_num(value), None, series


def _prom_auth(inst):
    """Basic auth when there is a user name and a password, a bearer token when there is only the
    secret, nothing when neither (a Prometheus on the LAN usually has no login)."""
    user, tok = str(inst.get("username") or ""), str(inst.get("secret") or "")
    if user and tok:
        return {"Authorization": "Basic " + base64.b64encode(f"{user}:{tok}".encode()).decode()}
    if tok:
        return {"Authorization": "Bearer " + tok}
    return {}


def _prom_result(read, problems, note=""):
    """The poll result: all values read is OK, some is a warning (it names what is missing), none is
    critical. Values read are metrics either way, so a threshold on one still works."""
    if not problems:
        return {
            "status": OK,
            "detail": plural(len(read), "value", "values") + " read" + note,
            "metrics": read,
        }
    shown = "; ".join(f"{n}: {why}" for n, why in problems[:3])
    more = f" (+{len(problems) - 3} more)" if len(problems) > 3 else ""
    return {"status": WARN if read else CRIT, "detail": shown + more, "metrics": read}


@_register(
    "prometheus",
    "Prometheus (PromQL query)",
    "observability",
    [
        _field(
            "prom_lines",
            "Values to read (one per line: name = PromQL expression)",
            TEXTAREA,
            placeholder='mem_active = node_memory_active_bytes{instance="192.168.0.1:9100"}\nload1 = node_load1{instance="192.168.0.1:9100"}',
        ),
        _field("username", "User name (optional, for Basic auth)", TEXT, optional=True),
        _field("secret", "Password or bearer token (optional)", PASSWORD, optional=True),
    ],
    notes="Reads values from a Prometheus server with its HTTP API (/api/v1/query). Give the "
    "server's URL, then one line for each value: a name, an equals sign and a PromQL expression. "
    "The first sample of each answer becomes a metric under that name, which you can alert on under "
    "Alert on a metric and see on the host the instance runs on. A query that returns nothing "
    "counts as a problem, so write one that always answers, such as  count(up == 0) or vector(0).",
)
def _prometheus(inst, c):
    lines = parse_query_lines(inst.get("prom_lines"))
    if not lines:
        raise IntegrationError("nothing to read: add a line such as  name = PromQL expression")
    headers = _prom_auth(inst)
    read, problems, several = {}, [], []
    deadline = time.monotonic() + _PROM_BUDGET_S
    for name, expr in lines:
        # Each query has its own timeout, so twelve slow ones could hold the poll for minutes. The
        # first is always asked; after that the poll stops asking and says which values it left.
        if (read or problems) and time.monotonic() > deadline:
            problems.append((name, "not asked; the server was too slow"))
            continue
        r = c.get("/api/v1/query", headers=headers, params={"query": expr})
        if r.status in (401, 403):
            raise IntegrationError(f"the server refused the credentials (HTTP {r.status})")
        doc = r.json()  # IntegrationError for a body that is not JSON, saying what it was instead
        if not isinstance(doc, dict) or doc.get("status") != "success":
            err = doc.get("error") if isinstance(doc, dict) else None
            problems.append((name, str(err or f"HTTP {r.status}")[:80]))
            continue
        value, why, series = prom_query_value(doc)
        if value is None:
            problems.append((name, why))
            continue
        read[name] = value
        if series > 1:
            several.append(name)
    note = (
        f" (several series answered for {', '.join(several[:3])}; the first is used)"
        if several
        else ""
    )
    return _prom_result(read, problems, note)


@_register(
    "prometheus_exporter",
    "Prometheus exporter (/metrics scrape)",
    "observability",
    [
        _field(
            "prom_path",
            "Metrics path (default /metrics)",
            TEXT,
            optional=True,
            placeholder="/metrics",
        ),
        _field(
            "prom_lines",
            'Values to read (one per line: name = metric, with {label="value"} if needed)',
            TEXTAREA,
            placeholder='mem_active = node_memory_active_bytes\nroot_free = node_filesystem_avail_bytes{mountpoint="/"}',
        ),
        _field("username", "User name (optional, for Basic auth)", TEXT, optional=True),
        _field("secret", "Password or bearer token (optional)", PASSWORD, optional=True),
    ],
    notes="Reads values from an exporter's /metrics page (node_exporter on port 9100, an OPNsense or "
    "Hubitat exporter, anything that speaks the Prometheus text format). Give the exporter's URL, "
    "then one line for each value: a name, an equals sign, a metric name and optionally label "
    "matchers with = or != in braces. The first sample that matches becomes a metric under that name, "
    "which you can alert on under Alert on a metric and see on the host the instance runs on. "
    "For a calculation across metrics, use the Prometheus (PromQL query) connector against a server.",
)
def _prometheus_exporter(inst, c):
    wanted = parse_scrape_lines(inst.get("prom_lines"))
    if not wanted:
        raise IntegrationError("nothing to read: add a line such as  name = metric_name")
    path = str(inst.get("prom_path") or "").strip() or "/metrics"
    if not path.startswith("/"):
        path = "/" + path
    r = c.get(path, headers=_prom_auth(inst))
    if r.status in (401, 403):
        raise IntegrationError(f"the exporter refused the credentials (HTTP {r.status})")
    if not r.ok:
        raise IntegrationError(f"HTTP {r.status} from {path}")
    if r.truncated:
        raise IntegrationError(
            f"{path} is larger than {MAX_RESPONSE_BYTES // (1024 * 1024)} MB; point it at a smaller page"
        )
    by_metric = {}
    for name, metric, matchers in wanted:
        by_metric.setdefault(metric, []).append((name, matchers))
    first, count, seen_any = {}, {}, False
    for metric, labels, value in iter_samples(r.text):
        seen_any = True
        for name, matchers in by_metric.get(metric, ()):
            if _prom_matches(labels, matchers):
                count[name] = count.get(name, 0) + 1
                first.setdefault(name, value)
    if not seen_any:
        raise IntegrationError(
            f"{path} holds no Prometheus samples; is this an exporter's metrics page?"
        )
    read, problems = {}, []
    for name, _metric, _matchers in wanted:
        if name not in first:
            problems.append((name, "not found on the page"))
        elif first[name] != first[name] or first[name] in (float("inf"), float("-inf")):
            problems.append((name, "the value is not a number"))
        else:
            read[name] = _prom_num(first[name])
    several = [n for n in read if count.get(n, 0) > 1]
    note = f" (several series match {', '.join(several[:3])}; the first is used)" if several else ""
    return _prom_result(read, problems, note)


# One GitHub owner/repo path segment pair. Repo names are interpolated into the
# outbound URL path, so they MUST be reduced to a strict charset first (the
# SSRF rule from the virt drivers: an absolute-URL "id" would otherwise pass
# the public-host preflight and redirect the authed call elsewhere).
_GH_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_GH_MAX_REPOS = 10  # per-instance bound (one HTTP call per repo per poll)
_GH_PER_PAGE = 30  # newest issues fetched per repo (detection window)


def _gh_repos(inst):
    """The instance's watched repo list — 'owner/repo, owner/repo' in ``slug``."""
    out, bad = [], []
    for raw in str(inst.get("slug") or "").split(","):
        r = raw.strip().strip("/")
        if not r:
            continue
        (out if _GH_REPO_RE.match(r) else bad).append(r)
    return out[:_GH_MAX_REPOS], bad


@_register(
    "github",
    "GitHub Issues",
    "apps",
    [
        _field(
            "slug",
            "Repositories (owner/repo, comma-separated)",
            TEXT,
            placeholder="tyxak/remotepower, owner/other-repo",
        ),
        _field(
            "secret",
            "Access token (optional — private repos / rate limit)",
            PASSWORD,
            optional=True,
        ),
    ],
    notes="Watches one or more GitHub repositories and raises a github_new_issue "
    "alert when a NEW issue is opened (pull requests are ignored; the first "
    "poll only baselines). URL is the API root — https://api.github.com, or "
    "your GitHub Enterprise /api/v3 root. A classic token with repo read "
    "scope lifts the anonymous rate limit and allows private repos.",
)
def _github(inst, c):
    repos, bad = _gh_repos(inst)
    if not repos:
        raise IntegrationError("no valid repositories configured (owner/repo, comma-separated)")
    # Forgive the predictable URL mistake: the WEBSITE (github.com) instead of the
    # API root (api.github.com). The website answers /repos/... with HTML 404s, so
    # every repo would "fail". v6.2.0 (BUG): the old code built an ABSOLUTE URL
    # (https://api.github.com/repos/...) and passed it to the client — but the
    # SSRF-safe client REJECTS absolute paths (ValueError), so the autocorrect was
    # dead and every github.com-configured instance errored. Instead rewrite the
    # client's BASE to the API root and keep paths relative. GHE roots pass through
    # untouched. (api.github.com is public, so the SSRF connect-time guard is happy.)
    u = str(inst.get("url") or "").strip().lower().rstrip("/")
    if u in (
        "https://github.com",
        "http://github.com",
        "https://www.github.com",
        "http://www.github.com",
    ):
        c.base = "https://api.github.com"
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if inst.get("secret"):
        headers.update(_hdr_token(inst, "Authorization", "Bearer "))
    open_count = 0
    state, latest, failed = {}, [], []
    for repo in repos:
        try:
            issues = c.get_json(
                f"/repos/{repo}/issues",
                headers=headers,
                params={
                    "state": "open",
                    "per_page": _GH_PER_PAGE,
                    "sort": "created",
                    "direction": "desc",
                },
            )
        except IntegrationError:
            failed.append(repo)
            continue
        if not isinstance(issues, list):
            failed.append(repo)
            continue
        # The issues endpoint interleaves PRs — a PR is an issue with a
        # `pull_request` stub; only real issues count/alert.
        real = [i for i in issues if isinstance(i, dict) and not i.get("pull_request")]
        open_count += len(real)
        state[repo] = max((int(i.get("number") or 0) for i in real), default=0)
        for i in real:
            latest.append(
                {
                    "repo": repo,
                    "number": int(i.get("number") or 0),
                    "title": str(i.get("title") or "")[:140],
                    "url": str(i.get("html_url") or "")[:300],
                }
            )
    if not state:
        raise IntegrationError(f"all repos failed: {', '.join(failed + bad)[:150]}")
    status = WARN if (failed or bad) else OK
    detail = (
        f"{plural(len(state), 'repo', 'repos')}, {plural(open_count, 'open issue', 'open issues')}"
    )
    if failed or bad:
        detail += f" — unreachable/invalid: {', '.join(failed + bad)[:100]}"
    return {
        "status": status,
        "detail": detail,
        "metrics": {"repos": len(state), "open_issues": open_count},
        # Consumed by api._persist_integration_results for edge-triggered
        # github_new_issue alerts (per-repo high-water issue number + the
        # newest issues so alert payloads can carry title/url).
        "gh_state": state,
        "gh_latest": latest,
    }


def format_stats(type_, metrics):
    """Render a connector's collected metrics as labeled display chips for the
    rich tiles. Returns [{label, value}, ...] (empty if the type has no spec or
    the metric is absent)."""
    metrics = metrics or {}
    out = []
    if type_ in DYNAMIC_STATS:
        # The names are the operator's own, so there is no fixed list: every number is a chip.
        for key, v in list(metrics.items())[:PROM_MAX_VALUES]:
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                out.append(
                    {"label": str(key)[:64], "value": f"{v:,.0f}" if abs(v) >= 1000 else f"{v:.4g}"}
                )
        return out
    for key, label, kind in _STATS.get(type_, []):
        if key in metrics and metrics[key] is not None:
            out.append({"label": label, "value": _fmt_stat(kind, metrics[key])})
    return out
