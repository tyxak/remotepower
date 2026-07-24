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
import urllib.parse

OK = "ok"
WARN = "warning"
CRIT = "critical"
UNKNOWN = "unknown"

# Field kinds the Settings UI knows how to render.
TEXT = "text"
PASSWORD = "password"


class IntegrationError(Exception):
    """Any failure reaching/parsing a target — caught by the poller → 'critical'."""


class Resp:
    __slots__ = ("status", "text", "headers")

    def __init__(self, status, text, headers=None):
        self.status = int(status)
        self.text = text or ""
        self.headers = headers or {}

    @property
    def ok(self):
        return 200 <= self.status < 300

    def json(self):
        try:
            return json.loads(self.text)
        except Exception:
            raise IntegrationError(f"invalid JSON (HTTP {self.status})")


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


def _register(type_, label, category, fields, notes="", version="", author="", homepage=""):
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
    by the operator (same as cgi-bin) — there is deliberately NO UI upload path;
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


@_register(
    "pihole",
    "Pi-hole",
    "dns",
    [_field("secret", "App password", PASSWORD)],
    notes="Pi-hole v6 API (app password under Settings → Web interface / API).",
)
def _pihole(inst, c):
    # v6: authenticate for a session ID, then read the summary.
    sid = ""
    try:
        auth = c.post_json("/api/auth", {"password": inst.get("secret") or ""}).json()
        sid = (((auth or {}).get("session") or {}).get("sid")) or ""
    except IntegrationError:
        sid = ""
    h = {"X-FTL-SID": sid} if sid else {}
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
    info = c.get_json("/api/v2.0/system/info", headers=h)
    ver = info.get("version", "")
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
        _field("username", "Username", TEXT),
        _field("secret", "Password", PASSWORD),
        _field("slug", "Site (default: default)", TEXT, optional=True),
    ],
    notes="Self-hosted UniFi Network controller (classic /api/login). UDM/UDM-Pro paths differ.",
)
def _unifi(inst, c):
    site = inst.get("slug") or "default"
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
    notes="PBS API token. Authorization: PBSAPIToken=<id>:<secret>.",
)
def _pbs(inst, c):
    h = {"Authorization": f"PBSAPIToken={inst.get('username','')}:{inst.get('secret','')}"}
    usage = c.get_json("/api2/json/status/datastore-usage", headers=h)
    stores = (usage or {}).get("data") or []
    worst = 0.0
    worst_name = ""
    # v6.3.0: per-datastore breakdown so the Backups page can render a tidy table
    # (name, fill %, total/avail). Robust to a store missing any size field.
    _GB = 1024.0**3
    datastores = []
    for s in stores:
        used = _pct(s.get("used"), s.get("total"))
        if used > worst:
            worst, worst_name = used, s.get("store", "?")
        _total = _num(s.get("total"))
        _avail = _num(s.get("avail"))
        ds = {
            "name": s.get("store", "?"),
            "used_pct": round(used, 1),
            "total_gb": round(_total / _GB, 1) if _total else 0,
            "avail_gb": round(_avail / _GB, 1) if _avail else 0,
        }
        # PBS reports a rolling dedup factor in the usage history when available.
        _dedup = s.get("deduplication-factor") or s.get("dedup")
        if isinstance(_dedup, (int, float)) and _dedup > 0:
            ds["dedup"] = round(float(_dedup), 2)
        # estimated-full-date (unix ts) → surface how long until the store fills.
        _eff = s.get("estimated-full-date")
        if isinstance(_eff, (int, float)) and _eff > 0:
            ds["full_eta"] = int(_eff)
        datastores.append(ds)
    status = OK
    if worst >= 90:
        status = CRIT
    elif worst >= 80:
        status = WARN
    ver = ""
    try:
        ver = ((c.get_json("/api2/json/version", headers=h) or {}).get("data") or {}).get(
            "version", ""
        )
    except IntegrationError:
        pass
    return {
        "status": status,
        "version": ver,
        "detail": f"{len(stores)} datastores, fullest {worst_name} {round(worst,1)}%",
        "metrics": {"datastores": len(stores), "fullest_pct": worst},
        "datastores": datastores,
    }


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
    notes="Grafana /api/health (DB reachability). Token optional for the basic check.",
)
def _grafana(inst, c):
    h = _hdr_token(inst, "Authorization", "Bearer ") if inst.get("secret") else {}
    hp = c.get_json("/api/health", headers=h)
    db = str(hp.get("database", "")).lower()
    ver = hp.get("version", "")
    status = OK if db == "ok" else CRIT
    return {
        "status": status,
        "version": ver,
        "detail": f"database {db or 'unknown'}",
        "metrics": {"database_ok": db == "ok"},
    }


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
    key = (inst.get("secret") or "").strip()
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
    notes="Jellyfin /System/Info with an API key (X-Emby-Token / api_key).",
)
def _jellyfin(inst, c):
    h = {"X-Emby-Token": inst.get("secret", "")}
    info = c.get_json("/System/Info", headers=h)
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
    status = CRIT if errors else (WARN if warnings else OK)
    detail = f"{app} {ver}"
    if errors:
        detail += f" · {len(errors)} error: {errors[0][:60]}"
    elif warnings:
        detail += f" · {len(warnings)} warning: {warnings[0][:60]}"
    else:
        detail += " · healthy"
    return {
        "status": status,
        "version": ver,
        "detail": detail,
        "metrics": {"app": app, "health_errors": len(errors), "health_warnings": len(warnings)},
    }


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
        "detail": f"up" + (f" · {issues} health issues" if issues else ""),
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
    notes="Immich API key (Account Settings → API Keys), sent as x-api-key.",
)
def _immich(inst, c):
    h = {"x-api-key": inst.get("secret", "")}
    about = c.get_json("/api/server/about", headers=h) or {}
    ver = str(about.get("version", "") or "")
    stats = c.get_json("/api/server/statistics", headers=h) or {}
    photos = int(_num(stats.get("photos", 0)))
    videos = int(_num(stats.get("videos", 0)))
    usage_mb = int(_num(stats.get("usage", 0)) / (1024 * 1024))
    return {
        "status": OK,
        "version": ver,
        "detail": f"{photos} photos, {videos} videos, {usage_mb} MB used",
        "metrics": {"photos": photos, "videos": videos, "usage_mb": usage_mb},
    }


@_register(
    "paperless",
    "Paperless-ngx",
    "apps",
    [_field("secret", "API token", PASSWORD)],
    notes="Paperless-ngx API token (profile → API auth token), sent as Authorization: Token.",
)
def _paperless(inst, c):
    h = _hdr_token(inst, "Authorization", "Token ")
    st = c.get_json("/api/statistics/", headers=h) or {}
    docs = int(_num(st.get("documents_total", 0)))
    inbox = int(_num(st.get("documents_inbox", 0)))
    return {
        "status": OK,
        "detail": f"{docs} documents, {inbox} in inbox",
        "metrics": {"documents": docs, "inbox": inbox},
    }


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
    return {
        "status": OK,
        "detail": f"{connected}/{len(conns)} devices connected, up {uptime // 3600}h",
        "metrics": {"devices_connected": connected, "devices": len(conns), "uptime_s": uptime},
    }


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
    [],
    notes="ESPHome dashboard device list (/devices) — counts nodes and flags "
    "out-of-date firmware. The dashboard has no token auth; protect it at the proxy.",
)
def _esphome(inst, c):
    data = c.get_json("/devices")
    nodes = (data.get("configured") if isinstance(data, dict) else data) or []
    outdated = 0
    for n in nodes:
        dep = (n or {}).get("deployed_version")
        cur = (n or {}).get("current_version")
        if dep and cur and str(dep) != str(cur):
            outdated += 1
    status = WARN if outdated else OK
    return {
        "status": status,
        "detail": f"{len(nodes)} nodes"
        + (f", {outdated} out of date" if outdated else ", all current"),
        "metrics": {"nodes": len(nodes), "outdated": outdated},
    }


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
    """Parse a Simple History GMT timestamp ('YYYY-MM-DD HH:MM:SS') → epoch.
    0 when unparseable — the UI renders that as '—' rather than 1970."""
    import calendar
    import time as _time

    try:
        return int(calendar.timegm(_time.strptime(str(s).strip(), "%Y-%m-%d %H:%M:%S")))
    except (TypeError, ValueError):
        return 0


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
    root = c.get_json("/wp-json/") or {}
    site = str(root.get("name") or "").strip()
    h = {}
    user, pw = inst.get("username") or "", inst.get("secret") or ""
    authed = False
    if user and pw:
        h["Authorization"] = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
        try:
            me = c.get_json("/wp-json/wp/v2/users/me", headers=h)
            authed = bool(isinstance(me, dict) and me.get("id"))
        except IntegrationError:
            authed = False
        if not authed:
            return {
                "status": WARN,
                "detail": f"{site or 'site up'} — credentials rejected "
                "(check the Application password)",
                "metrics": {},
            }
    logins = []
    logins_available = False
    if authed:
        try:
            ev = c.get_json(
                "/wp-json/simple-history/v1/events",
                headers=h,
                params={"per_page": 25, "loggers": "SimpleUserLogger"},
            )
            rows = ev.get("data") if isinstance(ev, dict) else ev
            if isinstance(rows, list):
                logins_available = True
                for e in rows:
                    le = _wp_login_event(e)
                    if le:
                        logins.append(le)
                    if len(logins) >= 5:
                        break
        except IntegrationError:
            logins_available = False
    import time as _time

    day_ago = int(_time.time()) - 86400
    detail = site or "site up"
    if logins_available:
        detail += f" — {len(logins)} recent login(s)"
    elif authed:
        detail += " — login history unavailable (Simple History plugin not detected)"
    return {
        "status": OK,
        "detail": detail,
        "metrics": (
            {"logins_24h": sum(1 for x in logins if x["ts"] >= day_ago)} if logins_available else {}
        ),
        "recent_logins": logins,
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
# Hostname NORMALISATION is deliberately NOT done here — connectors stay dumb
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
        out["detail"] = f"{infected} infected endpoint(s), " + out["detail"]
    out["metrics"]["infected"] = infected
    return out


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
    "unifi": [("subsystems", "Subsystems", "num"), ("subsystems_bad", "Degraded", "num")],
    "homeassistant": [("entities", "Entities", "int"), ("unavailable", "Unavailable", "num")],
    "pbs": [("datastores", "Datastores", "num"), ("fullest_pct", "Fullest", "pct")],
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
    "grafana": [("database_ok", "Database", "flag")],
    "remotepower": [
        ("devices", "Devices", "int"),
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
    "servarr": [("health_errors", "Errors", "num"), ("health_warnings", "Warnings", "num")],
    "bazarr": [("health_issues", "Issues", "num")],
    "overseerr": [("pending_requests", "Pending", "num"), ("update_available", "Update", "flag")],
    "immich": [
        ("photos", "Photos", "int"),
        ("videos", "Videos", "int"),
        ("usage_mb", "Usage", "mb"),
    ],
    "paperless": [("documents", "Documents", "int"), ("inbox", "Inbox", "num")],
    "vaultwarden": [("alive", "Alive", "flag")],
    "gitea": [("repos", "Repos", "int")],
    "syncthing": [("devices_connected", "Connected", "num"), ("devices", "Devices", "num")],
    "frigate": [("cameras", "Cameras", "num"), ("det_fps", "Detect FPS", "num")],
    "octoprint": [("printing", "Printing", "flag"), ("operational", "Operational", "flag")],
    "esphome": [("nodes", "Nodes", "num"), ("outdated", "Outdated", "num")],
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
    field = (inst.get("probe_json_field") or "").strip()
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
    for raw in (inst.get("slug") or "").split(","):
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
    u = (inst.get("url") or "").strip().lower().rstrip("/")
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
    detail = f"{len(state)} repo(s), {open_count} open issue(s)"
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
    for key, label, kind in _STATS.get(type_, []):
        if key in metrics and metrics[key] is not None:
            out.append({"label": label, "value": _fmt_stat(kind, metrics[key])})
    return out
