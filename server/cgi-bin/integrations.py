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

import json
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
        url = (
            path
            if path.startswith(("http://", "https://"))
            else self.base + (path if path.startswith("/") else "/" + path)
        )
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


def _register(type_, label, category, fields, notes=""):
    """Decorator registering a connector + its UI metadata."""

    def deco(fn):
        CONNECTORS[type_] = {
            "type": type_,
            "label": label,
            "category": category,
            "fields": fields,
            "notes": notes,
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
    return {
        "status": OK,
        "version": ver,
        "detail": f"{int(_num(total))} queries today, {round(_num(blocked_pct),1)}% blocked",
        "metrics": {
            "queries_today": total,
            "blocked_pct": blocked_pct,
            "domains_blocked": g.get("domains_being_blocked", 0),
        },
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
    try:
        stats = c.get_json("/control/stats", headers=h)
        queries = stats.get("num_dns_queries", 0)
        blocked = stats.get("num_blocked_filtering", 0)
    except IntegrationError:
        pass
    if not running:
        return {"status": CRIT, "detail": "DNS server not running", "version": ver, "metrics": {}}
    status = OK if prot else WARN
    detail = f"{int(_num(queries))} queries, {_pct(blocked, queries)}% blocked"
    if not prot:
        detail = "protection DISABLED · " + detail
    return {
        "status": status,
        "version": ver,
        "detail": detail,
        "metrics": {"queries": queries, "blocked": blocked, "protection": prot},
    }


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
    for s in stores:
        used = _pct(s.get("used"), s.get("total"))
        if used > worst:
            worst, worst_name = used, s.get("store", "?")
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
    "VMware vCenter / ESXi",
    "orchestration",
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
    for ver_path in ("v3", "v1"):
        r = c.get(f"/api/{ver_path}/system/status", headers=h)
        if r.ok:
            api, st = ver_path, (r.json() or {})
            break
    if api is None:
        raise IntegrationError(
            "system/status not found on /api/v3 or /api/v1 (check URL + API key)"
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


# ── per-connector headline stat chips (for the rich tiles) ─────────────────────
# Map each connector type to a few (metric_key, label, kind) the UI shows as
# labeled chips. kinds: int (humanized 12.3k), pct (18%), num (small count),
# rate (KB/s, value already in KB/s), mb (123 MB), flag (yes/no), str. Surfaces
# the metrics the connectors ALREADY collect — no extra API calls.
_STATS: dict = {
    "pihole": [
        ("queries_today", "Queries", "int"),
        ("blocked_pct", "Blocked", "pct"),
        ("domains_blocked", "Blocklist", "int"),
    ],
    "adguard": [("queries", "Queries", "int"), ("blocked", "Blocked", "int")],
    "truenas": [
        ("pools", "Pools", "num"),
        ("pools_bad", "Degraded", "num"),
        ("alerts_crit", "Crit alerts", "num"),
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
