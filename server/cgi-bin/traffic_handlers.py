"""RemotePower — the Traffic view: what each host's established TCP connections moved, a host's chart, the fleet's busiest remote addresses and the watch list (8.0.0)

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

Constants stay in api.py and are read here through A. Pure logic goes in a
sibling module (imported directly, like dmarc_monitor / tls_monitor): `traffic`.

What this module does. A Linux agent samples its established TCP connections (`ss -i`) every `traffic_every` seconds and sends the sample with its report; ingest()
cleans it and keeps one record per host. The two read routes show that record: one host (`/api/devices/<id>/traffic`, which the pre-dispatch gate has already
confined to the hosts the caller may see) and the fleet (`/api/traffic/fleet`, over the hosts the caller may see). The watch list is one list for the installation;
the platform operator edits it. The whole module is off until Settings → Advanced switches it on, and `_MODULES` answers 404 for the `/api/traffic` prefix until then.
"""

import sys
import time

import traffic as T


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


DEFAULT_EVERY = 60  # seconds between two samples on a host
MIN_EVERY = 30
MAX_EVERY = 3600
STALE_REPORTS = 3  # a host that has missed this many samples reads as stale
HOSTS_MAX = 500  # hosts listed on the fleet page
HITS_MAX = 100  # watch list matches listed on the fleet page
INTEL_MAX = 200  # addresses of one answer looked up in the intelligence store


# ── the setting and the heartbeat side ───────────────────────────────────────


def sampling_every(cfg=None):
    """Seconds between two samples, as a Linux agent is told with each report: 0 while the module is off, else `traffic_every` held to MIN_EVERY..MAX_EVERY."""
    if not A._module_on("traffic"):
        return 0
    cfg = cfg if isinstance(cfg, dict) else A._config_ro()
    v = cfg.get("traffic_every")
    if isinstance(v, bool) or not isinstance(v, (int, float)) or v != v or abs(v) > 10**9:
        return DEFAULT_EVERY
    return max(MIN_EVERY, min(MAX_EVERY, int(v)))


def ingest(dev_id, raw, now):
    """Keep the sample a host's agent sent with its report. Called from the heartbeat outside the devices lock; it does nothing while the module is off, drops a sample
    that is not one, and never raises, so a bad sample cannot fail the heartbeat that carried it."""
    if raw is None or not A._module_on("traffic"):
        return
    try:
        sample = T.clean_sample(raw, now)
        if sample is None:
            return
        prev = A._entity_read_one(A.TRAFFIC_FILE, dev_id, {}) or {}
        A._entity_write_one(A.TRAFFIC_FILE, dev_id, T.merge(prev, sample, now))
    except Exception as e:
        sys.stderr.write(f"[remotepower] traffic ingest failed dev={dev_id}: {type(e).__name__}: {e}\n")


# ── who is asking ────────────────────────────────────────────────────────────


def _is_operator():
    """An administrator, and on a multi-tenant install only the platform operator: the watch list belongs to the installation, not to a tenant."""
    try:
        return bool(A._caller_is_admin()) and (not A._tenancy_enforced() or A._caller_is_superadmin())
    except Exception:
        return False


def _gate():
    if not A._module_on("traffic"):
        A.respond(404, {"error": "Not found", "module_disabled": "traffic"})


def _watch(cfg):
    raw = cfg.get("traffic_watch")
    entries, err = T.clean_watch(raw if isinstance(raw, list) else [])
    return [] if err else entries


# ── what a remote address is ─────────────────────────────────────────────────


def _intel(ips):
    """{ip: reputation score} for the addresses that the Threat Intel store has a verdict for. Read-only, never raises."""
    try:
        st = (A._load_ro(A.IPINTEL_FILE) or {}) if A.backend_exists(A.IPINTEL_FILE) else {}
        atts = st.get("attackers") if isinstance(st.get("attackers"), dict) else {}
    except Exception:
        return {}
    out = {}
    for ip in list(ips)[:INTEL_MAX]:
        v = (atts.get(ip) or {}).get("verdict") if isinstance(atts.get(ip), dict) else None
        score = v.get("score") if isinstance(v, dict) else None
        if isinstance(score, (int, float)) and not isinstance(score, bool):
            out[ip] = score
    return out


def _where(ip):
    """{country, country_code, asn, org} of a public address from the GeoLite2 files the administrator configured; empty when none is."""
    try:
        g = A.geo_enrich(ip) or {}
    except Exception:
        return {}
    return {k: g[k] for k in ("country", "country_code", "asn", "org") if g.get(k) not in (None, "")}


def _remote_view(ip, geo_cache, scores):
    out = {"scope": T.scope_of(ip)}
    if out["scope"] == "public":
        if ip not in geo_cache:
            geo_cache[ip] = _where(ip)
        out.update(geo_cache[ip])
        if ip in scores:
            out["score"] = scores[ip]
    return out


def _row_view(r, watch, labels, geo_cache, scores, rec, now):
    out = dict(r)
    out["service"] = T.service_of(r["port"])
    out.update(_remote_view(r["ip"], geo_cache, scores))
    hits = T.watched(r, watch)
    if hits:
        out["watched"] = [{"kind": h["kind"], "value": h["value"], "label": h.get("label", "") if labels else ""} for h in hits]
    if rec is not None and T.is_new(rec, r["ip"], now):
        out["new"] = True
    return out


# ── the host view ────────────────────────────────────────────────────────────


def _state(dev, rec, now, every):
    """What a host's Traffic row is: 'unsupported' (only the Linux agent samples), 'waiting' (no sample yet), 'stale' (it stopped) or 'reporting'."""
    if A._device_os_family(dev) != "linux":
        return "unsupported"
    if not isinstance(rec, dict) or not isinstance(rec.get("sample"), dict):
        return "waiting"
    at = rec.get("at")
    if isinstance(at, bool) or not isinstance(at, (int, float)):
        return "waiting"
    return "stale" if now - at > max(STALE_REPORTS * max(every, MIN_EVERY), 300) else "reporting"


def handle_device_traffic(dev_id):
    """GET /api/devices/<id>/traffic -- what one host's connections moved at its last sample, as rows (remote address, service, program, connections, bytes each way),
    its chart and the watch list matches (8.0.0).

    Any signed-in role, like the host's own page. The path is under /api/devices/<id>/, so the pre-dispatch gate has already refused a host the caller may not see
    (another tenant's, or outside a scoped role); the module gate is repeated here because the prefix list cannot name this path."""
    A.require_auth()
    if A.method() != "GET":
        A.respond(405, {"error": "Method not allowed"})
    _gate()
    if not A._validate_id(dev_id):
        A.respond(404, {"error": "Host not found"})
    dev = A.device_get(dev_id)
    if not isinstance(dev, dict):
        A.respond(404, {"error": "Host not found"})
    now = int(time.time())
    cfg = A._config_ro()
    every = sampling_every(cfg)
    rec = A._entity_read_one(A.TRAFFIC_FILE, dev_id, {}) or {}
    state = _state(dev, rec, now, every)
    out = {
        "device_id": dev_id,
        "name": dev.get("name") or dev_id,
        "state": state,
        "every": every,
        "now": now,
        "supported": A._device_os_family(dev) == "linux",
        "rows": [],
        "series": [],
        "other": {"n": 0, "tx": 0, "rx": 0, "rows": 0},
        "geo": bool(cfg.get("geoip_db_path") or cfg.get("geoip_asn_db_path")),
    }
    if state in ("reporting", "stale"):
        sample = rec["sample"]
        rows = [r for r in (sample.get("rows") or []) if isinstance(r, dict)]
        scores = _intel({r["ip"] for r in rows if T.scope_of(r["ip"]) == "public"})
        geo_cache, watch, labels = {}, _watch(cfg), _is_operator() or not A._tenancy_enforced()
        out.update(
            {
                "at": rec.get("at"),
                "win": sample.get("win"),
                "tx": sample.get("tx", 0),
                "rx": sample.get("rx", 0),
                "conns": sample.get("conns", 0),
                "trunc": bool(sample.get("trunc")),
                "other": sample.get("other") or out["other"],
                "series": [p for p in (rec.get("series") or []) if isinstance(p, list) and len(p) == 4],
                "rows": [_row_view(r, watch, labels, geo_cache, scores, rec, now) for r in rows],
            }
        )
    A.respond(200, out)


# ── the fleet view ───────────────────────────────────────────────────────────


def handle_traffic_fleet():
    """GET /api/traffic/fleet -- the hosts the caller may see, added up: the busiest remote addresses (with the hosts that talk to each), programs and ports, the totals,
    the watch list matches and one line for each host (8.0.0). Any signed-in role; the host set is `_scope_filter_devices`, which holds role scope and tenant."""
    A.require_auth()
    if A.method() != "GET":
        A.respond(405, {"error": "Method not allowed"})
    _gate()
    now = int(time.time())
    cfg = A._config_ro()
    every = sampling_every(cfg)
    devices = A._scope_filter_devices(A._load_ro(A.DEVICES_FILE) or {})
    store = (A._load_ro(A.TRAFFIC_FILE) or {}) if A.backend_exists(A.TRAFFIC_FILE) else {}
    watch, labels = _watch(cfg), _is_operator() or not A._tenancy_enforced()
    entries, hosts, hits, by_state = [], [], [], {"reporting": 0, "stale": 0, "waiting": 0, "unsupported": 0}
    ranked = sorted(((str(d.get("name") or i).lower(), i, d) for i, d in devices.items() if isinstance(d, dict) and not d.get("agentless") and not d.get("decommissioned")))
    for _name_key, dev_id, dev in ranked:
        rec = store.get(dev_id) if isinstance(store.get(dev_id), dict) else None
        state = _state(dev, rec, now, every)
        by_state[state] += 1
        name = dev.get("name") or dev_id
        line = {"id": dev_id, "name": name, "state": state}
        if state in ("reporting", "stale") and rec is not None:
            sample = rec["sample"]
            win = max(1.0, float(sample.get("win") or 1))
            line.update({"at": rec.get("at"), "conns": sample.get("conns", 0), "tx": sample.get("tx", 0), "rx": sample.get("rx", 0), "tx_rate": round(sample.get("tx", 0) / win), "rx_rate": round(sample.get("rx", 0) / win)})
            if state == "reporting":
                entries.append((dev_id, name, sample))
                if watch and len(hits) < HITS_MAX:
                    for r in sample.get("rows") or []:
                        for w in T.watched(r, watch):
                            if len(hits) < HITS_MAX:
                                hits.append({"id": dev_id, "name": name, "ip": r["ip"], "port": r["port"], "proc": r.get("proc", ""), "d": r["d"], "tx": r["tx"], "rx": r["rx"], "kind": w["kind"], "value": w["value"], "label": w.get("label", "") if labels else ""})
        if len(hosts) < HOSTS_MAX:
            hosts.append(line)
    summary = T.fleet_summary(entries, top=50)
    public = {e["ip"] for e in summary["remotes"] if e["scope"] == "public"}
    scores, geo_cache = _intel(public), {}
    for e in summary["remotes"]:
        e.update({k: v for k, v in _remote_view(e["ip"], geo_cache, scores).items() if k != "scope"})
        if watch and T.watched({"ip": e["ip"], "port": 0, "proc": ""}, [w for w in watch if w["kind"] in ("ip", "cidr")]):
            e["watched"] = True
    A.respond(
        200,
        {
            "now": now,
            "every": every,
            "totals": summary["totals"],
            "remotes": summary["remotes"],
            "programs": summary["programs"],
            "ports": summary["ports"],
            "hits": hits,
            "hosts": hosts,
            "hosts_total": sum(by_state.values()),
            "by_state": by_state,
            "watch_count": len(watch),
            "geo": bool(cfg.get("geoip_db_path") or cfg.get("geoip_asn_db_path")),
        },
    )


# ── the watch list ───────────────────────────────────────────────────────────


def handle_traffic_config_get():
    """GET /api/traffic/config -- the sampling interval and the watch list (8.0.0). Any signed-in role may read the interval and how many entries there are; the entries
    themselves, with their labels, go to the platform operator and, on an installation with no tenants, to everyone: on a shared one they are the operator's notes."""
    A.require_auth()
    if A.method() != "GET":
        A.respond(405, {"error": "Method not allowed"})
    _gate()
    cfg = A._config_ro()
    watch, operator = _watch(cfg), _is_operator()
    show = operator or not A._tenancy_enforced()
    A.respond(200, {"every": sampling_every(cfg), "min_every": MIN_EVERY, "max_every": MAX_EVERY, "max_watch": T.MAX_WATCH, "count": len(watch), "watch": watch if show else [], "editable": operator})


def handle_traffic_config_set():
    """POST /api/traffic/config {watch?, every?} -- save the watch list and the sampling interval (8.0.0). The platform operator's, since both are the installation's.

    A key that is not in the body is left as it is. A watch list with one entry that is not an entry is refused whole, with the entry's number and what is wrong."""
    actor = A.require_admin_auth()
    if A.method() != "POST":
        A.respond(405, {"error": "Method not allowed"})
    _gate()
    body = A._read_valid(A.request_models.TrafficConfigRequest)
    A._require_platform_operator("The traffic settings")
    changes = {}
    if body.get("watch") is not None:
        entries, err = T.clean_watch(body.get("watch"))
        if err:
            A.respond(400, {"error": err})
        changes["traffic_watch"] = entries
    if body.get("every") is not None:
        every = body.get("every")
        if isinstance(every, bool) or not isinstance(every, (int, float)) or every != every or not MIN_EVERY <= every <= MAX_EVERY:
            A.respond(400, {"error": "The interval is a whole number of seconds from %d to %d" % (MIN_EVERY, MAX_EVERY)})
        changes["traffic_every"] = int(every)
    if changes:
        with A._LockedUpdate(A.CONFIG_FILE) as cfg:
            cfg.update(changes)
        A.audit_log(actor, "traffic_config_set", "watch=%s every=%s" % (len(changes["traffic_watch"]) if "traffic_watch" in changes else "-", changes.get("traffic_every", "-")))
    cfg = A._config_ro()
    A.respond(200, {"ok": True, "every": sampling_every(cfg), "watch": _watch(cfg)})
