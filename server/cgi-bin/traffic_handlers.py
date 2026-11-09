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
WIDGET_TOP = 3  # remote addresses on the Home widget
WIDGET_HITS_MAX = 999  # watch list matches counted for the Home widget


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
    """Keep the sample a host's agent sent with its report, and raise an alert for each watch list match that is due one. Called from the heartbeat outside the
    devices lock; it does nothing while the module is off, drops a sample that is not one, and never raises, so a bad sample cannot fail the heartbeat that
    carried it.

    The alerts go out only after the record that remembers them has been saved and read back: the write is best-effort and is skipped under lock contention, and
    an alert sent for a record that was not kept would be sent again with the next sample."""
    if raw is None or not A._module_on("traffic"):
        return
    hits = []
    try:
        sample = T.clean_sample(raw, now)
        if sample is None:
            return
        prev = A._entity_read_one(A.TRAFFIC_FILE, dev_id, {})
        if not isinstance(prev, dict):
            prev = {}        # a row that is not a map (the JSON backend drops it on read; a SQL backend hands it over) is replaced, not read
        rec = T.merge(prev, sample, now)
        if isinstance(prev.get("alerted"), dict):
            rec["alerted"] = prev["alerted"]            # kept through a sample that cannot be checked, so what was raised is not raised again
        watch = _watch(A._config_ro())
        due = []
        if watch and not sample.get("err"):
            due, rec["alerted"] = T.due_hits(prev.get("alerted") if isinstance(prev, dict) else None, sample["rows"], watch, now)
        A._entity_write_one(A.TRAFFIC_FILE, dev_id, rec)
        if due:
            kept = A._entity_read_one(A.TRAFFIC_FILE, dev_id, {}) or {}
            if isinstance(kept, dict) and kept.get("at") == now:
                hits = due
    except Exception as e:
        sys.stderr.write(f"[remotepower] traffic ingest failed dev={dev_id}: {type(e).__name__}: {e}\n")
        return
    _raise(dev_id, hits)


def _raise(dev_id, hits):
    """One `traffic_watch` event for each match. The payload names the remote address, the port and the program, which the inbox and the activity feed show; the
    entry that matched and the note written on it go in only on an installation without tenants, because with tenants they are the operator's list."""
    if not hits:
        return
    try:
        dev = A.device_get(dev_id)
        name = (dev.get("name") if isinstance(dev, dict) else None) or dev_id
        show = not A._tenancy_enforced()
        for row, entry in hits:
            payload = {"name": name, "device_id": dev_id, "ip": row["ip"], "port": row["port"], "detail": T.hit_detail(row, entry, show)}
            if row.get("proc"):
                payload["process"] = row["proc"]
            if show and entry.get("label"):
                payload["label"] = entry["label"]
            A.fire_webhook("traffic_watch", payload)
    except Exception as e:
        sys.stderr.write(f"[remotepower] traffic alert failed dev={dev_id}: {type(e).__name__}: {e}\n")


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


def _verdicts(ips):
    """{ip: the verdict} for the addresses that the Threat Intel store has one for: its reputation score, and the country and network the lookup named. Read-only
    (the dictionaries belong to the shared cache), never raises."""
    try:
        st = (A._load_ro(A.IPINTEL_FILE) or {}) if A.backend_exists(A.IPINTEL_FILE) else {}
        atts = st.get("attackers") if isinstance(st.get("attackers"), dict) else {}
    except Exception:
        return {}
    out = {}
    for ip in list(ips)[:INTEL_MAX]:
        v = (atts.get(ip) or {}).get("verdict") if isinstance(atts.get(ip), dict) else None
        if isinstance(v, dict):
            out[ip] = v
    return out


def _intel(ips, verdicts=None):
    """{ip: reputation score} for the addresses that the Threat Intel store has a verdict for."""
    out = {}
    for ip, v in (_verdicts(ips) if verdicts is None else verdicts).items():
        score = v.get("score")
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


def _lookup_where(v):
    """{country_code, org} of an address from the verdict a Threat Intel lookup stored (AbuseIPDB names a two-letter country and the network); empty when it names none."""
    out = {}
    cc, isp = v.get("country"), v.get("isp")
    if isinstance(cc, str) and len(cc.strip()) == 2 and cc.strip().isalpha():
        out["country_code"] = cc.strip().upper()
    if isinstance(isp, str) and isp.strip():
        out["org"] = isp.strip()[:120]
    return out


def _remote_view(ip, geo_cache, scores, verdicts=None):
    """What the page shows about a remote address: its scope, and for a public one the country and organisation (the GeoLite2 files first, then what a Threat Intel
    lookup of the address stored, field by field) and the reputation score."""
    out = {"scope": T.scope_of(ip)}
    if out["scope"] == "public":
        if ip not in geo_cache:
            geo_cache[ip] = _where(ip)
        out.update(geo_cache[ip])
        v = (verdicts or {}).get(ip)
        if isinstance(v, dict):
            for k, val in _lookup_where(v).items():
                out.setdefault(k, val)
        if ip in scores:
            out["score"] = scores[ip]
    return out


def _row_view(r, watch, labels, geo_cache, scores, rec, now, verdicts=None):
    out = dict(r)
    out["service"] = T.service_of(r["port"])
    out.update(_remote_view(r["ip"], geo_cache, scores, verdicts))
    hits = T.watched(r, watch)
    if hits:
        out["watched"] = [{"kind": h["kind"], "value": h["value"], "label": h.get("label", "") if labels else ""} for h in hits]
    if rec is not None and T.is_new(rec, r["ip"], now):
        out["new"] = True
    return out


# ── the host view ────────────────────────────────────────────────────────────


def _win(sample):
    """The window a stored sample covers, in seconds: the number when it is one from 1 to 3600, else 1."""
    v = sample.get("win") if isinstance(sample, dict) else None
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and 1 <= v <= 3600 else 1.0


def _step(dev, every):
    """Seconds between two samples that reach the server: the sampling interval, or the host's own poll interval when that is longer, since a sample travels with
    a report. A host that polls every ten minutes is not stale after five."""
    poll = dev.get("poll_interval") if isinstance(dev, dict) else None
    poll = poll if isinstance(poll, (int, float)) and not isinstance(poll, bool) and 0 < poll <= 86400 else 0
    return max(every, MIN_EVERY, poll)


def _state(dev, rec, now, every):
    """What a host's Traffic row is: 'unsupported' (only the Linux agent samples), 'waiting' (no sample yet), 'stale' (it stopped), 'error' (its last sample
    says it could not read its connections: no `ss`, or `ss` failed) or 'reporting'. A kernel that gives no byte counts still reports, with `err` set."""
    if A._device_os_family(dev) != "linux":
        return "unsupported"
    if not isinstance(rec, dict) or not isinstance(rec.get("sample"), dict):
        return "waiting"
    at = rec.get("at")
    if isinstance(at, bool) or not isinstance(at, (int, float)):
        return "waiting"
    if now - at > max(STALE_REPORTS * _step(dev, every), 300):
        return "stale"
    return "error" if rec["sample"].get("err") in ("no-ss", "ss-failed") else "reporting"


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
        "err": "",
        "geo": bool(cfg.get("geoip_db_path") or cfg.get("geoip_asn_db_path")),
    }
    if state in ("reporting", "stale", "error"):
        sample = rec["sample"]
        rows = T.stored_rows(sample)
        verdicts = _verdicts({r["ip"] for r in rows if T.scope_of(r["ip"]) == "public"})
        scores = _intel(None, verdicts)
        geo_cache, watch, labels = {}, _watch(cfg), _is_operator() or not A._tenancy_enforced()
        out.update(
            {
                "at": rec.get("at"),
                "win": _win(sample),
                "tx": T.num(sample.get("tx")),
                "rx": T.num(sample.get("rx")),
                "conns": T.num(sample.get("conns")),
                "trunc": bool(sample.get("trunc")),
                "err": sample.get("err") if sample.get("err") in T.ERRORS else "",
                "other": sample.get("other") if isinstance(sample.get("other"), dict) else out["other"],
                "series": [p for p in (rec.get("series") if isinstance(rec.get("series"), list) else []) if isinstance(p, list) and len(p) == 4 and all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in p)],
                "rows": [_row_view(r, watch, labels, geo_cache, scores, rec, now, verdicts) for r in rows],
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
    entries, hosts, hits, by_state = [], [], [], {"reporting": 0, "stale": 0, "waiting": 0, "unsupported": 0, "error": 0}
    ranked = sorted(((str(d.get("name") or i).lower(), i, d) for i, d in devices.items() if isinstance(d, dict) and not d.get("agentless") and not d.get("decommissioned")))
    for _name_key, dev_id, dev in ranked:
        rec = store.get(dev_id) if isinstance(store.get(dev_id), dict) else None
        state = _state(dev, rec, now, every)
        by_state[state] += 1
        name = dev.get("name") or dev_id
        line = {"id": dev_id, "name": name, "state": state}
        if state in ("reporting", "stale", "error") and rec is not None:
            sample = rec["sample"]
            win, tx, rx = _win(sample), T.num(sample.get("tx")), T.num(sample.get("rx"))
            line.update({"at": rec.get("at"), "conns": T.num(sample.get("conns")), "tx": tx, "rx": rx, "tx_rate": round(tx / win), "rx_rate": round(rx / win)})
            if sample.get("err") in T.ERRORS:
                line["err"] = sample["err"]
            if state == "reporting":
                entries.append((dev_id, name, sample))
                if watch and len(hits) < HITS_MAX:
                    for r in T.stored_rows(sample):
                        for w in T.watched(r, watch):
                            if len(hits) < HITS_MAX:
                                hits.append({"id": dev_id, "name": name, "ip": r["ip"], "port": r["port"], "proc": r.get("proc", ""), "d": r["d"], "tx": r["tx"], "rx": r["rx"], "kind": w["kind"], "value": w["value"], "label": w.get("label", "") if labels else ""})
        if len(hosts) < HOSTS_MAX:
            hosts.append(line)
    summary = T.fleet_summary(entries, top=50, is_new=lambda hid, ip: T.is_new(store.get(hid), ip, now))
    public = {e["ip"] for e in summary["remotes"] if e["scope"] == "public"}
    verdicts = _verdicts(public)
    scores, geo_cache = _intel(None, verdicts), {}
    for e in summary["remotes"]:
        e.update({k: v for k, v in _remote_view(e["ip"], geo_cache, scores, verdicts).items() if k != "scope"})
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


def traffic_widget(visible, now=None):
    """The numbers of the small Traffic widget on Home, for the hosts `visible` (the caller's own view, so another tenant's hosts and addresses are not in them): how
    many of the Linux hosts with an agent report, what they sent and received per second at their last sample, their connections, the watch list matches and the
    three busiest remote addresses. {'on': False} while the module is off. Never raises: a widget must not take the dashboard down."""
    try:
        if not A._module_on("traffic"):
            return {"on": False}
        now = int(now or time.time())
        cfg = A._config_ro()
        every = sampling_every(cfg)
        store = (A._load_ro(A.TRAFFIC_FILE) or {}) if A.backend_exists(A.TRAFFIC_FILE) else {}
        watch = _watch(cfg)
        entries, total, tx_rate, rx_rate, conns, hits = [], 0, 0, 0, 0, 0
        for dev_id, dev in (visible or {}).items():
            if not isinstance(dev, dict) or dev.get("agentless") or dev.get("decommissioned"):
                continue
            total += 1
            rec = store.get(dev_id) if isinstance(store.get(dev_id), dict) else None
            if _state(dev, rec, now, every) != "reporting":
                continue
            sample = rec["sample"]
            win = _win(sample)
            tx_rate += round(T.num(sample.get("tx")) / win)
            rx_rate += round(T.num(sample.get("rx")) / win)
            conns += T.num(sample.get("conns"))
            entries.append((dev_id, dev.get("name") or dev_id, sample))
            if watch and hits < WIDGET_HITS_MAX:
                hits += sum(1 for r in T.stored_rows(sample) if T.watched(r, watch))
        top = T.fleet_summary(entries, top=WIDGET_TOP)["remotes"]
        verdicts = _verdicts({e["ip"] for e in top if e["scope"] == "public"})
        scores, geo_cache, rows = _intel(None, verdicts), {}, []
        for e in top:
            view = _remote_view(e["ip"], geo_cache, scores, verdicts)
            rows.append({"ip": e["ip"], "tx": e["tx"], "rx": e["rx"], "hosts_n": e["hosts_n"], **{k: v for k, v in view.items() if k in ("scope", "country", "country_code", "org", "score")}})
        return {"on": True, "hosts": len(entries), "total": total, "tx": tx_rate, "rx": rx_rate, "conns": conns, "hits": min(hits, WIDGET_HITS_MAX), "top": rows}
    except Exception:
        return {}


# ── the Data Explorer and Fleet Query ────────────────────────────────────────


def explorer_rows(devices, store, now):
    """Data Explorer `traffic` (8.0.0): one row for each (host, direction, remote address, port, program) of the last sample of each host given. The hosts are already the
    caller's (the caller filters them) and the module gate is the caller's too. A row says whether the address is new for the host and whether any watch list entry matches it,
    never which entry: the entries and their notes are the operator's."""
    cfg = A._config_ro()
    every, watch = sampling_every(cfg), _watch(cfg)
    out = []
    for dev_id, dev in sorted(devices.items(), key=lambda kv: str((kv[1] or {}).get("name") or kv[0]).lower()):
        if not isinstance(dev, dict) or dev.get("agentless") or dev.get("decommissioned"):
            continue
        rec = store.get(dev_id) if isinstance(store, dict) else None
        state = _state(dev, rec, now, every)
        if state not in ("reporting", "stale"):
            continue
        for r in T.stored_rows(rec["sample"]):
            out.append(
                {
                    "device_id": dev_id,
                    "device_name": dev.get("name") or dev_id,
                    "direction": r.get("d"),
                    "address": r.get("ip"),
                    "scope": T.scope_of(r.get("ip")),
                    "port": r.get("port"),
                    "service": T.service_of(r.get("port")),
                    "program": r.get("proc") or "",
                    "connections": r.get("n"),
                    "sent": r.get("tx"),
                    "received": r.get("rx"),
                    "new": T.is_new(rec, r.get("ip"), now),
                    "watched": bool(watch and T.watched(r, watch)),
                    "state": state,
                    "sampled_at": rec.get("at"),
                }
            )
    return out


def hosts_talking(devices, store, needle):
    """Ids of the hosts of `devices` whose last sample has a connection to an address that contains `needle`, on that port (or its service name), or by a program that contains
    it, in any case: the Fleet Query `talks` criterion (8.0.0). Empty for an empty needle."""
    needle = str(needle or "").strip().lower()
    out = set()
    if not needle or not isinstance(store, dict):
        return out
    for dev_id, dev in devices.items():
        if not isinstance(dev, dict) or dev.get("agentless") or dev.get("decommissioned"):
            continue
        rec = store.get(dev_id)
        for r in T.stored_rows(rec.get("sample") if isinstance(rec, dict) else None):
            if needle in str(r.get("ip") or "").lower() or needle in str(r.get("proc") or "").lower() or needle == str(r.get("port")) or needle == T.service_of(r.get("port")):
                out.add(dev_id)
                break
    return out


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
