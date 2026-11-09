"""RemotePower — Detections: rules that look at what a host does, run on a schedule over the data the agents already send (8.0.0)

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

Constants stay in api.py and are read here through A. The rules are pure logic in a sibling module (`detections`).

What this module does. Every EVERY_S seconds the sweep reads three stores once (the Traffic records, the fleet event log, what Threat Intel knows about an address), builds
one context for each host, runs the enabled rules and keeps what they found in `detections.json`: per host, the findings of the last sweep and when each was raised. A
finding that was not raised lately becomes an alert of event `detection_found`, so acknowledging, resolving, muting, maintenance windows, tenant scope, notifications and AI
triage all work on it as they do on any alert. The page lists the findings of the last sweep and the rules. The whole module is off until Settings → Advanced switches it on,
and `_MODULES` answers 404 for the `/api/detections` prefix until then.
"""

import sys
import time
import urllib.parse

import detections as D
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


EVERY_S = 300  # seconds between two sweeps
FINDINGS_MAX = 200  # findings listed on the page
RAISE_MAX = 100  # alerts one sweep raises for the whole fleet, the worst first; what is held back is raised by the next sweep, so one address that turns bad cannot flood the inbox


# ── who is asking ────────────────────────────────────────────────────────────


def _is_operator():
    """An administrator, and on a multi-tenant install only the platform operator: the rules belong to the installation, not to a tenant."""
    try:
        return bool(A._caller_is_admin()) and (not A._tenancy_enforced() or A._caller_is_superadmin())
    except Exception:
        return False


def _query(name):
    """One value of the query string, or None: the same read the other handlers make of `QUERY_STRING` (through the request's own environment, never the process's)."""
    vals = urllib.parse.parse_qs(A._env("QUERY_STRING", "") or "").get(name)
    return vals[0] if vals else None


def _gate():
    if not A._module_on("detections"):
        A.respond(404, {"error": "Not found", "module_disabled": "detections"})


# ── what the sweep reads ─────────────────────────────────────────────────────


def _events_by_host(now):
    """{device_id: [event]} from the fleet event log: the events the rules read, of the last EVENT_LOOKBACK_S seconds. Read-only (the list belongs to the shared cache)."""
    try:
        store = (A._load_ro(A.FLEET_EVENTS_FILE) or {}) if A.backend_exists(A.FLEET_EVENTS_FILE) else {}
    except Exception:
        return {}
    events = store.get("events") if isinstance(store, dict) else None
    out = {}
    cutoff = now - D.EVENT_LOOKBACK_S
    for e in events if isinstance(events, list) else []:
        if not isinstance(e, dict) or e.get("event") not in D.EVENT_NAMES:
            continue
        ts, payload = e.get("ts"), e.get("payload")
        if isinstance(ts, bool) or not isinstance(ts, int) or ts < cutoff or not isinstance(payload, dict):
            continue
        dev_id = payload.get("device_id")
        if isinstance(dev_id, str) and dev_id:
            out.setdefault(dev_id, []).append({"event": e["event"], "ts": ts, "payload": payload})
    return out


def _intel_map():
    """{ip: {score, last}} from the Threat Intel store, once for the whole sweep: the reputation score a lookup stored, and the last time the address attacked a host here or
    the edge (the Cloudflare firewall events and the honeypot). Read-only; never raises."""
    try:
        st = (A._load_ro(A.IPINTEL_FILE) or {}) if A.backend_exists(A.IPINTEL_FILE) else {}
        atts = st.get("attackers") if isinstance(st.get("attackers"), dict) else {}
    except Exception:
        return {}
    out = {}
    for ip, a in atts.items():
        if not isinstance(ip, str) or not isinstance(a, dict):
            continue
        v = a.get("verdict")
        score = v.get("score") if isinstance(v, dict) else None
        if isinstance(score, bool) or not isinstance(score, (int, float)) or score != score:
            score = None
        last = None
        devices = a.get("devices")
        for seen in devices.values() if isinstance(devices, dict) else ():
            at = seen.get("at") if isinstance(seen, dict) else None
            if isinstance(at, int) and not isinstance(at, bool) and (last is None or at > last):
                last = at
        if score is not None or last is not None:
            out[ip] = {"score": score, "last": last}
    return out


# ── the sweep ────────────────────────────────────────────────────────────────


def _collect(cfg, now):
    """{device_id: (name, monitored, [finding])} for every host an agent reports for, from the rules in `cfg` and the stores as they are now."""
    rules = D.settings(cfg.get("detections"))
    if not any(r["enabled"] for r in rules.values()):
        return {}
    devices = A._load_ro(A.DEVICES_FILE) or {}
    th = A.traffic_handlers_mod
    traffic_on = A._module_on("traffic")
    store = (A._load_ro(A.TRAFFIC_FILE) or {}) if traffic_on and A.backend_exists(A.TRAFFIC_FILE) else {}
    every = th.sampling_every(cfg)
    events, intel = _events_by_host(now), _intel_map()
    out, failed = {}, {}
    for dev_id, dev in devices.items():
        if not isinstance(dev_id, str) or not isinstance(dev, dict) or dev.get("agentless") or dev.get("decommissioned"):
            continue
        try:
            rec = store.get(dev_id) if isinstance(store.get(dev_id), dict) else None
            rows = T.stored_rows(rec["sample"]) if rec is not None and th._state(dev, rec, now, every) == "reporting" else []
            name = dev.get("name") or dev_id
            ctx = {"host": {"id": dev_id, "name": name}, "now": now, "rec": rec, "rows": rows, "events": events.get(dev_id, []), "intel": intel}
            errors = []
            out[dev_id] = (name, bool(dev.get("monitored", True)), D.evaluate(ctx, rules, errors))
            for rid, why in errors:
                failed.setdefault(rid, [0, why])[0] += 1
        except Exception as e:
            sys.stderr.write(f"[remotepower] detections failed dev={dev_id}: {type(e).__name__}: {e}\n")
    for rid, (n, why) in failed.items():
        sys.stderr.write(f"[remotepower] detections: the rule {rid} failed on {n} host{'s' if n != 1 else ''} ({why}); the other rules ran\n")
    return out


def _apply(old, results, now):
    """(the store after this sweep, [(device_id, name, finding)] to raise). A host with nothing found and nothing remembered has no record, and a host that is no longer in
    `results` (deleted, decommissioned, no agent) loses its record. An unmonitored host's findings are kept and shown, and not raised: its alerts are silent by design."""
    new, fire, due = {}, [], {}
    for dev_id, (name, monitored, found) in results.items():
        prev = old.get(dev_id) if isinstance(old, dict) and isinstance(old.get(dev_id), dict) else {}
        alerted = prev.get("alerted") if isinstance(prev.get("alerted"), dict) else {}
        due[dev_id] = [f for f in found if D.is_due(alerted, f, now)][: D.MAX_PER_HOST] if monitored else []
    # the sweep raises at most RAISE_MAX alerts for the whole fleet, the worst first: what it holds back stays due and the next sweep raises it
    worst = sorted((D.RANK.get(f["severity"], 9), dev_id, f["key"]) for dev_id, fs in due.items() for f in fs)[:RAISE_MAX]
    allowed = {(dev_id, key) for _rank, dev_id, key in worst}
    for dev_id, (name, _monitored, found) in results.items():
        prev = old.get(dev_id) if isinstance(old, dict) and isinstance(old.get(dev_id), dict) else {}
        alerted = prev.get("alerted") if isinstance(prev.get("alerted"), dict) else {}
        raise_ = [f for f in due[dev_id] if (dev_id, f["key"]) in allowed]
        alerted = D.remember(alerted, raise_, now)
        shown = [D.compact(f) for f in found[: D.MAX_PER_HOST]]
        if shown or alerted:
            new[dev_id] = {"found": shown, "alerted": alerted}
        fire.extend((dev_id, name, f) for f in raise_)
    return new, fire


def _raise(dev_id, name, f):
    """One `detection_found` event. The payload carries the rule, the severity the rule found, the sentence and, when the finding has them, the address, port and program;
    the alert is told apart by (host, rule, address, port, program)."""
    payload = {"name": name, "device_id": dev_id, "rule": f["rule"], "severity": f["severity"], "detail": f["detail"]}
    for k in ("ip", "port", "process"):
        if f.get(k) not in (None, ""):
            payload[k] = f[k]
    try:
        A.fire_webhook("detection_found", payload)
    except Exception as e:
        sys.stderr.write(f"[remotepower] detection alert failed dev={dev_id}: {type(e).__name__}: {e}\n")


def run_detections_if_due():
    """Cadence sweep: every EVERY_S seconds, run the enabled rules over every host and raise what is new. Cheap when the module is off or it is not due: one config read.

    The alerts go out only after the store that remembers them has been saved. If the save cannot be made (the lock is busy), nothing is sent and the next sweep finds the same
    findings and tries again, so a finding is never sent twice for one that was not kept."""
    if not A._module_on("detections"):
        return
    cfg = A._config_ro()
    now = int(time.time())
    last = cfg.get("last_detections_run")
    if isinstance(last, (int, float)) and not isinstance(last, bool) and 0 <= now - last < EVERY_S:
        return
    A._claim_cadence_slot("last_detections_run", now)
    results = _collect(cfg, now)
    old = (A._load_ro(A.DETECTIONS_FILE) or {}) if A.backend_exists(A.DETECTIONS_FILE) else {}
    new, fire = _apply(old, results, now)
    if not fire and new == old:
        return                                    # nothing changed: no write
    with A._LockedUpdate(A.DETECTIONS_FILE) as store:
        new, fire = _apply(store, results, now)   # again from what is stored now, so two sweeps that overlap raise a finding once
        for dev_id in [k for k in store if k not in new]:
            store.pop(dev_id)
        for dev_id, rec in new.items():
            if store.get(dev_id) != rec:
                store[dev_id] = rec
    for dev_id, name, f in fire:
        _raise(dev_id, name, f)


# ── the Data Explorer and the host's own page ────────────────────────────────


def _visible_findings(devices, store, host=None):
    """[(host id, host record, finding, alerted map)] for the findings of the hosts in `devices` (already the caller's), the worst first. `host` narrows it to one host."""
    out = []
    for dev_id, dev in devices.items():
        rec = store.get(dev_id) if isinstance(dev, dict) and isinstance(store, dict) and isinstance(store.get(dev_id), dict) else None
        if rec is None or not isinstance(rec.get("found"), list) or (host is not None and dev_id != host):
            continue
        alerted = rec.get("alerted") if isinstance(rec.get("alerted"), dict) else {}
        out.extend((dev_id, dev, f, alerted) for f in rec["found"] if isinstance(f, dict) and f.get("rule") in D.RULES)
    out.sort(key=lambda t: (D.RANK.get(t[2].get("severity"), 9), str(t[1].get("name") or t[0]).lower(), str(t[2].get("rule"))))
    return out


def explorer_rows(devices, store):
    """Data Explorer `detections` (8.0.0): one row for each finding of the last sweep, for the hosts given. The hosts are already the caller's and the module gate is the
    caller's too. The rule is given by its id and by its title, and `raised_at` is empty for a finding that was held back or never raised."""
    out = []
    for dev_id, dev, f, alerted in _visible_findings(devices, store):
        at = alerted.get(f.get("key"))
        out.append(
            {
                "device_id": dev_id,
                "device_name": dev.get("name") or dev_id,
                "rule": f.get("rule"),
                "rule_title": D.RULES[f["rule"]]["title"],
                "severity": f.get("severity") or "",
                "detail": str(f.get("detail") or ""),
                "address": f.get("ip") or "",
                "port": f.get("port") if isinstance(f.get("port"), int) and not isinstance(f.get("port"), bool) else None,
                "program": f.get("process") or "",
                "raised_at": at if isinstance(at, int) and not isinstance(at, bool) else None,
                "monitored": bool(dev.get("monitored", True)),
            }
        )
    return out


def hosts_detected(devices, store, needle):
    """Ids of the hosts of `devices` that have a finding whose rule id or title, sentence, address or program contains `needle`, in any case: the Fleet Query `detected`
    criterion (8.0.0). Empty for an empty needle."""
    needle = str(needle or "").strip().lower()
    out = set()
    if not needle:
        return out
    for dev_id, _dev, f, _alerted in _visible_findings(devices, store):
        text = " ".join(str(x) for x in (f.get("rule"), D.RULES[f["rule"]]["title"], f.get("detail"), f.get("ip"), f.get("process"), f.get("severity")) if x)
        if needle in text.lower():
            out.add(dev_id)
    return out


# ── the page ─────────────────────────────────────────────────────────────────


def handle_detections_get():
    """GET /api/detections -- the rules with their settings, and the findings of the last sweep for the hosts the caller may see (8.0.0). Any signed-in role; the host set is
    `_scope_filter_devices`, which holds role scope and tenant. The settings are the installation's and are read-only unless the caller is the platform operator."""
    A.require_auth()
    if A.method() != "GET":
        A.respond(405, {"error": "Method not allowed"})
    _gate()
    now = int(time.time())
    cfg = A._config_ro()
    devices = A._scope_filter_devices(A._load_ro(A.DEVICES_FILE) or {})
    store = (A._load_ro(A.DETECTIONS_FILE) or {}) if A.backend_exists(A.DETECTIONS_FILE) else {}
    host = _query("host")
    findings = []
    for dev_id, dev, f, alerted in _visible_findings(devices, store, host if isinstance(host, str) and host else None):
        row = {k: v for k, v in f.items() if k != "key"}          # the key is the sweep's own name for the finding and embeds the host id: the page has no use for it
        row.update({"id": dev_id, "name": dev.get("name") or dev_id, "monitored": bool(dev.get("monitored", True))})
        at = alerted.get(f.get("key"))
        if isinstance(at, int) and not isinstance(at, bool):
            row["raised_at"] = at
        findings.append(row)
    counts = {s: sum(1 for r in findings if r.get("severity") == s) for s in D.RANK}
    last = cfg.get("last_detections_run")
    A.respond(
        200,
        {
            "now": now,
            "every": EVERY_S,
            "last_run": last if isinstance(last, int) and not isinstance(last, bool) else None,
            "rules": D.catalog(cfg.get("detections")),
            "findings": findings[:FINDINGS_MAX],
            "total": len(findings),
            "counts": counts,
            "traffic": A._module_on("traffic"),
            "editable": _is_operator(),
        },
    )


def handle_detections_rules_set():
    """POST /api/detections/rules {rules: {<rule id>: {enabled?, <parameter>?}}} -- switch rules on or off and set their limits (8.0.0). The platform operator's, since the rules
    are the installation's. A rule or setting that is not in the body is left as it is. A body with one unknown rule, an unknown setting or a value out of range is refused
    whole, naming the first."""
    actor = A.require_admin_auth()
    if A.method() != "POST":
        A.respond(405, {"error": "Method not allowed"})
    _gate()
    body = A._read_valid(A.request_models.DetectionsRulesRequest)
    A._require_platform_operator("The detection rules")
    update, err = D.clean_update(body.get("rules"))
    if err:
        A.respond(400, {"error": err})
    with A._LockedUpdate(A.CONFIG_FILE) as cfg:
        cfg["detections"] = D.merged(cfg.get("detections"), update)
    A.audit_log(actor, "detections_rules_set", "rules=%s" % ",".join(sorted(update)))
    A.respond(200, {"ok": True, "rules": D.catalog(A._config_ro().get("detections"))})
