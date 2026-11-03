"""RemotePower — Business services: groups of hosts, monitors, units, containers and scripts with a rule

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
sibling module (imported directly, like dmarc_monitor / tls_monitor).
"""

import bizsvc
import nagios_result


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


# ── handlers ─────────────────────────────────────────────────────────────────
# The part of a service each caller may see: a service that holds a host the caller cannot see is hidden from them,
# the way a script assigned to such a host is. The whole feature belongs to the organisation that runs the
# installation (its routes are in _OPERATOR_ORG_ROUTES), so under tenancy this narrows only by role scope.

_STATE_WORD = {"warning": "degraded", "critical": "down"}
SWEEP_EVERY_S = 60
HISTORY_KEEP = 200
AVAILABILITY_WINDOW_S = 30 * 86400


def _now():
    return int(A.time.time())


def _definitions():
    """The stored definitions that can be read: {id: record}."""
    raw = A.load(A.BUSINESS_SERVICES_FILE) or {}
    return {sid: rec for sid, rec in raw.items() if isinstance(sid, str) and isinstance(rec, dict)}


def _members_of(rec):
    return bizsvc.clean_members(rec.get("members"))


def _context(defs):
    """Everything a state is read from, loaded once. Hosts, monitors, units, containers and scripts all live in
    stores the product already keeps up to date; nothing here asks a host anything."""
    return {
        "now": _now(),
        "ttl": A.get_online_ttl(),
        "devices": A._load_ro(A.DEVICES_FILE) or {},
        "monitors": A._load_ro(A.MON_HIST_FILE) or {},
        "units": A._load_ro(A.SERVICES_FILE) or {},
        "containers": A._load_ro(A.CONTAINERS_FILE) or {},
        "scripts": A._load_custom_scripts(),
        "defs": defs,
    }


def _host_name(ctx, dev_id):
    d = ctx["devices"].get(dev_id)
    return (d.get("name") if isinstance(d, dict) else None) or dev_id


def _online(ctx, dev):
    try:
        return ctx["now"] - int(dev.get("last_seen") or 0) < ctx["ttl"]
    except (TypeError, ValueError, OverflowError):
        return False


def _part(m, ctx):
    """(state, label, reason) for one part that is not a service."""
    kind = m["kind"]
    if kind == bizsvc.KIND_MONITOR:
        hist = ctx["monitors"].get(m["label"])
        last = hist[-1] if isinstance(hist, list) and hist and isinstance(hist[-1], dict) else None
        if last is None:
            return "unknown", m["label"], "no result yet"
        up = last.get("up") if "up" in last else last.get("ok")
        return ("ok", m["label"], "up") if up is not False else ("critical", m["label"], "down")
    dev_id = m["device_id"]
    dev = ctx["devices"].get(dev_id)
    host = _host_name(ctx, dev_id)
    if not isinstance(dev, dict):
        return "unknown", host, "host not found"
    online = _online(ctx, dev)
    if kind == bizsvc.KIND_HOST:
        return ("ok", host, "online") if online else ("critical", host, "offline")
    # Everything below runs on the host: what a host that is not reporting last said is out of date
    if kind == bizsvc.KIND_UNIT:
        label = f"{m['unit']} on {host}"
        if not online:
            return "critical", label, "host offline"
        rec = ctx["units"].get(dev_id)
        for u in (rec.get("services") if isinstance(rec, dict) else None) or []:
            if isinstance(u, dict) and u.get("unit") == m["unit"]:
                active = str(u.get("active") or "")
                if active == "active":
                    return "ok", label, "active"
                return "critical", label, (active + (f"/{u.get('sub')}" if u.get("sub") else "")) or "not active"
        return "unknown", label, "not watched or not reported"
    if kind == bizsvc.KIND_CONTAINER:
        label = f"{m['name']} on {host}"
        if not online:
            return "critical", label, "host offline"
        rec = ctx["containers"].get(dev_id)
        items = rec.get("items") if isinstance(rec, dict) else None
        if not isinstance(items, list):
            return "unknown", label, "no container report"
        for c in items:
            if isinstance(c, dict) and c.get("name") == m["name"]:
                if not A._container_is_running(c.get("status")):
                    return "critical", label, "not running"
                if c.get("health") == "unhealthy":
                    return "warning", label, "unhealthy"
                return "ok", label, "running"
        return "critical", label, "not running"
    # a script
    sdef = ctx["scripts"].get(m["script_id"])
    label = f"{(sdef or {}).get('name') or m['script_id']} on {host}"
    res = (dev.get("custom_script_results") or {}).get(m["script_id"])
    if not isinstance(res, dict):
        return "unknown", label, "no result yet"
    st = nagios_result.stored_state(res)
    return st, label, str(res.get("status_text") or ("passed" if st == "ok" else st))[:120]


def _evaluate_all(defs, ctx):
    """{id: (state, [member rows])} for every definition, parts that are services read recursively. A service that
    contains itself, or sits more than MAX_DEPTH levels down, is unknown rather than an endless loop."""
    memo = {}

    def run(sid, stack):
        if sid in memo:
            return memo[sid]
        rec = defs.get(sid)
        if rec is None or sid in stack or len(stack) >= bizsvc.MAX_DEPTH:
            return "unknown", []
        rows = []
        for m in _members_of(rec):
            if m["kind"] == bizsvc.KIND_SERVICE:
                inner = defs.get(m["service_id"])
                st, _ = run(m["service_id"], stack + (sid,))
                row = {
                    "kind": m["kind"],
                    "key": bizsvc.member_key(m),
                    "service_id": m["service_id"],
                    "label": (inner or {}).get("name") or m["service_id"],
                    "state": st,
                    "reason": "service" if inner else "service not found",
                }
            else:
                st, label, reason = _part(m, ctx)
                row = dict(m, key=bizsvc.member_key(m), label=label, state=st, reason=reason)
            rows.append(row)
        result = (bizsvc.evaluate(rec.get("rule"), [r["state"] for r in rows]), rows)
        memo[sid] = result
        return result

    return {sid: run(sid, ()) for sid in defs}


def _visible_ids(defs):
    """The ids of the services the caller may see: every host a service holds, directly or through a service inside
    it, has to be one the caller can see. A host that no longer exists is nobody's secret, and a service that still
    names it has to stay in reach so that someone can take the name out."""
    everyone = A.load(A.DEVICES_FILE) or {}
    hosts = set(A._scope_filter_devices(everyone))
    hidden = set(everyone) - hosts
    memo = {}

    def ok(sid, stack):
        if sid in memo:
            return memo[sid]
        rec = defs.get(sid)
        if rec is None or sid in stack:
            return False
        good = True
        for m in _members_of(rec):
            if m.get('device_id') in hidden:
                good = False
            elif m['kind'] == bizsvc.KIND_SERVICE and m['service_id'] in defs and not ok(m['service_id'], stack + (sid,)):
                good = False
        memo[sid] = good
        return good

    return {sid for sid in defs if ok(sid, ())}


def _view(sid, rec, evaluated, stored, hist, now, detail=False):
    state, rows = evaluated
    good = sum(1 for r in rows if r["state"] == "ok")
    kept = stored.get(sid) if isinstance(stored.get(sid), dict) else {}
    transitions = hist.get(sid) if isinstance(hist.get(sid), list) else []
    out = {
        "id": sid,
        "name": str(rec.get("name") or sid),
        "description": str(rec.get("description") or ""),
        "rule": bizsvc.clean_rule(rec.get("rule")),
        "state": state,
        "confirmed_state": kept.get("state") if kept.get("state") in bizsvc.RANK else None,
        "since": kept.get("since") if isinstance(kept.get("since"), int) else None,
        "parts": len(rows),
        "parts_ok": good,
        "members": rows,
        "availability_30d": bizsvc.availability(transitions, now, AVAILABILITY_WINDOW_S, state),
        "updated_at": rec.get("updated_at") if isinstance(rec.get("updated_at"), int) else None,
    }
    if detail:
        out["history"] = [t for t in transitions[-30:] if isinstance(t, dict)][::-1]
    return out


def _clean_body(body, defs, sid=None):
    """(fields, error): the fields of a definition from a request body, or the reason it cannot be saved."""
    name = A._sanitize_str(str(body.get("name") or ""), bizsvc.MAX_NAME).strip()
    if not name:
        return None, "name required"
    for other_id, other in defs.items():
        if other_id != sid and str(other.get("name") or "").strip().lower() == name.lower():
            return None, "a service with that name exists"
    members = bizsvc.clean_members(body.get("members"))
    if not members:
        return None, "a service needs at least one part"
    rule = bizsvc.clean_rule(body.get("rule"))
    if rule["type"] == bizsvc.RULE_MIN and rule["min"] > len(members):
        return None, "the number of parts that have to be up is more than the parts"
    hosts = set(A._scope_filter_devices(A.load(A.DEVICES_FILE) or {}))
    monitors = {str(m.get("label")) for m in (A._config_ro().get("monitors") or []) if isinstance(m, dict)}
    scripts = A._load_custom_scripts()
    for m in members:
        if m.get("device_id") and m["device_id"] not in hosts:
            return None, "unknown host"
        if m["kind"] == bizsvc.KIND_MONITOR and m["label"] not in monitors:
            return None, "unknown monitor"
        if m["kind"] == bizsvc.KIND_SCRIPT and m["script_id"] not in scripts:
            return None, "unknown script"
        if m["kind"] == bizsvc.KIND_SERVICE and m["service_id"] not in defs:
            return None, "unknown service"
        if m["kind"] == bizsvc.KIND_SERVICE and m["service_id"] == sid:
            return None, "a service cannot contain itself"
    trial = {k: _members_of(v) for k, v in defs.items()}
    trial[sid or "_new"] = members
    cycle = bizsvc.find_cycle(trial)
    if cycle:
        return None, "services contain each other"
    if bizsvc.depth(trial, sid or "_new") > bizsvc.MAX_DEPTH:
        return None, "services are nested too deep"
    return {
        "name": name,
        "description": A._sanitize_str(str(body.get("description") or ""), bizsvc.MAX_DESC),
        "rule": rule,
        "members": members,
    }, None


def handle_business_services():
    """GET /api/business-services — every service the caller can see, with the live state of each part.
    POST — create one (administrators)."""
    if A.method() == "POST":
        actor = A.require_admin_auth()
        body = A._read_valid(A.request_models.BusinessServiceRequest)
        defs = _definitions()
        if len(defs) >= bizsvc.MAX_SERVICES:
            A.respond(400, {"error": "the limit of services is reached"})
        fields, err = _clean_body(body, defs)
        if err:
            A.respond(409 if "exists" in err else 400, {"error": err})
        sid = "bs_" + A.secrets.token_hex(5)
        now = _now()
        rec = dict(fields, id=sid, created_at=now, updated_at=now, created_by=actor)
        with A._LockedUpdate(A.BUSINESS_SERVICES_FILE) as store:
            store[sid] = rec
        A.audit_log(actor, "business_service_create", f'id={sid} name={fields["name"]}')
        defs[sid] = rec
        ev = _evaluate_all(defs, _context(defs))
        A.respond(201, _view(sid, rec, ev[sid], {}, {}, _now(), detail=True))
    if A.method() != "GET":
        A.respond(405, {"error": "Method not allowed"})
    A.require_auth()
    defs = _definitions()
    show = _visible_ids(defs)
    ev = _evaluate_all(defs, _context(defs))
    stored = (A.load(A.BUSINESS_SERVICE_STATE_FILE) or {}).get("services")
    stored = stored if isinstance(stored, dict) else {}
    hist = A.load(A.BUSINESS_SERVICE_HIST_FILE) or {}
    now = _now()
    rows = [
        _view(sid, defs[sid], ev[sid], stored, hist, now)
        for sid in sorted(show, key=lambda k: str(defs[k].get("name") or k).lower())
    ]
    counts = {s: sum(1 for r in rows if r["state"] == s) for s in bizsvc.STATES}
    A.respond(200, {"services": rows, "counts": counts, "limit": bizsvc.MAX_SERVICES})


def handle_business_service(sid):
    """GET /api/business-services/<id> — one service with its history. PUT — change it. DELETE — remove it (a service
    that another service holds has to be taken out of that one first)."""
    sid = A._sanitize_str(sid, 32)
    meth = A.method()
    if meth not in ("GET", "PUT", "DELETE"):
        A.respond(405, {"error": "Method not allowed"})
    actor = A.require_auth() if meth == "GET" else A.require_admin_auth()
    defs = _definitions()
    if sid not in defs or sid not in _visible_ids(defs):
        A.respond(404, {"error": "service not found"})
    if meth == "GET":
        ev = _evaluate_all(defs, _context(defs))
        stored = (A.load(A.BUSINESS_SERVICE_STATE_FILE) or {}).get("services")
        A.respond(
            200,
            _view(
                sid,
                defs[sid],
                ev[sid],
                stored if isinstance(stored, dict) else {},
                A.load(A.BUSINESS_SERVICE_HIST_FILE) or {},
                _now(),
                detail=True,
            ),
        )
    if meth == "PUT":
        body = A._read_valid(A.request_models.BusinessServiceRequest)
        fields, err = _clean_body(body, defs, sid)
        if err:
            A.respond(409 if "exists" in err else 400, {"error": err})
        with A._LockedUpdate(A.BUSINESS_SERVICES_FILE) as store:
            rec = store.get(sid)
            if not isinstance(rec, dict):
                A.respond(404, {"error": "service not found"})
            rec.update(fields)
            rec["updated_at"] = _now()
            defs[sid] = rec
        A.audit_log(actor, "business_service_update", f'id={sid} name={fields["name"]}')
        ev = _evaluate_all(defs, _context(defs))
        stored = (A.load(A.BUSINESS_SERVICE_STATE_FILE) or {}).get("services")
        A.respond(
            200,
            _view(
                sid,
                defs[sid],
                ev[sid],
                stored if isinstance(stored, dict) else {},
                A.load(A.BUSINESS_SERVICE_HIST_FILE) or {},
                _now(),
                detail=True,
            ),
        )
    # DELETE
    holders = sorted(
        str(r.get("name") or k)
        for k, r in defs.items()
        if k != sid and any(m["kind"] == bizsvc.KIND_SERVICE and m["service_id"] == sid for m in _members_of(r))
    )
    if holders:
        A.respond(409, {"error": "in use by: " + ", ".join(holders[:5])})
    name = str(defs[sid].get("name") or sid)
    with A._LockedUpdate(A.BUSINESS_SERVICES_FILE) as store:
        store.pop(sid, None)
    with A._LockedUpdate(A.BUSINESS_SERVICE_STATE_FILE) as st:
        (st.get("services") or {}).pop(sid, None)
    with A._LockedUpdate(A.BUSINESS_SERVICE_HIST_FILE) as h:
        h.pop(sid, None)
    _close_alerts(sid)
    A.audit_log(actor, "business_service_delete", f"id={sid} name={name}")
    A.respond(200, {"ok": True})


def handle_business_services_impact():
    """GET /api/business-services/impact?device_id=<id> — the services that depend on a host, directly or through
    a service that holds them, each with its state. For the host's page and for an alert on it."""
    A.require_auth()
    qs = A.urllib.parse.parse_qs(A._env("QUERY_STRING", ""))
    dev_id = A._sanitize_str((qs.get("device_id") or [""])[0], 64)
    if not dev_id or dev_id not in set(A._scope_filter_devices(A.load(A.DEVICES_FILE) or {})):
        A.respond(404, {"error": "host not found"})
    defs = _definitions()
    show = _visible_ids(defs)
    direct = {sid for sid, rec in defs.items() if dev_id in bizsvc.device_ids(_members_of(rec))}
    hit, grew = set(direct), True
    while grew:
        grew = False
        for sid, rec in defs.items():
            if sid not in hit and any(
                m["kind"] == bizsvc.KIND_SERVICE and m["service_id"] in hit for m in _members_of(rec)
            ):
                hit.add(sid)
                grew = True
    ev = _evaluate_all(defs, _context(defs))
    rows = [
        {"id": sid, "name": str(defs[sid].get("name") or sid), "state": ev[sid][0], "direct": sid in direct}
        for sid in sorted(hit & show, key=lambda k: str(defs[k].get("name") or k).lower())
    ]
    A.respond(200, {"device_id": dev_id, "services": rows})


# ── the sweep ────────────────────────────────────────────────────────────────
def _close_alerts(sid):
    """Resolve the open alerts of a service that has been deleted: nothing will ever send the recovery."""
    try:
        with A._LockedUpdate(A.ALERTS_FILE) as store:
            now = _now()
            for a in store.get("alerts", []):
                if (
                    isinstance(a, dict)
                    and a.get("event") == "business_service_down"
                    and not a.get("resolved_at")
                    and (a.get("payload") or {}).get("service_id") == sid
                ):
                    a["resolved_at"] = now
                    a["resolved_by"] = "service-deleted"
    except Exception:  # noqa: BLE001 — a failed cleanup must not fail the delete
        pass


def _detail_text(rows):
    bad = [r for r in rows if r["state"] != "ok"]
    return "; ".join(f"{r['label']} ({r['reason']})" for r in bad[:6]) + (
        f" (+{len(bad) - 6} more)" if len(bad) > 6 else ""
    )


def run_business_services_if_due():
    """Read every service's state about once a minute, keep the history of its changes, and tell people when a service
    goes down, gets better or worse, or comes back. A change has to hold for two reads before anyone is told, so one
    missed report does not page. A service whose parts report nothing (unknown) changes no one's mind: what was last
    known stays the state of record until something definite replaces it."""
    defs = _definitions()
    now = _now()
    state_doc = A.load(A.BUSINESS_SERVICE_STATE_FILE) or {}
    last = state_doc.get("last_run")
    if isinstance(last, (int, float)) and now - last < SWEEP_EVERY_S:
        return
    if not defs and not (state_doc.get("services") or {}):
        return
    ev = _evaluate_all(defs, _context(defs))
    to_fire = []
    with A._LockedUpdate(A.BUSINESS_SERVICE_STATE_FILE) as doc:
        doc["last_run"] = now
        kept = doc.setdefault("services", {})
        if not isinstance(kept, dict):
            kept = doc["services"] = {}
        for sid in [k for k in kept if k not in defs]:
            kept.pop(sid, None)
        history = []
        for sid, (state, rows) in ev.items():
            cur = kept.get(sid) if isinstance(kept.get(sid), dict) else None
            if cur is None:
                kept[sid] = {
                    "state": state,
                    "since": now,
                    "alerted": state if state in ("ok", "warning", "critical") else "",
                    "pending": None,
                }
                history.append((sid, state))
                if state in ("warning", "critical"):
                    to_fire.append((sid, state, rows))
                continue
            if state == cur.get("state"):
                cur["pending"] = None
                continue
            pend = cur.get("pending") if isinstance(cur.get("pending"), dict) else None
            if not pend or pend.get("state") != state:
                cur["pending"] = {"state": state, "n": 1}
                continue
            # second read in a row: the change is real
            cur["state"], cur["since"], cur["pending"] = state, now, None
            history.append((sid, state))
            if state in ("ok", "warning", "critical") and state != cur.get("alerted"):
                was = cur.get("alerted")
                cur["alerted"] = state
                if state == "ok":
                    if was in ("warning", "critical"):
                        to_fire.append((sid, "ok", rows))
                else:
                    to_fire.append((sid, state, rows))
    if history:
        with A._LockedUpdate(A.BUSINESS_SERVICE_HIST_FILE) as h:
            for sid, state in history:
                lst = h.setdefault(sid, [])
                if isinstance(lst, list):
                    lst.append({"ts": now, "state": state})
                    del lst[:-HISTORY_KEEP]
            for sid in [k for k in h if k not in defs]:
                h.pop(sid, None)
    for sid, state, rows in to_fire:
        name = str(defs[sid].get("name") or sid)
        if state == "ok":
            A.fire_webhook("business_service_up", {"service_id": sid, "service_name": name, "name": name})
        else:
            A.fire_webhook(
                "business_service_down",
                {
                    "service_id": sid,
                    "service_name": name,
                    "name": name,
                    "state": state,
                    "detail": _detail_text(rows),
                    "parts_ok": sum(1 for r in rows if r["state"] == "ok"),
                    "parts": len(rows),
                },
            )
