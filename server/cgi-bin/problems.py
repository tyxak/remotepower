"""RemotePower - one list of problems (#56).

Alerts, Needs attention and Checks each say what is wrong with a host, by their own rules. One problem can sit in
all three, and closing it in one does not close it in the others: an alert you resolved can sit beside a Needs
attention item for what the host still reports. This module joins the three on one key and says where each problem
stands.

It is a read model. It stores nothing, changes nothing and holds no policy of its own about severities or wording:
the caller hands in the three lists and the few maps that join them, so nothing in here imports api.

THE KEY is (host, kind of problem). Needs attention and Checks carry no finer key than that: a Needs attention item
names its resources only in prose. So the model is honest at that level and no finer. A host with two failed units is
one row, with both alerts and the one Needs attention item listed under it, and its state is judged for the host and
the kind together. A fleet-level problem (no host) is keyed by what tells its alerts apart (a certificate, an
integration) or by the text of its Needs attention item.

THE KIND is the Needs attention kind. An alert belongs to the kind whose events include its event (the same map that
decides which Needs attention item a mute silences), a metric alert to the kind named by its `metric`, and a check
to the kind in `check_family`. Anything the maps do not reach still gets a row, of its own kind: `alert:<event>`,
`check:<id>` or the Needs attention kind itself, so no problem is hidden by a gap in a map.
"""

from typing import Any

FAILING = "failing"  # an alert is open, or the host reports it and no alert is
HOST_CLEAR = "host_clear"  # an alert is open and the host's last report no longer shows the problem
RESOLVED_BUT_FAILING = "resolved_but_failing"  # resolved by hand, and the host still reports it
WAITING = "waiting_for_report"  # resolved by hand, and the host has not reported since
RESOLVED = "resolved"  # resolved, and the host does not report it
RECOVERED = "recovered"  # closed by a recovery event

STATES = (FAILING, HOST_CLEAR, WAITING, RESOLVED_BUT_FAILING, RESOLVED, RECOVERED)
ACTIVE = frozenset((FAILING, HOST_CLEAR, WAITING, RESOLVED_BUT_FAILING))

# What alerts record in `resolved_by` when no person closed them. Anything else is a user name, or an address
# of the ticket system (`itsm:<ref>`), and counts as closed by hand.
SYSTEM_RESOLVERS = frozenset(
    (
        "auto",
        "exposure-mute",
        "muted",
        "device-removed",
        "check-deleted",
        "script-deleted",
        "secrets-host-mute",
    )
)

# One scale for the three vocabularies: alerts say critical/high/medium/low, Needs attention says
# critical/warning/info, Checks say critical/warning.
SEVERITY_RANK = {"critical": 4, "high": 3, "warning": 2, "medium": 2, "info": 1, "low": 1}

METRIC_EVENTS = frozenset(("metric_warning", "metric_critical", "metric_recovered"))
# The Needs attention kind of a metric whose own name is not it.
METRIC_KIND = {"diskio": "disk"}

HISTORY_PER_PROBLEM = 5
# Every open alert of a problem can be closed from its row, however many are listed under it.
OPEN_IDS_PER_PROBLEM = 200


def _num(value: Any) -> int:
    """A stored timestamp as an int; anything else (a hand-edited store) is 0."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0
    try:
        return int(value)
    except (OverflowError, ValueError):
        return 0


def _text(value: Any, limit: int = 200) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _rank(label: Any) -> int:
    return SEVERITY_RANK.get(str(label).lower(), 0)


def resolved_by_hand(alert: dict[str, Any]) -> bool:
    """Did a person close this alert? A recovery event, a mute and the removal of the host do not count."""
    by = alert.get("resolved_by")
    if not alert.get("resolved_at") or not isinstance(by, str) or not by:
        return False
    return by not in SYSTEM_RESOLVERS


def resolution_how(alert: dict[str, Any]) -> str:
    """open | hand | auto | system"""
    if not alert.get("resolved_at"):
        return "open"
    if resolved_by_hand(alert):
        return "hand"
    return "auto" if alert.get("resolved_by") == "auto" else "system"


def alert_family(alert: dict[str, Any], kind_of_event: dict[str, str]) -> str:
    """The kind of problem an alert belongs to."""
    event = _text(alert.get("event"), 64)
    payload = alert.get("payload")
    if event in METRIC_EVENTS and isinstance(payload, dict):
        metric = _text(payload.get("metric"), 64)
        if metric:
            return METRIC_KIND.get(metric, metric)
    return kind_of_event.get(event) or "alert:" + event


def discriminator(alert: dict[str, Any], identity_fields: tuple[str, ...]) -> str:
    """What tells this alert from the other alerts of the same event on the same host: the fields the alert store
    itself coalesces on (a unit, a mount, a metric, a port). Empty when the alert has none."""
    payload = alert.get("payload")
    if not isinstance(payload, dict):
        return ""
    parts = [f"{k}={payload[k]}" for k in identity_fields if payload.get(k) not in (None, "")]
    return ";".join(parts)[:200]


def _alert_entry(alert: dict[str, Any], identity_fields: tuple[str, ...]) -> dict[str, Any]:
    how = resolution_how(alert)
    if how == "open":
        status = "acknowledged" if alert.get("acknowledged_at") else "open"
    else:
        status = "resolved"
    return {
        "id": _text(alert.get("id"), 64),
        "alertid": _text(alert.get("alertid"), 32),
        "event": _text(alert.get("event"), 64),
        "title": _text(alert.get("title"), 256),
        "severity": _text(alert.get("severity"), 16),
        "status": status,
        "how": how,
        "detail": discriminator(alert, identity_fields),
        "first_seen": _num(alert.get("first_seen")) or _num(alert.get("ts")),
        "ts": _num(alert.get("ts")),
        "count": _num(alert.get("count")) or 1,
        "acknowledged_by": _text(alert.get("acknowledged_by"), 64),
        "resolved_at": _num(alert.get("resolved_at")),
        "resolved_by": _text(alert.get("resolved_by"), 64),
        "note": _text(alert.get("resolve_note"), 256),
    }


def _state(
    open_alerts: list[dict[str, Any]],
    resolved: list[dict[str, Any]],
    has_evidence: bool,
    mapped: bool,
    last_report: int,
) -> str:
    """Where one problem stands.

    `mapped` is whether Needs attention or Checks could show this kind of problem at all. For an alert whose kind
    neither can show, "the host no longer reports it" is not a thing anyone can know, so such an alert stays failing
    until it is closed."""
    if open_alerts:
        return FAILING if (has_evidence or not mapped) else HOST_CLEAR
    if not resolved:
        return FAILING
    newest = max(resolved, key=lambda e: e["resolved_at"])
    if newest["how"] == "hand":
        if not has_evidence:
            return RESOLVED
        if last_report and last_report < newest["resolved_at"]:
            return WAITING
        return RESOLVED_BUT_FAILING
    if has_evidence:
        return FAILING  # a recovery event closed it and the host still reports it
    return RECOVERED if newest["how"] == "auto" else RESOLVED


def build(
    *,
    alerts: list[Any],
    attention: list[Any],
    checks: list[Any],
    kind_of_event: dict[str, str],
    check_family: dict[str, str],
    shown_kinds: frozenset[str],
    identity_fields: tuple[str, ...],
    reports: dict[str, int],
    now: int,
    window_s: int,
) -> list[dict[str, Any]]:
    """The problems, newest trouble first.

    alerts      alert records the caller may see. Open ones always count; a resolved one only when it closed within
                `window_s`, so the list is the present and the recent past, not the whole ledger.
    attention   Needs attention items: {kind, severity, summary, device_id, device}
    checks      failing checks only: {device_id, device, id, name, status, output}
    shown_kinds the kinds Needs attention or Checks can show for a host, whether or not they show one now. An
                open alert of any other kind cannot be told from one the host has stopped reporting
    reports     {host: time of its last report}, to tell "still failing" from "has not reported since"
    """
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}

    def group(dev: str, family: str, sub: str, name: str) -> dict[str, Any]:
        g = groups.setdefault(
            (dev, family, sub),
            {
                "device_id": dev,
                "device": name,
                "family": family,
                "alerts": [],
                "attention": [],
                "checks": [],
            },
        )
        if name and not g["device"]:
            g["device"] = name
        return g

    cutoff = now - window_s
    for a in alerts:
        if not isinstance(a, dict):
            continue
        resolved_at = _num(a.get("resolved_at"))
        if resolved_at and resolved_at < cutoff:
            continue
        dev = _text(a.get("device_id"), 64)
        family = alert_family(a, kind_of_event)
        # A host's alerts of one kind are one problem. Without a host, what tells alerts apart is the problem.
        sub = "" if dev else discriminator(a, identity_fields)
        group(dev, family, sub, _text(a.get("device_name"), 128))["alerts"].append(a)

    def evidence_group(dev: str, family: str, name: str, text: str) -> dict[str, Any]:
        """The group a Needs attention item or a check belongs to: the host's group of that kind. A fleet-level item
        joins the fleet-level alert of its kind only when there is exactly one (a certificate, an integration);
        with several there is nothing to tell which is which, so it stands alone."""
        if dev:
            return group(dev, family, "", name)
        fleet = [k for k in groups if not k[0] and k[1] == family and groups[k]["alerts"]]
        if len(fleet) == 1:
            return groups[fleet[0]]
        return group("", family, _text(text, 120), name)

    for item in attention:
        if not isinstance(item, dict):
            continue
        dev = _text(item.get("device_id"), 64)
        kind = _text(item.get("kind"), 64) or "attention"
        evidence_group(dev, kind, _text(item.get("device"), 128), _text(item.get("summary")))[
            "attention"
        ].append(item)

    for chk in checks:
        if not isinstance(chk, dict):
            continue
        dev = _text(chk.get("device_id"), 64)
        cid = _text(chk.get("id"), 64)
        family = check_family.get(cid) or "check:" + cid
        evidence_group(dev, family, _text(chk.get("device"), 128), _text(chk.get("name")))[
            "checks"
        ].append(chk)

    rows: list[dict[str, Any]] = []
    for (dev, family, sub), g in groups.items():
        entries = [_alert_entry(a, identity_fields) for a in g["alerts"]]
        entries.sort(key=lambda e: e["ts"], reverse=True)
        open_alerts = [e for e in entries if e["status"] != "resolved"]
        resolved = [e for e in entries if e["status"] == "resolved"]
        has_evidence = bool(g["attention"] or g["checks"])
        mapped = bool(dev) and family in shown_kinds
        state = _state(
            open_alerts, resolved, has_evidence, mapped, _num(reports.get(dev)) if dev else 0
        )

        labels = [e["severity"] for e in open_alerts or entries]
        labels += [_text(i.get("severity"), 16) for i in g["attention"]]
        labels += [_text(c.get("status"), 16) for c in g["checks"]]
        severity = max(labels, key=_rank) if labels else ""

        title = (
            (entries[0]["title"] if entries else "")
            or (_text(g["attention"][0].get("summary")) if g["attention"] else "")
            or (_text(g["checks"][0].get("name")) if g["checks"] else "")
            or family
        )
        times = [e["ts"] for e in entries] + [e["resolved_at"] for e in entries]
        rows.append(
            {
                "key": f"{dev}|{family}|{sub}",
                "device_id": dev,
                "device": g["device"],
                "family": family,
                "title": title,
                "severity": severity,
                "state": state,
                "active": state in ACTIVE,
                "since": min((e["first_seen"] for e in open_alerts if e["first_seen"]), default=0),
                "updated": max(times, default=0),
                "sources": [
                    s
                    for s, on in (
                        ("alert", entries),
                        ("attention", g["attention"]),
                        ("check", g["checks"]),
                    )
                    if on
                ],
                "alerts": entries[:HISTORY_PER_PROBLEM],
                "alert_total": len(entries),
                "attention": [
                    {"severity": _text(i.get("severity"), 16), "summary": _text(i.get("summary"))}
                    for i in g["attention"]
                ],
                "checks": [
                    {
                        "id": _text(c.get("id"), 64),
                        "name": _text(c.get("name")),
                        "status": _text(c.get("status"), 16),
                    }
                    for c in g["checks"]
                ],
                "last_report": _num(reports.get(dev)) if dev else 0,
                "can_resolve": bool(open_alerts),
                "open_ids": [e["id"] for e in open_alerts if e["id"]][:OPEN_IDS_PER_PROBLEM],
            }
        )

    rows.sort(
        key=lambda r: (
            not r["active"],
            STATES.index(r["state"]),
            -_rank(r["severity"]),
            -r["updated"],
            r["device"],
            r["family"],
        )
    )
    return rows


def counts(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """How many problems are in each state, and how many came from each source."""
    by_state = {s: 0 for s in STATES}
    by_source = {"alert": 0, "attention": 0, "check": 0}
    for r in rows:
        by_state[r["state"]] += 1
        for s in r["sources"]:
            by_source[s] += 1
    return {
        "states": by_state,
        "sources": by_source,
        "active": sum(by_state[s] for s in ACTIVE),
        "total": len(rows),
    }
