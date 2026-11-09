"""RemotePower: what deleting a host removes from the stores that name it (8.0.0).

`_purge_device` used to clear the stores it knew by hand. Deleting each host of the demo instance in turn and reading every store afterwards found 66 stores that still named it
(`tests/test_v800_host_purge.py` repeats the count). Some of those stores are history and stay on purpose: an alert, a ticket, a time entry and the audit trail say what happened
and to which host. The rest were the host's own data (its CMDB record, its runbook, its trend rings, its baselines), schedules and mutes that name only that host, and its place in
groups, services, script assignments and links. Those go when the host goes.

A rule says where a host id can sit in a store and what to do about it. The rules are data, so the test can read the same table the purge runs.

  pop         a map keyed by host id: the host's entry goes
  pop_prefix  a map keyed "<host id>:<something>": every key that starts with the host goes
  pop_edge    a map keyed "<a>:<b>" (a link between two hosts): a key that names the host on either side goes
  drop        records (a list, or a map of records) whose `field` is the host, or a list that holds it, go
  unlist      a list of host ids: the host goes, the rest stays
  put         records whose `field` is the host get the values in `to` (switched off, unbound); `NOW` in a value is the time of the purge

`where` narrows a rule to records with those values. `path` walks into the store, one name for each level, and "*" stands for every value of a map or every element of a list.
Host ids are `[A-Za-z0-9_-]{1,64}`, so a ":" in a key is always the separator.

Stdlib only. Nothing here reads a store: the caller hands over the data it holds the lock on.
"""

from __future__ import annotations

from typing import Any, Iterator, NamedTuple

NOW = "@now"  # in a `to` value: the time of the purge


class Rule(NamedTuple):
    kind: str
    path: tuple[str, ...] = ()
    field: str = ""
    to: dict[str, Any] | None = None
    where: dict[str, Any] | None = None


def pop(*path: str) -> Rule:
    return Rule("pop", path)


def pop_prefix(*path: str) -> Rule:
    return Rule("pop_prefix", path)


def pop_edge(*path: str) -> Rule:
    return Rule("pop_edge", path)


def drop(*path: str, field: str, where: dict[str, Any] | None = None) -> Rule:
    return Rule("drop", path, field, None, where)


def unlist(*path: str) -> Rule:
    return Rule("unlist", path)


def put(*path: str, field: str, to: dict[str, Any], where: dict[str, Any] | None = None) -> Rule:
    return Rule("put", path, field, to, where)


# Store file name -> the rules that clear a host from it. Every store here is read by a person through the host's own page, a fleet page that lists hosts, or a sweep that
# acts on a host, so a record that names a host that is gone either cannot be reached or cannot do what it says.
RULES: dict[str, tuple[Rule, ...]] = {
    # the host's own data, kept under its id
    "acme_state.json": (pop(),),
    "cmdb.json": (
        pop(),
    ),  # the record of the host in the CMDB: its notes, documents and credentials
    "discovery.json": (pop(),),
    "disk_usage.json": (pop(),),
    "flow.json": (pop(),),
    "gpu_history.json": (pop(),),
    "health_history.json": (pop("devices"),),
    "helm.json": (pop(),),
    "image_cves.json": (pop(),),
    "ip_intel.json": (pop("blocks"), pop("attackers", "*", "devices")),
    "ip_intel_intake.json": (pop("sensors"),),
    "lldp_neighbors.json": (pop(),),
    "metrics_history.json": (pop(),),
    "patch_age.json": (pop(), unlist("_breaching")),
    "pii_findings.json": (pop(),),
    "runbooks.json": (
        pop(),
    ),  # generated for the host, listed by its page, and read by the AI index
    "scap.json": (pop(),),
    "secret_findings.json": (pop(),),
    "smart_history.json": (pop(),),
    "snmp_traps.json": (pop(),),
    "speedtest.json": (pop(),),
    "sshgw_state.json": (pop(),),
    "sudo_log.json": (pop(),),
    "thermal_history.json": (pop(),),
    "thermal_rollup.json": (pop(),),
    "backup_state.json": (pop_prefix(),),  # "<host id>:<repository>"
    "flow_deps.json": (pop_edge("edges"),),
    # what was set up to act on the host, or to be quiet about it, and means nothing without it
    "alert_mutes.json": (drop("mutes", field="device_id"),),
    "backup_jobs.json": (drop("jobs", field="device_id"),),
    "compose_stacks.json": (drop(field="device_id"),),
    "maintenance.json": (drop("windows", field="target", where={"scope": "device"}),),
    "netscan_schedules.json": (drop(field="device_id"),),
    "scan_schedules.json": (drop(field="device_id"),),
    "schedule.json": (drop("jobs", field="device_id"),),
    "tunnels.json": (drop(field="endpoints"),),  # a link needs both ends
    "fleet_events.json": (
        drop("events", field="payload.device_id"),  # how _record_fleet_event stores a host
        drop("events", field="device_id"),  # the shape the purge used to look for
    ),
    # a rule and a token are switched off, not deleted: a person built them, and what they were for stays visible
    "automation_rules.json": (
        put("rules", field="match.device_match.device_id", to={"enabled": False}),
    ),
    "inbound_webhooks.json": (put("tokens", field="scope_device_id", to={"enabled": False}),),
    # an approval nobody can act on any more is declined, in the words the page already shows for a decline
    "pending_confirmations.json": (
        put(
            "confirmations",
            field="device_id",
            where={"status": "pending"},
            to={
                "status": "rejected",
                "decided_by": "system",
                "decided_at": NOW,
                "reject_note": "the host was deleted",
            },
        ),
    ),
    # the host's place in something that stays
    "business_services.json": (drop("*", "members", field="device_id"),),
    "custom_scripts.json": (unlist("*", "assigned_devices"),),
    "kb.json": (unlist("articles", "*", "linked_devices"),),
    "smart_groups.json": (unlist("*", "members"),),
    "devices.json": (put(field="connected_to", to={"connected_to": ""}), unlist("*", "depends_on")),
    "config.json": (
        put("integrations", field="device_id", to={"device_id": ""}),
    ),  # an integration that ran on the host is unbound
}

STORES = tuple(RULES)


def _get(rec: Any, dotted: str) -> Any:
    for part in dotted.split("."):
        if not isinstance(rec, dict):
            return None
        rec = rec.get(part)
    return rec


def _names(rec: Any, field: str, host: str) -> bool:
    """Whether `field` (a dotted path) of the record is the host, or a list that holds it."""
    value = _get(rec, field)
    return value == host or (isinstance(value, list) and host in value)


def _fits(rec: Any, where: dict[str, Any] | None) -> bool:
    return not where or (isinstance(rec, dict) and all(rec.get(k) == v for k, v in where.items()))


def _hit(rec: Any, rule: Rule, host: str) -> bool:
    return _fits(rec, rule.where) and _names(rec, rule.field, host)


def _containers(node: Any, path: tuple[str, ...]) -> Iterator[Any]:
    """The values `path` leads to: one name for each level, "*" for every value of a map or element of a list."""
    if not path:
        yield node
        return
    head, rest = path[0], path[1:]
    children: Any = ()
    if head == "*":
        if isinstance(node, dict):
            children = list(node.values())
        elif isinstance(node, list):
            children = list(node)
    elif isinstance(node, dict) and head in node:
        children = (node[head],)
    for child in children:
        yield from _containers(child, rest)


def _records(c: Any) -> list[Any]:
    if isinstance(c, dict):
        return list(c.values())
    return list(c) if isinstance(c, list) else []


def _pop(c: Any, rule: Rule, host: str, now: int, dry: bool) -> int:
    if isinstance(c, dict) and host in c:
        if not dry:
            del c[host]
        return 1
    return 0


def _pop_keys(c: Any, keys: list[Any], dry: bool) -> int:
    if not dry:
        for k in keys:
            del c[k]
    return len(keys)


def _pop_prefix(c: Any, rule: Rule, host: str, now: int, dry: bool) -> int:
    if not isinstance(c, dict):
        return 0
    return _pop_keys(c, [k for k in c if isinstance(k, str) and k.startswith(host + ":")], dry)


def _pop_edge(c: Any, rule: Rule, host: str, now: int, dry: bool) -> int:
    if not isinstance(c, dict):
        return 0
    return _pop_keys(c, [k for k in c if isinstance(k, str) and host in k.split(":")], dry)


def _drop(c: Any, rule: Rule, host: str, now: int, dry: bool) -> int:
    if isinstance(c, list):
        keep = [r for r in c if not _hit(r, rule, host)]
        n = len(c) - len(keep)
        if n and not dry:
            c[:] = keep
        return n
    if isinstance(c, dict):
        return _pop_keys(c, [k for k, r in c.items() if _hit(r, rule, host)], dry)
    return 0


def _unlist(c: Any, rule: Rule, host: str, now: int, dry: bool) -> int:
    if not isinstance(c, list):
        return 0
    n = c.count(host)
    if n and not dry:
        c[:] = [x for x in c if x != host]
    return n


def _put(c: Any, rule: Rule, host: str, now: int, dry: bool) -> int:
    n = 0
    to = rule.to or {}
    stamped = any(
        v == NOW for v in to.values()
    )  # a rule that stamps the time is kept from repeating by its `where`
    for rec in _records(c):
        if not isinstance(rec, dict) or not _hit(rec, rule, host):
            continue
        new = {k: (now if v == NOW else v) for k, v in to.items()}
        if not stamped and all(k in rec and rec[k] == v for k, v in new.items()):
            continue  # already as the rule leaves it
        n += 1
        if not dry:
            rec.update(new)
    return n


_APPLY = {
    "pop": _pop,
    "pop_prefix": _pop_prefix,
    "pop_edge": _pop_edge,
    "drop": _drop,
    "unlist": _unlist,
    "put": _put,
}


def run(rule: Rule, data: Any, host: str, now: int = 0, dry: bool = False) -> int:
    """One rule over `data`. Returns how many places it changed (or would change, with `dry`, which touches nothing)."""
    return sum(
        _APPLY[rule.kind](c, rule, host, now, dry) for c in list(_containers(data, rule.path))
    )


def apply(name: str, data: Any, host: str, now: int = 0, dry: bool = False) -> int:
    """Run the rules of store `name` over `data`, which the caller holds the lock on. Returns how many places it changed."""
    return sum(run(rule, data, host, now, dry) for rule in RULES.get(name, ()))


def affects(name: str, data: Any, host: str) -> bool:
    """Whether `apply` would change store `name`: read-only, so a store that does not name the host is never locked or rewritten."""
    return apply(name, data, host, dry=True) > 0
