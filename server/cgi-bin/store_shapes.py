"""The shape each store file is expected to have, and the repair applied when a file does not have it.

Every reader of a store assumes a shape: `alerts.json` is a map holding a list of maps, `av_status.json` is a map of maps with a
map for each scanner, a ticket's `updated_at` is a number. The loaders hand out whatever JSON holds, so one row that is `null`, a
string or a number (a hand edit, an import, a restore from a mixed-up backup) made the home page, the problems page, the alert
summary, the risk page and every periodic sweep that reads the file raise, for every user, until someone found the row. The 7.4.9
sweep counted 202 readers behind 110 stores. They could not be fixed one at a time: the next reader written would carry the same
assumption.

This module is the one place that states the shapes. `normalize(name, data)` runs where a store is read (`api._load_uncached`, and
the locked read-modify-write of the SQL backends), checks the registered shape, and repairs what does not fit:

* a container of the wrong kind is replaced by an empty one of the right kind;
* a row or list element that is not what the store holds is left out, and the file is read without it;
* a listed field of the wrong kind is repaired where that loses nothing (a number stored as text is read as the number, a number
  stored where text goes is read as its text) and otherwise removed, so that the reader's own default applies.

Nothing else is touched. A field is checked only when it is listed here, and only a field that always holds the same kind of value:
`firewall` on a host is a map on Linux and a list on Windows, so it is not listed. The repair is applied to the copy in memory. A
later write of the same store saves the repaired copy, so the bad entry leaves the file at that point; one line on stderr says how
many there were.

Two stores are repaired the other way, because an empty value there would grant something: the tenant registry (a tenant that
vanished from it would put its users into the default tenant, which is the operator's: `dict_of(keep=True)`) and a smart group's
rules (an empty rule set matches every host: `req(DICT)`).

The registry is checked by `tests/test_v749_store_shapes.py`: every entry accepts the demo data without changing it, every kind of
spec repairs each wrong shape, and the product's own pages answer below 500 with a bad row in each store the sweep named.
"""

import json
import math
import os
import re
import sys
import threading
from typing import Any

DICT = "dict"
LIST = "list"
STR = "str"  # text. A number is read as its text. null is not text.
OPT_STR = "str?"  # text or null
NUM = "num"  # a number. Text that holds one is read as the number. null is not a number.
OPT_NUM = "num?"  # a number or null
SCALAR = "scalar"  # anything that is not a map or a list
OPT_DICT = "dict?"  # a map or null (a saved query without a filter stores null)

_LEAVES = frozenset((STR, OPT_STR, NUM, OPT_NUM, SCALAR, OPT_DICT))
_NUM_LIMIT = 10**20  # a 64-bit counter fits; a 400-digit integer does not
_INT_TEXT = re.compile(r"\s*-?\d+\s*$")


def dict_of(child: Any = DICT, skip: str = "", keep: bool = False, meta: Any = None) -> Any:
    """A map whose values are all `child`. A value that is not is left out, unless `keep` is set: then the key stays, with an empty
    value. Keys that start with `skip` (the `_last_run` and `_meta` entries some stores keep beside their rows) are not rows; the
    ones named in `meta` are checked against their own shape, the others are not looked at."""
    return ("dict_of", child, skip, keep, meta or {})


def req(spec: Any) -> Any:
    """A field that, when present with the wrong kind, makes its whole row unusable instead of being replaced by an empty value.
    For a field where "empty" does not mean "unusable": a smart group with an empty rule set matches every host.
    """
    return ("req", spec)


def list_of(child: Any = DICT) -> Any:
    """A list whose elements are all `child`. An element that is not is left out."""
    return ("list_of", child)


def fields(need: tuple = (), **named: Any) -> Any:
    """A map where each named field, when present, has the given shape. Other keys are not looked at. `need` names keys every
    real row carries (an id, a unit name) and that readers index without a default: a row that lacks one, or holds it as the
    wrong kind of value, is not a row, and is left out like any other."""
    return ("fields", named, tuple(need))


def _empty(spec: Any) -> Any:
    if spec == LIST or (isinstance(spec, tuple) and spec[0] == "list_of"):
        return []
    return {}


def _finite(v: Any) -> bool:
    return isinstance(v, int) or math.isfinite(v)


def _leaf(value: Any, kind: str) -> Any:
    """(value, ok) for a scalar field. `value` may come back changed (text read as a number, a number read as text)."""
    if kind == SCALAR:
        return value, not isinstance(value, (dict, list))
    if kind == OPT_DICT:
        return value, value is None or isinstance(value, dict)
    if value is None:
        return value, kind.endswith("?")
    if isinstance(value, bool):
        return value, False
    if kind.startswith("str"):
        if isinstance(value, str):
            return value, True
        if isinstance(value, (int, float)) and _finite(value) and abs(value) < _NUM_LIMIT:
            return str(value), True
        return value, False
    # a number
    if isinstance(value, (int, float)):
        return value, _finite(value) and abs(value) < _NUM_LIMIT
    if isinstance(value, str):
        if _INT_TEXT.match(value):
            n = int(value)
            return (n, True) if abs(n) < _NUM_LIMIT else (value, False)
        try:
            f = float(value)
        except ValueError:
            return value, False
        return (f, True) if math.isfinite(f) and abs(f) < _NUM_LIMIT else (value, False)
    return value, False


def _fix(value: Any, spec: Any) -> Any:
    """(value, ok, repaired). `ok` is False when `value` is not the kind of thing `spec` asks for, and the caller decides
    whether to leave it out (a row, an element) or replace or remove it (a field). `repaired` counts what was left out inside.
    """
    if spec == DICT:
        return value, isinstance(value, dict), 0
    if spec == LIST:
        return value, isinstance(value, list), 0
    if isinstance(spec, str):
        if spec in _LEAVES:
            nv, ok = _leaf(value, spec)
            return nv, ok, 0
        raise ValueError(f"unknown shape {spec!r}")
    kind = spec[0]
    if kind == "dict_of":
        if not isinstance(value, dict):
            return value, False, 0
        child, skip, keep, meta = spec[1], spec[2], spec[3], spec[4]
        bad, n = [], 0
        for k, v in value.items():
            if skip and isinstance(k, str) and k.startswith(skip):
                if k in meta:
                    nv, ok, r = _fix(v, meta[k])
                    n += r
                    if not ok:
                        bad.append(k)
                    elif nv is not v:
                        value[k] = nv
                continue
            nv, ok, r = _fix(v, child)
            n += r
            if not ok:
                bad.append(k)
            elif nv is not v:
                value[k] = nv
        for k in bad:
            _note(f"row {k!r}", value.get(k))
            if k in meta:
                value[k] = (
                    _empty(meta[k])
                    if not (isinstance(meta[k], str) and meta[k] in _LEAVES)
                    else None
                )
                if value[k] is None:
                    del value[k]
            elif keep:
                value[k] = _empty(child)
            else:
                del value[k]
        return value, True, n + len(bad)
    if kind == "list_of":
        if not isinstance(value, list):
            return value, False, 0
        child = spec[1]
        kept, n = [], 0
        changed = False
        for v in value:
            nv, ok, r = _fix(v, child)
            n += r
            if ok:
                kept.append(nv)
                if nv is not v:
                    changed = True
            else:
                _note("element", v)
        if len(kept) != len(value):
            n += len(value) - len(kept)
            value[:] = kept
        elif changed:
            value[:] = (
                kept  # an element read as another type (a number read as text) is written back in place
            )
        return value, True, n
    # fields
    if not isinstance(value, dict):
        return value, False, 0
    need = spec[2]
    for key in need:
        if key not in value:
            return value, False, 0
    n = 0
    for name, sub in spec[1].items():
        if name not in value:
            continue
        v = value[name]
        if isinstance(sub, str) and sub in _LEAVES:  # the common case, kept free of the recursion
            nv, ok = _leaf(v, sub)
            if not ok:
                if name in need:
                    return value, False, 0  # a row whose id or unit is the wrong kind is not a row
                _note(f"field {name!r}", v)
                del value[name]  # a wrong scalar is removed: the reader's default applies
                n += 1
            elif nv is not v:
                value[name] = nv
            continue
        if isinstance(sub, tuple) and sub[0] == "req":
            _, ok, r = _fix(v, sub[1])
            if not ok:
                return value, False, 0
            n += r
            continue
        nv, ok, r = _fix(v, sub)
        n += r
        if not ok:
            _note(f"field {name!r}", v)
            value[name] = _empty(sub)
            n += 1
        elif nv is not v:
            value[name] = nv
    return value, True, n


_WARNED: set[str] = set()
_TLS = threading.local()


def _dropped() -> list:
    d = getattr(_TLS, "dropped", None)
    if d is None:
        d = _TLS.dropped = []
    return d


def _note(where: str, value: Any) -> None:
    """Remember (a few of) the things a repair removed, for the report. Costs nothing on the path where nothing is removed."""
    d = _dropped()
    if len(d) < 5:
        try:
            d.append(f"{where}: {value!r}"[:240])
        except Exception:
            d.append(f"{where}: <unprintable>")


def drain_dropped() -> list:
    """The examples noted by the last normalize() on this thread, and forget them."""
    d = _dropped()
    out = list(d)
    d.clear()
    return out


_REPORT = os.environ.get("RP_SHAPES_REPORT", "")


def normalize(name: str, data: Any) -> Any:
    """The store `name` (a file's base name) as it should be read. `data` is the parsed document; it is repaired in place and
    returned. A store with no registered shape is returned as it is.

    RP_SHAPES_REPORT=<file> appends one JSON line for every store that needed repair, with a few of the entries removed. The test
    suite is run with it to find a registry entry that disagrees with what the product itself writes.
    """
    spec = SHAPES.get(name)
    if spec is None:
        return data
    drain_dropped()
    key = _WRAP.get(name)
    if key and isinstance(data, list):
        data = {key: data}  # the shape older installs have on disk; the readers accept it too
    fixed, ok, n = _fix(data, spec)
    if not ok:
        _note("document", data)
        fixed, n = _empty(spec), 1
    if n and _REPORT:
        try:
            with open(_REPORT, "a") as fh:
                fh.write(
                    json.dumps(
                        {"store": name, "n": n, "examples": _dropped()[:5], "pid": os.getpid()}
                    )
                    + "\n"
                )
        except OSError:
            pass
    if n and name not in _WARNED:
        _WARNED.add(name)
        sys.stderr.write(
            f'[remotepower] WARN: {name}: {n} entr{"y was" if n == 1 else "ies were"} not the expected shape '
            f'and {"was" if n == 1 else "were"} left out of what is read\n'
        )
    return fixed


# fmt: off
# The numeric settings of the settings document (the tunables Settings saves as integers or decimals, and the sweep intervals, ports,
# retention periods and "last run" stamps the server reads through int() or float()). A value of another kind used to stop the sweep
# that reads it, such as the offline check or the monitors, on every request until someone edited config.json.
_CONFIG_NUMBERS = (
    'after_hours_na_window_hours', 'agentless_ping_fail_threshold', 'alerts_retention_days', 'apikey_default_expiry_days',
    'attention_event_ttl_hours', 'audit_forward_port', 'audit_log_retention_days', 'av_sig_stale_days',
    'backup_size_anomaly_pct', 'batch_max_devices', 'batch_max_fleet_percent', 'battery_health_low_pct',
    'brute_force_threshold', 'brute_force_window_seconds', 'cert_file_expiring_days', 'cis_disk_pct_max',
    'cis_swap_pct_max', 'clock_skew_threshold_ms', 'cloud_autosync_interval', 'command_history_max',
    'compliance_lookback_days', 'compliance_tls_expiring_days', 'conntrack_crit_percent', 'conntrack_warn_percent',
    'container_restart_delta_threshold', 'container_restarting_min', 'container_stale_ttl', 'contract_soon_days',
    'contract_warn_days', 'cpu_pct_crit', 'cpu_pct_warn', 'csp_report_throttle_per_minute',
    'ct_fail_backoff', 'cve_cache_days', 'default_poll_interval', 'defender_sig_warn_days',
    'dependency_check_interval_s', 'dependency_silence_min', 'disk_forecast_crit_days', 'disk_forecast_warn_days',
    'disk_predict_medium_eta_days', 'disk_watchdog_pct', 'diskio_crit_percent', 'diskio_sustain',
    'diskio_warn_percent', 'dmarc_pct_min', 'drivetemp_crit_c', 'drivetemp_hdd_crit_c',
    'drivetemp_hdd_warn_c', 'drivetemp_nvme_crit_c', 'drivetemp_nvme_warn_c', 'drivetemp_ssd_crit_c',
    'drivetemp_ssd_warn_c', 'drivetemp_warn_c', 'ecc_error_alert_min_delta', 'fd_crit_percent',
    'fd_warn_percent', 'fleet_events_retention_days', 'flow_export_check_seconds', 'flow_export_silence_seconds',
    'gateway_latency_high_ms', 'github_new_issue_per_poll_cap', 'gpu_hot_c', 'health_alert_threshold',
    'health_grade_fair', 'health_grade_good', 'health_grade_poor', 'healthchecks_interval_seconds',
    'heartbeat_min_interval_s', 'history_retention_days', 'idle_timeout_minutes', 'image_scan_interval',
    'incident_device_threshold', 'inode_crit_percent', 'inode_warn_percent', 'integrations_interval',
    'ip_rep_confirm_scans', 'laptop_offline_grace_hours', 'last_disk_predict_check', 'last_healthchecks_ping',
    'last_kev_epss_refresh', 'last_mitigate_verify', 'last_monitor_run', 'last_posture_digest',
    'last_sidecar_watch', 'last_snmp_poll', 'ldap_timeout', 'log_buffer_max_bytes_per_unit',
    'log_buffer_retention_hours', 'max_devices', 'max_sessions_per_user', 'metric_failures_before_alert',
    'metric_recovery_buffer', 'metric_samples_retention_days', 'min_online_ttl', 'monitor_history_max',
    'monitor_history_retention_days', 'monitor_interval', 'netconfig_backup_interval_s', 'nic_drop_alert_min',
    'nic_err_alert_min', 'offline_missed_polls', 'online_ttl', 'oom_recent_window_seconds',
    'os_eol_soon_days', 'otlp_interval', 'otlp_traces_interval', 'password_min_length',
    'patch_alert_threshold', 'patch_na_warn_count', 'proxmox_backup_warn_days', 'proxmox_snapshot_warn_days',
    'reliability_crit', 'reliability_high', 'reliability_medium', 'reliability_reboot_churn_min',
    'reliability_wear_high_pct', 'resolver_failures_before_alert', 'risk_level_critical', 'risk_level_high',
    'risk_level_medium', 'rotate_after_days', 'self_high_load_ratio', 'self_mem_warn_pct',
    'self_online_pct_warn', 'session_ttl_long', 'session_ttl_short', 'slo_target_percent',
    'slow_handler_ms', 'smart_realloc_crit_sectors', 'smart_wear_high_pct', 'smart_wear_warn_pct',
    'smtp_port', 'snapshot_stale_days', 'snmp_cpu_crit_percent', 'snmp_cpu_warn_percent',
    'snmp_dead_threshold', 'snmp_failures_before_alert', 'sshgw_public_port', 'temp_alert_threshold_c',
    'thermal_crit_c', 'thermal_hot_c', 'tls_crit_days', 'tls_warn_days',
    'unit_flap_restarts', 'unstable_host_returns_min', 'unstable_host_window_days', 'vpn_port_base',
    'webhook_log_retention_days', 'wol_port',
)

# fmt: on


# Settings the server reads as text and calls a string method on (.lower(), .strip(), .rstrip()). A number or a list there raised
# AttributeError: the audit forwarder dropped the entry into its retry spool, the others failed the page that reads them.
_CONFIG_TEXT = (
    "audit_forward_mode",
    "issuer_name",
    "ldap_user_filter",
    "oidc_scopes",
    "siem_format",
    "smtp_tls",
)


def _config_fields() -> dict:
    spec = dict(
        webhook_urls=list_of(),
        metric_thresholds=DICT,
        service_baselines=list_of(),
        slo_objects=list_of(),
        custom_checks=list_of(),
        report_definitions=list_of(),
        drift=DICT,
        after_hours=DICT,
        integrations=list_of(fields(type=SCALAR, url=OPT_STR)),
        integration_notified=DICT,
        ticket_sla=DICT,
        ticket_imap=DICT,
        ticket_autoreply=DICT,
        ip_intel=DICT,
        file_manager=DICT,
        monitors=list_of(),
        backup_monitors=list_of(),
        mailflow=DICT,
        ct_watch_domains=list_of(STR),
        quiet_hours=DICT,
        escalation=DICT,
        oncall=DICT,
        alert_runbooks=DICT,
        patch_sla=list_of(),
        monitoring_profiles=list_of(),
    )
    for k in _CONFIG_TEXT:
        spec[k] = STR
    spec["ai"] = fields(base_url=OPT_STR, embeddings=fields(base_url=OPT_STR))
    # null is not a number here: int(None) stopped a sweep, and a removed key reads as its default
    for k in _CONFIG_NUMBERS:
        spec.setdefault(k, NUM)
    return spec


# fmt: off
# Stores whose document may also be a bare list of the entries (older installs, and a file edited by hand); the readers accept it.
_WRAP = {'webhook_log.json': 'entries'}

BUCKETS = list_of(fields(need=('ts',), ts=NUM))   # a roll-up tier: the merge indexes b['ts'] on every bucket

# name -> the shape. The stores whose readers failed on a wrong row in the 7.4.9 sweep, and the ones the fleet pages read.
SHAPES: dict = {
    # ── a map keyed by host id ──────────────────────────────────────────────────────────────────────────────────────────
    'devices.json': dict_of(fields(
        group=STR, name=STR, hostname=OPT_STR, os=OPT_STR, site=OPT_STR, last_seen=NUM, compose_projects=LIST, log_watch=list_of(),
        tags=list_of(STR), depends_on=list_of(STR),
        sysinfo=fields(proc_names=list_of(STR), canary_status=LIST, cpu_count=OPT_NUM, cron=DICT, custom_check_results=DICT,
                       firewall=fields(backends=list_of(fields(rules=OPT_NUM))), firewall_fp=fields(rules=OPT_NUM),
                       disk_io=list_of(fields(busy_pct=OPT_NUM, read_mbs=OPT_NUM, write_mbs=OPT_NUM)),
                       storage_health=list_of(fields(capacity=OPT_NUM)),
                       guard_quarantine=LIST, listening_ports=LIST,
                       mounts=list_of(fields(percent=OPT_NUM, total_gb=OPT_NUM, used_gb=OPT_NUM)), network_io=LIST, packages=DICT,
                       timers=LIST))),
    'acme_state.json': dict_of(fields(certs=list_of(), updated_at=OPT_NUM)),
    'av_status.json': dict_of(fields(clamav=DICT, rkhunter=DICT)),
    'cmdb.json': dict_of(fields(docs=list_of(), credentials=list_of(), rack_id=SCALAR, server_function=OPT_STR)),
    'containers.json': dict_of(fields(items=list_of(fields(restart_count=NUM, runtime=SCALAR, tag=OPT_STR)))),
    'cve_findings.json': dict_of(fields(findings=list_of(fields(aliases=LIST, package=OPT_STR, severity=OPT_STR,
                                                                summary=OPT_STR, version=OPT_STR, vuln_id=OPT_STR)))),
    'discovery.json': dict_of(fields(hosts=list_of(fields(need=('ip',), ip=STR, mac=OPT_STR, hostname=OPT_STR)))),
    'drift_state.json': dict_of(fields(files=dict_of(fields(last_check=OPT_NUM, drift_count=OPT_NUM)))),
    'gpu_history.json': dict_of(dict_of(fields(samples=list_of()))),
    'hardware.json': dict_of(fields(
        smart=list_of(fields(reallocated_sectors=OPT_NUM, pending_sectors=OPT_NUM, offline_uncorrectable=OPT_NUM,
                             reported_uncorrect=OPT_NUM, crc_errors=OPT_NUM, temperature_c=OPT_NUM, power_on_hours=OPT_NUM,
                             wear_pct=OPT_NUM, spare_pct=OPT_NUM, spare_threshold_pct=OPT_NUM, selftest_hours=OPT_NUM)),
        gpus=list_of(fields(util_pct=OPT_NUM, mem_used_mb=OPT_NUM, mem_total_mb=OPT_NUM, temp_c=OPT_NUM, power_w=OPT_NUM,
                            fan_pct=OPT_NUM)),
        kernel=DICT, ups=list_of(fields(battery_pct=OPT_NUM, load_pct=OPT_NUM, power_w=OPT_NUM)), hardware=DICT, _drive_temp=DICT)),
    'ansible_playbooks.json': fields(playbooks=list_of(fields(last_rc=OPT_NUM))),
    'helm.json': dict_of(fields(releases=list_of())),
    'image_cves.json': dict_of(fields(images=list_of(fields(top=list_of(), critical=NUM, high=NUM, medium=NUM, image=OPT_STR)))),
    'lldp_neighbors.json': dict_of(fields(neighbors=list_of())),
    'log_watch.json': dict_of(fields(units=dict_of(list_of()))),
    'metrics_history.json': dict_of(fields(samples=list_of(fields(mounts=list_of())))),
    'packages.json': dict_of(fields(collected_at=OPT_NUM, count=OPT_NUM, os_id=OPT_STR, pkg_manager=OPT_STR, version_id=OPT_STR,
                                    packages=list_of(fields(arch=OPT_STR, name=OPT_STR, version=OPT_STR)))),
    'patch_age.json': dict_of(fields(all_first=OPT_NUM, sec_first=OPT_NUM), skip='_', meta={'_last_run': OPT_NUM, '_breaching': list_of(STR)}),
    'pii_findings.json': dict_of(fields(findings=list_of(fields(count=OPT_NUM, kind=OPT_STR, path=OPT_STR)))),
    'scap.json': dict_of(fields(available_profiles=list_of(STR), failed_rules=LIST, fail=OPT_NUM, score=OPT_NUM)),
    'secret_findings.json': dict_of(fields(findings=list_of(fields(fingerprint=OPT_STR, line=OPT_NUM)), _seen=LIST)),
    'services.json': dict_of(fields(services=list_of(fields(need=('unit',), unit=STR, active=OPT_STR, sub=OPT_STR,
                                                             since=OPT_NUM)))),
    'smart_history.json': dict_of(dict_of(fields(samples=list_of()))),
    'snmp_data.json': dict_of(),
    'software_violations.json': dict_of(fields(violations=list_of())),
    'ssh_key_baseline.json': dict_of(dict_of(list_of(STR))),
    'sshgw_state.json': dict_of(fields(last_session=OPT_NUM, tunnel_seen=OPT_NUM)),
    'thermal_history.json': dict_of(fields(samples=list_of(), sensors=DICT)),
    'uptime.json': dict_of(fields(events=list_of(fields(ts=NUM)))),
    'runbooks.json': dict_of(),
    # ── a map keyed by something else ───────────────────────────────────────────────────────────────────────────────────
    'apikeys.json': dict_of(),
    'users.json': dict_of(),
    'tenants.json': dict_of(fields(name=STR), keep=True),
    'sites.json': dict_of(fields(name=STR)),
    'racks.json': dict_of(fields(height_u=OPT_NUM, name=STR, site=OPT_STR)),
    'subnets.json': dict_of(fields(reservations=DICT, cidr=STR, site=OPT_STR)),
    'links.json': dict_of(fields(category=OPT_STR, title=STR)),
    'satellites.json': dict_of(),
    'scans.json': dict_of(fields(findings=list_of(), created=OPT_NUM, target_device_id=OPT_STR)),
    'scan_schedules.json': dict_of(fields(created=OPT_NUM, last_run=OPT_NUM, next_run=OPT_NUM)),
    'scan_targets.json': dict_of(fields(created=OPT_NUM)),
    'compose_stacks.json': dict_of(fields(created_ts=SCALAR, device_id=SCALAR, last_action_ts=SCALAR, last_rc=OPT_NUM)),
    'custom_scripts.json': dict_of(fields(need=('id',), id=SCALAR, assigned_devices=list_of(STR), created_at=NUM)),
    'dmarc_results.json': dict_of(fields(status=OPT_STR)),
    'ip_reputation_results.json': dict_of(fields(checked_at=NUM, listed_count=OPT_NUM)),
    'ip_reputation_targets.json': dict_of(fields(ip=STR)),
    'netscan_schedules.json': dict_of(fields(device_id=OPT_STR, interval_minutes=OPT_NUM, last_run=OPT_NUM)),
    'patch_snapshots.json': dict_of(fields(created=NUM, entry_count=OPT_NUM)),
    'query_templates.json': dict_of(fields(where=OPT_DICT)),
    'resolver_health_results.json': dict_of(fields(checked_at=NUM)),
    'resolver_health_targets.json': dict_of(fields(name=STR)),
    'smart_groups.json': dict_of(fields(rules=req(DICT), members=list_of(STR)), skip='_'),
    'tls_results.json': dict_of(fields(addresses=LIST, checked_at=NUM, expires_at=OPT_NUM)),
    'tls_targets.json': dict_of(fields(crit_days=NUM, host=STR, port=NUM, warn_days=NUM)),
    'tunnels.json': dict_of(fields(endpoints=list_of(STR))),
    'metrics.json': dict_of(list_of(fields(ts=NUM))),
    'business_services.json': dict_of(fields(created_at=NUM, updated_at=NUM)),
    'business_service_history.json': dict_of(list_of(fields(ts=NUM))),
    'sudo_log.json': dict_of(list_of(fields(ts=NUM))),
    'monitor_history.json': dict_of(list_of(fields(ts=NUM))),
    'commands.json': dict_of(LIST),
    # ── a map holding one or more named lists ───────────────────────────────────────────────────────────────────────────
    'alerts.json': fields(alerts=list_of(fields(id=SCALAR, resolved_at=OPT_NUM, assigned_at=OPT_NUM, assigned_to=OPT_STR))),
    'alert_mutes.json': fields(mutes=list_of(fields(device_id=OPT_STR))),
    # 7.4.9: business services. The definitions are read through bizsvc's cleaners, so the registry only guards the container shape
    'business_service_state.json': fields(last_run=NUM, services=dict_of(fields(since=NUM))),
    'audit_log.json': fields(entries=list_of(fields(_hash=OPT_STR, ts=OPT_NUM))),
    'automation_rules.json': fields(rules=list_of(fields(cooldown_seconds=OPT_NUM, fire_count=OPT_NUM))),
    'autonomy_receipts.json': fields(receipts=list_of(), last_run=NUM),
    'autopatch_policies.json': fields(policies=list_of()),
    'backup_jobs.json': fields(jobs=list_of()),
    'blueprints.json': fields(blueprints=list_of(fields(need=('id',), id=SCALAR, variables=list_of()))),
    'calendar.json': fields(events=list_of()),
    'contacts.json': fields(contacts=list_of()),
    'cve_campaigns.json': fields(campaigns=list_of(fields(samples=list_of(), created_at=OPT_NUM, cve_ids=LIST, severities=LIST)),
                                 _last_sample=NUM),
    'fleet_events.json': fields(events=list_of(fields(event=OPT_STR, ts=NUM, payload=fields(device_id=OPT_STR,
                                                                                         device_name=OPT_STR)))),
    'history.json': fields(entries=list_of()),
    'inbound_webhooks.json': fields(tokens=list_of(fields(scope_device_id=OPT_STR, hit_count=OPT_NUM))),
    'incidents.json': fields(incidents=list_of(fields(need=('id',), id=SCALAR, updates=list_of(), created_at=NUM))),
    'invoices.json': fields(invoices=list_of(fields(need=('id',), id=SCALAR, issued_at=NUM, site_id=OPT_STR))),
    'kb.json': fields(articles=list_of(fields(category=OPT_STR, id=OPT_STR))),
    'kmip_log.json': fields(entries=list_of()),
    'log_rules_global.json': fields(rules=list_of(fields(pattern=STR, unit=STR))),
    'maintenance.json': fields(windows=list_of(fields(created_by=OPT_STR, cron=OPT_STR, duration=OPT_NUM, reason=STR,
                                                      scope=OPT_STR))),
    'pending_confirmations.json': fields(confirmations=list_of(fields(params=DICT, device_id=OPT_STR, requested_at=OPT_NUM))),
    'portal_ticket_queue.json': fields(pending=list_of(fields(created_at=OPT_NUM))),
    'quotes.json': fields(quotes=list_of(fields(need=('id',), id=SCALAR, created_at=OPT_NUM, site_id=OPT_STR))),
    'report_archive.json': fields(entries=list_of(fields(ts=OPT_NUM)), trimmed=OPT_NUM),
    'roles.json': fields(roles=list_of()),
    'rollouts.json': fields(rollouts=list_of(fields(created_at=OPT_NUM))),
    'schedule.json': fields(jobs=list_of(fields(cron=OPT_STR, device_id=OPT_STR, run_at=OPT_NUM))),
    'scripts.json': fields(scripts=list_of(fields(need=('id',), id=SCALAR, last_lint=DICT, body=STR, created_by=OPT_STR))),
    'sshgw_sessions.json': fields(sessions=list_of(fields(device_id=OPT_STR, started=OPT_NUM))),
    'tasks.json': fields(tasks=list_of(fields(device_id=OPT_STR, state=OPT_STR, created_at=OPT_NUM, updated_at=OPT_NUM))),
    'tickets.json': fields(tickets=list_of(fields(need=('id',), id=SCALAR, affected_devices=LIST, created_at=OPT_NUM, updated_at=NUM))),
    'time_entries.json': fields(entries=list_of(fields(need=('id',), id=SCALAR, date=STR))),
    'vpn.json': fields(tunnels=list_of(fields(id=SCALAR, iface=OPT_STR, expires_at=OPT_NUM,
                                               clients=list_of(fields(id=SCALAR, pubkey=OPT_STR, expires_at=OPT_NUM))))),
    'webhook_dlq.json': fields(entries=list_of(fields(attempts=OPT_NUM))),
    'webhook_log.json': fields(entries=list_of()),
    'health_history.json': fields(fleet=list_of(), devices=DICT),
    'compliance_history.json': fields(fleet=list_of(fields(ts=OPT_NUM))),
    'proxmox_backup_cache.json': fields(guests=list_of(fields(age_days=OPT_NUM))),
    'incident_memory.json': fields(outcomes=list_of(fields(resolved_at=OPT_NUM)), seen=list_of(STR), last_run=NUM),
    'ignored_items.json': fields(needs_attention=list_of(), containers=list_of(), devices=list_of()),
    'autonomy_policy.json': fields(tenants=dict_of(fields(allowed_actions=list_of(STR)))),
    'batch_jobs.json': fields(jobs=dict_of()),
    'flow_deps.json': fields(edges=dict_of(fields(last_observed=OPT_NUM)), last_run=NUM),
    'image_updates.json': fields(images=dict_of(fields(last_checked=NUM)), last_full_scan=NUM),
    'integrations_state.json': fields(latest=dict_of(fields(metrics=DICT, checked=NUM)), history=DICT),
    'ip_intel.json': fields(attackers=dict_of(fields(verdict=DICT, devices=DICT, last_seen=OPT_NUM, report_log=LIST)),
                            blocks=dict_of(dict_of(fields(until=NUM))), budget=fields(abuseipdb=NUM, sniffcat=NUM), last_sweep=NUM, edge=DICT, edgelist=DICT,
                            edgeban=DICT),
    'ip_intel_intake.json': fields(queue=LIST, sensors=dict_of(fields(sources=LIST, ignored=DICT)), cursors=DICT),
    'kev_epss.json': fields(kev=list_of(STR), epss=dict_of(NUM)),
    'kmip.json': fields(clients=dict_of(fields(not_after=OPT_NUM)), daemon=fields(last_state_fetch=OPT_NUM),
                        ca=fields(not_after=OPT_NUM), server_cert=DICT, _cert_check=fields(last_run=OPT_NUM, alerted=LIST)),
    'kmip_objects.json': fields(objects=dict_of(fields(client_id=OPT_STR, created=OPT_NUM, length=OPT_NUM))),
    'wan_state.json': fields(outages=list_of(fields(end=OPT_NUM, start=OPT_NUM)), checked=NUM, first_seen=OPT_NUM),
    # ── smaller stores ─────────────────────────────────────────────────────────────────────────────────────────────────
    'app_catalog_custom.json': dict_of(),
    'backup_state.json': dict_of(),
    'brute_force.json': DICT,
    'cmd_library.json': fields(snippets=list_of()),
    'device_profiles.json': dict_of(fields(services_watched=list_of(STR), log_watch=list_of(), metric_thresholds=DICT)),
    'disk_usage.json': dict_of(fields(paths=DICT)),
    'diskio_history.json': dict_of(dict_of(LIST)),
    'dmarc_reports.json': fields(reports=list_of(), sources=DICT, mailbox=DICT),
    'flow.json': dict_of(fields(latest=DICT, history=list_of())),
    'gitops_state.json': fields(last_summary=DICT),
    'mailflow_state.json': fields(last_tick=NUM),
    'port_baseline.json': DICT,
    'remediations.json': fields(attempts=list_of(), last_verify=OPT_NUM),
    'service_history.json': DICT,
    'snmp_traps.json': dict_of(list_of()),
    'speedtest.json': dict_of(list_of(fields(download_mbps=OPT_NUM, upload_mbps=OPT_NUM, ping_ms=OPT_NUM, jitter_ms=OPT_NUM))),
    'thermal_rollup.json': dict_of(fields(last_ts=NUM, fivemin=BUCKETS, hourly=BUCKETS, daily=BUCKETS, sensors=DICT), skip='_', meta={'_meta': fields(last_run=NUM)}),
    'metrics_rollup.json': dict_of(fields(last_ts=NUM, fivemin=BUCKETS, hourly=BUCKETS, daily=BUCKETS, sensors=DICT), skip='_', meta={'_meta': fields(last_run=NUM)}),
    'ct_watch.json': dict_of(fields(last_check=NUM, fail_streak=NUM)),
    'ipam_state.json': fields(last_run=NUM, conflicts=list_of(STR), mac_conflicts=list_of(STR)),
    'proxmox_snapshot_cache.json': dict_of(),
    'self_backup_state.json': fields(last_run=NUM, last_drill_at=NUM),
    'update_logs.json': dict_of(list_of()),
    'patch_previews.json': dict_of(fields(pending=OPT_DICT, plan=OPT_DICT)),   # 7.4.9: per host, the waiting request and the last plan
    # The settings document. Only the keys that always hold a map or a list. The lists listed with `list_of()` hold maps by
    # design (their shape is documented where they are read).
    'config.json': ('fields', _config_fields(), ()),
}
# fmt: on
