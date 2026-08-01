#!/usr/bin/env python3
"""
RemotePower Prometheus Exporter — v1.7.0

Standalone module imported by api.py. Renders the /api/metrics endpoint
as Prometheus text exposition format 0.0.4.

Docs: https://prometheus.io/docs/instrumenting/exposition_formats/

Metric families exposed:

    remotepower_info
    remotepower_devices_total
    remotepower_devices_online
    remotepower_device_online{device,name,group,os}
    remotepower_device_last_seen_timestamp_seconds{device,name,group}
    remotepower_device_cpu_percent{device,name,group}
    remotepower_device_mem_percent{device,name,group}
    remotepower_device_disk_percent{device,name,group}
    remotepower_device_upgradable_packages{device,name,group,manager}
    remotepower_device_cve_findings{device,name,group,severity}
    remotepower_monitor_up{label,type,target}
    remotepower_monitor_last_check_timestamp_seconds{label,type,target}
    remotepower_scheduled_jobs_total
    remotepower_commands_pending_total
    remotepower_webhook_deliveries_total{status}
    remotepower_webhook_log_size

v6.4.2 added the families below. They cover signals the product already
computed for its own UI but never exported, so a Grafana user could not alert
on a failing drive, a UPS on battery or a stale backup from RemotePower's own
exporter. Each is emitted only when the caller supplies the backing store, so
a trimmed context still produces a valid exposition:

    remotepower_device_temperature_celsius{device,name,group,sensor}
    remotepower_device_temperature_max_celsius{device,name,group}
    remotepower_device_smart_disk_healthy{device,name,group,disk,model}
    remotepower_device_smart_disks_failed{device,name,group}
    remotepower_device_smart_reallocated_sectors{device,name,group,disk}
    remotepower_device_smart_pending_sectors{device,name,group,disk}
    remotepower_device_smart_power_on_seconds{device,name,group,disk}
    remotepower_device_smart_wear_ratio{device,name,group,disk}
    remotepower_device_smart_spare_ratio{device,name,group,disk}
    remotepower_ups_on_battery{device,name,group,ups}
    remotepower_ups_battery_charge_ratio{device,name,group,ups}
    remotepower_ups_load_ratio{device,name,group,ups}
    remotepower_ups_runtime_seconds{device,name,group,ups}
    remotepower_ups_input_volts{device,name,group,ups}
    remotepower_ups_power_watts{device,name,group,ups}
    remotepower_backup_ok{device,name,group,path}
    remotepower_backup_age_seconds{device,name,group,path}
    remotepower_backup_max_age_seconds{device,name,group,path}
    remotepower_device_disk_fill_eta_seconds{device,name,group}
    remotepower_device_risk_score{device,name,group}
    remotepower_risk_devices{level}
    remotepower_device_reliability_score{device,name,group}
    remotepower_reliability_devices{level}
    remotepower_compliance_pass_ratio
    remotepower_compliance_devices_evaluated
    remotepower_device_compliance_pass_ratio{device,name,group}
    remotepower_compliance_check_devices{check,severity,result}

Percentages the stores keep as 0-100 (SMART wear, UPS charge, compliance) are
exported as 0-1 ratios and hour counts as seconds, per Prometheus base-unit
convention. The pre-v6.4.2 *_percent families keep their names for
compatibility with existing dashboards and alert rules.

Uptime tracking, user counts, and api key counts can be added later if needed.
"""

import math
import time


# ── Label escaping (per Prometheus spec) ──────────────────────────────────────

def _escape_label(value: str) -> str:
    """Escape \\, \", \\n inside label values."""
    if value is None:
        return ''
    s = str(value)
    return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')


def _labels(pairs: dict) -> str:
    """Render a dict of label=value pairs."""
    if not pairs:
        return ''
    parts = [f'{k}="{_escape_label(v)}"' for k, v in pairs.items() if v is not None and v != '']
    if not parts:
        return ''
    return '{' + ','.join(parts) + '}'


def _metric(name: str, labels: dict, value) -> str:
    return f'{name}{_labels(labels)} {value}'


# ── Main generator ────────────────────────────────────────────────────────────

def generate_metrics(ctx: dict) -> str:
    """
    Build the full text exposition payload.

    ctx must contain:
      - server_version
      - now (unix ts)
      - online_ttl (seconds — devices with last_seen within this are "online")
      - devices  : dict of device_id -> device record
      - monitors : list of {label, type, target}
      - monitor_state : dict keyed by label with {'up': bool, 'last': ts}
      - schedule : list
      - pending_cmds : dict device_id -> list
      - webhook_log : list of {ts, event, status, ...}
      - webhook_log_cap : int
      - cve_findings : dict device_id -> {findings, scanned_at}
      - cve_ignore : dict vuln_id -> {scope, ...}

    Optional (v6.4.2) — omit any of these and its families are simply not
    emitted; the rest of the exposition is unaffected:
      - hardware       : hardware.json — dict device_id -> {smart, hardware:
                         {temps}, gpus, ups}
      - backup_state   : backup_state.json — dict '<device_id>:<path>' ->
                         {ok, age_h}
      - backup_monitors: config `backup_monitors` list, for the per-path
                         max_age_hours threshold
      - disk_fill_eta  : dict device_id -> days-to-full (_disk_fill_eta)
      - risk           : list of {device_id, device_name, score, level}
      - reliability    : list of {device_id, name, score, level}
      - compliance     : the _compute_compliance() report dict
    """
    lines = []
    now         = ctx['now']
    online_ttl  = ctx['online_ttl']
    devices     = ctx['devices']
    version     = ctx['server_version']

    # v4.4.0 (RELIABILITY): a single corrupt store record must not 500 the whole
    # scrape. Keep only well-formed dict records here so every downstream
    # `d.get(...)` loop is safe; the handler also wraps this in try/except.
    if isinstance(devices, dict):
        devices = {k: v for k, v in devices.items() if isinstance(v, dict)}
    else:
        devices = {}

    # ── Build-info gauge ───────────────────────────────────────────────────────
    lines.append('# HELP remotepower_info Server build information.')
    lines.append('# TYPE remotepower_info gauge')
    lines.append(_metric('remotepower_info', {'version': version}, 1))

    # ── Device totals ──────────────────────────────────────────────────────────
    online_count = sum(
        1 for d in devices.values()
        if (now - (d.get('last_seen') or 0)) < online_ttl
    )
    lines.append('# HELP remotepower_devices_total Total enrolled devices.')
    lines.append('# TYPE remotepower_devices_total gauge')
    lines.append(f'remotepower_devices_total {len(devices)}')

    lines.append('# HELP remotepower_devices_online Currently online devices.')
    lines.append('# TYPE remotepower_devices_online gauge')
    lines.append(f'remotepower_devices_online {online_count}')

    # ── Per-device metrics ─────────────────────────────────────────────────────
    lines.append('# HELP remotepower_device_online Whether device is currently online (1/0).')
    lines.append('# TYPE remotepower_device_online gauge')
    for dev_id, d in devices.items():
        is_online = int((now - (d.get('last_seen') or 0)) < online_ttl)
        lines.append(_metric(
            'remotepower_device_online',
            {
                'device': dev_id,
                'name':   d.get('name', dev_id),
                'group':  d.get('group', ''),
                'os':     d.get('os', ''),
            },
            is_online,
        ))

    lines.append('# HELP remotepower_device_last_seen_timestamp_seconds Last heartbeat time.')
    lines.append('# TYPE remotepower_device_last_seen_timestamp_seconds gauge')
    for dev_id, d in devices.items():
        lines.append(_metric(
            'remotepower_device_last_seen_timestamp_seconds',
            {'device': dev_id, 'name': d.get('name', dev_id), 'group': d.get('group', '')},
            d.get('last_seen') or 0,
        ))

    # CPU/MEM/DISK from latest sysinfo
    _emit_metric_family(
        lines,
        devices,
        'remotepower_device_cpu_percent',
        'CPU utilization percentage.',
        lambda d: (d.get('sysinfo') or {}).get('cpu_percent'),
    )
    _emit_metric_family(
        lines,
        devices,
        'remotepower_device_mem_percent',
        'Memory utilization percentage.',
        lambda d: (d.get('sysinfo') or {}).get('mem_percent'),
    )
    _emit_metric_family(
        lines,
        devices,
        'remotepower_device_disk_percent',
        'Root filesystem usage percentage.',
        lambda d: (d.get('sysinfo') or {}).get('disk_percent'),
    )

    # Patch counts
    lines.append('# HELP remotepower_device_upgradable_packages Pending package upgrades.')
    lines.append('# TYPE remotepower_device_upgradable_packages gauge')
    for dev_id, d in devices.items():
        pkg = (d.get('sysinfo') or {}).get('packages') or {}
        upg = pkg.get('upgradable')
        if upg is None:
            continue
        lines.append(_metric(
            'remotepower_device_upgradable_packages',
            {
                'device':  dev_id,
                'name':    d.get('name', dev_id),
                'group':   d.get('group', ''),
                'manager': pkg.get('manager', 'unknown'),
            },
            upg,
        ))

    # ── CVE findings per severity ──────────────────────────────────────────────
    lines.append('# HELP remotepower_device_cve_findings CVE findings by severity (excludes ignored).')
    lines.append('# TYPE remotepower_device_cve_findings gauge')
    cve_findings_all = ctx.get('cve_findings') or {}
    ignore_data      = ctx.get('cve_ignore') or {}
    for dev_id, d in devices.items():
        entry = cve_findings_all.get(dev_id) or {}
        findings = entry.get('findings') or []
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unknown': 0}
        for f in findings:
            if not isinstance(f, dict):
                continue   # v4.4.0: skip a malformed finding, don't break the scrape
            vid = f.get('vuln_id')
            ig = ignore_data.get(vid)
            if ig and (ig.get('scope') == 'global' or ig.get('scope') == dev_id):
                continue
            sev = f.get('severity', 'unknown')
            counts[sev if sev in counts else 'unknown'] += 1
        for sev, n in counts.items():
            lines.append(_metric(
                'remotepower_device_cve_findings',
                {
                    'device':   dev_id,
                    'name':     d.get('name', dev_id),
                    'group':    d.get('group', ''),
                    'severity': sev,
                },
                n,
            ))

    # ── Monitor state ──────────────────────────────────────────────────────────
    monitors      = ctx.get('monitors') or []
    monitor_state = ctx.get('monitor_state') or {}
    lines.append('# HELP remotepower_monitor_up Whether a configured monitor target is up.')
    lines.append('# TYPE remotepower_monitor_up gauge')
    for m in monitors:
        state = monitor_state.get(m.get('label', '')) or {}
        lines.append(_metric(
            'remotepower_monitor_up',
            {'label': m.get('label', ''), 'type': m.get('type', ''), 'target': m.get('target', '')},
            int(bool(state.get('up', True))),
        ))

    lines.append('# HELP remotepower_monitor_last_check_timestamp_seconds Last check ts per monitor.')
    lines.append('# TYPE remotepower_monitor_last_check_timestamp_seconds gauge')
    for m in monitors:
        state = monitor_state.get(m.get('label', '')) or {}
        lines.append(_metric(
            'remotepower_monitor_last_check_timestamp_seconds',
            {'label': m.get('label', ''), 'type': m.get('type', ''), 'target': m.get('target', '')},
            state.get('last', 0),
        ))

    # ── v1.8.0: Service monitoring ─────────────────────────────────────────────
    services_all = ctx.get('services') or {}
    lines.append('# HELP remotepower_service_active Whether a watched systemd unit is active (1/0).')
    lines.append('# TYPE remotepower_service_active gauge')
    for dev_id, entry in services_all.items():
        dev = devices.get(dev_id) or {}
        for svc in (entry.get('services') or []):
            lines.append(_metric(
                'remotepower_service_active',
                {
                    'device': dev_id,
                    'name':   dev.get('name', dev_id),
                    'group':  dev.get('group', ''),
                    'unit':   svc.get('unit', ''),
                    'sub':    svc.get('sub', ''),
                },
                int(svc.get('active') == 'active'),
            ))

    # Device-level aggregates (useful for "any service down on device X")
    lines.append('# HELP remotepower_services_down_total Number of watched services currently not active per device.')
    lines.append('# TYPE remotepower_services_down_total gauge')
    for dev_id, entry in services_all.items():
        dev = devices.get(dev_id) or {}
        svcs = entry.get('services') or []
        down = sum(1 for s in svcs if s.get('active') != 'active')
        lines.append(_metric(
            'remotepower_services_down_total',
            {'device': dev_id, 'name': dev.get('name', dev_id), 'group': dev.get('group', '')},
            down,
        ))

    # ── v1.8.0: Maintenance window status ──────────────────────────────────────
    maint_active = int(ctx.get('maintenance_active_count', 0))
    lines.append('# HELP remotepower_maintenance_windows_active Number of currently-active maintenance windows.')
    lines.append('# TYPE remotepower_maintenance_windows_active gauge')
    lines.append(f'remotepower_maintenance_windows_active {maint_active}')

    # ── Queues and logs ────────────────────────────────────────────────────────
    lines.append('# HELP remotepower_commands_pending_total Commands waiting to be picked up.')
    lines.append('# TYPE remotepower_commands_pending_total gauge')
    pending = ctx.get('pending_cmds') or {}
    lines.append(f'remotepower_commands_pending_total {sum(len(v) for v in pending.values())}')

    lines.append('# HELP remotepower_scheduled_jobs_total Scheduled jobs currently queued.')
    lines.append('# TYPE remotepower_scheduled_jobs_total gauge')
    lines.append(f"remotepower_scheduled_jobs_total {len(ctx.get('schedule') or [])}")

    # Webhook deliveries — derive counts from the log buffer
    wlog = ctx.get('webhook_log') or []
    wh_counts = {'ok': 0, 'error': 0, 'other': 0}
    for entry in wlog:
        st = entry.get('status', '')
        if st == 'error':
            wh_counts['error'] += 1
        elif isinstance(st, int) or (isinstance(st, str) and st.isdigit()):
            wh_counts['ok'] += 1
        else:
            wh_counts['other'] += 1

    lines.append('# HELP remotepower_webhook_deliveries_total Webhook deliveries observed in log buffer.')
    lines.append('# TYPE remotepower_webhook_deliveries_total gauge')
    for k, v in wh_counts.items():
        lines.append(_metric('remotepower_webhook_deliveries_total', {'status': k}, v))

    lines.append('# HELP remotepower_webhook_log_size Current size of the webhook delivery log.')
    lines.append('# TYPE remotepower_webhook_log_size gauge')
    lines.append(f'remotepower_webhook_log_size {len(wlog)}')

    # ── v3.4.1: fleet health score ──────────────────────────────────────────────
    health = ctx.get('health') or {}
    if health:
        lines.append('# HELP remotepower_fleet_health_score Fleet health score (0-100).')
        lines.append('# TYPE remotepower_fleet_health_score gauge')
        lines.append(f"remotepower_fleet_health_score {health.get('score', 100)}")
        lines.append('# HELP remotepower_device_health_score Per-device health score (0-100).')
        lines.append('# TYPE remotepower_device_health_score gauge')
        for d in health.get('devices', []):
            # v6.4.2: key on the device ID like every other per-device family
            # here. This one carried the operator-editable DISPLAY NAME in the
            # `device` label: two hosts sharing a name (cloned images, default
            # `raspberrypi`/`localhost`, multi-site estates) emitted the same
            # series identity twice, so Prometheus dropped one of them as a
            # duplicate sample and that host had no health score at all — and
            # even with unique names no `on(device)` join against
            # remotepower_device_online/cpu/cve could ever match.
            lines.append(_metric('remotepower_device_health_score',
                         {'device': d.get('device_id', ''),
                          'name':   d.get('device_name') or d.get('device_id', '')},
                         d.get('score', 100)))
        counts = health.get('counts') or {}
        lines.append('# HELP remotepower_attention_items Needs-attention items by severity.')
        lines.append('# TYPE remotepower_attention_items gauge')
        for sev in ('critical', 'warning', 'info'):
            lines.append(_metric('remotepower_attention_items', {'severity': sev},
                                 counts.get(sev, 0)))

    # ── v3.4.1: timeline event counts (last 24h, by kind) ────────────────────────
    evs = (ctx.get('fleet_events') or {}).get('events') or []
    cutoff = now - 86400
    by_kind = {}
    for e in evs:
        if not isinstance(e, dict):
            continue   # v4.4.0: skip a malformed event record
        if (e.get('ts') or 0) >= cutoff:
            k = e.get('event', '') or 'unknown'
            by_kind[k] = by_kind.get(k, 0) + 1
    if by_kind:
        lines.append('# HELP remotepower_timeline_events_24h Fleet events in the last 24h by kind.')
        lines.append('# TYPE remotepower_timeline_events_24h gauge')
        for k, v in sorted(by_kind.items()):
            lines.append(_metric('remotepower_timeline_events_24h', {'event': k}, v))

    # ── v3.4.1: CVEs a pending patch would fix ───────────────────────────────────
    cf = ctx.get('cve_fixable_total')
    if cf is not None:
        lines.append('# HELP remotepower_cve_fixable_total Critical/high CVEs a pending patch would fix.')
        lines.append('# TYPE remotepower_cve_fixable_total gauge')
        lines.append(f'remotepower_cve_fixable_total {cf}')

    # v5.4.1 (F3): availability SLO + error-budget per monitor (for Grafana SLO
    # dashboards / burn-rate alerts).
    slo = ctx.get('slo')
    if isinstance(slo, dict):
        lines.append('# HELP remotepower_slo_target_percent Configured availability SLO target.')
        lines.append('# TYPE remotepower_slo_target_percent gauge')
        lines.append(f'remotepower_slo_target_percent {float(slo.get("target") or 0)}')
        mons = slo.get('monitors') or []
        if mons:
            lines.append('# HELP remotepower_monitor_availability_percent Monitor availability over the recent check window.')
            lines.append('# TYPE remotepower_monitor_availability_percent gauge')
            for m in mons:
                lines.append(_metric('remotepower_monitor_availability_percent',
                                     {'label': str(m.get('label', ''))}, float(m.get('availability') or 0)))
        # v6.4.2: monitors whose check window is too coarse to resolve the SLO
        # target are skipped — the budget there is binary (100 or 0), so the
        # gauge would flip a service that was up 99.67% straight to "budget
        # exhausted". Same reasoning as the no-data object skip below.
        budget_mons = [m for m in mons if m.get('budget_measurable') is not False]
        if budget_mons:
            lines.append('# HELP remotepower_monitor_slo_budget_remaining_percent Error budget remaining for the monitor (omitted while the check window is too short to resolve the target).')
            lines.append('# TYPE remotepower_monitor_slo_budget_remaining_percent gauge')
            for m in budget_mons:
                lines.append(_metric('remotepower_monitor_slo_budget_remaining_percent',
                                     {'label': str(m.get('label', ''))}, float(m.get('budget_remaining_pct') or 0)))
            lines.append('# HELP remotepower_monitor_slo_burn_rate Error-budget burn rate (>1 = over budget).')
            lines.append('# TYPE remotepower_monitor_slo_burn_rate gauge')
            for m in budget_mons:
                lines.append(_metric('remotepower_monitor_slo_burn_rate',
                                     {'label': str(m.get('label', ''))}, float(m.get('burn_rate') or 0)))
        # v6.4.0: named SLA/SLO objects (monitor attachments, per-object window).
        # Objects with no measured checks yet are skipped — a 0 would read as a
        # hard breach on a freshly-created object.
        slo_objs = [o for o in (slo.get('objects') or [])
                    if isinstance(o, dict) and o.get('availability') is not None]
        if slo_objs:
            lines.append('# HELP remotepower_slo_object_target_percent Availability target of the SLA/SLO object.')
            lines.append('# TYPE remotepower_slo_object_target_percent gauge')
            for o in slo_objs:
                lines.append(_metric('remotepower_slo_object_target_percent',
                                     {'name': str(o.get('name', ''))}, float(o.get('target') or 0)))
            lines.append('# HELP remotepower_slo_object_availability_percent Check-weighted availability of the attached monitors over the object window.')
            lines.append('# TYPE remotepower_slo_object_availability_percent gauge')
            for o in slo_objs:
                lines.append(_metric('remotepower_slo_object_availability_percent',
                                     {'name': str(o.get('name', ''))}, float(o.get('availability') or 0)))
            # v6.4.2: same unmeasurable-window skip as the per-monitor budget.
            budget_objs = [o for o in slo_objs if o.get('budget_measurable') is not False]
            if budget_objs:
                lines.append('# HELP remotepower_slo_object_budget_remaining_percent Error budget remaining for the SLA/SLO object (omitted while the window holds too few checks to resolve the target).')
                lines.append('# TYPE remotepower_slo_object_budget_remaining_percent gauge')
                for o in budget_objs:
                    lines.append(_metric('remotepower_slo_object_budget_remaining_percent',
                                         {'name': str(o.get('name', ''))}, float(o.get('budget_remaining_pct') or 0)))

    # v5.4.1 (G3): observed control-plane availability over rolling windows.
    # A gap is downtime OR a quiet hour with zero traffic (see the API note).
    cu = ctx.get('control_uptime')
    if isinstance(cu, dict) and cu.get('tracking'):
        wins = cu.get('windows') or {}
        if wins:
            lines.append('# HELP remotepower_control_plane_uptime_percent Observed hours the control plane served a request, over hours tracked.')
            lines.append('# TYPE remotepower_control_plane_uptime_percent gauge')
            for label, w in sorted(wins.items()):
                if isinstance(w, dict):
                    lines.append(_metric('remotepower_control_plane_uptime_percent',
                                         {'window': str(label)}, float(w.get('percent') or 0)))

    # ── v6.4.2: hardware telemetry (temperature / SMART / UPS) ─────────────────
    # These have driven the product's own alerts, drawers and risk score since
    # v3.14.0/v4.1.0 but never reached the exporter, so a Grafana user could not
    # alert on a failing drive or a UPS on battery from RemotePower's own
    # metrics. Each block is skipped entirely when the caller does not supply
    # the store, exactly like `health`/`slo` above.
    hardware = ctx.get('hardware')
    if hardware:
        _emit_temperatures(lines, devices, hardware)
        _emit_smart(lines, devices, hardware)
        _emit_ups(lines, devices, hardware)

    # ── v6.4.2: backup freshness ───────────────────────────────────────────────
    backup_state = ctx.get('backup_state')
    if backup_state:
        _emit_backups(lines, devices, backup_state, ctx.get('backup_monitors'))

    # ── v6.4.2: predicted disk-fill ────────────────────────────────────────────
    eta = ctx.get('disk_fill_eta')
    if isinstance(eta, dict) and eta:
        lines.append('# HELP remotepower_device_disk_fill_eta_seconds Predicted time until a filesystem reaches 100%; only emitted for hosts already trending full.')
        lines.append('# TYPE remotepower_device_disk_fill_eta_seconds gauge')
        for dev_id, days in eta.items():
            v = _num(days)
            if v is None:
                continue
            lines.append(_metric('remotepower_device_disk_fill_eta_seconds',
                                 _dev_labels(devices, str(dev_id)),
                                 round(v * 86400.0)))

    # ── v6.4.2: risk and reliability lenses ────────────────────────────────────
    # Both are separate from fleet health on purpose (health = Needs-Attention,
    # risk = security posture, reliability = predicted hardware failure), so
    # they get their own families rather than folding into the health score.
    risk = ctx.get('risk')
    if risk:
        _emit_scored_rollup(
            lines, devices, risk,
            'remotepower_device_risk_score', 'remotepower_risk_devices',
            'Per-device security-posture risk score (0-100, higher is worse).',
            'Devices per risk level.')
    reliability = ctx.get('reliability')
    if reliability:
        _emit_scored_rollup(
            lines, devices, reliability,
            'remotepower_device_reliability_score', 'remotepower_reliability_devices',
            'Per-device predicted failure likelihood (0-100, higher is worse).',
            'Devices per failure-likelihood level.')

    # ── v6.4.2: baseline compliance ────────────────────────────────────────────
    compliance = ctx.get('compliance')
    if isinstance(compliance, dict) and compliance:
        _emit_compliance(lines, devices, compliance)

    # Trailing newline per spec
    lines.append('')
    return '\n'.join(lines)


# ── Shared helpers for the v6.4.2 families ────────────────────────────────────

def _num(value):
    """A finite float, or None for anything that is not a usable sample.

    A NaN/inf sample, or a value Prometheus cannot parse, makes the WHOLE
    scrape invalid — not just that line — so a junk field has to vanish rather
    than be emitted. Numeric strings are accepted because these stores are
    hand-editable JSON as well as agent-written.
    """
    if isinstance(value, bool) or value is None:
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def _as_items(store):
    """Yield (key, record) over a store that may be a dict-of-id OR a list.

    Every store below is loaded api-side with `load(FILE) or {}` and the risk /
    reliability / compliance rollups are lists of rows, so normalise once here
    instead of guessing per call site. Non-dict rows are dropped: a single
    corrupt record must never break the scrape for the whole fleet.
    """
    if isinstance(store, dict):
        for k, v in store.items():
            if isinstance(v, dict):
                yield str(k), v
    elif isinstance(store, list):
        for v in store:
            if isinstance(v, dict):
                yield str(v.get('device_id') or v.get('id') or ''), v


def _dev_labels(devices, dev_id, extra=None):
    """The {device,name,group} identity every per-device family here shares.

    Keyed on the device ID, never the display name: two hosts can carry the
    same name (cloned images, a default `raspberrypi`) and Prometheus then
    drops one of them as a duplicate series — the v6.4.2 device_health_score
    bug. `name` stays as a decorative label for dashboards.
    """
    d = devices.get(dev_id) or {}
    labels = {'device': dev_id, 'name': d.get('name', dev_id),
              'group': d.get('group', '')}
    if extra:
        labels.update(extra)
    return labels


def _uniq(seen, base):
    """Disambiguate a repeated discriminator label (twin CPU packages, two
    identical NVMe models). Prometheus silently drops a duplicate series, so
    suffixing is the difference between reporting both sensors and losing one.
    """
    name, n = base, 1
    while name in seen:
        n += 1
        name = f'{base} #{n}'
    seen.add(name)
    return name


def _temp_readings(rec):
    """(sensor, celsius) pairs out of one hardware.json record.

    Mirrors what the server treats as thermal input for temp_high: board
    sensors live one level down under `hardware.temps` (reading them flat
    yields [] on every real agent-reported host — the v6.4.1 _hw_temps fix),
    while SMART drives and GPUs sit at the record's top level.
    """
    nested = rec.get('hardware')
    temps = nested.get('temps') if isinstance(nested, dict) else None
    if not isinstance(temps, list):
        temps = rec.get('temps')          # pre-v6.4.1 records / seeded demo data
    if isinstance(temps, list):
        for t in temps:
            if isinstance(t, dict):
                yield str(t.get('label') or 'sensor'), t.get('current_c')
    smart = rec.get('smart')
    if isinstance(smart, list):
        for d in smart:
            if isinstance(d, dict) and d.get('temperature_c') is not None:
                yield f"disk:{d.get('device') or 'unknown'}", d.get('temperature_c')
    gpus = rec.get('gpus')
    if isinstance(gpus, list):
        for g in gpus:
            if isinstance(g, dict) and g.get('temp_c') is not None:
                yield f"gpu:{g.get('name') or 'gpu'}", g.get('temp_c')


def _emit_temperatures(lines, devices, hardware):
    lines.append('# HELP remotepower_device_temperature_celsius Sensor temperature; sensor is the board sensor label, disk:<dev> for a SMART drive, or gpu:<name>.')
    lines.append('# TYPE remotepower_device_temperature_celsius gauge')
    hottest = {}
    for dev_id, rec in _as_items(hardware):
        seen = set()
        for sensor, raw in _temp_readings(rec):
            v = _num(raw)
            if v is None:
                continue
            hottest[dev_id] = max(hottest.get(dev_id, v), v)
            lines.append(_metric('remotepower_device_temperature_celsius',
                                 _dev_labels(devices, dev_id,
                                             {'sensor': _uniq(seen, sensor)}), v))
    lines.append('# HELP remotepower_device_temperature_max_celsius Hottest reading across board sensors, SMART drives and GPUs.')
    lines.append('# TYPE remotepower_device_temperature_max_celsius gauge')
    for dev_id, v in hottest.items():
        lines.append(_metric('remotepower_device_temperature_max_celsius',
                             _dev_labels(devices, dev_id), v))


def _emit_smart(lines, devices, hardware):
    """Per-drive SMART health and the pre-fail counters behind it."""
    rows = []          # (device_id, disk label, entry)
    failed = {}
    for dev_id, rec in _as_items(hardware):
        disks = rec.get('smart')
        if not isinstance(disks, list):
            continue
        failed.setdefault(dev_id, 0)
        seen = set()
        for d in disks:
            if not isinstance(d, dict):
                continue
            rows.append((dev_id, _uniq(seen, str(d.get('device') or 'unknown')), d))
            if d.get('failed'):
                failed[dev_id] += 1
    if not rows and not failed:
        return
    # `failed` is the verdict the server persists on ingest (_smart_disk_failed
    # is the one source of truth for the alert, the NA digest and the badge) —
    # re-deriving the rule here would be a second copy free to drift.
    lines.append('# HELP remotepower_device_smart_disk_healthy Whether the drive passes the server-side SMART verdict (1/0).')
    lines.append('# TYPE remotepower_device_smart_disk_healthy gauge')
    for dev_id, disk, d in rows:
        lines.append(_metric('remotepower_device_smart_disk_healthy',
                             _dev_labels(devices, dev_id,
                                         {'disk': disk,
                                          'model': str(d.get('model') or '')}),
                             int(not d.get('failed'))))

    lines.append('# HELP remotepower_device_smart_disks_failed Drives currently failing the SMART verdict on this host.')
    lines.append('# TYPE remotepower_device_smart_disks_failed gauge')
    for dev_id, n in failed.items():
        lines.append(_metric('remotepower_device_smart_disks_failed',
                             _dev_labels(devices, dev_id), n))

    for name, key, help_text, scale in (
        ('remotepower_device_smart_reallocated_sectors', 'reallocated_sectors',
         'Reallocated sector count (a growing value is a dying drive).', 1),
        ('remotepower_device_smart_pending_sectors', 'pending_sectors',
         'Sectors pending reallocation.', 1),
        ('remotepower_device_smart_power_on_seconds', 'power_on_hours',
         'Drive power-on time.', 3600),
    ):
        lines.append(f'# HELP {name} {help_text}')
        lines.append(f'# TYPE {name} gauge')
        for dev_id, disk, d in rows:
            v = _num(d.get(key))
            if v is None:
                continue
            lines.append(_metric(name, _dev_labels(devices, dev_id, {'disk': disk}),
                                 round(v * scale)))

    # wear_pct / spare_pct are percentages in the store; the exposition carries
    # base units, so they go out as 0-1 ratios.
    for name, key, help_text in (
        ('remotepower_device_smart_wear_ratio', 'wear_pct',
         'Share of the flash write endurance consumed (0-1).'),
        ('remotepower_device_smart_spare_ratio', 'spare_pct',
         'Share of the NVMe remap reserve still available (0-1).'),
    ):
        lines.append(f'# HELP {name} {help_text}')
        lines.append(f'# TYPE {name} gauge')
        for dev_id, disk, d in rows:
            v = _num(d.get(key))
            if v is None:
                continue
            lines.append(_metric(name, _dev_labels(devices, dev_id, {'disk': disk}),
                                 round(v / 100.0, 4)))


def _emit_ups(lines, devices, hardware):
    """UPS / power state. `status` is the raw NUT-style flag string; the
    on-battery gauge applies the same OB/BATT test the ups_on_battery alert
    does so a dashboard and an alert can never disagree."""
    rows = []
    for dev_id, rec in _as_items(hardware):
        upses = rec.get('ups')
        if not isinstance(upses, list):
            continue
        seen = set()
        for u in upses:
            if isinstance(u, dict):
                rows.append((dev_id, _uniq(seen, str(u.get('name') or 'ups')), u))
    if not rows:
        return
    lines.append('# HELP remotepower_ups_on_battery Whether the UPS is running on battery rather than line power (1/0).')
    lines.append('# TYPE remotepower_ups_on_battery gauge')
    for dev_id, ups, u in rows:
        status = str(u.get('status') or '').upper()
        lines.append(_metric('remotepower_ups_on_battery',
                             _dev_labels(devices, dev_id, {'ups': ups}),
                             int('OB' in status or 'BATT' in status)))

    for name, key, help_text, scale in (
        ('remotepower_ups_battery_charge_ratio', 'battery_pct',
         'Battery charge remaining (0-1).', 0.01),
        ('remotepower_ups_load_ratio', 'load_pct',
         'Output load as a share of the UPS rating (0-1).', 0.01),
        ('remotepower_ups_runtime_seconds', 'runtime_s',
         'Estimated runtime left on battery.', 1),
        ('remotepower_ups_input_volts', 'input_v', 'Input line voltage.', 1),
        ('remotepower_ups_power_watts', 'power_w', 'Output power draw.', 1),
    ):
        lines.append(f'# HELP {name} {help_text}')
        lines.append(f'# TYPE {name} gauge')
        for dev_id, ups, u in rows:
            v = _num(u.get(key))
            if v is None:
                continue
            lines.append(_metric(name, _dev_labels(devices, dev_id, {'ups': ups}),
                                 round(v * scale, 4)))


def _emit_backups(lines, devices, state, monitors):
    """Per-device backup freshness.

    backup_state.json is keyed `<device_id>:<path>` — iterating it without
    splitting hands every host every other host's rows (the bug documented on
    posture_signals.stale_backups_by_device).
    """
    thresholds = {}
    if isinstance(monitors, list):
        for m in monitors:
            if isinstance(m, dict) and m.get('path'):
                h = _num(m.get('max_age_hours'))
                if h is not None:
                    thresholds[str(m['path'])] = h
    rows = []
    for key, entry in _as_items(state):
        if ':' not in key:
            continue
        dev_id, path = key.split(':', 1)
        rows.append((dev_id, path or 'unknown', entry))
    if not rows:
        return
    lines.append('# HELP remotepower_backup_ok Whether the watched backup path is present and fresh enough (1/0).')
    lines.append('# TYPE remotepower_backup_ok gauge')
    for dev_id, path, entry in rows:
        lines.append(_metric('remotepower_backup_ok',
                             _dev_labels(devices, dev_id, {'path': path}),
                             int(bool(entry.get('ok', True)))))

    lines.append('# HELP remotepower_backup_age_seconds Age of the newest file at the watched backup path.')
    lines.append('# TYPE remotepower_backup_age_seconds gauge')
    for dev_id, path, entry in rows:
        v = _num(entry.get('age_h'))
        if v is None:
            continue
        lines.append(_metric('remotepower_backup_age_seconds',
                             _dev_labels(devices, dev_id, {'path': path}),
                             round(v * 3600.0)))

    # Only emitted where a configured monitor names the path, so an alert rule
    # comparing the two never silently compares against an invented default.
    lines.append('# HELP remotepower_backup_max_age_seconds Configured freshness threshold for the watched backup path.')
    lines.append('# TYPE remotepower_backup_max_age_seconds gauge')
    for dev_id, path, _entry in rows:
        if path not in thresholds:
            continue
        lines.append(_metric('remotepower_backup_max_age_seconds',
                             _dev_labels(devices, dev_id, {'path': path}),
                             round(thresholds[path] * 3600.0)))


def _emit_scored_rollup(lines, devices, rows, score_name, count_name,
                        score_help, count_help):
    """A {device: score} family plus a {level: n} rollup.

    The risk and reliability lenses share a row shape ({device_id, score,
    level}) and differ only in the field the display name lands in — risk rows
    carry `device_name`, reliability rows carry `name`.
    """
    counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
    lines.append(f'# HELP {score_name} {score_help}')
    lines.append(f'# TYPE {score_name} gauge')
    seen = set()
    for _key, row in _as_items(rows):
        dev_id = str(row.get('device_id') or '')
        if not dev_id or dev_id in seen:
            continue
        seen.add(dev_id)
        lvl = str(row.get('level') or '')
        if lvl:
            counts[lvl] = counts.get(lvl, 0) + 1
        v = _num(row.get('score'))
        if v is None:
            continue
        labels = _dev_labels(devices, dev_id)
        if dev_id not in devices:
            # The rollup can outlive its device row by up to the cache TTL.
            labels['name'] = row.get('device_name') or row.get('name') or dev_id
        lines.append(_metric(score_name, labels, v))
    lines.append(f'# HELP {count_name} {count_help}')
    lines.append(f'# TYPE {count_name} gauge')
    for lvl in sorted(counts):
        lines.append(_metric(count_name, {'level': lvl}, counts[lvl]))


def _emit_compliance(lines, devices, report):
    """Baseline (CIS-style) compliance: the fleet ratio, the per-device ratio,
    and per-check device counts so a dashboard can name the failing control."""
    score = _num(report.get('score'))
    if score is not None:
        lines.append('# HELP remotepower_compliance_pass_ratio Severity-weighted share of baseline checks passing fleet-wide (0-1).')
        lines.append('# TYPE remotepower_compliance_pass_ratio gauge')
        lines.append(f'remotepower_compliance_pass_ratio {round(score / 100.0, 4)}')

    evaluated = _num(report.get('devices_evaluated'))
    if evaluated is not None:
        lines.append('# HELP remotepower_compliance_devices_evaluated Devices with enough telemetry for the baseline to be evaluated.')
        lines.append('# TYPE remotepower_compliance_devices_evaluated gauge')
        lines.append(f'remotepower_compliance_devices_evaluated {int(evaluated)}')

    dev_rows = list(_as_items(report.get('devices')))
    if dev_rows:
        lines.append('# HELP remotepower_device_compliance_pass_ratio Share of applicable baseline checks this host passes (0-1).')
        lines.append('# TYPE remotepower_device_compliance_pass_ratio gauge')
        seen = set()
        for _key, r in dev_rows:
            dev_id = str(r.get('device_id') or '')
            # pct is null when no check applied to the host — a 0 there would
            # read as total failure on a dashboard, so the sample is omitted.
            v = _num(r.get('pct'))
            if not dev_id or dev_id in seen or v is None:
                continue
            seen.add(dev_id)
            lines.append(_metric('remotepower_device_compliance_pass_ratio',
                                 _dev_labels(devices, dev_id), round(v / 100.0, 4)))

    checks = list(_as_items(report.get('checks')))
    if checks:
        lines.append('# HELP remotepower_compliance_check_devices Devices per outcome for one baseline check (result: pass, fail or na).')
        lines.append('# TYPE remotepower_compliance_check_devices gauge')
        for _key, c in checks:
            cid = str(c.get('id') or '')
            if not cid:
                continue
            sev = str(c.get('severity') or 'unknown')
            for result in ('pass', 'fail', 'na'):
                n = _num(c.get(result))
                if n is None:
                    continue
                lines.append(_metric('remotepower_compliance_check_devices',
                                     {'check': cid, 'severity': sev,
                                      'result': result}, int(n)))


def _emit_metric_family(lines, devices, metric_name, help_text, extractor):
    """Helper to emit a gauge per device when the extractor returns a value."""
    lines.append(f'# HELP {metric_name} {help_text}')
    lines.append(f'# TYPE {metric_name} gauge')
    for dev_id, d in devices.items():
        val = extractor(d)
        if val is None:
            continue
        lines.append(_metric(
            metric_name,
            {'device': dev_id, 'name': d.get('name', dev_id), 'group': d.get('group', '')},
            val,
        ))
