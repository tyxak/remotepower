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

Uptime tracking, user counts, and api key counts can be added later if needed.
"""

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
    """
    lines = []
    now         = ctx['now']
    online_ttl  = ctx['online_ttl']
    devices     = ctx['devices']
    version     = ctx['server_version']

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

    # Trailing newline per spec
    lines.append('')
    return '\n'.join(lines)


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
