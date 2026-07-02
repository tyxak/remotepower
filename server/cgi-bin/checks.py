"""RemotePower — the per-host Checks engine (pure).

_host_checks(dev_id, dev, ...) is THE one place every check row is built
(reachability, resources, posture, hardware, custom checks, custom-script
results — see CLAUDE.md "Per-host Checks engine"). handle_device_checks,
handle_fleet_checks and the checksrollup dashboard widget all call it
through api.py, which threads every input in (cve_high, disk_eta,
custom_defs, scripts, exposure_mutes, ...) — nothing here touches storage,
the request, or the network, which is what makes the engine unit-testable
and lets the three callers stay consistent by construction.

Custom checks split into SERVER_CHECK_TYPES (process/port — evaluated here
in _eval_custom_check against the reported sysinfo) and AGENT_CHECK_TYPES
(file/job/log/unit — pushed to the agent in the heartbeat `agent_checks`
key, evaluated by the agent's eval_agent_checks, reported back in
sysinfo.custom_check_results).

Carved out of api.py (same model as notify.py / integrations.py /
hypervisor.py); api.py re-binds these names for its call sites and the
test suite. Part of the Makefile LINT + TYPECHECK baseline.
"""
import time


def _exposure_muted(process, proto, port, mutes, device_id=None):
    """True if a (process, proto, port) socket matches any exposure-mute rule.
    A rule is a dict with any subset of {device_id, process, proto, port}; a
    socket matches a rule when every field the rule specifies equals the
    socket's. A rule with only `device_id` mutes ALL exposure from that host. An
    empty rule matches nothing (so it can't accidentally silence everything)."""
    for m in mutes or []:
        if not isinstance(m, dict):
            continue
        if not any(k in m for k in ('device_id', 'process', 'proto', 'port')):
            continue
        if 'device_id' in m and (m.get('device_id') or '') != (device_id or ''):
            continue
        if 'process' in m and (m.get('process') or '') != (process or ''):
            continue
        if 'proto' in m and (m.get('proto') or '') != (proto or ''):
            continue
        if 'port' in m:
            try:
                if int(m.get('port')) != int(port or 0):
                    continue
            except (TypeError, ValueError):
                continue
        return True
    return False

def _host_checks(dev_id, dev, hw_rec=None, disabled=None, now=0, ttl=180,
                 cve_high=None, disk_eta=None, custom_defs=None, scripts=None,
                 exposure_mutes=None):
    """v4.1.0: unified per-host check list for the CheckMK-style Checks view.

    Each entry: {key, name, group, status: ok|warning|critical|unknown, output,
    enabled}. Derived entirely from data RemotePower already collects (sysinfo,
    metric_state, hardware flags, drift) — no new probing. `disabled` is the set
    of check keys the operator turned off for this host.
    """
    hw_rec = hw_rec or {}
    disabled = set(disabled or [])
    si = dev.get('sysinfo') or {}
    ms = dev.get('metric_state') or {}
    now = now or int(time.time())
    out = []

    def add(key, name, group, status, output):
        out.append({'key': key, 'name': name, 'group': group, 'status': status,
                    'output': str(output)[:200], 'enabled': key not in disabled})

    def lvl(state_key):
        v = ms.get(state_key)
        return v if v in ('warning', 'critical') else 'ok'

    # ── core reachability ──────────────────────────────────────────────
    last = dev.get('last_seen', 0)
    if last:
        age = now - last
        add('reachability', 'Reachability', 'core',
            'critical' if age > ttl else 'ok',
            f'offline {age // 60} min' if age > ttl else f'online, {age}s ago')
    else:
        add('reachability', 'Reachability', 'core', 'unknown', 'never reported')

    # ── resource thresholds (reuse metric_state; show current value) ───
    if isinstance(si.get('loadavg_1m'), (int, float)):
        cc = si.get('cpu_count') or 1
        la = si['loadavg_1m']
        add('cpu', 'CPU load', 'resources', lvl('cpu:'),
            f'load {la:.2f} (ratio {la / (cc or 1):.2f}, {cc} cores)')
    for key, name, field in (('memory', 'Memory', 'mem_percent'),
                             ('swap', 'Swap', 'swap_percent'),
                             ('fd', 'File descriptors', 'fd_percent'),
                             ('conntrack', 'Conntrack table', 'conntrack_percent')):
        v = si.get(field)
        if isinstance(v, (int, float)):
            add(key, name, 'resources', lvl(f'{key}:'), f'{v:.0f}%')
    for m in (si.get('mounts') or []):
        p = m.get('path')
        if not p:
            continue
        if isinstance(m.get('percent'), (int, float)):
            add(f'disk:{p}', f'Disk {p}', 'storage', lvl(f'disk:{p}'),
                f"{m['percent']:.0f}% used")
        if isinstance(m.get('inode_percent'), (int, float)):
            add(f'inode:{p}', f'Inodes {p}', 'storage', lvl(f'inode:{p}'),
                f"{m['inode_percent']:.0f}% used")

    # ── boolean / state checks ─────────────────────────────────────────
    fu = si.get('failed_units') or []
    add('services', 'Systemd units', 'services', 'critical' if fu else 'ok',
        f'{len(fu)} failed: ' + ', '.join(fu[:5]) if fu else 'all active')
    ti = [t for t in (si.get('timers') or []) if isinstance(t, dict) and t.get('failed')]
    if si.get('timers') is not None:
        add('timers', 'Scheduled timers', 'services', 'warning' if ti else 'ok',
            f'{len(ti)} failed' if ti else 'all ok')
    drifted = [f for f, s in (dev.get('drift_state') or {}).items()
               if isinstance(s, dict) and s.get('status') == 'drifted' and not s.get('ignored')]
    if dev.get('drift_state'):
        add('drift', 'Config drift', 'posture', 'warning' if drifted else 'ok',
            f'{len(drifted)} file(s) drifted' if drifted else 'baseline matches')
    mi = si.get('mount_issues') or []
    if mi:
        add('mounts', 'Mount points', 'storage', 'critical', f'{len(mi)} issue(s)')
    # v4.1.0: respect exposure mutes (set on the Exposed page) — a world port the
    # operator has muted there must not re-appear as a warning check here.
    wp = [p for p in (si.get('listening_ports') or [])
          if (p or {}).get('scope') == 'world'
          and not _exposure_muted(p.get('process'), p.get('proto'), p.get('port'),
                                  exposure_mutes or [], dev_id)]
    if si.get('listening_ports') is not None:
        add('exposure', 'World-exposed ports', 'posture', 'warning' if wp else 'ok',
            f'{len(wp)} world-reachable' if wp else 'none')
    if si.get('reboot_required'):
        add('reboot', 'Reboot required', 'patch', 'warning',
            si.get('reboot_reason') or 'pending')
    up = (si.get('packages') or {}).get('upgradable')
    if isinstance(up, int):
        # v5.0.0: surface the distro's own SECURITY-flagged count. The vendor
        # saying "patch now" is the highest-signal update state, so a host with
        # pending security updates is a warning even when the total is small.
        sec = (si.get('packages') or {}).get('security_updates')
        sec = sec if isinstance(sec, int) else None
        if sec:
            detail = f'{up} update(s), {sec} security'
        else:
            detail = f'{up} update(s)'
        add('patches', 'Pending updates', 'patch',
            'warning' if (up > 0 or sec) else 'ok', detail)
    if cve_high is not None:
        add('cve', 'CVEs (crit+high)', 'security', 'critical' if cve_high else 'ok',
            f'{cve_high} finding(s)')

    # ── hardware / posture flags (from the hardware record + sysinfo) ──
    if hw_rec.get('_smart_failed') is not None or hw_rec.get('smart'):
        add('smart', 'Disk SMART', 'hardware',
            'critical' if hw_rec.get('_smart_failed') else 'ok',
            'a disk FAILED' if hw_rec.get('_smart_failed') else 'all passing')
    if hw_rec.get('_ups_on_battery') is not None or hw_rec.get('ups'):
        add('ups', 'UPS power', 'hardware',
            'critical' if hw_rec.get('_ups_on_battery') else 'ok',
            'on battery' if hw_rec.get('_ups_on_battery') else 'on line')
    if hw_rec.get('_temp_high') is not None or hw_rec.get('hardware', {}).get('temps'):
        add('temperature', 'Temperature', 'hardware',
            'critical' if hw_rec.get('_temp_high') else 'ok',
            'over threshold' if hw_rec.get('_temp_high') else 'normal')
    clk = si.get('clock')
    if isinstance(clk, dict):
        sk = clk.get('skewed')
        add('clock', 'Clock / NTP', 'core', 'warning' if sk else 'ok',
            ('unsynchronised' if clk.get('synced') is False else 'drifted') if sk
            else 'in sync')
    gw = si.get('gateway')
    if isinstance(gw, dict):
        reach = gw.get('reachable')
        add('gateway', 'Default gateway', 'network',
            'critical' if reach is False else ('unknown' if reach is None else 'ok'),
            f"{gw.get('ip','?')}: " + ('unreachable' if reach is False
                                       else 'unknown' if reach is None else 'reachable'))
    lo = si.get('last_oom_ts')
    if isinstance(lo, (int, float)) and lo > 0:
        recent = (now - lo) < 86400
        add('oom', 'OOM killer', 'core', 'warning' if recent else 'ok',
            'fired in last 24h' if recent else f'last {(now - lo) // 86400}d ago')
    # v4.1.0: mail queue depth (agent reads postfix/sendmail/exim mailq).
    mq = si.get('mailq')
    if isinstance(mq, (int, float)):
        # v4.2.0 sweep: thresholds come from the standard metric_thresholds
        # store (settable in the Thresholds modal); the old 'mailq_thresholds'
        # key never had a writer but is honoured for hand-edited stores.
        mto = dev.get('metric_thresholds') or {}
        legacy = dev.get('mailq_thresholds') or {}
        warn = mto.get('mailq_warn_count', legacy.get('warn', 50))
        crit = mto.get('mailq_crit_count', legacy.get('crit', 500))
        add('mailq', 'Mail queue', 'services',
            'critical' if mq >= crit else 'warning' if mq >= warn else 'ok',
            f'{int(mq)} message(s) queued')
    # v4.1.0: a local filesystem the kernel remounted read-only = silent outage.
    ro_mounts = [m.get('path') for m in (si.get('mounts') or [])
                 if isinstance(m, dict) and m.get('ro') and not m.get('network')]
    if any(isinstance(m, dict) and 'ro' in m for m in (si.get('mounts') or [])):
        add('readonly_fs', 'Read-only filesystems', 'storage',
            'warning' if ro_mounts else 'ok',
            (', '.join(p for p in ro_mounts if p)[:180] + ' read-only')
            if ro_mounts else 'all read-write')
    # v4.1.0: disk-fill ETA (linear trend over the time-series; near-full only).
    if isinstance(disk_eta, (int, float)):
        add('disk_eta', 'Disk fill ETA', 'storage',
            'critical' if disk_eta <= 2 else 'warning' if disk_eta <= 7 else 'ok',
            f'~{disk_eta:.1f} day(s) to full at current trend')
    pools = si.get('storage_health') or []
    if pools:
        bad = [p for p in pools if isinstance(p, dict)
               and (p.get('state') or '').lower() not in
               ('online', 'active', 'clean', 'healthy', 'ok')]
        add('storage', 'Storage / RAID', 'storage', 'critical' if bad else 'ok',
            f'{len(bad)} pool(s) degraded' if bad else f'{len(pools)} pool(s) healthy')
    # v4.1.0: operator-defined custom checks (process/port), scoped to this host.
    if custom_defs:
        out.extend(_custom_checks_for(dev_id, dev, custom_defs, disabled))
    # v4.1.0: custom monitoring-script results surfaced as checks (pass/fail).
    if scripts:
        for sid, res in (dev.get('custom_script_results') or {}).items():
            if not isinstance(res, dict):
                continue
            name = (scripts.get(sid) or {}).get('name') or sid
            okv = res.get('ok')
            status = 'unknown' if okv is None else ('ok' if okv else 'critical')
            last = ''
            if res.get('output'):
                parts = str(res['output']).strip().splitlines()
                last = parts[-1] if parts else ''
            add(f'script:{sid}', f'Script: {name}', 'script', status,
                last or ('passed' if okv else 'failed'))
    return out

# ── Custom checks (v4.1.0) ──────────────────────────────────────────────────
# Operator-defined checks assignable to a single host, a tag, a group, or the
# whole fleet. SERVER_CHECK_TYPES are evaluated here from data the agent already
# reports; AGENT_CHECK_TYPES are pushed to the agent (in the heartbeat response),
# evaluated on-host, and reported back in sysinfo['custom_check_results'].
SERVER_CHECK_TYPES = ('process', 'port_open', 'port_closed')

AGENT_CHECK_TYPES = ('file_present', 'file_absent', 'log_errors', 'job_fresh', 'systemd_unit')

def _custom_check_applies(cdef, dev_id, dev):
    """True if a custom-check definition targets this device."""
    tk = cdef.get('target_kind', 'all')
    tv = str(cdef.get('target', ''))
    if tk == 'all':
        return True
    if tk == 'host':
        return dev_id == tv
    if tk == 'tag':
        return tv in [str(t) for t in (dev.get('tags') or [])]
    if tk == 'group':
        return str(dev.get('group', '')) == tv
    return False

def _eval_custom_check(cdef, dev):
    """Evaluate one custom check against a device's reported sysinfo.
    Returns (status, output). Unknown/missing data → 'unknown'."""
    si = dev.get('sysinfo') or {}
    ctype = cdef.get('type')
    param = str(cdef.get('param', '')).strip()
    if ctype == 'process':
        names = si.get('proc_names')
        if not isinstance(names, list):
            return 'unknown', 'no process data reported'
        hit = any(param == n or param.lower() in n.lower() for n in names)
        return ('ok', f'"{param}" running') if hit else ('critical', f'"{param}" not running')
    if ctype in ('port_open', 'port_closed'):
        ports = si.get('listening_ports')
        if not isinstance(ports, list):
            return 'unknown', 'no port data reported'
        try:
            want = int(param)
        except (TypeError, ValueError):
            return 'unknown', f'invalid port "{param}"'
        listening = any(int(p.get('port', -1)) == want
                        for p in ports if isinstance(p, dict))
        if ctype == 'port_open':
            return ('ok', f'port {want} open') if listening else ('critical', f'port {want} closed')
        return ('critical', f'port {want} unexpectedly open') if listening else ('ok', f'port {want} closed')
    if ctype in AGENT_CHECK_TYPES:
        # Evaluated on-host; the agent reports {status, output} keyed by id.
        res = (si.get('custom_check_results') or {}).get(cdef.get('id'))
        if not isinstance(res, dict) or res.get('status') not in (
                'ok', 'warning', 'critical', 'unknown'):
            return 'unknown', 'not yet reported by agent'
        return res['status'], str(res.get('output', ''))[:200]
    return 'unknown', 'unknown check type'

def _custom_checks_for(dev_id, dev, defs, disabled):
    """Per-device list of custom-check entries (same shape as _host_checks)."""
    out = []
    for cdef in defs or []:
        if not isinstance(cdef, dict) or not _custom_check_applies(cdef, dev_id, dev):
            continue
        status, output = _eval_custom_check(cdef, dev)
        key = f"custom:{cdef.get('id', '')}"
        out.append({'key': key, 'name': cdef.get('name') or cdef.get('id', 'custom'),
                    'group': 'custom', 'status': status, 'output': str(output)[:200],
                    'enabled': key not in (disabled or set()), 'custom': True})
    return out
