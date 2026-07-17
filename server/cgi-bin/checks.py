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

# v6.2.2 threshold batch 5: seconds-per-day, for the OOM "days ago" display
# divisor. The OOM *recency* window itself is operator-configurable and passed
# in as `oom_recent_window_seconds` (single source, mirrors api.py) — this
# constant is only the fixed calendar divisor, never a threshold.
_SECONDS_PER_DAY = 86400


def _exposure_muted(process, proto, port, mutes, device_id=None):
    """True if a (process, proto, port) socket matches any exposure-mute rule.
    A rule is a dict with any subset of {device_id, process, proto, port}; a
    socket matches a rule when every field the rule specifies equals the
    socket's. A rule with only `device_id` mutes ALL exposure from that host. An
    empty rule matches nothing (so it can't accidentally silence everything)."""
    for m in mutes or []:
        if not isinstance(m, dict):
            continue
        if not any(k in m for k in ("device_id", "process", "proto", "port")):
            continue
        if "device_id" in m and (m.get("device_id") or "") != (device_id or ""):
            continue
        if "process" in m and (m.get("process") or "") != (process or ""):
            continue
        if "proto" in m and (m.get("proto") or "") != (proto or ""):
            continue
        if "port" in m:
            try:
                if int(m.get("port")) != int(port or 0):
                    continue
            except (TypeError, ValueError):
                continue
        return True
    return False


def _host_checks(
    dev_id,
    dev,
    hw_rec=None,
    disabled=None,
    now=0,
    ttl=180,
    cve_high=None,
    disk_eta=None,
    custom_defs=None,
    scripts=None,
    exposure_mutes=None,
    disk_forecast_crit_days=7,
    disk_forecast_warn_days=21,
    oom_recent_window_seconds=_SECONDS_PER_DAY,
    av_sig_stale_days=7,
    defender_sig_warn_days=3,
):
    """v4.1.0: unified per-host check list for the CheckMK-style Checks view.

    Each entry: {key, name, group, status: ok|warning|critical|unknown, output,
    enabled}. Derived entirely from data RemotePower already collects (sysinfo,
    metric_state, hardware flags, drift) — no new probing. `disabled` is the set
    of check keys the operator turned off for this host.
    """
    hw_rec = hw_rec or {}
    disabled = set(disabled or [])
    si = dev.get("sysinfo") or {}
    ms = dev.get("metric_state") or {}
    now = now or int(time.time())
    out = []

    def add(key, name, group, status, output):
        out.append(
            {
                "key": key,
                "name": name,
                "group": group,
                "status": status,
                "output": str(output)[:200],
                "enabled": key not in disabled,
            }
        )

    def lvl(state_key):
        v = ms.get(state_key)
        return v if v in ("warning", "critical") else "ok"

    # ── core reachability ──────────────────────────────────────────────
    last = dev.get("last_seen", 0)
    if last:
        age = now - last
        add(
            "reachability",
            "Reachability",
            "core",
            "critical" if age > ttl else "ok",
            f"offline {age // 60} min" if age > ttl else f"online, {age}s ago",
        )
    else:
        add("reachability", "Reachability", "core", "unknown", "never reported")

    # ── resource thresholds (reuse metric_state; show current value) ───
    if isinstance(si.get("loadavg_1m"), (int, float)):
        cc = si.get("cpu_count") or 1
        la = si["loadavg_1m"]
        add(
            "cpu",
            "CPU load",
            "resources",
            lvl("cpu:"),
            f"load {la:.2f} (ratio {la / (cc or 1):.2f}, {cc} cores)",
        )
    elif isinstance(si.get("cpu_percent"), (int, float)):
        # v6.2.0: Windows/macOS report cpu_percent, not a loadavg. Surface the same
        # CPU check row from that so the resources group isn't empty on Windows.
        # Thresholds mirror the metric engine's default busy/overloaded bands.
        cpu = si["cpu_percent"]
        add(
            "cpu",
            "CPU load",
            "resources",
            "critical" if cpu >= 95 else "warning" if cpu >= 85 else "ok",
            f"{cpu:.0f}% busy",
        )
    for key, name, field in (
        ("memory", "Memory", "mem_percent"),
        ("swap", "Swap", "swap_percent"),
        ("fd", "File descriptors", "fd_percent"),
        ("conntrack", "Conntrack table", "conntrack_percent"),
    ):
        v = si.get(field)
        if isinstance(v, (int, float)):
            add(key, name, "resources", lvl(f"{key}:"), f"{v:.0f}%")
    for m in si.get("mounts") or []:
        p = m.get("path")
        if not p:
            continue
        if isinstance(m.get("percent"), (int, float)):
            add(f"disk:{p}", f"Disk {p}", "storage", lvl(f"disk:{p}"), f"{m['percent']:.0f}% used")
        if isinstance(m.get("inode_percent"), (int, float)):
            add(
                f"inode:{p}",
                f"Inodes {p}",
                "storage",
                lvl(f"inode:{p}"),
                f"{m['inode_percent']:.0f}% used",
            )

    # ── boolean / state checks ─────────────────────────────────────────
    fu = si.get("failed_units") or []
    add(
        "services",
        "Systemd units",
        "services",
        "critical" if fu else "ok",
        f"{len(fu)} failed: " + ", ".join(fu[:5]) if fu else "all active",
    )
    ti = [t for t in (si.get("timers") or []) if isinstance(t, dict) and t.get("failed")]
    if si.get("timers") is not None:
        add(
            "timers",
            "Scheduled timers",
            "services",
            "warning" if ti else "ok",
            f"{len(ti)} failed" if ti else "all ok",
        )
    drifted = [
        f
        for f, s in (dev.get("drift_state") or {}).items()
        if isinstance(s, dict) and s.get("status") == "drifted" and not s.get("ignored")
    ]
    if dev.get("drift_state"):
        add(
            "drift",
            "Config drift",
            "posture",
            "warning" if drifted else "ok",
            f"{len(drifted)} file(s) drifted" if drifted else "baseline matches",
        )
    mi = si.get("mount_issues") or []
    if mi:
        add("mounts", "Mount points", "storage", "critical", f"{len(mi)} issue(s)")
    # v4.1.0: respect exposure mutes (set on the Exposed page) — a world port the
    # operator has muted there must not re-appear as a warning check here.
    wp = [
        p
        for p in (si.get("listening_ports") or [])
        if (p or {}).get("scope") == "world"
        and not _exposure_muted(
            p.get("process"), p.get("proto"), p.get("port"), exposure_mutes or [], dev_id
        )
    ]
    if si.get("listening_ports") is not None:
        add(
            "exposure",
            "World-exposed ports",
            "posture",
            "warning" if wp else "ok",
            f"{len(wp)} world-reachable" if wp else "none",
        )
    if si.get("reboot_required"):
        add("reboot", "Reboot required", "patch", "warning", si.get("reboot_reason") or "pending")
    # v6.2.2: kernel-module visibility — FORCED (deliberately ignores the
    # per-host disable list). An agent context that can't see /lib/modules
    # builds module-less, unbootable initrds on the next package upgrade;
    # that signal must not be muteable into invisibility. The agent omits
    # the field where no initramfs generator exists → no row (tri-state).
    if isinstance(si.get("modules_visible"), bool):
        mv = si["modules_visible"]
        out.append(
            {
                "key": "modules",
                "name": "Kernel modules visible",
                "group": "posture",
                "status": "ok" if mv else "critical",
                "output": (
                    "/lib/modules readable from the agent context"
                    if mv
                    else "/lib/modules NOT visible from the agent context — a package "
                    "upgrade could build an unbootable initramfs; check the agent "
                    "service sandboxing"
                ),
                "enabled": True,
            }
        )
    up = (si.get("packages") or {}).get("upgradable")
    if isinstance(up, int):
        # v5.0.0: surface the distro's own SECURITY-flagged count. The vendor
        # saying "patch now" is the highest-signal update state, so a host with
        # pending security updates is a warning even when the total is small.
        sec = (si.get("packages") or {}).get("security_updates")
        sec = sec if isinstance(sec, int) else None
        if sec:
            detail = f"{up} update(s), {sec} security"
        else:
            detail = f"{up} update(s)"
        add("patches", "Pending updates", "patch", "warning" if (up > 0 or sec) else "ok", detail)
    if cve_high is not None:
        add(
            "cve",
            "CVEs (crit+high)",
            "security",
            "critical" if cve_high else "ok",
            f"{cve_high} finding(s)",
        )

    # ── hardware / posture flags (from the hardware record + sysinfo) ──
    if hw_rec.get("_smart_failed") is not None or hw_rec.get("smart"):
        add(
            "smart",
            "Disk SMART",
            "hardware",
            "critical" if hw_rec.get("_smart_failed") else "ok",
            "a disk FAILED" if hw_rec.get("_smart_failed") else "all passing",
        )
    if hw_rec.get("_ups_on_battery") is not None or hw_rec.get("ups"):
        add(
            "ups",
            "UPS power",
            "hardware",
            "critical" if hw_rec.get("_ups_on_battery") else "ok",
            "on battery" if hw_rec.get("_ups_on_battery") else "on line",
        )
    if hw_rec.get("_temp_high") is not None or hw_rec.get("hardware", {}).get("temps"):
        add(
            "temperature",
            "Temperature",
            "hardware",
            "critical" if hw_rec.get("_temp_high") else "ok",
            "over threshold" if hw_rec.get("_temp_high") else "normal",
        )
    clk = si.get("clock")
    if isinstance(clk, dict):
        sk = clk.get("skewed")
        add(
            "clock",
            "Clock / NTP",
            "core",
            "warning" if sk else "ok",
            ("unsynchronised" if clk.get("synced") is False else "drifted") if sk else "in sync",
        )
    gw = si.get("gateway")
    if isinstance(gw, dict):
        reach = gw.get("reachable")
        add(
            "gateway",
            "Default gateway",
            "network",
            "critical" if reach is False else ("unknown" if reach is None else "ok"),
            f"{gw.get('ip','?')}: "
            + ("unreachable" if reach is False else "unknown" if reach is None else "reachable"),
        )
    # NIC errors/drops. The agent has always reported these and they were rendered
    # in the device drawer and nowhere else — no check, no event — so a NIC shedding
    # packets (a failing cable, a dirty SFP, a dying switch port) was invisible to
    # every fleet-wide view and could not page anyone. `err_delta` is computed at
    # ingest against the previous heartbeat, so this fires on errors accruing NOW,
    # not on a counter a long-lived host accumulated months ago.
    nics = si.get("network_io")
    if isinstance(nics, list):
        bad = [
            n
            for n in nics
            if isinstance(n, dict) and isinstance(n.get("err_delta"), int) and n["err_delta"] > 0
        ]
        if bad:
            worst = max(bad, key=lambda n: n["err_delta"])
            add(
                "nic_errors",
                "NIC errors / drops",
                "network",
                "warning",
                f"{worst.get('iface', '?')}: +{worst['err_delta']} since last check"
                + (f" (+{len(bad) - 1} more)" if len(bad) > 1 else ""),
            )

    lo = si.get("last_oom_ts")
    if isinstance(lo, (int, float)) and lo > 0:
        recent = (now - lo) < oom_recent_window_seconds
        _win_h = max(1, int(oom_recent_window_seconds // 3600))
        add(
            "oom",
            "OOM killer",
            "core",
            "warning" if recent else "ok",
            f"fired in last {_win_h}h" if recent else f"last {(now - lo) // _SECONDS_PER_DAY}d ago",
        )
    # v4.1.0: mail queue depth (agent reads postfix/sendmail/exim mailq).
    mq = si.get("mailq")
    if isinstance(mq, (int, float)):
        # v4.2.0 sweep: thresholds come from the standard metric_thresholds
        # store (settable in the Thresholds modal); the old 'mailq_thresholds'
        # key never had a writer but is honoured for hand-edited stores.
        mto = dev.get("metric_thresholds") or {}
        legacy = dev.get("mailq_thresholds") or {}
        warn = mto.get("mailq_warn_count", legacy.get("warn", 50))
        crit = mto.get("mailq_crit_count", legacy.get("crit", 500))
        add(
            "mailq",
            "Mail queue",
            "services",
            "critical" if mq >= crit else "warning" if mq >= warn else "ok",
            f"{int(mq)} message(s) queued",
        )
    # v4.1.0: a local filesystem the kernel remounted read-only = silent outage.
    ro_mounts = [
        m.get("path")
        for m in (si.get("mounts") or [])
        if isinstance(m, dict) and m.get("ro") and not m.get("network")
    ]
    if any(isinstance(m, dict) and "ro" in m for m in (si.get("mounts") or [])):
        add(
            "readonly_fs",
            "Read-only filesystems",
            "storage",
            "warning" if ro_mounts else "ok",
            (
                (", ".join(p for p in ro_mounts if p)[:180] + " read-only")
                if ro_mounts
                else "all read-write"
            ),
        )
    # v4.1.0: disk-fill ETA (linear trend over the time-series; near-full only).
    if isinstance(disk_eta, (int, float)):
        add(
            "disk_eta",
            "Disk fill ETA",
            "storage",
            (
                "critical"
                if disk_eta <= disk_forecast_crit_days
                else "warning" if disk_eta <= disk_forecast_warn_days else "ok"
            ),
            f"~{disk_eta:.1f} day(s) to full at current trend",
        )
    pools = si.get("storage_health") or []
    if pools:
        bad = [
            p
            for p in pools
            if isinstance(p, dict)
            and (p.get("state") or "").lower() not in ("online", "active", "clean", "healthy", "ok")
        ]
        add(
            "storage",
            "Storage / RAID",
            "storage",
            "critical" if bad else "ok",
            f"{len(bad)} pool(s) degraded" if bad else f"{len(pools)} pool(s) healthy",
        )
    # ── v6.2.0: Windows security-posture checks (from sysinfo.win_posture) ──
    # These render ONLY when the Windows agent reported posture, so a Linux host
    # never shows an empty "BitLocker" row. Classic RMM check-library staples that
    # have no Linux analogue.
    wp = si.get("win_posture")
    if isinstance(wp, dict):
        # Windows Defender real-time protection. AV that is installed but switched
        # off is the single highest-signal endpoint-protection failure.
        if "defender_realtime" in wp:
            rt = bool(wp["defender_realtime"])
            add(
                "win_av_realtime",
                "Defender real-time protection",
                "security",
                "ok" if rt else "critical",
                "enabled" if rt else "DISABLED",
            )
        # Signature age — stale definitions blind the scanner.
        age = wp.get("defender_sig_age_days")
        if isinstance(age, (int, float)):
            add(
                "win_av_signatures",
                "Defender signature age",
                "security",
                (
                    "critical"
                    if age >= av_sig_stale_days
                    else "warning" if age >= defender_sig_warn_days else "ok"
                ),
                f"{int(age)} day(s) old",
            )
        # BitLocker on the OS volume.
        bl = wp.get("bitlocker")
        if isinstance(bl, list):
            unprot = [
                v
                for v in bl
                if isinstance(v, dict)
                and str(v.get("status", "")).lower() not in ("on", "encrypted")
            ]
            add(
                "win_bitlocker",
                "BitLocker (OS drive)",
                "security",
                "warning" if (unprot or not bl) else "ok",
                (
                    f"{len(unprot)} volume(s) unprotected"
                    if unprot
                    else "encrypted" if bl else "no OS volume reported"
                ),
            )
        # Windows Firewall — per-profile enabled state.
        fw = wp.get("firewall")
        if isinstance(fw, list) and fw:
            off = [p.get("name") for p in fw if isinstance(p, dict) and not p.get("enabled")]
            add(
                "win_firewall",
                "Windows Firewall",
                "security",
                "warning" if off else "ok",
                (
                    f"{', '.join(str(n) for n in off if n)} profile(s) OFF"
                    if off
                    else "all profiles on"
                ),
            )
        # Windows Update service — if it's not running, the host silently stops
        # patching, and every other patch signal quietly goes stale.
        wu = wp.get("wu_service")
        if wu:
            running = str(wu).lower() == "running"
            add(
                "win_update_service",
                "Windows Update service",
                "patch",
                "ok" if running else "warning",
                "running" if running else f"{wu} (not running)",
            )

    # v4.1.0: operator-defined custom checks (process/port), scoped to this host.
    if custom_defs:
        out.extend(_custom_checks_for(dev_id, dev, custom_defs, disabled))
    # v4.1.0: custom monitoring-script results surfaced as checks (pass/fail).
    if scripts:
        for sid, res in (dev.get("custom_script_results") or {}).items():
            if not isinstance(res, dict):
                continue
            name = (scripts.get(sid) or {}).get("name") or sid
            okv = res.get("ok")
            status = "unknown" if okv is None else ("ok" if okv else "critical")
            last = ""
            if res.get("output"):
                parts = str(res["output"]).strip().splitlines()
                last = parts[-1] if parts else ""
            add(
                f"script:{sid}",
                f"Script: {name}",
                "script",
                status,
                last or ("passed" if okv else "failed"),
            )
    return out


# ── Custom checks (v4.1.0) ──────────────────────────────────────────────────
# Operator-defined checks assignable to a single host, a tag, a group, or the
# whole fleet. SERVER_CHECK_TYPES are evaluated here from data the agent already
# reports; AGENT_CHECK_TYPES are pushed to the agent (in the heartbeat response),
# evaluated on-host, and reported back in sysinfo['custom_check_results'].
SERVER_CHECK_TYPES = ("process", "port_open", "port_closed")

AGENT_CHECK_TYPES = (
    "file_present",
    "file_absent",
    "log_errors",
    "job_fresh",
    "systemd_unit",
    # v6.2.0: the Windows analogue of systemd_unit — is a named
    # Windows service Running? Evaluated on-host via Get-Service.
    "windows_service",
)


# v6.2.3: a shipped catalog of RECOMMENDED baseline checks — the checks analogue
# of "service baselines". The operator applies a selection to a scope (all / a
# group / a tag) in one click and each becomes a scoped custom_check (target_kind
# all/group/tag), so it evaluates, shows OK/WARN/CRIT, alerts and can be silenced
# per host exactly like any custom check — and stays live as hosts join the scope.
# `param` defaults suit a Debian/Ubuntu fleet and are EDITABLE after applying
# (e.g. crond.service on RHEL, firewalld/nftables, chrony vs systemd-timesyncd).
# Adding a template = one dict; the apply handler and UI read this list.
CHECK_BASELINE_CATALOG = (
    # ── Core liveness ────────────────────────────────────────────────────────
    {
        "cat": "Core liveness",
        "id": "agent_running",
        "type": "systemd_unit",
        "param": "remotepower-agent.service",
        "name": "Monitoring agent running",
        "desc": "The RemotePower agent service is active.",
    },
    {
        "cat": "Core liveness",
        "id": "time_sync",
        "type": "systemd_unit",
        "param": "systemd-timesyncd.service",
        "name": "Time sync active",
        "desc": "Clock sync daemon is running (chrony.service on some hosts).",
    },
    {
        "cat": "Core liveness",
        "id": "cron_running",
        "type": "systemd_unit",
        "param": "cron.service",
        "name": "Cron/scheduler running",
        "desc": "The system scheduler is up (crond.service on RHEL family).",
    },
    # ── Security posture ─────────────────────────────────────────────────────
    {
        "cat": "Security posture",
        "id": "firewall_active",
        "type": "systemd_unit",
        "param": "ufw.service",
        "name": "Firewall active",
        "desc": "Host firewall is running (firewalld.service / nftables.service elsewhere).",
    },
    {
        "cat": "Security posture",
        "id": "auditd_running",
        "type": "systemd_unit",
        "param": "auditd.service",
        "name": "Audit daemon running",
        "desc": "The Linux audit daemon is active.",
    },
    {
        "cat": "Security posture",
        "id": "unattended_upgrades",
        "type": "systemd_unit",
        "param": "unattended-upgrades.service",
        "name": "Unattended upgrades running",
        "desc": "Automatic security updates are enabled (Debian/Ubuntu).",
    },
    {
        "cat": "Security posture",
        "id": "ssh_reachable",
        "type": "port_open",
        "param": "22",
        "name": "SSH port 22 reachable",
        "desc": "The host is listening on SSH.",
    },
    {
        "cat": "Security posture",
        "id": "telnet_closed",
        "type": "port_closed",
        "param": "23",
        "name": "Telnet (23) not listening",
        "desc": "Cleartext telnet must never be exposed.",
    },
    # ── Filesystem / OS ──────────────────────────────────────────────────────
    {
        "cat": "Filesystem / OS",
        "id": "nologin_absent",
        "type": "file_absent",
        "param": "/etc/nologin",
        "name": "Logins not disabled",
        "desc": "/etc/nologin present means all non-root logins are blocked (stuck maintenance).",
    },
    {
        "cat": "Filesystem / OS",
        "id": "no_oom",
        "type": "log_errors",
        "param": "Out of memory|oom-kill|Killed process",
        "name": "No OOM-kill in the last hour",
        "desc": "Watches the journal for kernel out-of-memory kills.",
        "extras": {"window_min": 60, "warn": 1, "crit": 1},
    },
    {
        "cat": "Filesystem / OS",
        "id": "reboot_not_pending",
        "type": "file_absent",
        "param": "/run/reboot-required",
        "name": "No pending reboot",
        "desc": "A kernel/library update is waiting for a reboot (Debian/Ubuntu).",
    },
    # ── Role-tagged (apply to the matching tag, not fleet-wide) ───────────────
    {
        "cat": "Role-tagged",
        "id": "docker_running",
        "type": "systemd_unit",
        "param": "docker.service",
        "name": "Docker running",
        "desc": "Container runtime is up.",
        "target_kind": "tag",
        "target": "docker",
    },
    {
        "cat": "Role-tagged",
        "id": "nginx_running",
        "type": "systemd_unit",
        "param": "nginx.service",
        "name": "nginx running",
        "desc": "Web server is up.",
        "target_kind": "tag",
        "target": "web",
    },
    {
        "cat": "Role-tagged",
        "id": "postgres_running",
        "type": "systemd_unit",
        "param": "postgresql.service",
        "name": "PostgreSQL running",
        "desc": "Database server is up.",
        "target_kind": "tag",
        "target": "db",
    },
)


def _custom_check_applies(cdef, dev_id, dev):
    """True if a custom-check definition targets this device."""
    tk = cdef.get("target_kind", "all")
    tv = str(cdef.get("target", ""))
    if tk == "all":
        return True
    if tk == "host":
        return dev_id == tv
    if tk == "tag":
        return tv in [str(t) for t in (dev.get("tags") or [])]
    if tk == "group":
        return str(dev.get("group", "")) == tv
    return False


def _eval_custom_check(cdef, dev):
    """Evaluate one custom check against a device's reported sysinfo.
    Returns (status, output). Unknown/missing data → 'unknown'."""
    si = dev.get("sysinfo") or {}
    ctype = cdef.get("type")
    param = str(cdef.get("param", "")).strip()
    if ctype == "process":
        names = si.get("proc_names")
        if not isinstance(names, list):
            return "unknown", "no process data reported"
        hit = any(param == n or param.lower() in n.lower() for n in names)
        return ("ok", f'"{param}" running') if hit else ("critical", f'"{param}" not running')
    if ctype in ("port_open", "port_closed"):
        ports = si.get("listening_ports")
        if not isinstance(ports, list):
            return "unknown", "no port data reported"
        try:
            want = int(param)
        except (TypeError, ValueError):
            return "unknown", f'invalid port "{param}"'
        listening = any(int(p.get("port", -1)) == want for p in ports if isinstance(p, dict))
        if ctype == "port_open":
            return ("ok", f"port {want} open") if listening else ("critical", f"port {want} closed")
        return (
            ("critical", f"port {want} unexpectedly open")
            if listening
            else ("ok", f"port {want} closed")
        )
    if ctype in AGENT_CHECK_TYPES:
        # Evaluated on-host; the agent reports {status, output} keyed by id.
        res = (si.get("custom_check_results") or {}).get(cdef.get("id"))
        if not isinstance(res, dict) or res.get("status") not in (
            "ok",
            "warning",
            "critical",
            "unknown",
        ):
            return "unknown", "not yet reported by agent"
        return res["status"], str(res.get("output", ""))[:200]
    return "unknown", "unknown check type"


def _custom_checks_for(dev_id, dev, defs, disabled):
    """Per-device list of custom-check entries (same shape as _host_checks)."""
    out = []
    for cdef in defs or []:
        if not isinstance(cdef, dict) or not _custom_check_applies(cdef, dev_id, dev):
            continue
        status, output = _eval_custom_check(cdef, dev)
        key = f"custom:{cdef.get('id', '')}"
        out.append(
            {
                "key": key,
                "name": cdef.get("name") or cdef.get("id", "custom"),
                "group": "custom",
                "status": status,
                "output": str(output)[:200],
                "enabled": key not in (disabled or set()),
                "custom": True,
            }
        )
    return out
