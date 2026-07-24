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
    cpu_pct_warn=85,
    cpu_pct_crit=95,
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
        # v6.4.0: bands are operator-tunable (Settings → Alert parameters);
        # descending-clamp so an inverted config can't break the ladder.
        cpu = si["cpu_percent"]
        _cw, _cc = cpu_pct_warn, cpu_pct_crit
        if _cc <= _cw:
            _cc = _cw + 1
        add(
            "cpu",
            "CPU load",
            "resources",
            "critical" if cpu >= _cc else "warning" if cpu >= _cw else "ok",
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
        # v6.3.0 posture gaps. Tamper protection guards Defender from being
        # silently switched off by malware — off is a real weakening.
        if "tamper_protection" in wp:
            tp = bool(wp["tamper_protection"])
            add(
                "win_tamper_protection",
                "Defender tamper protection",
                "security",
                "ok" if tp else "warning",
                "enabled" if tp else "DISABLED",
            )
        if "secure_boot" in wp:
            sb = bool(wp["secure_boot"])
            add(
                "win_secure_boot",
                "Secure Boot",
                "security",
                "ok" if sb else "warning",
                "enabled" if sb else "off / unsupported",
            )
        if "uac_enabled" in wp:
            uac = bool(wp["uac_enabled"])
            add(
                "win_uac",
                "User Account Control",
                "security",
                "ok" if uac else "warning",
                "enabled" if uac else "DISABLED",
            )
        # A host stuck pending-reboot has not finished applying its updates.
        if wp.get("pending_reboot"):
            add(
                "win_pending_reboot",
                "Pending reboot",
                "patch",
                "warning",
                "reboot required to finish patching",
            )

    # ── v6.3.0: macOS security-posture checks (from sysinfo.mac_posture) ──
    # Parity with the Windows posture rows above; render ONLY when the macOS agent
    # reported posture, so a Linux/Windows host never shows an empty FileVault row.
    mp = si.get("mac_posture")
    if isinstance(mp, dict):
        if "filevault" in mp:
            fv = bool(mp["filevault"])
            add(
                "mac_filevault",
                "FileVault disk encryption",
                "security",
                "ok" if fv else "warning",
                "on" if fv else "OFF",
            )
        if "firewall" in mp:
            mfw = bool(mp["firewall"])
            add(
                "mac_firewall",
                "Application Firewall",
                "security",
                "ok" if mfw else "warning",
                "enabled" if mfw else "OFF",
            )
        if "gatekeeper" in mp:
            gk = bool(mp["gatekeeper"])
            add(
                "mac_gatekeeper",
                "Gatekeeper",
                "security",
                "ok" if gk else "warning",
                "enabled" if gk else "DISABLED",
            )
        if "sip" in mp:
            sip = bool(mp["sip"])
            add(
                "mac_sip",
                "System Integrity Protection",
                "security",
                "ok" if sip else "warning",
                "enabled" if sip else "DISABLED",
            )
        if "auto_security_update" in mp:
            au = bool(mp["auto_security_update"])
            add(
                "mac_auto_update",
                "Automatic security updates",
                "patch",
                "ok" if au else "warning",
                "on" if au else "off",
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

# Integrity-Guard check types: they hold a learned on-host baseline, so a row
# of one of these types is a "protect" check regardless of how it was created
# (mirrors the client's _CC_GUARD_TYPES in app-checks.js).
GUARD_CHECK_TYPES = ("dir_baseline", "file_hash", "egress_flagged")
# Types whose baseline an operator may legitimately re-accept (a real deploy)
# — these get a "Reset baseline" action in the UI (client _CC_BASELINE_TYPES).
BASELINE_CHECK_TYPES = ("dir_baseline", "file_hash",
                        "egress_baseline", "auth_new_source")

AGENT_CHECK_TYPES = (
    "file_present",
    "file_absent",
    "log_errors",
    "job_fresh",
    "systemd_unit",
    # v6.2.0: the Windows analogue of systemd_unit — is a named
    # Windows service Running? Evaluated on-host via Get-Service.
    "windows_service",
    # ── on-host integrity & network tripwires ───────────────────────────────
    # All three take only `param` (no extra pushed fields) and reuse the
    # generic custom_check_failed/recovered alert flow. Evaluated on-host,
    # read-only, bounded. Baseline-on-first-run types store a small marker in
    # the agent state dir keyed by the check id.
    #   file_hash      — a pinned file's SHA-256 changed since first seen.
    #   dir_baseline   — a new/changed/removed file appeared under a watched
    #                    subtree; `param` is "path" or "path::glob"
    #                    (e.g. /var/www::*.php). Skips cache/tmp/log/.git dirs.
    #   egress_flagged — an active outbound connection matches an operator
    #                    IP/CIDR flag-list (`param` = comma/space-separated).
    "file_hash",
    "dir_baseline",
    "egress_flagged",
    #   file_contains  — a CONTENT match across a subtree: `param` is the path
    #                    (or path::glob) and `pattern` a regex. Turns "a file
    #                    appeared" into "a file appeared AND it looks like a web
    #                    shell". Read-only, bounded by file count and bytes.
    "file_contains",
    #   egress_baseline — learns the EXTERNAL destinations a host normally
    #                     reaches (by /24 or /64, so CDN churn does not flap)
    #                     and alerts ONCE per genuinely new one. Needs no prior
    #                     threat intel, unlike egress_flagged. `param` is an
    #                     optional CIDR ignore-list.
    "egress_baseline",
    #   auth_new_source — learns which source networks successfully log in over
    #                     SSH and alerts the first time one appears from
    #                     somewhere new. `param` is an optional CIDR
    #                     ignore-list (office / VPN ranges).
    "auth_new_source",
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
    # v6.3.1: optional watcher for the agentless syslog receiver — apply it to
    # the RemotePower server host (tag it `rp-server`). Pairs with the
    # informational Server-status subsystems row; this catalog row is the
    # opt-in ALERTING side (a critical Checks row when the unit stops).
    {
        "cat": "Role-tagged",
        "id": "rp_syslogd_running",
        "type": "systemd_unit",
        "param": "remotepower-syslogd.service",
        "name": "RemotePower syslog receiver running",
        "desc": "The agentless syslog intake daemon (remotepower-syslogd) is "
                "active. Optional — apply to the RemotePower server host "
                "(tag it rp-server).",
        "target_kind": "tag",
        "target": "rp-server",
    },
    # ── Web / application security (apply to the `web` tag) ───────────────────
    # Tripwires for hosts that serve web applications. Params are EDITABLE after
    # applying — point them at your own web root, configs, and threat ranges.
    {
        "cat": "Web / application security",
        "id": "webroot_integrity",
        "type": "dir_baseline",
        "param": "/var/www::*.php",
        "name": "Web root code integrity",
        "desc": "Baselines executable files under the web root on first run, "
                "then alerts if any PHP file is added, changed, or removed. "
                "Edit the path/glob to match your document root "
                "(e.g. /srv/www::*.php).",
        "target_kind": "tag",
        "target": "web",
    },
    {
        "cat": "Web / application security",
        "id": "webshell_signature",
        "type": "file_contains",
        "param": "/var/www::*.php",
        "pattern": r"eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)",
        "name": "No obfuscated PHP loader in the web root",
        "desc": "Greps the web root for the classic packed-web-shell idiom — eval() "
                "wrapped around base64_decode/gzinflate/str_rot13. Content-based, so "
                "it fires on a NAME you have never seen, unlike a filename tripwire. "
                "Edit the path/glob for your document root.",
        "target_kind": "tag",
        "target": "web",
    },
    {
        "cat": "Web / application security",
        "id": "wp_muplugins_integrity",
        "type": "dir_baseline",
        "param": "/var/www/html/wp-content/mu-plugins",
        "name": "No new must-use plugins (WordPress)",
        "desc": "mu-plugins load automatically on EVERY request and never appear in "
                "the plugin admin list, which makes the directory a favourite "
                "persistence and credential-capture spot. It is normally empty or "
                "tiny, so anything new here is worth a look. Edit the path to your "
                "document root.",
        "target_kind": "tag",
        "target": "web",
    },
    {
        "cat": "Web / application security",
        "id": "wp_config_integrity",
        "type": "file_hash",
        "param": "/var/www/html/wp-config.php",
        "name": "WordPress wp-config.php unchanged",
        "desc": "Holds the database credentials and auth salts. A change is either a "
                "real config edit or someone tampering with keys and constants. Edit "
                "the path to your document root.",
        "target_kind": "tag",
        "target": "web",
    },
    {
        "cat": "Web / application security",
        "id": "accounts_integrity",
        "type": "file_hash",
        "param": "/etc/passwd",
        "name": "User accounts file unchanged",
        "desc": "Alerts if /etc/passwd changes — a new account is a classic "
                "post-exploitation step. Baselines on first run.",
    },
    {
        "cat": "Web / application security",
        "id": "crontab_integrity",
        "type": "file_hash",
        "param": "/etc/crontab",
        "name": "System crontab unchanged",
        "desc": "Alerts if /etc/crontab changes — a common persistence spot. "
                "Baselines on first run.",
    },
    {
        "cat": "Web / application security",
        "id": "crond_dir_integrity",
        "type": "dir_baseline",
        "param": "/etc/cron.d",
        "name": "No new cron jobs (/etc/cron.d)",
        "desc": "Baselines /etc/cron.d, then alerts if a cron file is added or "
                "changed — another common persistence spot.",
    },
    {
        "cat": "Web / application security",
        "id": "egress_new_destination",
        "type": "egress_baseline",
        "param": "192.0.2.0/24",
        "name": "No new outbound destinations",
        "desc": "Learns which external networks this host normally connects out to, "
                "then alerts the first time it reaches somewhere new — a beacon to a "
                "C2 you have never heard of shows up with no threat intel at all. "
                "Each new destination alerts once and is then remembered. The param "
                "is a CIDR IGNORE-list for your own infrastructure; the shipped "
                "value is RFC-5737 documentation space, a harmless placeholder.",
        "target_kind": "tag",
        "target": "web",
    },
    {
        "cat": "Web / application security",
        "id": "egress_flagged_ranges",
        "type": "egress_flagged",
        "param": "192.0.2.0/24",
        "name": "No outbound to flagged ranges",
        "desc": "Alerts if a host opens an outbound connection to an address in "
                "your flag-list. The example range is RFC-5737 documentation "
                "space — replace it with your threat-intel IPs/CIDRs "
                "(comma or space separated).",
    },

    # ── Hardening — services that should be running ───────────────────────────
    {"cat": "Hardening — services", "id": "fail2ban_running", "type": "systemd_unit",
     "param": "fail2ban.service", "name": "Brute-force protection running",
     "desc": "fail2ban is active, so repeated auth failures get banned instead of retried forever."},
    {"cat": "Hardening — services", "id": "apparmor_running", "type": "systemd_unit",
     "param": "apparmor.service", "name": "AppArmor active",
     "desc": "Mandatory access control is enforcing (use selinux equivalents on RHEL family)."},
    {"cat": "Hardening — services", "id": "sshd_running", "type": "systemd_unit",
     "param": "ssh.service", "name": "SSH daemon running",
     "desc": "Remote access is up (sshd.service on RHEL family). Pair with the port check."},
    {"cat": "Hardening — services", "id": "journald_running", "type": "systemd_unit",
     "param": "systemd-journald.service", "name": "System journal running",
     "desc": "Without the journal you lose the log trail every other detection depends on."},
    {"cat": "Hardening — services", "id": "rsyslog_running", "type": "systemd_unit",
     "param": "rsyslog.service", "name": "Syslog daemon running",
     "desc": "Needed if you forward logs off-box; a silenced logger hides an intrusion."},
    {"cat": "Hardening — services", "id": "freshclam_running", "type": "systemd_unit",
     "param": "clamav-freshclam.service", "name": "AV signature updater running",
     "desc": "Antivirus definitions keep updating — stale signatures detect nothing new."},
    {"cat": "Hardening — services", "id": "clamd_running", "type": "systemd_unit",
     "param": "clamav-daemon.service", "name": "AV scanning daemon running",
     "desc": "clamd is the engine on-access scanning actually scans WITH. Without it "
             "a file-integrity monitor still collects events but scans nothing, so "
             "on-access protection fails silently — check the daemon, not just the "
             "signature updater. Also confirm it is enabled at boot."},

    # ── Hardening — services that must NOT be reachable ───────────────────────
    {"cat": "Hardening — must not listen", "id": "ftp_closed", "type": "port_closed",
     "param": "21", "name": "FTP (21) not listening",
     "desc": "Cleartext file transfer. Use SFTP/FTPS instead."},
    {"cat": "Hardening — must not listen", "id": "rlogin_closed", "type": "port_closed",
     "param": "513", "name": "rlogin (513) not listening",
     "desc": "Legacy trust-based remote login with no real authentication."},
    {"cat": "Hardening — must not listen", "id": "rsh_closed", "type": "port_closed",
     "param": "514", "name": "rsh (514) not listening",
     "desc": "Legacy remote shell, cleartext and trivially spoofed."},
    {"cat": "Hardening — must not listen", "id": "rpcbind_closed", "type": "port_closed",
     "param": "111", "name": "rpcbind (111) not listening",
     "desc": "Portmapper is a classic reflection/amplification and enumeration vector."},
    {"cat": "Hardening — must not listen", "id": "nfs_closed", "type": "port_closed",
     "param": "2049", "name": "NFS (2049) not listening",
     "desc": "Apply to hosts that are not deliberate NFS servers."},
    {"cat": "Hardening — must not listen", "id": "smb_closed", "type": "port_closed",
     "param": "445", "name": "SMB (445) not listening",
     "desc": "Apply to hosts that are not deliberate file servers — a top ransomware vector."},
    {"cat": "Hardening — must not listen", "id": "netbios_closed", "type": "port_closed",
     "param": "139", "name": "NetBIOS (139) not listening",
     "desc": "Legacy Windows file sharing; should not be exposed on a Linux host."},
    {"cat": "Hardening — must not listen", "id": "vnc_closed", "type": "port_closed",
     "param": "5900", "name": "VNC (5900) not listening",
     "desc": "Remote desktop, frequently unauthenticated. Tunnel it over SSH instead."},
    {"cat": "Hardening — must not listen", "id": "rdp_closed", "type": "port_closed",
     "param": "3389", "name": "RDP (3389) not listening",
     "desc": "Should never be open on a Linux host; a top brute-force target."},
    {"cat": "Hardening — must not listen", "id": "dockerapi_closed", "type": "port_closed",
     "param": "2375", "name": "Docker API (2375) not listening",
     "desc": "The unauthenticated Docker socket over TCP is effectively remote root. Never expose it."},
    {"cat": "Hardening — must not listen", "id": "mysql_closed", "type": "port_closed",
     "param": "3306", "name": "MySQL (3306) not listening",
     "desc": "Apply to hosts that are not database servers — databases should not be network-reachable."},
    {"cat": "Hardening — must not listen", "id": "postgres_closed", "type": "port_closed",
     "param": "5432", "name": "PostgreSQL (5432) not listening",
     "desc": "Apply to hosts that are not database servers."},
    {"cat": "Hardening — must not listen", "id": "redis_closed", "type": "port_closed",
     "param": "6379", "name": "Redis (6379) not listening",
     "desc": "Redis defaults to no auth — an exposed instance is a well-known RCE path."},
    {"cat": "Hardening — must not listen", "id": "mongo_closed", "type": "port_closed",
     "param": "27017", "name": "MongoDB (27017) not listening",
     "desc": "Historically unauthenticated by default; a mass-ransom target."},
    {"cat": "Hardening — must not listen", "id": "elastic_closed", "type": "port_closed",
     "param": "9200", "name": "Elasticsearch (9200) not listening",
     "desc": "Open clusters leak whole datasets and are trivially wiped."},
    {"cat": "Hardening — must not listen", "id": "memcached_closed", "type": "port_closed",
     "param": "11211", "name": "memcached (11211) not listening",
     "desc": "A record-setting UDP amplification source when exposed."},
    {"cat": "Hardening — must not listen", "id": "snmp_closed", "type": "port_closed",
     "param": "161", "name": "SNMP (161) not listening",
     "desc": "v1/v2c community strings are cleartext. Apply where SNMP is not deliberate."},

    # ── Integrity — critical files (baseline on first run, alert on change) ───
    {"cat": "Integrity — critical files", "id": "shadow_integrity", "type": "file_hash",
     "param": "/etc/shadow", "name": "Password hashes unchanged",
     "desc": "Any edit to /etc/shadow outside a known change is a credential event."},
    {"cat": "Integrity — critical files", "id": "group_integrity", "type": "file_hash",
     "param": "/etc/group", "name": "Group membership unchanged",
     "desc": "Catches a user being quietly added to sudo/wheel/docker."},
    {"cat": "Integrity — critical files", "id": "sudoers_integrity", "type": "file_hash",
     "param": "/etc/sudoers", "name": "sudoers unchanged",
     "desc": "A sudoers edit is a direct privilege-escalation persistence step."},
    {"cat": "Integrity — critical files", "id": "sshd_config_integrity", "type": "file_hash",
     "param": "/etc/ssh/sshd_config", "name": "SSH server config unchanged",
     "desc": "Catches re-enabled root login, password auth, or an added AuthorizedKeysCommand."},
    {"cat": "Integrity — critical files", "id": "hosts_integrity", "type": "file_hash",
     "param": "/etc/hosts", "name": "Hosts file unchanged",
     "desc": "A pinned hostname is a cheap way to redirect updates or exfiltration."},
    {"cat": "Integrity — critical files", "id": "nsswitch_integrity", "type": "file_hash",
     "param": "/etc/nsswitch.conf", "name": "Name-service switch unchanged",
     "desc": "Controls where users/groups resolve from — a subtle backdoor location."},
    {"cat": "Integrity — critical files", "id": "pam_integrity", "type": "file_hash",
     "param": "/etc/pam.d/common-auth", "name": "PAM auth stack unchanged",
     "desc": "A malicious PAM module line captures every password on the host."},
    {"cat": "Integrity — critical files", "id": "fstab_integrity", "type": "file_hash",
     "param": "/etc/fstab", "name": "Mount table unchanged",
     "desc": "Catches a re-mounted or newly attached filesystem."},
    {"cat": "Integrity — critical files", "id": "resolvconf_integrity", "type": "file_hash",
     "param": "/etc/resolv.conf", "name": "DNS resolvers unchanged",
     "desc": "Hijacked resolvers redirect traffic without touching anything else."},
    {"cat": "Integrity — critical files", "id": "sources_integrity", "type": "file_hash",
     "param": "/etc/apt/sources.list", "name": "Package sources unchanged",
     "desc": "A rogue apt source lets an attacker ship you signed-looking packages."},

    # ── Integrity — persistence paths (a new file here is how things survive) ─
    {"cat": "Integrity — persistence paths", "id": "crondaily_integrity", "type": "dir_baseline",
     "param": "/etc/cron.daily", "name": "No new daily cron jobs",
     "desc": "Baselines /etc/cron.daily and alerts on anything added or changed."},
    {"cat": "Integrity — persistence paths", "id": "cronhourly_integrity", "type": "dir_baseline",
     "param": "/etc/cron.hourly", "name": "No new hourly cron jobs",
     "desc": "Baselines /etc/cron.hourly and alerts on anything added or changed."},
    {"cat": "Integrity — persistence paths", "id": "systemdunits_integrity", "type": "dir_baseline",
     "param": "/etc/systemd/system", "name": "No new systemd units",
     "desc": "A dropped unit file is the most common modern persistence mechanism."},
    {"cat": "Integrity — persistence paths", "id": "sudoersd_integrity", "type": "dir_baseline",
     "param": "/etc/sudoers.d", "name": "No new sudoers drop-ins",
     "desc": "One file here can grant passwordless root to any account."},
    {"cat": "Integrity — persistence paths", "id": "rootssh_integrity", "type": "dir_baseline",
     "param": "/root/.ssh", "name": "root SSH keys unchanged",
     "desc": "An added authorized_keys entry is silent, permanent remote root."},
    {"cat": "Integrity — persistence paths", "id": "profiled_integrity", "type": "dir_baseline",
     "param": "/etc/profile.d", "name": "No new shell profile scripts",
     "desc": "Runs for every interactive login — a classic quiet persistence spot."},
    {"cat": "Integrity — persistence paths", "id": "localbin_integrity", "type": "dir_baseline",
     "param": "/usr/local/bin", "name": "No new local binaries",
     "desc": "Early on PATH, so a dropped binary here can shadow a real command."},
    {"cat": "Integrity — persistence paths", "id": "sourceslistd_integrity", "type": "dir_baseline",
     "param": "/etc/apt/sources.list.d", "name": "No new package sources",
     "desc": "Catches an added repository that would feed you attacker packages."},
    {"cat": "Integrity — persistence paths", "id": "ldsoconfd_integrity", "type": "dir_baseline",
     "param": "/etc/ld.so.conf.d", "name": "No new linker search paths",
     "desc": "Adding a library path enables library hijacking against every binary."},

    # ── Files that must NOT exist ────────────────────────────────────────────
    {"cat": "Integrity — must not exist", "id": "ldpreload_absent", "type": "file_absent",
     "param": "/etc/ld.so.preload", "name": "No global library preload",
     "desc": "/etc/ld.so.preload injects a library into EVERY process — a hallmark of userland rootkits. It should not exist on a normal host."},
    {"cat": "Integrity — must not exist", "id": "rhosts_absent", "type": "file_absent",
     "param": "/root/.rhosts", "name": "No root .rhosts trust file",
     "desc": "Legacy host-based trust that bypasses authentication entirely."},
    {"cat": "Integrity — must not exist", "id": "hostsequiv_absent", "type": "file_absent",
     "param": "/etc/hosts.equiv", "name": "No hosts.equiv trust file",
     "desc": "Grants passwordless access to every user from the listed hosts."},

    # ── Detection — log signals ──────────────────────────────────────────────
    {"cat": "Detection — log signals", "id": "auth_new_source", "type": "auth_new_source",
     "param": "10.0.0.0/8, 192.168.0.0/16",
     "name": "No SSH login from a new network",
     "desc": "Learns which source networks successfully authenticate over SSH, then "
             "alerts the first time someone signs in from somewhere new — the signal "
             "a stolen key or password produces, which a failure-rate check cannot "
             "see because the login SUCCEEDS. Each new network alerts once. The param "
             "is a CIDR ignore-list for your office/VPN ranges."},
    {"cat": "Detection — log signals", "id": "auth_failures", "type": "log_errors",
     "param": "authentication failure|Failed password|Invalid user",
     "name": "Auth failure burst", "extras": {"window_min": 15, "warn": 10, "crit": 50},
     "desc": "Warns on a spike of failed logins — credential stuffing or a brute-force run."},
    {"cat": "Detection — log signals", "id": "sudo_abuse", "type": "log_errors",
     "param": "NOT in the sudoers|incorrect password attempts",
     "name": "sudo misuse attempts", "extras": {"window_min": 60, "warn": 1, "crit": 5},
     "desc": "Someone is probing for privilege escalation they don't have."},
    {"cat": "Detection — log signals", "id": "mac_denials", "type": "log_errors",
     "param": "apparmor=\"DENIED\"|avc: *denied",
     "name": "MAC policy denials", "extras": {"window_min": 30, "warn": 5, "crit": 25},
     "desc": "AppArmor/SELinux blocked something — either a misconfig or a process doing what it shouldn't."},
    {"cat": "Detection — log signals", "id": "segfaults", "type": "log_errors",
     "param": "segfault|general protection fault",
     "name": "Process crashes", "extras": {"window_min": 60, "warn": 3, "crit": 20},
     "desc": "A burst of segfaults can mean instability — or exploitation attempts against a service."},
    {"cat": "Detection — log signals", "id": "fs_errors", "type": "log_errors",
     "param": "EXT4-fs error|I/O error|Buffer I/O error",
     "name": "Filesystem / disk I/O errors", "extras": {"window_min": 60, "warn": 1, "crit": 10},
     "desc": "Early warning of a failing disk before it takes data with it."},

    # ── Freshness — things that must keep running ────────────────────────────
    {"cat": "Freshness — scheduled jobs", "id": "apt_update_fresh", "type": "job_fresh",
     "param": "/var/lib/apt/periodic/update-success-stamp|/var/lib/apt/lists",
     "name": "Package index updated recently", "extras": {"max_age_hours": 48},
     "desc": "If apt stopped updating, your patch data (and CVE view) is silently "
             "stale. Checks the apt-daily success stamp AND the package-list "
             "directory mtime (updated by every `apt update`, even a manual one) "
             "and uses the freshest — so it works whether or not unattended-"
             "upgrades is configured."},
    {"cat": "Freshness — scheduled jobs", "id": "clamav_db_fresh", "type": "job_fresh",
     "param": "/var/lib/clamav/daily.cld|/var/lib/clamav/daily.cvd",
     "name": "AV signatures updated recently", "extras": {"max_age_hours": 48},
     "desc": "Stale antivirus definitions give false comfort. freshclam ships "
             "daily.cvd on a fresh install but rewrites it as daily.cld once it "
             "applies incremental updates (the steady state on a running host), "
             "so this checks BOTH and uses the freshest — no need to guess which "
             "extension yours uses."},
)


# Which catalog categories belong to the Security → Protect picker rather than
# the operational Monitoring → Checks one. Hardening and tamper-detection
# templates are a different job from liveness checks, so they get their own
# surface — same apply mechanics, same scoping, different question being asked.
PROTECT_CATEGORIES = frozenset({
    "Web / application security",
    "Hardening — services",
    "Hardening — must not listen",
    "Integrity — critical files",
    "Integrity — persistence paths",
    "Integrity — must not exist",
    "Detection — log signals",
    "Freshness — scheduled jobs",
})


def baseline_kind(cat):
    """'protect' for hardening/tamper-detection templates, else 'ops'."""
    return 'protect' if cat in PROTECT_CATEGORIES else 'ops'


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
        status, output = res["status"], str(res.get("output", ""))[:200]
        # v6.4.0: SERVER-AUTHORITATIVE baseline acceptance. When the operator
        # clicked "Accept as new baseline", the server recorded the exact
        # failing output they accepted. Suppress the check (show OK) as long as
        # the agent keeps reporting that SAME value — instantly, without waiting
        # for the agent round-trip, surviving refresh/cache. A genuinely NEW
        # change reports a DIFFERENT output → the match fails → it re-fires. The
        # agent also re-baselines in the background so its own state agrees.
        if status in ("critical", "warning"):
            acc = (dev.get("custom_check_accepted") or {}).get(cdef.get("id"))
            if acc is not None and output == acc:
                return "ok", "change accepted as the new baseline"
        return status, output
    return "unknown", "unknown check type"


def repair_applied_catalog_checks(checks):
    """v6.4.0: backfill fields that an older apply dropped, or that a later
    catalog fix supersedes, on ALREADY-APPLIED checks — so an operator doesn't
    have to delete + re-apply across a fleet. Matches an applied check to its
    catalog template by NAME (unique) and, in place:
      - backfills a missing `pattern` on a file_contains check (the top-level
        catalog field the apply used to drop → 'no pattern configured');
      - upgrades a job_fresh `param` to the catalog's multi-path form when the
        current param is a single component of it (ClamAV .cvd/.cld, the apt
        stamp) — so a check applied before the multi-path fix stops
        false-alarming, WITHOUT clobbering a param the operator customised.
    Returns the count changed."""
    by_name = {t.get("name"): t for t in CHECK_BASELINE_CATALOG}
    changed = 0
    for c in checks or []:
        if not isinstance(c, dict):
            continue
        tmpl = by_name.get(c.get("name"))
        if not tmpl:
            continue
        if (c.get("type") == "file_contains" and not c.get("pattern")
                and tmpl.get("pattern")):
            c["pattern"] = tmpl["pattern"]
            changed += 1
        if c.get("type") == "job_fresh":
            tp, cp = str(tmpl.get("param") or ""), str(c.get("param") or "")
            if "|" in tp and cp and cp != tp and cp in tp.split("|"):
                c["param"] = tp
                changed += 1
    return changed


def _custom_checks_for(dev_id, dev, defs, disabled):
    """Per-device list of custom-check entries (same shape as _host_checks)."""
    out = []
    for cdef in defs or []:
        if not isinstance(cdef, dict) or not _custom_check_applies(cdef, dev_id, dev):
            continue
        status, output = _eval_custom_check(cdef, dev)
        key = f"custom:{cdef.get('id', '')}"
        # v6.3.1: expose the check type + protect kind so the Checks page can
        # offer "Reset baseline" on baseline-holding types and badge protect
        # checks instead of labelling everything "custom".
        kind = "protect" if (cdef.get("kind") == "protect"
                             or cdef.get("type") in GUARD_CHECK_TYPES) else "custom"
        out.append(
            {
                "key": key,
                "name": cdef.get("name") or cdef.get("id", "custom"),
                "group": kind,
                "ctype": cdef.get("type") or "",
                "kind": kind,
                "status": status,
                "output": str(output)[:200],
                "enabled": key not in (disabled or set()),
                "custom": True,
            }
        )
    return out
