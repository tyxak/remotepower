# Checks

**Monitoring → Checks** is the CheckMK-style rollup: every monitored signal
on every host as one row — **OK / WARN / CRIT / UNKNOWN** — with the check's
output text. It merges reachability, resource thresholds, security posture,
hardware health, custom checks and custom-script results into a single
sortable, filterable table.

## Using the page

- **Filter** by state, host, or check name; sort any column.
- **Toggle a check off** on a host to silence it there — the mute is stored
  server-side (`exposure`-style mutes) and honoured by alerting.
- *Hide muted* and *hide unmonitored* default ON.
- **Remediate** *(v6.3.0)* — every failing (non-OK) row has a wrench button
  that generates a host-scoped remediation runbook through the AI advisor:
  step-by-step fix instructions with verification steps, built from the
  check's name, group, status and output. Uses your configured AI provider.
- **Posture radar** *(v6.3.0)* — the device drawer's Audit tab opens with a
  radar built from these same rows: each check group (core, resources,
  security, services, hardware, …) is an axis, scored by its share of
  healthy checks. A host's shape shows *where* it is weak at a glance.

## Where rows come from

- **Built-ins** — reachability, CPU/RAM/disk thresholds, posture (world-
  exposed ports honour exposure mutes), SMART, patch backlog, CVEs.
- **OS security posture** — reported by the agent and rendered only on the
  matching OS, so a host never shows an irrelevant empty row:
  - **Windows** (`win_posture`) — Defender real-time protection, signature age,
    tamper protection, BitLocker (OS volume), Windows Firewall profiles, Secure
    Boot, UAC, the Windows Update service, and a pending-reboot signal.
  - **macOS** (`mac_posture`) — FileVault disk encryption, the Application
    Firewall, Gatekeeper, System Integrity Protection (SIP), and automatic
    security updates.
- **Custom checks** — server-side process/port checks and agent-side
  file/journal/log checks defined in the Check catalog.
- **Custom scripts** — a [custom script](custom-scripts.md) whose exit code
  maps to OK/WARN/CRIT.

The same engine feeds the per-device checks view in the device drawer and
the dashboard checks-rollup widget.

## Baseline checks

**Baseline checks** (toolbar button) is the checks analogue of *Service
baselines*: a shipped catalog of recommended checks you apply to a **scope** —
the whole fleet, a group, or a tag — in one click. Each becomes an ordinary
scoped check, so it evaluates, shows OK/WARN/CRIT, alerts and can be silenced
per host exactly like any custom check, and it stays live as hosts join the
scope. The catalog is grouped into **Core liveness** (agent, time sync, cron),
**Security posture** (firewall, auditd, unattended-upgrades, SSH reachable,
telnet closed), **Filesystem / OS** (no OOM-kill, no pending reboot, logins not
disabled) and **Role-tagged** (Docker/nginx/PostgreSQL, applied to their tag).
Applying is idempotent — a check already present for that scope is skipped.
Defaults suit a Debian/Ubuntu fleet and are editable from the Check catalog
afterwards (e.g. `crond.service` on RHEL, `firewalld`/`nftables`).
