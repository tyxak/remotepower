# Checks

**Monitoring → Checks** is the CheckMK-style rollup: every monitored signal
on every host as one row — **OK / WARN / CRIT / UNKNOWN** — with the check's
output text. It merges reachability, resource thresholds, security posture,
hardware health, custom checks and custom-script results into a single
sortable, filterable table.

## Using the page

- **Filter** by state, host, or check name; sort any column.
- **Toggle a check off** on a host to silence it there — the mute is stored
  server-side (`exposure`-style mutes) and honoured by alerting. Disabling
  stops the check *everywhere*, not just on the page: it is dropped from the
  check set pushed to the agent, so the agent stops evaluating it (and, for
  guard checks, stops quarantining), and any open alert it raised is resolved.
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
  - **Linux** — separate rows rather than one. `linux_firewall` (is any of
    nftables / iptables / ufw actually enforcing) is **always on** — an
    unprotected host is real exposure, not a preference. `linux_ssh_hardening`
    (root login, password authentication, empty passwords, and — since
    v6.4.3 — X11 forwarding) and `linux_auto_update` (unattended-upgrades /
    dnf-automatic and friends) are **opt-in**: they only render when *Security
    hardening* is enabled under Settings → Security, because password SSH and
    manual patching are deliberate choices on plenty of fleets, and an advisory
    nobody asked for is an advisory that gets muted. `linux_disk_encryption`
    (dm-crypt / LUKS) is opt-in too, under its own *Disk encryption checks*
    setting — BitLocker and FileVault are the platform default, so their absence
    is always worth reporting, whereas an unencrypted Linux root is the norm.
    A host whose agent cannot see device-mapper reports nothing either way,
    rather than being reported as unencrypted: being unable to look is not a
    finding.
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
disabled) and **Role-tagged** (Docker/nginx/PostgreSQL, plus RemotePower's own syslog
receiver and KMIP key server on the `rp-server` tag — each applied to its tag).
Applying is idempotent — a check already present for that scope is skipped.
Defaults suit a Debian/Ubuntu fleet and are editable from the Check catalog
afterwards (e.g. `crond.service` on RHEL, `firewalld`/`nftables`). Besides the
fleet/group/tag scopes you can also target **a specific host**, picked by a
device search rather than typed as a raw id.

## Two baseline pickers

The catalog is split by intent, and each picker only offers (and lists) its own
side:

- **Monitoring → Checks → Baseline checks** — the operational set above: is the
  host alive, patched, and running what it should.
- **Security → Protect → Baseline protect checks** — ~63 hardening and
  tamper-detection templates: ports that must not listen, critical-file
  integrity, persistence paths, log signals. See
  [Integrity Guard](integrity-guard.md).

Both create ordinary scoped checks and both evaluate into the same Checks table
here — only the *definition* lives on separate pages.

## Integrity & egress check types

Six agent-side types back the Protect set and can be used in any check:

- **`file_hash`** — SHA-256 of one file; baselines on first run, alerts on
  change.
- **`dir_baseline`** — a subtree's file list (`path` or `path::glob`); alerts on
  anything added, changed or removed, and can optionally **auto-quarantine** new
  files into an on-host vault.
- **`file_contains`** — a regex content match across a subtree (`path` or
  `path::glob` plus `pattern`), so a file whose *contents* turn malicious is
  caught, not just one appearing.
- **`egress_flagged`** — alerts on an active outbound connection to an address
  in your flagged IP/CIDR list.
- **`egress_baseline`** — learns the external destinations the host normally
  reaches (grouped by /24 or /64) and alerts once on each genuinely new one;
  `param` takes an optional CIDR ignore-list.
- **`auth_new_source`** — learns which source networks successfully authenticate
  over SSH, and alerts the first time a new one does.

Full behaviour, the quarantine vault and the safety rails are documented in
[Integrity Guard](integrity-guard.md).

## Service checks per platform

"Is this service running" has a different mechanism on each OS, so there is one
check type per platform. They behave identically otherwise — same alerting, same
silencing, same catalog:

| Type | Platform | `param` | Evaluated with |
|---|---|---|---|
| `systemd_unit` | Linux | unit name (`nginx.service`) | `systemctl is-active` |
| `windows_service` | Windows | short service name (`wuauserv`) | `Get-Service` |
| `launchd_service` | macOS | launchd label (`com.openssh.sshd`) | `launchctl list` |

On macOS a job that is **loaded but not running** reports **warning**, not
critical — that is the normal state for an on-demand launchd job, and treating it
as a failure would alert on healthy hosts.

A check type assigned to a host that cannot evaluate it reports `unknown` with a
"not applicable" note, rather than a misleading OK or a false alert. The
integrity and egress guard types above are Linux-only today.

## When a check starts alerting

The first definitive observation of a check is **seeded silently**, so applying
a batch of baselines never emits a storm on the same beat. A check **still
failing on its next report** raises `custom_check_failed`, then stays quiet
until it recovers. Agent-side results ride `sysinfo`, which is sent every 10th
poll — so allow ~10 minutes after applying before rows leave `unknown`.
