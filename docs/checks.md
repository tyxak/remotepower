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
- **Alerts for the same problem** — a failing check whose host has alerts for the same kind of problem says so beside
  its output: **Alert open**, **Alert resolved, still failing** (someone closed the alert and the host still
  reports it) or **Alert resolved, waiting for the host**. A bar above the table links to
  [Problems](problems.md), which lists each problem once across Alerts, Needs Attention and Checks. The API adds
  `problem` to those checks on `GET /api/checks?problems=1`.
- **Remediate** *(v6.3.0)* — every failing (non-OK) row has a wrench button
  that generates a host-scoped remediation runbook through the AI advisor:
  step-by-step fix instructions with verification steps, built from the
  check's name, group, status and output. Uses your configured AI provider.
- **Posture radar** *(v6.3.0)* — the host drawer's Audit tab opens with a
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
    Boot, UAC, the Windows Update service, and a pending-reboot signal. The
    Windows Update service starts on demand, so it is only a warning when its
    start type is Disabled (an agent older than 7.3.0 does not report the start
    type and keeps the old rule, a service that is not running).
    **Windows Update search** is a separate row, from the state the agent sends
    with each search (see [Windows Update](windows-client.md#windows-update)):
    it is amber after 3 days without a search that worked and red after 14. One
    failed search is not a finding, since the next may work.
  - **macOS** (`mac_posture`) — FileVault disk encryption, the Application
    Firewall, Gatekeeper, System Integrity Protection (SIP), and automatic
    security updates.
  - **Linux** — separate rows rather than one. `linux_firewall` (is any of
    nftables / iptables / ufw actually enforcing) is **always on** — an
    unprotected host is real exposure, not a preference. `linux_ssh_hardening`
    (root login, password authentication, empty passwords, and — since
    v7.0.0 — X11 forwarding) and `linux_auto_update` (unattended-upgrades /
    dnf-automatic and friends) are **opt-in**: they only render when *Security
    hardening* is enabled under Settings → Security, because password SSH and
    manual patching are reasonable choices on plenty of fleets, and an advisory
    nobody asked for is an advisory that gets muted. `linux_disk_encryption`
    (dm-crypt / LUKS) is opt-in too, under its own *Disk encryption checks*
    setting — BitLocker and FileVault are the platform default, so their absence
    is always worth reporting, whereas an unencrypted Linux root is the norm.
    A host whose agent cannot see device-mapper reports nothing either way,
    rather than being reported as unencrypted: being unable to look is not a
    finding. Since 7.5.0 the firewall row raises an alert when a host turns up
    with no active ruleset (`linux_firewall_off`), and so does the encryption
    row when its setting is on (`linux_encryption_off`). Each clears itself
    when the host is fixed, and switching *Disk encryption checks* off clears
    the open encryption alerts. The first heartbeat after the upgrade raises
    one alert for every Linux host that has no active firewall; mute the event
    for a host (or route the *Firewall* kind elsewhere) if that is by design. `secure_boot` (UEFI Secure Boot) is opt-in on the same grounds,
    under *Secure Boot checks* — out-of-tree kernel modules such as ZFS, NVIDIA
    or VirtualBox will not load under Secure Boot unless you enroll their
    signing key, so switching it off is a routine decision rather than an
    oversight. A host with no EFI variable to read — a BIOS/CSM boot, a
    container, a virtual machine without UEFI firmware — stays silent whichever
    way the setting is left. The state still appears on the host drawer as a
    plain fact; the setting controls the check and the advisory finding.
- **Certificate files** — the certificate files the host's own services read. The `cert_files` row is critical when a file has
  expired, a warning when one expires inside the window (**Cert-file expiring (days)**, 21 by default) and green otherwise. A host
  that reported no files shows no row, and the system CA bundle is left out. The **Certificate file expiry** setting turns the row
  off with the alert, the risk factor and the rest; see [certificate files](tls-monitor.md#certificate-files-on-your-hosts)
  *(7.5.0)*.
- **Custom checks** — server-side process/port checks and agent-side
  file/journal/log checks defined in the Check catalog, and, on Windows hosts,
  [registry value](#windows-registry-values) checks.
- **Custom scripts** — a [custom script](custom-scripts.md) whose exit code
  maps to OK/WARN/CRIT.

The same engine feeds the per-host checks view in the host drawer and
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
host search rather than typed as a raw id.

## Two baseline pickers

The catalog is split by intent, and each picker only offers (and lists) its own
side:

- **Monitoring → Checks → Baseline checks** — the operational set above: is the
  host alive, patched, and running what it should.
- **Security → Protect → Baseline protect checks** — about 69 hardening and
  tamper-detection templates: ports that must not listen, critical-file
  integrity, persistence paths, log signals, and six
  [Windows registry](#windows-registry-values) settings. See
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
  reaches (grouped by /24 or /64) and alerts once on each new one;
  `param` takes an optional CIDR ignore-list.
- **`auth_new_source`** — learns which source networks successfully authenticate
  over SSH, and alerts the first time a new one does.

Full behaviour, the quarantine vault and the safety rails are documented in
[Integrity Guard](integrity-guard.md).

## Windows registry values

The **Windows registry value** type reads one value under `HKLM` on a Windows
host and compares it with the one you expect. It answers questions such as "is
SMBv1 off?" or "is UAC on?" for every Windows host in a scope, and it shows OK
or critical and alerts like any other check.

Choose the type in the **Add check** dialog and fill in four fields:

| Field | What to enter |
|---|---|
| **Registry path (under HKLM)** | For example `SYSTEM\CurrentControlSet\Control\Lsa`. It starts with `SOFTWARE` or `SYSTEM`, has at most 12 parts and 200 characters, and holds only letters, digits, spaces, backslashes and `. - _ ( ) { }`. |
| **Value name** | For example `LmCompatibilityLevel`. Up to 64 characters from the same set, without backslashes. |
| **Condition** | `equals`, `does not equal`, `is at least`, `is at most`, `is set` or `is not set`. |
| **Expected value** | A whole number (`5` or `0x5`) or a text. The two *at least* and *at most* conditions need a number, and *is set* and *is not set* take no value. |

How the agent reads it:

- **Read-only.** It opens the key for reading and asks for that one value. It never
  writes, creates or deletes anything in the registry.
- **`HKLM` only.** The agent runs as SYSTEM, so `HKCU` would be SYSTEM's own hive
  and say nothing about your users. A path outside `SOFTWARE` and `SYSTEM` is
  refused too, so the hives that hold password hashes are out of reach.
- **The 64-bit view.** A check reads the same key that PowerShell and the Windows
  tools read.
- **What comes back.** A DWORD or QWORD is a number. A text is compared without
  regard to case, and a text that looks like a number (`"10"`) is compared as one.
  A binary value is reported as `binary, N bytes`, never as its bytes, and every
  answer is cut at 200 characters.
- **Secrets are kept off the page.** A text value whose name looks like a password,
  a key or a token (`DefaultPassword`, `AccessKey`, `Authorization` and `SharedKey`
  are examples) is not read at all. In any other text value, the password after a
  name such as `password`, `token` or `secret` (a `--password` flag, `Password=` in a
  connection string) and the password of a URL are replaced by `[REDACTED]` before
  the text leaves the host. That is a second line of defence, not a guarantee: a secret
  written with no such name before it is not found, so do not point a check at a value that
  holds one. A number with such a name is read.
- **A value that is not set** passes *is not set* and *does not equal*, and fails
  the other conditions. The description of each baseline check says which applies.
- **Windows hosts only.** A Linux or macOS host in the same scope is not given the
  check and shows no row for it, so a fleet-wide apply adds nothing there.

The server checks a definition when you save it and tells you what it refused
(another hive, a path outside `SOFTWARE` and `SYSTEM`, more than 12 parts, a
character that is not allowed, a missing value name). The agent applies the same
rules again to every definition it receives.

Six ready-made checks are in the **Hardening — Windows registry** group of the
baseline protect checks. Each names the value it reads:

| Check | Reads | Passes when |
|---|---|---|
| SMBv1 server off | `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1` | the value is not 1 (no value passes) |
| NTLM level 5 | `SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel` | the value is at least 5 |
| UAC enabled | `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA` | the value is 1 |
| Defender real-time protection not disabled by policy | `SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring` | the value is not 1 (no value means no policy) |
| RDP network-level authentication required | `SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication` | the value is 1 |
| Cached logons at most 4 | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount` | the value is 4 or less (no value fails, because the default is 10) |

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
