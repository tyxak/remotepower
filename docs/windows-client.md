# Windows client

The Windows agent (`client/remotepower-agent-win.py`) speaks the same heartbeat
protocol as the Linux agent. It is **stdlib-only** (Python 3.8+); `psutil` is an
optional dependency that unlocks the richer metric set (CPU/memory/disk/network,
disk I/O, the process list). It runs as a **Scheduled Task** (`RemotePowerAgent`),
not a service — no third-party service wrapper is involved.

## Install

### One-liner (recommended)

In the dashboard: **Add device → Quick install command** copies a one-liner with a
one-time token baked in. On the target host, in an **elevated** PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -Command "iwr 'https://rp.example.com/install.ps1?t=<token>' -UseBasicParsing | iex"
```

It downloads the agent from the server, **verifies its SHA-256**, best-effort
installs `psutil`, enrolls, and registers the `RemotePowerAgent` scheduled task
(runs `--run` at startup as SYSTEM). **Python is installed automatically if it's
missing** — via `winget` on modern Windows, else the official python.org silent
installer — so the one-liner works on a bare box. Self-checks for elevation.

### Scripted / offline

The `install-windows.ps1` script is the scripted equivalent (uses the agent from
beside it if present, else downloads + verifies it from the server):

```powershell
powershell -ExecutionPolicy Bypass -File install-windows.ps1 `
  -Server https://rp.example.com -Token <enrollment-token> -Name HostA
# self-signed CA:  -CaFingerprint AA:BB:..
# remove:          -Uninstall
```

## Command-line

The agent takes flags, not sub-commands:

```powershell
remotepower-agent-win.py --enroll --server https://rp.example.com --token <t> --name HostA
remotepower-agent-win.py --run       # scheduled-task entrypoint (the heartbeat loop)
remotepower-agent-win.py --once      # a single heartbeat, printed as JSON (debugging)
remotepower-agent-win.py --version
```

Task + log management:

```powershell
schtasks /query /tn RemotePowerAgent
schtasks /end /tn RemotePowerAgent ; schtasks /run /tn RemotePowerAgent   # restart
Get-Content "$env:ProgramData\RemotePower\agent.log" -Tail 50 -Wait       # v6.1.3: real log
```

## What the Windows agent reports and does

Parity with the Linux agent for the core management surface (v6.1.3 buildout):

| Capability | Linux | Windows |
|---|---|---|
| Core metrics (CPU/mem/disk/net) | psutil | psutil (optional; reduced set without it) |
| Disk I/O rate | yes | yes *(v6.1.3)* |
| Reboot / shutdown | `systemctl` | `shutdown /r`/`/s` |
| **reboot-required** detection | `/run/reboot-required` | registry (CBS / WindowsUpdate / PendingFileRenameOperations) *(v6.1.3)* |
| Remote command | `exec:` (shell) | `exec:` (PowerShell); explicit **`ps:`** / **`cmd:`** verbs *(v6.1.3)* |
| **Service** enumerate + control | systemd | `Get-Service` + Start/Stop/Restart-Service *(v6.1.3)* |
| **Process** list + kill | `/proc` + signals | psutil + `taskkill` *(v6.1.3)* |
| **File manager** (`files:`) | yes | yes, Windows-rooted allowlist *(v6.1.3)* |
| Patch detect | apt/dnf/… | Windows Update COM API |
| Patch apply | package manager | PSWindowsUpdate → COM fallback |
| **Third-party patch** (winget) | flatpak/snap/pip/npm (detect) | `winget:` detect **and remediate** *(v6.1.3)* |
| AV posture | ClamAV/rkhunter | Windows Defender (`Get-MpComputerStatus`) |
| Event Log | journalctl | `Get-WinEvent` — System/Application **+ Security**, with a RecordId cursor (no dup/loss) and Event IDs in each line for alert rules *(v6.1.3)* |
| Local accounts / privileged-group tripwire | `/etc/group` | `Get-LocalGroupMember` |
| Listening ports | yes | yes |
| Secrets-on-disk scan | yes | yes |
| **Signed self-update** | yes (fail-closed GPG gate) | yes (fail-closed GPG gate) *(v6.1.3)* |
| **SMART** disk health | smartctl | `Get-PhysicalDisk` + reliability counters *(v6.1.3)* |
| **Hardware inventory** | dmidecode | WMI (system + memory) *(v6.1.3)* |
| **Config drift** (file hashing) | yes | yes *(v6.1.3)* |
| **Containers** | docker/podman/k8s | docker CLI (Desktop / Windows containers) *(v6.1.3)* |
| **Custom checks** (file/job/log/service) | yes | yes; `windows_service` type *(v6.1.3)* |
| Security posture → Checks | (n/a) | BitLocker, Firewall, Defender real-time + sig age, WU service *(v6.1.3)* |
| Compliance scan | OpenSCAP | not ported (oscap is Linux-only; use the cross-platform CIS baseline) |
| Read-only audit mode | `/etc/remotepower/audit-mode` | `%ProgramData%\RemotePower\audit-mode` |

### Interpreter selection (`exec:` vs `ps:` vs `cmd:`)

On Windows `exec:` runs the command body through **PowerShell** (the native
default). If you have a script written for `cmd.exe`/batch, or want to be
explicit, use the dedicated verbs so the interpreter is never a function of which
OS the command happened to land on:

- `ps:<script>` — PowerShell, explicitly
- `cmd:<command>` — `cmd.exe /c`, for batch one-liners

### Signed self-update

Identical trust model to Linux. The agent compares its own file's SHA-256 against
the server's advertised hash (`/api/agent/win/version`), downloads the new bytes,
verifies the hash, and — if a release public key is pinned at
`%ProgramData%\RemotePower\release.pub` — **requires a valid detached GPG
signature** before swapping its own file and relaunching the scheduled task.
Touch `%ProgramData%\RemotePower\require-signed-updates` to make the signed path
mandatory (refuse any unsigned update). Needs `gpg` on PATH (Gpg4win) to enforce.

### Security notes

- Every fixed system binary (`powershell`, `winget`, `shutdown`, `icacls`,
  `schtasks`, `taskkill`, `cmd`) is invoked by **absolute path**, never bare name
  — the agent runs as SYSTEM, so a writable `%PATH%` entry would otherwise be a
  privilege-escalation vector *(v6.1.3)*.
- The credential file (`agent.json`, holds the device token) has its ACL locked
  to SYSTEM + Administrators, inheritance stripped, written before the first token
  is stored.
- HTTPS is required; TLS 1.2 floor; 3xx redirects are never followed (no
  token-replay / downgrade).
- **Code signing:** the agent `.py` and installer are **not** Authenticode-signed
  today — a valid code-signing certificate is a procurement step, not a code
  change. Windows Defender may prompt on first run until one is in place.

### Config / data paths

Everything lives under `%ProgramData%\RemotePower\`: `agent.json` (creds),
`agent.log` (v6.1.3), `eventlog_cursor.json`, `audit-mode` / `release.pub` /
`require-signed-updates` markers, and the optional `file-roots` override for the
file manager.

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
