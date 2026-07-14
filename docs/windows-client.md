# Windows client

The Windows agent (`client/remotepower-agent-win.py`) speaks the same heartbeat
protocol as the Linux agent and reaches near-parity with it for the core
management surface (see the [capability table](#what-the-windows-agent-reports-and-does)).
It is **stdlib-only** Python (3.8+); two pip packages sharpen it:

- **`psutil`** — the richer metric set (CPU / memory / disk / network, the process
  list). Without it the agent still runs, with a reduced metric set.
- **`pywin32`** — lets the agent run as a **real Windows service** (see below).
  Without it the agent falls back to a scheduled task.

Both are installed automatically by the installer.

## How it runs: a Windows service (default) *(v6.2.0)*

By default the agent installs as a **Windows service** named `RemotePowerAgent`
("RemotePower Agent" in `services.msc`), running as **LocalSystem**, start type
**Automatic**. This is the recommended and default mode:

- The **Service Control Manager restarts it on any exit** — a crash, or a
  self-update that simply exits — via configured failure actions (restart after
  5 s). There is no window where the host silently stops reporting.
- Self-update becomes trivial: the agent swaps its own file and lets the SCM
  relaunch it with the new code.
- It's visible and controllable in `services.msc` like any other service.

If `pywin32` cannot be installed (e.g. an offline box with no PyPI mirror), the
installer falls back to a **SYSTEM scheduled task** (`RemotePowerAgent`, trigger
*At startup*, restart-on-failure) — same persistence, less graceful restart
semantics. Everything below notes which mechanism a command targets.

> **Requirement: a machine-wide Python.** The service (and the SYSTEM scheduled
> task) run as the SYSTEM/LocalSystem account, which **cannot launch a per-user
> Python** — including the **Microsoft Store / "App Execution Alias" Python**
> under `…\AppData\Local\Microsoft\WindowsApps\`. The installer detects this and
> installs an **all-users** Python automatically; if you install Python by hand,
> choose **"Install for all users"** (lands in `C:\Program Files\Python3xx\`). A
> Store/per-user Python is why a service or task can register but never run — see
> [Troubleshooting](#troubleshooting).

## Install

### One-liner (recommended)

In the dashboard: **Add device → Quick install** copies a one-liner with a
one-time enrollment token baked in. On the target host, in an **elevated**
PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -Command "iwr 'https://rp.example.com/install.ps1?t=<token>' -UseBasicParsing | iex"
```

On a bare box this single command does everything:

1. **Self-checks for Administrator** (the service/task register as SYSTEM).
2. **Ensures a machine-wide Python** — installs one (winget `--scope machine`,
   else the official python.org all-users installer) if the only Python found is
   per-user or the Store alias, or none at all.
3. **Downloads the agent** from the server and **verifies its SHA-256**.
4. **Installs `psutil` + `pywin32`** into that machine Python, and registers
   pywin32's service DLLs (`pywin32_postinstall`, the fix for service error 1053).
5. **Enrolls** with the baked one-time token.
6. **Registers and starts the service** (falls back to a scheduled task only if
   `pywin32` is unavailable).

It prints whether it installed as a *service* or a *scheduled task*, and the host
appears on the dashboard within ~60 s.

### Scripted / offline

`client/install-windows.ps1` is the scripted equivalent — it uses the agent file
beside it if present, else downloads + verifies it from the server, and takes the
same machine-Python → pywin32 → service path:

```powershell
powershell -ExecutionPolicy Bypass -File install-windows.ps1 `
  -Server https://rp.example.com -Token <enrollment-token> -Name HostA
# a 6-digit PIN instead of a long token:  -Pin 123456
# self-signed CA:                         -CaFingerprint AA:BB:..
# remove everything:                      -Uninstall
```

### Enrollment credential: token vs PIN

Two credentials enroll a host; **don't mix up the flags**:

- **Enrollment token** — a long (16–256 char) one-time string, e.g. the `t=…`
  value baked into the one-liner. Pass with **`--token`** / `-Token`.
- **PIN** — a **6-digit** code from **Add device**. Pass with **`--pin`** /
  `-Pin`.

A 6-digit value passed to `--token` is rejected by the server (tokens must be
≥16 chars); the agent catches this and tells you to use `--pin` instead.

## Managing the agent

> **PowerShell gotcha:** `sc` is an **alias for `Set-Content`** in PowerShell — so
> `sc query RemotePowerAgent` silently does nothing. Use **`sc.exe`** (note the
> `.exe`) or the native `Get-Service` / `Start-Service` / `Stop-Service` /
> `Restart-Service` cmdlets.

### Start / stop / restart (service mode)

From an **elevated** PowerShell, or the `services.msc` GUI (right-click →
Start/Stop/Restart on "RemotePower Agent"):

```powershell
Get-Service RemotePowerAgent | Format-List Name, Status, StartType
Start-Service   RemotePowerAgent
Stop-Service    RemotePowerAgent
Restart-Service RemotePowerAgent
sc.exe qc       RemotePowerAgent     # config: binPath, start type, account
sc.exe qfailure RemotePowerAgent     # the auto-restart (failure) actions
```

Stop is normally immediate (the agent is asleep between heartbeats and that sleep
is interruptible). If a stop lands *during* a heartbeat it can take up to the HTTP
timeout (~20 s) to return — the service reports a wait hint so `services.msc`
won't declare "could not stop". If a Stop ever appears stuck, see
[the service won't stop/start](#services-msc-cant-start-stop-or-restart-the-service)
below.

Install / remove the service directly with the agent (Administrator):

```powershell
$py = "C:\Program Files\Python312\python.exe"
$agent = "C:\Program Files\RemotePower\remotepower-agent-win.py"
& $py $agent --install-service     # registers + starts; self-heals error 1053; prints RUNNING
& $py $agent --uninstall-service   # stops + deletes the service
```

### Scheduled task (fallback mode)

```powershell
schtasks /query /tn RemotePowerAgent
schtasks /end /tn RemotePowerAgent ; schtasks /run /tn RemotePowerAgent   # restart
```

### Logs

The agent writes a rotating log regardless of mechanism:

```powershell
Get-Content "$env:ProgramData\RemotePower\agent.log" -Tail 50 -Wait
```

A healthy start logs `RemotePower Windows agent vX.Y.Z starting` and then goes
quiet (heartbeats aren't logged). `ERROR not enrolled` means the credentials
aren't readable — see [Troubleshooting](#troubleshooting).

## Command-line

The agent takes flags, not sub-commands:

```powershell
remotepower-agent-win.py --enroll --server https://rp.example.com --token <t> --name HostA
remotepower-agent-win.py --enroll --server https://rp.example.com --pin 123456   # PIN instead
remotepower-agent-win.py --run                # heartbeat loop (task/manual entrypoint)
remotepower-agent-win.py --once               # a single heartbeat, printed as JSON (debug)
remotepower-agent-win.py --install-service    # register + start the Windows service
remotepower-agent-win.py --uninstall-service  # stop + delete the service
remotepower-agent-win.py --version
```

(`--service-run` also exists; it's the internal entry point the SCM invokes — you
never call it by hand.)

## Uninstall

### From the dashboard (recommended)

**Devices → the host → Uninstall agent** queues an `uninstall` command. On its
next heartbeat the agent removes **both** persistence mechanisms (service *and*
scheduled task) and deletes its credentials, then stops reporting. Delete the
device row afterward.

### With the installer script

If you have `install-windows.ps1` (it ships beside the agent, or re-download it),
run it elevated with `-Uninstall` — it removes the service/task and the creds:

```powershell
powershell -ExecutionPolicy Bypass -File install-windows.ps1 -Uninstall
```

### Fully manual removal

Removes the service **and** the task, the agent files, and all data (elevated
PowerShell):

```powershell
# 1. Stop + remove the service (and the scheduled task, if that's what you have)
Stop-Service RemotePowerAgent -ErrorAction SilentlyContinue
sc.exe delete RemotePowerAgent
schtasks /delete /tn RemotePowerAgent /f 2>$null

# 2. Remove the agent program files
Remove-Item -Recurse -Force "C:\Program Files\RemotePower" -ErrorAction SilentlyContinue

# 3. Remove all agent data (credentials, logs, markers)
Remove-Item -Recurse -Force "C:\ProgramData\RemotePower" -ErrorAction SilentlyContinue
```

Then delete the device from the dashboard. Leaving `psutil` / `pywin32` /
Python installed is harmless; remove them separately if you installed them only
for the agent.

## What the Windows agent reports and does

Parity with the Linux agent for the core management surface (v6.2.0 buildout):

| Capability | Linux | Windows |
|---|---|---|
| Core metrics (CPU/mem/disk/net) | psutil | psutil (optional; reduced set without it) |
| Reboot / shutdown | `systemctl` | `shutdown /r`/`/s` |
| **reboot-required** detection | `/run/reboot-required` | registry (CBS / WindowsUpdate / PendingFileRenameOperations) *(v6.2.0)* |
| Remote command | `exec:` (shell) | `exec:` (PowerShell); explicit **`ps:`** / **`cmd:`** verbs *(v6.2.0)* |
| **Service** enumerate + control | systemd | `Get-Service` + Start/Stop/Restart-Service *(v6.2.0)* |
| **Process** list + kill | `/proc` + signals | psutil + `taskkill` *(v6.2.0)* |
| **File manager** (`files:`) | yes | yes, Windows-rooted allowlist *(v6.2.0)* |
| Patch detect | apt/dnf/… | Windows Update COM API |
| Patch apply | package manager | PSWindowsUpdate → COM fallback (never auto-reboots) |
| **Third-party patch** (winget) | flatpak/snap/pip/npm (detect) | `winget:` detect **and remediate** *(v6.2.0)* |
| AV posture | ClamAV/rkhunter | Windows Defender (`Get-MpComputerStatus`) |
| Event Log | journalctl | `Get-WinEvent` — System/Application **+ Security**, RecordId cursor that survives a **log clear** (no dup/loss), Event IDs in each line for alert rules *(v6.2.0)* |
| Privileged-group tripwire | `sudo`/`wheel` | `Administrators` (`Get-LocalGroupMember`) *(v6.2.0)* |
| Listening ports | yes | yes |
| Secrets-on-disk scan | yes | yes |
| **Signed self-update** | yes (fail-closed GPG gate) | yes (fail-closed GPG gate) *(v6.2.0)* |
| **SMART** disk health | smartctl | `Get-PhysicalDisk` + reliability counters *(v6.2.0)* |
| **Hardware inventory** | dmidecode | WMI (system + memory) *(v6.2.0)* |
| **Config drift** (file hashing) | yes | yes *(v6.2.0)* |
| **Containers** | docker/podman/k8s | docker CLI (Desktop / Windows containers) *(v6.2.0)* |
| **Custom checks** (file/job/log/service) | yes | yes; `windows_service` type *(v6.2.0)* |
| Security posture → Checks | (n/a) | BitLocker, Firewall (per profile), Defender real-time + signature age, Windows Update service *(v6.2.0)* |
| Compliance scan | OpenSCAP | not ported (oscap is Linux-only; use the cross-platform CIS baseline) |
| Runs as | systemd service | **Windows service** (services.msc); scheduled-task fallback *(v6.2.0)* |
| Read-only audit mode | `/etc/remotepower/audit-mode` | `%ProgramData%\RemotePower\audit-mode` |

### Interpreter selection (`exec:` vs `ps:` vs `cmd:`)

On Windows `exec:` runs the command body through **PowerShell** (the native
default). If you have a script written for `cmd.exe`/batch, or want to be
explicit, use the dedicated verbs so the interpreter is never a function of which
OS the command happened to land on:

- `ps:<script>` — PowerShell, explicitly
- `cmd:<command>` — `cmd.exe /c`, for batch one-liners

### Patch execution

Windows installs pending OS updates via **PSWindowsUpdate** (`Install-WindowsUpdate`)
if present, else the built-in **Microsoft.Update COM API** — it **never
auto-reboots**. Third-party app CVEs (Chrome, 7-Zip, VLC, …) are remediated with
**winget**: `winget:<id>` upgrades one package, `winget:` upgrades all (argv-only,
package-id charset-validated, no shell). Both ride the audited, maker-checker-gated
`upgrade` command, and reboot-flagged rollouts queue a `reboot` afterward (Windows
agents don't reboot on their own).

### Signed self-update

Identical trust model to Linux. The agent compares its own file's SHA-256 against
the server's advertised hash (`/api/agent/win/version`), downloads the new bytes,
verifies the hash, and — if a release public key is pinned at
`%ProgramData%\RemotePower\release.pub` — **requires a valid detached GPG
signature** before swapping its own file. It then restarts **via the SCM** (`sc
stop`/`start`) under a service, or a detached task relaunch under the scheduled
task. Touch `%ProgramData%\RemotePower\require-signed-updates` to make the signed
path mandatory (refuse any unsigned update). Needs `gpg` on PATH (Gpg4win) to
enforce.

## Troubleshooting

Nearly every Windows onboarding problem is one of the following. The agent's log
(`%ProgramData%\RemotePower\agent.log`) and `Get-Service RemotePowerAgent` are the
two things to check first.

### "not enrolled" in the log, even though `--enroll` succeeded

The service/task runs as SYSTEM and can't read the credentials. Two causes:

1. **The enroll ran under the Microsoft Store Python.** Store/MSIX Python
   *virtualizes* filesystem writes, so `agent.json` landed in a per-user package
   cache, not the real `C:\ProgramData\RemotePower\`. **Fix:** re-enroll with the
   **machine** Python (`C:\Program Files\Python3xx\python.exe`).
2. **The credential-file ACL locked SYSTEM out** (agents before the v6.2.0 fix).
   Reading `agent.json` as an admin returns *Access Denied*. **Fix:** grant SYSTEM
   + Administrators and restart:
   ```powershell
   takeown /F "C:\ProgramData\RemotePower\agent.json" | Out-Null
   icacls  "C:\ProgramData\RemotePower\agent.json" /inheritance:r /grant "*S-1-5-18:F" "*S-1-5-32-544:F"
   Restart-Service RemotePowerAgent   # or: schtasks /run /tn RemotePowerAgent
   ```
   (`*S-1-5-18` = LocalSystem, `*S-1-5-32-544` = Administrators — locale-proof
   SIDs.) Current agents write this ACL correctly at enroll time.

### The service registers but won't reach RUNNING (error 1053)

`sc start` times out because pywin32's service DLLs aren't registered. Current
agents **self-heal** this (run `pywin32_postinstall` and retry inside
`--install-service`). To do it by hand:

```powershell
& "C:\Program Files\Python312\python.exe" "C:\Program Files\Python312\Scripts\pywin32_postinstall.py" -install
Start-Service RemotePowerAgent
```

### `services.msc` can't Start, Stop, or Restart the service

Almost always one of:

- **You're not elevated.** Service control needs Administrator — open
  `services.msc` (or PowerShell) *as administrator*.
- **Stop looks stuck for a few seconds.** A stop that lands during a heartbeat
  waits up to the HTTP timeout (~20 s). The service sends the SCM a wait hint so
  it shouldn't error — give it a moment. If it's genuinely wedged, force it:
  ```powershell
  $svc = Get-CimInstance Win32_Service -Filter "Name='RemotePowerAgent'"
  Stop-Process -Id $svc.ProcessId -Force        # kill the process; SCM marks it stopped
  Start-Service RemotePowerAgent
  ```
- **Old agent build.** The prompt wait-hint + shutdown handling shipped in the
  v6.2.0 hardening. If the box is on an older agent, reinstall the service with a
  current agent (`--uninstall-service` then `--install-service`, or re-run the
  installer).
- **Stuck in STOP_PENDING / won't start again.** Delete and recreate:
  ```powershell
  sc.exe delete RemotePowerAgent
  & "C:\Program Files\Python312\python.exe" "C:\Program Files\RemotePower\remotepower-agent-win.py" --install-service
  ```

### A scheduled task fails at boot with `0x80070780` (the task never runs)

The task was registered with a **per-user or Store Python** the SYSTEM account
can't access (`ERROR_CANT_ACCESS_FILE`). `sc.exe qc RemotePowerAgent` (or the
task's action) shows an `…\AppData\Local\Microsoft\WindowsApps\` or `C:\Users\…`
path. **Fix:** install a machine-wide Python (all users) and re-run the installer,
or re-point the task at `C:\Program Files\Python3xx\pythonw.exe`.

### Went offline right after an agent update

Fixed in v6.2.0. Older agents relaunched by killing their own scheduled task
inline (which had no restart trigger). Bring it back with `schtasks /run /tn
RemotePowerAgent`; switching to the service removes the failure mode entirely (the
SCM restarts the agent after any self-update exit).

### The device shows a terminal icon, or no green "verified" badge

Cosmetic and server-side — the fixes ship with the server. Redeploy the server
(`git pull && ./deploy-server.sh`); the content-hash cache-bust also clears a
stale service-worker copy of the dashboard (a hard refresh is the manual
equivalent). The "verified" badge additionally needs the served Windows-agent
hash to match the running agent (it will once both are current).

### Manual / repair service install

To (re)create the service without re-running the installer, PowerShell's
`New-Service` avoids all `sc.exe` quoting pitfalls:

```powershell
$py    = "C:\Program Files\Python312\pythonw.exe"
$agent = "C:\Program Files\RemotePower\remotepower-agent-win.py"
$bin   = "`"$py`" `"$agent`" --service-run"
schtasks /delete /tn RemotePowerAgent /f 2>$null
New-Service -Name RemotePowerAgent -BinaryPathName $bin -DisplayName "RemotePower Agent" -StartupType Automatic
sc.exe failure RemotePowerAgent reset= 86400 actions= restart/5000/restart/5000/restart/5000
Start-Service RemotePowerAgent
```

## Security notes

- Every fixed system binary (`powershell`, `winget`, `shutdown`, `icacls`,
  `schtasks`, `taskkill`, `cmd`, `sc`) is invoked by **absolute path**, never bare
  name — the agent runs as SYSTEM, so a writable `%PATH%` entry would otherwise be
  a privilege-escalation vector *(v6.2.0)*.
- The credential file (`agent.json`, holds the device token) has its ACL locked to
  **SYSTEM + Administrators** via locale-proof SIDs, inheritance stripped, written
  before the first token is stored.
- HTTPS is required; TLS 1.2 floor; 3xx redirects are never followed (no
  token-replay / downgrade).
- **Code signing:** the agent `.py` and installer are **not** Authenticode-signed
  today — a valid code-signing certificate is a procurement step, not a code
  change. Windows Defender / SmartScreen may prompt on first run until one is in
  place. (This is separate from the agent's own GPG-signed *self-update* gate,
  which is fully implemented.)

## Config / data paths

Everything lives under `%ProgramData%\RemotePower\`:

| File | Purpose |
|---|---|
| `agent.json` | credentials (server URL, device id, token) — ACL-locked |
| `agent.log` | rotating agent log *(v6.2.0)* |
| `eventlog_cursor.json` | per-channel Event Log RecordId cursor |
| `audit-mode` | marker: read-only mode (refuse write commands) |
| `release.pub` | pinned release public key (enables signature enforcement) |
| `require-signed-updates` | marker: refuse any unsigned self-update |
| `file-roots` | optional override for the file-manager allowlist roots |

The agent itself installs to `C:\Program Files\RemotePower\remotepower-agent-win.py`.

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
