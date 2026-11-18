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

## How it runs: a Windows service (default)

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

In the dashboard, click **Enroll host** on the Hosts page and then **Quick install
command**. It shows a one-liner with an enrollment token baked in (one host, unless you raise
**Hosts that can use it** first). On the target host, in an **elevated**
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
5. **Enrolls** with the baked token.
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

- **Enrollment token** — a long (16–256 char) string, e.g. the `t=…`
  value baked into the one-liner. It enrols one host unless it was made for more
  (**Hosts that can use it**), which is how you run one command on many hosts from group policy or Intune. Pass with **`--token`** / `-Token`.
- **PIN** — a **6-digit** code from **Enroll host**. Pass with **`--pin`** /
  `-Pin`. The agent also reads `REMOTEPOWER_ENROLL_PIN` and `REMOTEPOWER_ENROLL_TOKEN` from the
  environment, and the installers use them, so neither shows up in the process list *(7.5.0)*.

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
[the service won't stop/start](#servicesmsc-cant-start-stop-or-restart-the-service)
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

**Hosts → the host → Uninstall agent** queues an `uninstall` command. On its
next heartbeat the agent removes **both** persistence mechanisms (service *and*
scheduled task) and deletes its credentials, then stops reporting. Delete the
host row afterward.

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

Then delete the host from the dashboard. Leaving `psutil` / `pywin32` /
Python installed is harmless; remove them separately if you installed them only
for the agent.

## What the Windows agent reports and does

Parity with the Linux agent for the core management surface:

| Capability | Linux | Windows |
|---|---|---|
| Core metrics (CPU/mem/disk/net) | psutil | psutil (optional; reduced set without it) |
| OS version and build | `/etc/os-release` | The build, revision, display version, edition, product name and installation type from the registry (see [Windows version and build](#windows-version-and-build)) |
| File shares and TPM | not collected | `Get-SmbShare`, `Get-Tpm` and `Win32_Tpm` (see [File shares and the TPM](#file-shares-and-the-tpm)) |
| Reboot / shutdown | `systemctl` | `shutdown /r`/`/s` |
| **reboot-required** detection | `/run/reboot-required` | registry (CBS / WindowsUpdate / PendingFileRenameOperations) |
| Remote command | `exec:` (shell) | `exec:` (PowerShell); explicit **`ps:`** / **`cmd:`** verbs |
| **Service** enumerate + control | systemd | `Get-Service` + Start/Stop/Restart-Service |
| **Process** list + kill | `/proc` + signals | psutil + `taskkill` |
| **File manager** (`files:`) | yes | yes, Windows-rooted allowlist |
| Patch detect | apt/dnf/… | Windows Update COM API; Defender definition updates are counted apart, and each search says whether it worked (see [Windows Update](#windows-update)) |
| Patch apply | package manager | PSWindowsUpdate → COM fallback (never auto-reboots) |
| **Third-party patch** (winget) | flatpak/snap/pip/npm (detect) | `winget:` detect **and remediate** |
| AV posture | ClamAV/rkhunter | Windows Defender (`Get-MpComputerStatus`) |
| Event Log | journalctl | `Get-WinEvent` — System/Application **+ Security**, RecordId cursor that survives a **log clear** (no dup/loss), Event IDs in each line: these lines are the host's journal. **Log rules** read the events they name through `wevtutil`, as `eventlog.<Channel>.<id>` units with their own cursor — see [Windows event rules](log-watch.md#windows-event-rules) |
| Privileged-group tripwire | `sudo`/`wheel` | `Administrators` (`Get-LocalGroupMember`) |
| Listening ports | yes | yes |
| Secrets-on-disk scan | yes | yes |
| **Signed self-update** | yes (fail-closed GPG gate) | yes (fail-closed GPG gate) |
| **SMART** disk health | smartctl | `Get-PhysicalDisk` + reliability counters |
| **Hardware inventory** | dmidecode | WMI (system + memory) |
| **Config drift** (file hashing) | yes | yes |
| **Containers** | docker/podman/k8s | docker CLI (Desktop / Windows containers) |
| **Custom checks** (file/job/log/service) | yes | yes; `windows_service` type, and a read-only [`registry`](checks.md#windows-registry-values) type (one `HKLM` value through `winreg`) |
| Security posture → Checks | (n/a) | BitLocker, Firewall (per profile), Defender real-time + signature age, Windows Update service |
| Compliance scan | OpenSCAP | not ported (oscap is Linux-only; use the cross-platform CIS baseline). Triggering an OpenSCAP scan on a Windows/macOS host now returns an honest "Linux only, skipped" instead of a silent no-op |
| **Installed software** | `dpkg` / `rpm` / `apk` / `pacman` package list | The Uninstall keys of the registry (read only), sent to the software views; see [Software inventory](patches.md#software-inventory) |
| **Scan packages now** (`force_package_scan`) | apt/dnf refresh and the package list | Windows Update pending refresh and the installed-software list |
| **Update agent now** (`force_agent_upgrade`) | signed self-update | signed self-update |
| **Backup-freshness monitors** (`backup_monitors`) | mtime + size | mtime + size |
| Runs as | systemd service | **Windows service** (services.msc); scheduled-task fallback |
| Read-only audit mode | `/etc/remotepower/audit-mode` | `%ProgramData%\RemotePower\audit-mode` |

### Installed software

The agent reads the programs of the machine from the Uninstall key under
`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` and from its `WOW6432Node` twin, which holds the
32-bit programs. It only reads: it opens keys for reading and never loads, saves or writes a registry hive. An entry with no
name, a component Windows hides from the list (`SystemComponent` is 1) and an update or a hotfix of another program (it names a
`ParentKeyName`) are left out and counted. A program that was installed for one user alone lives in that user's own registry
and is not listed. A program that Windows does not record under these keys, such as an app from the Microsoft Store, is not
listed either. [Software inventory](patches.md#software-inventory) says how the server shows the list, and
[CVE scanning](cve.md#windows-and-macos-hosts) why it is not checked for vulnerabilities.

### Windows Update

The agent asks Windows Update for the updates that are not installed, with the system information (about every 12 polls)
and when you press **Scan now**. Two things about the answer are worth knowing.

- **Defender definition updates are not counted.** Windows offers them several times a day, so counting them put one or
  two pending updates on every Windows host. A title is a definition update when it contains "Security Intelligence
  Update", when it contains "Definition Update for" and names Defender or Antivirus, or when it names KB2267602. The agent
  reports them apart: the pending count, the patch alert, the patch SLA and the risk score leave them out, and the
  host's Packages card shows how many there were under **Definition updates**. The Defender platform update (KB4052623) is
  a program update and is counted. An agent older than this one sends the definition updates with the rest, and the server
  takes the ones it can see out of the count when the report arrives.
- **The search is reported.** Each report says when the search ran, whether it worked and where it asked: Windows Update,
  or a WSUS server that a policy points the host at. A search that failed says why in one word: `timeout`, `access`,
  `service`, `network` or `unknown`. It never sends the text of the error. A failed search does not clear the count and
  does not refresh it. The host keeps the count it had and says when that count was taken. For 3 days that count is still
  what the reports use. After that it is too old to say the host is patched, so the patch reports list the host as No data
  and keep the count and its date beside it (`stale_count`), and the badge of an upgrade you queued waits for a count that
  was taken after the upgrade.

You see the search on the host's **Packages** card and in its patch report (*Last search 12 minutes ago, ok*, or in amber
*Last search failed (access); count taken 5d ago*; the Time display setting under My Account > Appearance shows the
exact time instead). The Checks page has a row, **Windows Update search**, that turns amber after 3 days without a
successful search and red after 14. Silence it for one host like any other row.

### Windows version and build

The agent reads `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion` (read only) and sends the build number,
the revision after it (`UBR`, which changes with every cumulative update), the display version (`23H2`, or the release id
on a build from before 20H2), the edition, the product name and the installation type (`Client`, `Server` or `Server Core`).
The server shows them as one line, for example *Windows 11 Pro 23H2 (build 22631.3593)*, in the **OS** row of the host's
System info and in the OS column of the Hosts list.

The family comes from the build number: 22000 and up is Windows 11. The product name cannot say, because many builds of
Windows 11 still write "Windows 10" into it. A server keeps the name of its product, since a server and a client share
build numbers (Windows Server 2025 and Windows 11 24H2 are both 26100). The installation type says which a system is. The
edition id cannot, because Windows 10 and 11 Enterprise multi-session (what Azure Virtual Desktop runs) is a client system
whose edition id is `ServerRdsh`. A host on an agent that does not send the installation type is read from its product
name and its edition id, with `ServerRdsh` counted as a client.

The [Data Explorer](data-explorer.md#windows-hosts) has the fields (`win_build`, `win_ubr`, `win_display_version`,
`win_edition`, `win_product`, `win_family`), so "which hosts are still on Windows 10" and "which Windows 11 hosts are behind
revision 3593" are queries. [Fleet Query](fleet-query.md) has **Windows build contains**.

### File shares and the TPM

With the system information the agent also asks for the file shares the host exports (`Get-SmbShare`) and for its TPM
(`Get-Tpm`, and the `Win32_Tpm` class for the version of the specification). Each is its own PowerShell, they share a time
budget of 40 seconds, and a probe that fails or that the host cannot answer sends nothing. What is not sent is not read as
"none": a TPM that was never reported is not a host without one.

- **Shares.** A share whose name ends in `$` (`ADMIN$`, `C$`, `IPC$` and any other hidden one) is administrative: the agent
  counts those and does not list them. The other shares are listed with their name, path, description and whether the share
  is encrypted, at most 100, and the count says how many there are. The host drawer shows the number in the **Shares** row of
  System info and the shares themselves under it.
- **TPM.** Present, ready and enabled, as Windows reports them, and the version of the specification (`2.0`). The **TPM** row
  of System info reads, for example, *present · ready · spec 2.0*, *present · not ready* or *none*.

Both are fields of the [Data Explorer](data-explorer.md#windows-hosts) (`shares_count`, `tpm_present`, `tpm_ready`) and
criteria of [Fleet Query](fleet-query.md) (**Shares >**, **TPM**). There is no alert and no check for either.

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
`upgrade` command, and reboot-flagged policies/rollouts queue a
**`reboot-if-required`** afterward — the agent consults its
pending-reboot registry signals and reboots only when Windows actually asks
for one, reporting "no reboot required — skipped" otherwise. (Windows agents
never reboot on their own; the explicit `reboot` command remains
unconditional.)

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
  it shouldn't error — give it a moment. If it's wedged, force it:
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

### The host shows a terminal icon, or no green "verified" badge

Cosmetic and server-side — the fixes ship with the server. Redeploy the server
(`git pull &&./deploy-server.sh`); the content-hash cache-bust also clears a
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
  a privilege-escalation vector.
- The credential file (`agent.json`, holds the host token) has its ACL locked to
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
| `agent.json` | credentials (server URL, host id, token) — ACL-locked |
| `agent.log` | rotating agent log |
| `eventlog_cursor.json` | per-channel Event Log RecordId cursor |
| `pkg_hash` | the fingerprint of the installed-software list the server took last; the list is sent again only when it changes |
| `winevent_cursor.json` | for each Event Log channel and event id a log rule reads, the RecordId of the last event sent |
| `audit-mode` | marker: read-only mode (refuse write commands) |
| `release.pub` | pinned release public key (enables signature enforcement) |
| `require-signed-updates` | marker: refuse any unsigned self-update |
| `require-signed-commands` | marker: refuse any command that is unsigned or not addressed to this host (see [Signed commands](agent-commands.md#signed-commands)) |
| `file-roots` | optional override for the file-manager allowlist roots |

The agent itself installs to `C:\Program Files\RemotePower\remotepower-agent-win.py`.

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
