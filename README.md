# RemotePower

<div align="center">

![RemotePower Dashboard](docs/screenshots/Index.png)

**Self-hosted remote management for your Linux fleet — and your homelab.**
Web dashboard, push-based agents, no inbound ports. Set it up in five minutes.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)](https://kernel.org)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://hub.docker.com)
[![Nginx](https://img.shields.io/badge/server-Nginx-green.svg)](https://nginx.org)
[![Python](https://img.shields.io/badge/python-3.8+-yellow.svg)](https://python.org)
[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/tyxak/remotepower/releases)

[Live demo](https://demoremote.tvipper.com) · [Quick start](#quick-start) · [What you get](#what-you-can-do-with-it) · [Full features](#features)

</div>

---

## What is RemotePower?

A web dashboard that manages your Linux machines (and Windows, kind of) without opening firewall ports on them. Each host runs a small Python agent that **polls** the central server every 60 seconds — outbound HTTPS only. Enrolment is a 6-digit PIN, like pairing a console controller.

It's deliberately small: nginx + Python CGI + flat JSON files. No database, no Node.js, no Redis, no Kubernetes. The whole `/var/lib/remotepower/` directory backs up with `tar`. Tested on real homelabs running 5–50 devices, fine up to a few hundred.

---

## Quick Start

The fastest path. Three commands on the server, two on the client.

### Server

```bash
git clone https://github.com/tyxak/remotepower
cd remotepower
sudo bash install-server.sh        # nginx + fcgiwrap + Python deps + initial admin password
```

That's it. The installer prints the URL and the auto-generated admin password. Open it in a browser, log in, change the password under Settings → Account.

### Client (on the host you want to manage)

```bash
sudo bash install-client.sh
# Paste the server URL and the 6-digit PIN from the dashboard. Done.
```

The device shows up in the dashboard within ~60 seconds.

### Optional but recommended

```bash
sudo bash packaging/install-webterm.sh    # browser-based SSH terminal (separate daemon)
```

Auto-detects your nginx user (`www-data` / `nginx` / `http` / etc.) and wires everything up. Run with `--dry-run` first if you want to see what it'll do.

### Public demo / sandbox

If you want to host a read-only demo at e.g. `demoremote.example.com` alongside your production install:

```bash
sudo bash packaging/install-demo.sh demoremote.example.com
sudo certbot --nginx -d demoremote.example.com
```

This creates a SEPARATE vhost — different data dir (`/var/lib/remotepower-demo/`), shared CGI code, `RP_READ_ONLY=1` set per-vhost. Visitors log in as `demo` / `demo`, browse everything, but mutations get a friendly 403 toast. Your production install at `remote.<domain>` is untouched. The vhost auto-seeds 16 fake homelab devices using the unallocated `.lab` TLD.

### Docker (one-liner alternative)

```bash
git clone https://github.com/tyxak/remotepower && cd remotepower
docker compose up -d
```

Dashboard at `http://localhost:8080`. Put a TLS-terminating reverse proxy (Caddy, Traefik, nginx) in front for production.

---

## What you can do with it

Day-to-day fleet operations, without leaving the browser:

| | |
|---|---|
| 🟢 **See what's up** | Live online/offline status, every device every 60s. Sparklines for CPU / RAM / disk. Service health matrix. Containers (Docker/Podman/k8s pods). Patches pending. Open CVEs. |
| ⚡ **Run commands** | Reboot, shutdown, Wake-on-LAN, run arbitrary shell commands as root, batch any of the above across many devices. Scheduled (cron-style) and one-shot. Saved-snippets library. Long-poll endpoint for waiting on output. |
| 🌐 **SSH from your browser** | Click a device, get a real interactive xterm.js terminal proxied through a hardened daemon. Sessions are recorded as asciinema replayable casts. |
| 🚨 **Alert on what matters** | Disk %, memory %, swap %, CPU load — per-device and per-mount thresholds. Service down. Container stopped/restarting. Patches piling up. CVEs found. TLS expiring. Webhooks to Discord, ntfy, Slack, or anything that takes a JSON POST. |
| 📦 **CMDB built in** | Asset metadata, server function, hypervisor URL. Encrypted credentials vault (AES-GCM, shared admin passphrase, audit-logged reveals). Multiple Markdown documents per asset. SSH-link buttons. Network topology map. Agentless devices for switches / APs / printers. |
| 🛡️ **CVE scanning** | Installed packages cross-checked against [OSV.dev](https://osv.dev) on a schedule. Severity-ranked findings per device with fixed-version hints. Per-CVE ignore list for accepted risk. |
| 🔑 **Auth that scales** | Local users with bcrypt + TOTP 2FA. Optional LDAP/AD integration. Named API keys for automation. Enrolment tokens for cloud-init / Ansible / golden-image stamping. |
| 📈 **Time-series, the homelab way** | Every device's CPU/RAM/disk recorded; sparkline for the dashboard, full-size chart on click. Prometheus `/api/metrics` endpoint for Grafana. |

---

## Why RemotePower

**It's small.** ~6000 lines of Python on the server. ~1200 lines of agent. The whole web UI is one HTML file plus one CSS file plus one JS file — no build step, no bundler, no framework. You can read every line.

**It's lightweight.** nginx + fcgiwrap + Python. RAM footprint is dominated by nginx itself (~10 MB). Per-request cost is whatever Python imports are needed. Idle CPU usage is zero. Tested on a Raspberry Pi 4 managing 12 devices.

**It's self-hosted, properly.** No telemetry. No "cloud sync" you have to opt out of. No license server. Backs up with `tar czf /var/lib/remotepower/`. Restores by un-tarring. The whole architecture is one diagram you can hold in your head.

**But the features aren't toys.** Browser SSH with session recording. Per-mount disk thresholds with hysteresis. Atomic JSON writes with flock-protected concurrency and `.bak` fallback recovery. Encrypted credentials vault with PBKDF2-derived keys. AES-GCM. OSV-backed CVE scanning. Prometheus exposition. OpenAPI spec with interactive Swagger UI. asciinema-format session recordings. fcgiwrap + per-process unique tmp filenames + fsync-before-rename atomic writes. None of this is "we'll add it later."

If you've been bouncing between Cockpit (no fleet view), Ansible (not real-time), Tactical RMM (heavy, Windows-first), and Wazuh (security-first, not management) — give RemotePower a try.

---

## Features

The complete list. Items marked with a version number indicate when they were added.

### Fleet visibility

| Feature | Notes |
|---|---|
| 🟢 **Live status** | Green/red per device, auto-refreshes every 60s, configurable per device (10–3600 s) |
| 📊 **Metrics history** | CPU/RAM/disk/swap/loadavg sparklines per device, full-size chart on click |
| 📊 **Per-mount disk** | Each non-pseudo mount tracked individually (v1.11.10) |
| 📈 **Live metrics on Monitor page** | All-fleet view of current sysinfo, color-coded by alert level (v1.12.0) |
| 📈 **Metric trend modal from Monitor** | Time-series chart per device, one click from the fleet view (v2.0) |
| 🐧 **OS icons** | Auto-detected SVG glyphs: Linux, Windows, fallback. Penguin, tile, question-mark |
| ⏱️ **Adjustable poll interval** | Per-device heartbeat cadence from dashboard |
| 📊 **Uptime tracking** | Online/offline state changes stored per device |
| 📦 **Container awareness** | Auto-detected Docker / Podman / Kubernetes pods. Read-only — image, status, restart count, ports, namespace. Alerts on stop / restart / stale data |
| 🌐 **Network map** | Manual topology graph from per-device `connected_to` links. Switches and APs as agentless devices |

### Commands & automation

| Feature | Notes |
|---|---|
| 🔁 **Reboot / shutdown** | Queue actions, reported success on next heartbeat |
| ⚡ **Wake-on-LAN** | Magic packet from dashboard, unicast over VPN/routed networks |
| 🖥️ **Custom commands** | Run arbitrary shell as root; output returned via heartbeat. 64 KB cap |
| 📚 **Command library** | Saved named snippets, pick from dropdown |
| 🔒 **Per-device allowlist** | Whitelist of allowed exec commands per device |
| 🕐 **Scheduled commands** | One-shot (datetime) or recurring (cron) |
| 🗓️ **Maintenance windows** | Suppress webhook alerts during scheduled windows. Per-device, per-group, or fleet-global. Audit trail of suppressed events |
| 📜 **Update history** | Rolling 10-run buffer of `apt`/`dnf`/`pacman` output per device with timestamps, exit codes, durations |
| ⚡ **Long-poll exec** | `/api/exec/wait` holds connection open until output arrives — useful for synchronous CI |
| 🌐 **Web terminal** | Real xterm.js SSH terminal in the browser, proxied through a hardened daemon. asciinema v2 session recordings (output-only by default; opt-in keystroke capture) (v1.11.11) |

### Alerts & monitoring

| Feature | Notes |
|---|---|
| 📡 **Ping / TCP / HTTP probes** | ICMP, TCP port, HTTP HEAD checks from the server. Configurable schedule (v1.11.8: runs even when dashboard is closed) |
| 📈 **Monitor history** | Uptime %, sparkline, last 50 results per target |
| 🚨 **Metric alerts** | Disk / memory / swap / CPU load thresholds with hysteresis (v1.11.10) |
| 🚨 **Per-device thresholds** | Override fleet defaults per device, plus per-mount disk overrides (v1.12.0 UI) |
| ⚙️ **Service monitoring** | Agent watches systemd units; matrix view; webhooks on transitions |
| 📜 **Log tail + alerts** | Agent submits journalctl per watched unit; rolling 6-hour buffer with regex search; pattern-match alerts |
| 🔔 **Webhooks** | Generic JSON, Discord, ntfy, Slack, Gotify. Auto-format detection. 17 event types, per-event toggles, test-event button |
| 🛡️ **CVE scanner** | OSV.dev-backed; severity-ranked findings per device; ignore list for accepted risk |
| 🔐 **TLS / DNS expiry** | Server-side probes against a watchlist; alerts via existing webhooks |
| 📦 **Patch alerts** | Webhook when pending updates exceed configurable threshold |

### CMDB & documentation

| Feature | Notes |
|---|---|
| 🗄️ **Asset metadata** | Asset ID, server function, hypervisor URL, SSH port |
| 📝 **Multi-doc attachments** | Multiple titled Markdown documents per asset (v2.0) |
| 🔐 **Credentials vault** | AES-GCM + PBKDF2-SHA256, shared admin passphrase, audit-logged reveals |
| 🔗 **SSH-link buttons** | Per-credential `ssh://user@host:port` link + Copy button |
| 🔌 **Agentless devices** | Manual records for switches, APs, printers, IPMI, cameras — same CMDB / vault / SSH-link as agented devices |
| 📖 **In-app docs** | Curated documentation page in the dashboard with substring search across all topics (v2.0) |

### Authentication & access

| Feature | Notes |
|---|---|
| 🔐 **bcrypt** | Password hashing with transparent SHA-256 upgrade on login |
| 🔢 **TOTP 2FA** | Per-user, scan-QR setup; required to disable |
| 🏢 **LDAP / AD** | Optional bind-mode auth; auto-creates local user record |
| 👥 **Roles** | Admin (full access) and Viewer (read-only) per user |
| 📟 **PIN enrolment** | 6-digit, single-use, 10-minute expiry |
| 🎫 **API enrolment tokens** | One-time-use tokens for Ansible / cloud-init / golden images. Default group + tags applied at enrolment (v1.11.10) |
| 🔑 **API keys** | Named non-expiring keys for scripts and CI |
| 🛡️ **Rate limiting** | Per-IP login throttle, prevents brute force |
| 🚫 **Read-only demo mode** | Config flag rejects all mutations with a friendly error. For public sandboxes (v2.0) |

### Operational quality

| Feature | Notes |
|---|---|
| 🔄 **Agent self-update** | SHA-256 verified, atomic replace, no SSH needed |
| 🛡️ **Agent integrity** | `integrity` subcommand compares binary SHA-256 vs server |
| 🔄 **Re-enrolment** | Preserves device history, tags, group, and notes |
| 📤 **Backup export** | One-click ZIP of all data JSON files |
| 💾 **Hardened persistence** | flock-serialised writes, per-process unique tmp, fsync, rolling .bak fallback (v1.12.1). Recovery script for damaged files |
| 📜 **Audit log** | Every admin action logged with actor, IP, timestamp |
| 📊 **Prometheus metrics** | `/api/metrics` endpoint for Grafana scraping |
| 📊 **Digest endpoint** | `/api/digest` for cron-driven email summaries |
| 📖 **Swagger / OpenAPI** | OpenAPI 3.1 spec at `/api/openapi.json`, interactive UI at `/swagger.html` with auto-injected session token |

### UX

| Feature | Notes |
|---|---|
| 🌙 **Dark/light mode** | Toggle in header, persisted per browser |
| 🏷️ **Tags & groups** | Tag devices and namespace by group (e.g. `dc1/prod`, `homelab`); filter and batch by either |
| 📝 **Device notes** | Free-text per device, shown as tooltip |
| 🔍 **Filter & sort everywhere** | Substring filter + clickable headers on every fleet table; multi-key sort with Shift-click |
| 📐 **Density modes** | Minimal (table), Compact, Comfortable, Spacious — synced per user |
| ☑️ **Multi-select** | Batch actions on cards or minimal table; selection survives density switching (v1.12.1) |
| 🗂️ **Collapsible sidebar** | Main / Security / Planning / Admin / Help groups; state persists per browser (v2.0) |
| 🎨 **Real branding** | Favicon + header logo, clickable logo returns home, full-size logo on login (v2.0) |


---

## Architecture

```
Browser ──HTTPS──► Nginx (your server, bare metal or Docker)
                      │
                      ├─ /              → Dashboard (1 HTML + 1 CSS + 1 JS, no framework, no build)
                      ├─ /api/*         → Python CGI (via fcgiwrap)
                      ├─ /api/webterm/connect → wss://, proxied to remotepower-webterm daemon
                      ├─ /static/*      → Logos, CSS, JS
                      ├─ /agent/        → Agent binary (static, for self-update)
                      ├─ /swagger.html  → Interactive OpenAPI UI
                      ├─ /Manual.html   → Reference manual
                      └─ /var/lib/remotepower/   (state — flat JSON, hardened with flock + .bak fallback in v1.12.1)
                              ├── Identity:        users.json, tokens.json, apikeys.json, pins.json,
                              │                    enrollment_tokens.json
                              ├── Fleet state:     devices.json, metrics.json, packages.json,
                              │                    services.json, containers.json
                              ├── CMDB:            cmdb.json, cmdb_vault.json
                              ├── Operations:      commands.json, history.json, schedule.json,
                              │                    cmd_output.json, cmd_library.json, longpoll.json,
                              │                    update_logs.json, tasks.json, calendar.json
                              ├── Monitoring:      monitor_history.json, uptime.json, log_watch.json,
                              │                    log_rules_global.json, service_history.json
                              ├── Security:        cve_findings.json, cve_ignore.json,
                              │                    cve_details_cache.json
                              ├── TLS / DNS:       tls_targets.json, tls_results.json
                              ├── Webterm:         webterm_tickets.json, webterm-sessions/<id>.cast
                              ├── Other:           config.json, links.json, tunnels.json,
                              │                    maintenance.json, maint_suppressed.json,
                              │                    audit_log.json, webhook_log.json, ratelimit.json
                              └── (each .json gets a rolling .json.bak sibling on every save)

Optional sibling daemon (only if you install the web terminal):
  systemd: remotepower-webterm.service
  └─ asyncio Python (websockets + asyncssh)
       └─ Listens on 127.0.0.1:8765, proxied by nginx
            ├─ Validates one-time tickets minted by the CGI auth handler
            ├─ Pumps WebSocket bytes <-> SSH session
            └─ Records every session as asciinema v2 .cast file

Linux client (CachyOS, Ubuntu, Debian, Arch, Fedora, etc.)
  └─ systemd: remotepower-agent.service
       └─ Python daemon
            └─ POST /api/heartbeat every N seconds (configurable, default 60)
                 ├─ receives: shutdown | reboot | update | exec:<cmd> | poll_interval:<n>
                 ├─ sends sysinfo + journal every 10th poll (~10 min)
                 ├─ sends per-mount disk + swap + loadavg (v1.11.10+)
                 ├─ sends patch count every 180th poll (~3 hr)
                 └─ sends cpu/mem/disk metrics (if psutil installed)

Windows client (Windows 10/11, Server 2019+)
  └─ NSSM service: RemotePowerAgent
       └─ Python script (remotepower-agent.py)
            └─ Same heartbeat protocol as Linux agent
                 ├─ shutdown/reboot via shutdown.exe /s /r
                 ├─ patch info via Windows Update COM API
                 ├─ journal via wevtutil (System event log)
                 └─ metrics via psutil (optional)
```

---

## Windows Client

The Windows agent uses the same heartbeat protocol as the Linux agent. It requires Python 3.8+ and runs as a Windows Service via [NSSM](https://nssm.cc).

### Install (PowerShell)

```powershell
# Run as Administrator
powershell -ExecutionPolicy Bypass -File install-client.ps1
```

The installer will:
1. Check for Python 3.8+
2. Install `psutil` for metrics (optional)
3. Run the enrollment wizard
4. Download NSSM and install the agent as a Windows Service

### Manual install

```powershell
# Copy agent
mkdir "$env:ProgramFiles\RemotePower"
copy client\remotepower-agent.py "$env:ProgramFiles\RemotePower\"

# Enroll
python "$env:ProgramFiles\RemotePower\remotepower-agent.py" enroll

# Run in foreground (for testing)
python "$env:ProgramFiles\RemotePower\remotepower-agent.py" run
```

### Windows agent commands

```powershell
python remotepower-agent.py status        # Show enrollment info
python remotepower-agent.py enroll        # Enroll interactively
python remotepower-agent.py re-enroll     # Re-enroll preserving history
python remotepower-agent.py integrity     # Verify binary SHA-256 vs server
python remotepower-agent.py run           # Run in foreground

# Service management (if installed via NSSM)
Get-Service RemotePowerAgent
Restart-Service RemotePowerAgent
Get-Content "$env:ProgramData\RemotePower\agent.log" -Tail 50 -Wait
```

### Windows-specific behavior

| Feature | Linux | Windows |
|---------|-------|---------|
| Shutdown | `systemctl poweroff` | `shutdown /s /t 30` |
| Reboot | `systemctl reboot` | `shutdown /r /t 30` |
| Patch info | apt/dnf/pacman | Windows Update COM API |
| Journal | journalctl | wevtutil (System event log) |
| Service | systemd | NSSM |
| Self-update | Automatic | Manual (logged when available) |
| Config path | `/etc/remotepower/` | `%ProgramData%\RemotePower\` |

---

## Upgrading

```bash
cd /path/to/remotepower
git pull origin main
sudo bash deploy-server.sh
```

Clients self-update automatically within ~1 hour, or push from the dashboard with the ↺ button.

---

## Feature Guide

### Container awareness *(v1.11.0, alerts in v1.11.4)*
Every agent v1.11.0+ detects Docker, Podman, and kubectl-accessible Kubernetes pods on its host and posts a normalised list to the server every ~5 minutes. The Containers tab in the sidebar shows fleet-wide status; per-device drill-down shows image, tag, ports, restart count, and namespace. Read-only — RemotePower surfaces what's running, doesn't manage it.

**v1.11.4** adds three webhook events: `container_stopped` (running container vanished or transitioned to exited), `container_restarting` (restart count climbed since last report — Kubernetes-only in practice), and `containers_stale` (no fresh report within `container_stale_ttl`, default 15 min). Stale rows in the UI now get an amber `STALE` pill so old data is impossible to mistake for current data. Reference: **[docs/containers.md](docs/containers.md)**.

### Network map *(v1.11.0)*
Set `connected_to` on each device (Edit links button on the Network page) to record what plugs into what. The map renders nodes coloured by online/offline status and outlined by agent vs. agentless. Manual topology only — no auto-discovery. Reference: **[docs/network-map.md](docs/network-map.md)**.

### Agentless devices *(v1.11.0)*
"+ Agentless device" on the Devices toolbar adds a record for things that can't run the agent — switches, APs, printers, IPMI cards, cameras, smart plugs. Same CMDB metadata, vault credentials, SSH link as agented devices. Status is whatever you set it to. Reference: **[docs/agentless-devices.md](docs/agentless-devices.md)**.

### TLS / DNS expiry monitor *(v1.11.0)*
Add hostnames to the TLS / DNS page. The server runs a probe via `cgi-bin/remotepower-tls-check` (cron, every 6 hours suggested) or "Scan now" from the page. Default thresholds: warn at 14 days, critical at 3 days. Stdlib-only — no extra dependencies. Reference: **[docs/tls-monitor.md](docs/tls-monitor.md)**.

### API documentation (Swagger)
Click **API Docs** in the sidebar to open `/swagger.html` — Swagger UI rendering the OpenAPI 3.1 spec for every public endpoint. The page auto-injects your existing session token, so "Try it out" works without an Authorize step. The raw spec is at `/api/openapi.json`. Reference: **[docs/swagger.md](docs/swagger.md)**.

### SSH from credentials
Set the per-asset SSH port on the CMDB asset modal (Properties tab). Each credential row in the Credentials tab gets an SSH button that opens `ssh://user@host:port` in your default handler, plus a Copy button for the equivalent `ssh user@host -p port` command. Passwords are deliberately not in the URI.

### Update history
The device dropdown menu has an "Update history" link that opens the rolling buffer of the last 10 package-upgrade runs on that device — full output, exit codes, timestamps. Output is captured automatically on the next heartbeat after a run completes (~60s). Reference: **[docs/update-history.md](docs/update-history.md)**.

### CMDB & credential vault
The **CMDB** tab gives every enrolled device an asset record: free-text asset ID, server function (web, db, dc…) with autocomplete, optional hypervisor URL, and Markdown documentation up to 64 KB. Underneath that sits an opt-in encrypted credential vault: AES-GCM 256-bit, PBKDF2-SHA256 key derivation, shared admin passphrase, audit-logged reveals.

Setup is a one-time **Set up vault** click on the CMDB page. The passphrase is never persisted server-side — the derived key lives in the browser tab and clears on logout or page reload.

Full reference, threat model, API examples, and backup story: **[docs/cmdb.md](docs/cmdb.md)**.

### Device Groups
Assign a namespace to a device via the group button (👥) on the device card. Groups like `dc1/prod`, `homelab`, `office` cause the device grid to sort and visually group by namespace. Batch commands (`device_ids`, `tag`, or `group` field) can target an entire group at once.

### Device Notes
Click the 📄 button on any device card to add free-text notes. Notes are shown as a tooltip on the device name. Useful for documenting quirks: "NAS in basement - WoL unreliable", "kids' PC - check before rebooting".

### Batch Commands
Click the device icon (top-left of a card) to select it - it turns into a checkmark. A batch action bar appears above the grid with Shut down all / Reboot all / Update all. The API also accepts `tag:` or `group:` targets directly:

```bash
curl -X POST https://your-server/api/reboot \
  -H "X-Token: YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tag": "servers"}'
```

### Recurring Scheduled Commands
In the Schedule tab, leave the datetime blank and fill in a cron expression instead:

| Cron | Meaning |
|------|---------|
| `0 3 * * 0` | Every Sunday at 03:00 |
| `0 2 * * 1-5` | Mon–Fri at 02:00 |
| `*/30 * * * *` | Every 30 minutes |

One-shot jobs are removed after firing. Recurring jobs stay.

### Command Library
Save frequently-used commands in the Library page. When you open the exec modal (>_ button on a device card), a dropdown lets you pick from your saved snippets - no retyping.

### Command Allowlist
For higher-security devices, lock down which commands can be run via exec. Click the 🔒 button on a device card, enter one command per line. When the list is non-empty, only those exact commands are accepted; all others return 403.

### Metrics (CPU / RAM / Disk)
Install `psutil` on client machines for automatic metrics collection:

```bash
pip install psutil --break-system-packages
sudo systemctl restart remotepower-agent
```

The server stores up to 1440 snapshots (~24 h at 60 s intervals) in `metrics.json`. Click the 📈 button on a device card to see sparkline charts.

### Adjustable Poll Interval
Click the ⏱ button on a device card to change how often the agent checks in (10–3600 s). The new interval is queued as a `poll_interval:<n>` command and applied on the agent's next heartbeat - no restart needed.

### API Keys
Go to API Keys (nav) and create a named key. Keys are non-expiring and use the same `X-Token` header as session tokens. Assign `admin` for full access or `viewer` for read-only. Use them in scripts:

```bash
curl https://your-server/api/digest \
  -H "X-Token: YOUR_API_KEY"
```

Keys are shown once at creation. Store them in your secrets manager.

### Re-enrollment
When re-enrolling a device (e.g. after reinstalling the OS), use `re-enroll` instead of `enroll` to preserve the device's existing history, tags, group, and notes:

```bash
sudo remotepower-agent re-enroll
```

### Agent Integrity Check
Verify the running agent binary matches the server's known-good hash:

```bash
sudo remotepower-agent integrity
# ✓ OK - ok
# or: ✗ MISMATCH: local=abc123… server=def456…
```

Exit code 0 = OK, 1 = mismatch. Wire into a daily cron with a webhook alert if needed.

### Backup Export
Settings → Export backup downloads a ZIP of all data JSON files (excluding session tokens). Or via API:

```bash
curl https://your-server/api/export \
  -H "X-Token: YOUR_TOKEN" -o remotepower-backup.zip
```

### Digest for Email / Cron
```bash
# Add to cron for a daily status email
curl -s https://your-server/api/digest \
  -H "X-Token: YOUR_API_KEY" | jq .
```

Returns: `total`, `online`, `offline`, `pending_patches`, `recent_commands`.

### Long-Poll Exec
For near-interactive command output (instead of waiting 60 s for the next heartbeat):

```bash
curl -X POST https://your-server/api/exec/wait \
  -H "X-Token: YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"device_id": "DEVICE_ID", "cmd": "df -h", "timeout": 90}'
```

The connection stays open until the agent delivers the output (up to `timeout` seconds). On timeout, falls back to a `timeout: true` response; poll `/api/devices/:id/output` for the result.

### Wake-on-LAN
MAC is reported at enroll time. Sends unicast to the device's last known IP - works over routed networks and VPNs without broadcast forwarding.

### Offline Webhook Events

```json
{ "event": "device_offline",      "name": "mypc", "last_seen": 1712345678 }
{ "event": "device_online",       "name": "mypc" }
{ "event": "patch_alert",         "name": "mypc", "upgradable": 15, "threshold": 10 }
{ "event": "command_queued",      "name": "mypc", "command": "reboot", "actor": "admin" }
{ "event": "command_executed",    "name": "mypc", "command": "exec:df -h" }
```

Compatible with Ntfy, Gotify, Slack, Discord, n8n, Home Assistant.

---

## API Reference

All authenticated endpoints require: `X-Token: <session_token_or_api_key>`

### Devices
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/devices` | ✓ | List enrolled devices |
| `DELETE` | `/api/devices/:id` | admin | Remove a device |
| `PATCH` | `/api/devices/:id/tags` | admin | Set device tags |
| `PATCH` | `/api/devices/:id/notes` | admin | Set device notes |
| `PATCH` | `/api/devices/:id/group` | admin | Set device group |
| `PATCH` | `/api/devices/:id/poll_interval` | admin | Set poll interval hint |
| `GET` | `/api/devices/:id/sysinfo` | ✓ | Cached sysinfo + journal |
| `GET` | `/api/devices/:id/uptime` | ✓ | Uptime event history |
| `GET` | `/api/devices/:id/output` | ✓ | Custom command output |
| `GET` | `/api/devices/:id/metrics` | ✓ | CPU/RAM/disk time-series |
| `GET/POST` | `/api/devices/:id/allowlist` | admin | Get/set command allowlist |

### Commands (support `device_id`, `device_ids[]`, `tag`, or `group`)
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/shutdown` | admin | Queue shutdown |
| `POST` | `/api/reboot` | admin | Queue reboot |
| `POST` | `/api/update-device` | admin | Queue agent self-update |
| `POST` | `/api/wol` | admin | Send WoL magic packet |
| `POST` | `/api/exec` | admin | Queue custom shell command |
| `POST` | `/api/exec/wait` | admin | Long-poll exec (up to 120 s) |

### Enrollment & Heartbeat
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/login` | - | Login, returns session token |
| `POST` | `/api/enroll/pin` | admin | Generate enrollment PIN |
| `POST` | `/api/enroll/register` | - | Register device with PIN (pass `device_id` for re-enroll) |
| `POST` | `/api/heartbeat` | device | Client keepalive + fetch commands |

### Schedule
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/schedule` | ✓ | List scheduled jobs |
| `POST` | `/api/schedule` | admin | Add job (`run_at` or `cron`) |
| `DELETE` | `/api/schedule/:id` | admin | Cancel scheduled job |

### Monitor
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/monitor` | ✓ | Run ping/TCP/HTTP checks |
| `GET` | `/api/monitor/history?label=X` | ✓ | Check history for a target |

### Users & Auth
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/users` | ✓ | List admin users (with role) |
| `POST` | `/api/users` | admin | Create user (pass `role`: admin\|viewer) |
| `DELETE` | `/api/users/:name` | admin | Delete user |
| `POST` | `/api/users/passwd` | ✓ | Change password |

### API Keys
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/apikeys` | admin | List API keys |
| `POST` | `/api/apikeys` | admin | Create API key (value shown once) |
| `DELETE` | `/api/apikeys/:id` | admin | Delete API key |

### Command Library
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/cmd-library` | ✓ | List command snippets |
| `POST` | `/api/cmd-library` | admin | Add command snippet |
| `DELETE` | `/api/cmd-library/:id` | admin | Delete command snippet |

### Misc
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/history` | ✓ | Command history log |
| `GET` | `/api/config` | ✓ | Get config |
| `POST` | `/api/config` | admin | Save config |
| `GET` | `/api/agent/version` | - | Agent version + SHA-256 |
| `GET` | `/api/version` | ✓ | Server version + GitHub check |
| `GET` | `/api/export` | admin | Download ZIP backup |
| `GET` | `/api/digest` | ✓ | Summary (total, online, patches, recent cmds) |
| `GET` | `/api/patch-report` | ✓ | Full patch report (JSON) |
| `GET` | `/api/patch-report/csv` | ✓ | Patch report as CSV (`?group=X&device_id=Y`) |
| `GET` | `/api/patch-report/xml` | ✓ | Patch report as XML (`?group=X&device_id=Y`) |
| `GET` | `/api/patch-report/pdf` | ✓ | Patch report as PDF (`?group=X&device_id=Y`) |
| `GET` | `/api/patch-report/device/:id` | ✓ | Per-device patch detail |
| `DELETE` | `/api/history` | admin | Clear command history |
| `GET` | `/api/audit-log` | admin | Security audit log |
| `DELETE` | `/api/audit-log` | admin | Clear audit log |
| `POST` | `/api/sessions/revoke` | admin | Revoke user sessions |
| `POST` | `/api/totp/setup` | ✓ | Generate TOTP secret for 2FA |
| `POST` | `/api/totp/confirm` | ✓ | Confirm & enable 2FA |
| `POST` | `/api/totp/disable` | ✓ | Disable 2FA (requires password) |
| `GET` | `/api/totp/status` | ✓ | Check if 2FA is enabled |

---

## Client Agent Commands

```bash
remotepower-agent status        # Show enrollment info, version, all interfaces
sudo remotepower-agent enroll   # Enroll interactively
sudo remotepower-agent re-enroll  # Re-enroll preserving history/tags/group/notes
sudo remotepower-agent update   # Force self-update check immediately
sudo remotepower-agent integrity  # Verify binary SHA-256 vs server
sudo remotepower-agent run      # Run in foreground (debug)

systemctl status remotepower-agent
journalctl -u remotepower-agent -f
systemctl restart remotepower-agent
```

### Optional: metrics collection

```bash
pip install psutil --break-system-packages
sudo systemctl restart remotepower-agent
```

---

## Data Storage

All data in `/var/lib/remotepower/` (owned by `www-data`, mode `700`):

| File | Contents |
|------|----------|
| `users.json` | Admin accounts + bcrypt hashes + roles |
| `devices.json` | Enrolled devices, MAC, group, notes, cached sysinfo + journal |
| `tokens.json` | Active browser sessions (7-day TTL) |
| `apikeys.json` | Named API keys (values stored here) |
| `pins.json` | Pending enrollment PINs |
| `commands.json` | Pending command queue per device |
| `config.json` | Webhook URL, WoL settings, monitor targets, patch threshold |
| `history.json` | Command log (last 200 entries) |
| `schedule.json` | Scheduled jobs (one-shot + recurring cron) |
| `uptime.json` | Online/offline state changes per device |
| `monitor_history.json` | Check results per monitor target (last 50) |
| `cmd_output.json` | Custom command output per device (last 100) |
| `metrics.json` | CPU/RAM/disk snapshots per device (last 1440) |
| `cmd_library.json` | Saved command snippets |
| `longpoll.json` | Pending long-poll output slots (transient) |

**Backup:**
```bash
sudo tar czf remotepower-backup-$(date +%F).tar.gz /var/lib/remotepower/
# Or via dashboard: Settings → Export backup
```

---

## Security Notes

- Use HTTPS for anything internet-facing
- Session tokens expire after 7 days; API keys do not expire - rotate them if compromised
- Enrollment PINs are single-use, expire after 10 minutes
- Device tokens are 256-bit random secrets
- Passwords stored as **bcrypt** (cost 12); SHA-256 hashes auto-upgraded on next login
- Webhook URL stored server-side only, never returned to the browser
- Custom commands run as root - use the per-device command allowlist for untrusted operators
- Viewer role users cannot queue commands, change config, or access API keys
- `apikeys.json` is owned by `www-data` mode `700` - protect your server

---

## HTTPS Setup

### With acme.sh

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name power.yourdomain.com;

    ssl_certificate     /root/.acme.sh/yourdomain.com/fullchain.cer;
    ssl_certificate_key /root/.acme.sh/yourdomain.com/yourdomain.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    root /var/www/remotepower;
    index index.html;

    location /api/ {
        include fastcgi_params;
        fastcgi_pass unix:/run/fcgiwrap.socket;
        fastcgi_param SCRIPT_FILENAME /var/www/remotepower/cgi-bin/api.py;
        fastcgi_param PATH_INFO $uri;
        fastcgi_param REQUEST_METHOD $request_method;
        fastcgi_param CONTENT_TYPE $content_type;
        fastcgi_param CONTENT_LENGTH $content_length;
        fastcgi_param HTTP_X_TOKEN $http_x_token;
        fastcgi_param RP_DATA_DIR /var/lib/remotepower;
        # Long-poll exec needs an extended timeout
        fastcgi_read_timeout 130s;
        limit_except GET POST DELETE PATCH { deny all; }
    }

    location /agent/ {
        root /var/www/remotepower;
        add_header Content-Disposition 'attachment; filename=remotepower-agent';
        add_header Content-Type application/octet-stream;
    }

    location / { try_files $uri $uri/ /index.html; }
    location ~* \.(json|tmp)$ { deny all; }
}
```

> **Note:** `fastcgi_read_timeout 130s` is required for `/api/exec/wait` long-poll connections. Without it, Nginx will close the connection after the default 60 s.

---

## Troubleshooting

**IPv6 error on nginx start**
```bash
sudo sed -i '/listen \[::\]/d' /etc/nginx/sites-available/remotepower
sudo nginx -t && sudo systemctl reload nginx
```

**fcgiwrap socket permission denied**
```bash
sudo chmod 660 /run/fcgiwrap.socket
sudo chown www-data:www-data /run/fcgiwrap.socket
sudo systemctl restart fcgiwrap nginx
```

**Long-poll exec times out immediately**
- Check `fastcgi_read_timeout` in your Nginx config - must be ≥ 130 s
- The CGI process holds the connection; fcgiwrap must not be configured with a process limit that kills long-running requests

**Metrics not appearing**
```bash
pip install psutil --break-system-packages
sudo systemctl restart remotepower-agent
# Metrics only appear after the first sysinfo poll (~60s)
```

**Device shows offline after enrolling**
```bash
journalctl -u remotepower-agent -f
curl -v https://your-server/api/heartbeat
```

**Shutdown/reboot queued but nothing happens**
- Executes on the client's next poll (up to 60s by default)
- Agent must run as root: `systemctl cat remotepower-agent | grep User`

**Re-enroll creates a new device instead of updating**
- Use `sudo remotepower-agent re-enroll` (not `enroll`)
- The existing `device_id` from `/etc/remotepower/credentials` must be present

**Reset everything**
```bash
sudo rm -rf /var/lib/remotepower/
sudo systemctl restart nginx fcgiwrap
sudo python3 /var/www/remotepower/cgi-bin/remotepower-passwd
```

---

## File Layout

```
remotepower/
├── README.md
├── CHANGELOG.md
├── LICENSE
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── install-server.sh
├── install-client.sh              # Linux client installer
├── install-client.ps1             # Windows client installer
├── deploy-server.sh
├── docker/
│   ├── nginx-docker.conf          # Nginx config for Docker
│   └── entrypoint.sh              # Docker entrypoint
├── server/
│   ├── html/index.html            # Dashboard (vanilla HTML/CSS/JS, no framework)
│   ├── cgi-bin/api.py             # REST API (Python 3, CGI via fcgiwrap)
│   ├── conf/remotepower.conf      # Nginx site config
│   └── remotepower-passwd         # User management utility
├── client/
│   ├── remotepower-agent          # Linux polling daemon (Python 3)
│   ├── remotepower-agent.py       # Windows polling daemon (Python 3)
│   └── remotepower-agent.service  # systemd unit (Linux)
├── tests/
│   ├── test_api.py
│   └── test_agent.py
└── docs/
    └── screenshots/
```

---

## License

MIT - see [LICENSE](LICENSE)

<div align="center"><sub>Made with ☕ and vi</sub></div>
