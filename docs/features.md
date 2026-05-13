# Features

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

**It's small.** ~6000 lines of Python on the server. ~1200 lines of agent. The whole web UI is one HTML file plus one CSS file plus one JS file — no build step, no bundler, no framework. You can read every line.

**It's lightweight.** nginx + fcgiwrap + Python. RAM footprint is dominated by nginx itself (~10 MB). Per-request cost is whatever Python imports are needed. Idle CPU usage is zero. Tested on a Raspberry Pi 4 managing 12 devices.

**It's self-hosted, properly.** No telemetry. No "cloud sync" you have to opt out of. No license server. Backs up with `tar czf /var/lib/remotepower/`. Restores by un-tarring. The whole architecture is one diagram you can hold in your head.

**But the features aren't toys.** Browser SSH with session recording. Per-mount disk thresholds with hysteresis. Atomic JSON writes with flock-protected concurrency and `.bak` fallback recovery. Encrypted credentials vault with PBKDF2-derived keys. AES-GCM. OSV-backed CVE scanning. Prometheus exposition. OpenAPI spec with interactive Swagger UI. asciinema-format session recordings. fcgiwrap + per-process unique tmp filenames + fsync-before-rename atomic writes. None of this is "we'll add it later."

If you've been bouncing between Cockpit (no fleet view), Ansible (not real-time), Tactical RMM (heavy, Windows-first), and Wazuh (security-first, not management) — give RemotePower a try.

---

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

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
