# Features

Day-to-day fleet operations, without leaving the browser:

| | |
|---|---|
| **See what's up** | Live online/offline status, every device every 60s. Sparklines for CPU / RAM / disk. Service health matrix. Containers (Docker/Podman/k8s pods). Patches pending. Open CVEs. |
| **Run commands** | Reboot, shutdown, Wake-on-LAN, run arbitrary shell commands as root, batch any of the above across many devices. Scheduled (cron-style) and one-shot. Saved-snippets library. Long-poll endpoint for waiting on output. |
| **SSH from your browser** | Click a device, get a real interactive xterm.js terminal proxied through a hardened daemon. Sessions are recorded as asciinema replayable casts. |
| **Alert on what matters** | Disk %, memory %, swap %, CPU load — per-device and per-mount thresholds. Service down. Container stopped/restarting. Patches piling up. CVEs found. TLS expiring. Webhooks to Discord, ntfy, Slack, or anything that takes a JSON POST. |
| **CMDB built in** | Asset metadata, server function, hypervisor URL. Encrypted credentials vault (AES-GCM, shared admin passphrase, audit-logged reveals). Multiple Markdown documents per asset. SSH-link buttons. Network topology map. Agentless devices for switches / APs / printers. |
| **CVE scanning** | Installed packages cross-checked against [OSV.dev](https://osv.dev) on a schedule. Severity-ranked findings per device with fixed-version hints. Per-CVE ignore list for accepted risk. |
| **Auth that scales** | Local users with bcrypt + TOTP 2FA. Optional LDAP/AD integration. Named API keys for automation. Enrolment tokens for cloud-init / Ansible / golden-image stamping. |
| **Time-series, the homelab way** | Every device's CPU/RAM/disk recorded; sparkline for the dashboard, full-size chart on click. Prometheus `/api/metrics` endpoint for Grafana. |
| **AI assistant** | Optional LLM integration (Ollama, LocalAI, Anthropic, OpenAI, DeepSeek). Explain command output, triage CVEs and TLS expiry, prioritise patches, diagnose failed services, generate and audit shell scripts, free-form chat. Disabled by default; no external calls unless you choose a cloud provider. Regex-based secret redaction before any bytes leave the process. |
| **MCP server** | Bundled Model Context Protocol server — lets any MCP-capable AI client (Claude Desktop, etc.) query fleet state through 12 read-only tools. No write tools in this release. |
| **Custom monitoring scripts** | Define bash health checks server-side, assign to devices, run every 5 minutes. Exit 0 = OK, anything else = FAIL. Fleet-wide results table, edge-triggered webhooks (`custom_script_fail` / `custom_script_recover`). AI-assisted script generation built into the create modal. |
| **Host configuration** | Declare desired state per device: repos, netplan, nmcli, resolv.conf, /etc/hosts, enabled services, users + SSH keys, groups, sudoers, MOTD. Agent applies on heartbeat (~60 s), reports current state every 15 min. Drift detected and `config_drift` webhook fires edge-triggered. Audit-only — never auto-remediates. |

---

**It's small.** ~17,600 lines of Python on the server. ~2,100 lines of agent. The whole web UI is one HTML file plus one CSS file plus one JS file — no build step, no bundler, no framework. You can read every line.

**It's lightweight.** nginx + fcgiwrap + Python. RAM footprint is dominated by nginx itself (~10 MB). Per-request cost is whatever Python imports are needed. Idle CPU usage is zero. Tested on a Raspberry Pi 4 managing 12 devices.

**It's self-hosted, properly.** No telemetry. No "cloud sync" you have to opt out of. No license server. Backs up with `tar czf /var/lib/remotepower/`. Restores by un-tarring. The whole architecture is one diagram you can hold in your head.

**But the features aren't toys.** Browser SSH with session recording. Per-mount disk thresholds with hysteresis. Atomic JSON writes with flock-protected concurrency and `.bak` fallback recovery. Encrypted credentials vault with PBKDF2-derived keys. AES-GCM. OSV-backed CVE scanning. Prometheus exposition. OpenAPI spec with interactive Swagger UI. asciinema-format session recordings. fcgiwrap + per-process unique tmp filenames + fsync-before-rename atomic writes. None of this is "we'll add it later."

If you've been bouncing between Cockpit (no fleet view), Ansible (not real-time), Tactical RMM (heavy, Windows-first), and Wazuh (security-first, not management) — give RemotePower a try.

---

The complete list. Items marked with a version number indicate when they were added.

### Fleet visibility

| Feature | Notes |
|---|---|
| **Live status** | Green/red per device, auto-refreshes every 60s, configurable per device (10–3600 s) |
| **Metrics history** | CPU/RAM/disk/swap/loadavg sparklines per device, full-size chart on click |
| **Per-mount disk** | Each non-pseudo mount tracked individually (v1.11.10) |
| **Live metrics on Monitor page** | All-fleet view of current sysinfo, color-coded by alert level (v1.12.0) |
| **Metric trend modal from Monitor** | Time-series chart per device, one click from the fleet view (v2.0) |
| **OS icons** | Auto-detected SVG glyphs: Linux, Windows, fallback. Penguin, tile, question-mark |
| **Adjustable poll interval** | Per-device heartbeat cadence from dashboard |
| **Uptime tracking** | Online/offline state changes stored per device |
| **Container awareness** | Auto-detected Docker / Podman / Kubernetes pods. Read-only — image, status, restart count, ports, namespace. Alerts on stop / restart / stale data |
| **Network map** | Manual topology graph from per-device `connected_to` links. Switches and APs as agentless devices |
| ⟳ **Pending Reboot indicator** | Amber ⟳ Reboot badge next to hostname on the Patches page when `/run/reboot-required` exists on the host (Debian/Ubuntu). Tooltip explains the source (v2.4.14) |

### Custom monitoring scripts *(v2.5.0)*

| Feature | Notes |
|---|---|
| **Script library** | Admin-defined bash scripts stored server-side in `custom_scripts.json`. Up to 50 fleet-wide, 10 per device |
| **Per-device assignment** | Each script is assigned to a set of devices. Assignments are pushed via heartbeat — no SSH needed |
| **5-minute cadence** | Agent runs all assigned scripts every 5 polls (~5 min at default 60 s). First poll after assignment is skipped; results start from poll 2 |
| **Binary exit code** | Exit 0 = OK, anything else = FAIL. No MRPE severity levels — deliberately simple |
| **Fleet results page** | Custom Scripts page shows all device × script results: status badge, last output snippet (click for full 4 KB), timestamp, duration |
| **Edge-triggered alerts** | `custom_script_fail` fires once on OK→FAIL transition (includes first output line). `custom_script_recover` fires once on FAIL→OK. Never re-fires on every failing run |
| **AI generation** | Inline in the create modal: describe the check in plain English, click Generate, review and save. Uses the existing AI assistant configuration |
| **Secure execution** | Script written to temp file (chmod 700), executed by `/bin/bash`, deleted after run. 30 s timeout. stdout+stderr merged, capped at 4 KB |

### Commands & automation

| Feature | Notes |
|---|---|
| **Reboot / shutdown** | Queue actions, reported success on next heartbeat |
| **Wake-on-LAN** | Magic packet from dashboard, unicast over VPN/routed networks |
| **Custom commands** | Run arbitrary shell as root; output returned via heartbeat. 64 KB cap |
| **Command library** | Saved named snippets, pick from dropdown |
| **Per-device allowlist** | Whitelist of allowed exec commands per device |
| **Scheduled commands** | One-shot (datetime) or recurring (cron) |
| **Maintenance windows** | Suppress webhook alerts during scheduled windows. Per-device, per-group, or fleet-global. Audit trail of suppressed events |
| **Update history** | Rolling 10-run buffer of `apt`/`dnf`/`pacman` output per device with timestamps, exit codes, durations |
| **Long-poll exec** | `/api/exec/wait` holds connection open until output arrives — useful for synchronous CI |
| **Web terminal** | Real xterm.js SSH terminal in the browser, proxied through a hardened daemon. asciinema v2 session recordings (output-only by default; opt-in keystroke capture) (v1.11.11) |

### Alerts & monitoring

| Feature | Notes |
|---|---|
| **Ping / TCP / HTTP probes** | ICMP, TCP port, HTTP HEAD checks from the server. Configurable schedule (v1.11.8: runs even when dashboard is closed) |
| **Monitor history** | Uptime %, sparkline, last 50 results per target |
| **Metric alerts** | Disk / memory / swap / CPU load thresholds with hysteresis (v1.11.10) |
| **Per-device thresholds** | Override fleet defaults per device, plus per-mount disk overrides (v1.12.0 UI) |
| **Service monitoring** | Agent watches systemd units; matrix view; webhooks on transitions |
| **Log tail + alerts** | Agent submits journalctl per watched unit; rolling 6-hour buffer with regex search; pattern-match alerts |
| **Webhooks** | Generic JSON, Discord, ntfy, Slack, Gotify. Auto-format detection. 17 event types, per-event toggles, test-event button |
| **CVE scanner** | OSV.dev-backed; severity-ranked findings per device; ignore list for accepted risk |
| **TLS / DNS expiry** | Server-side probes against a watchlist; alerts via existing webhooks |
| **Patch alerts** | Webhook when pending updates exceed configurable threshold |

### CMDB & documentation

| Feature | Notes |
|---|---|
| **Asset metadata** | Asset ID, server function, hypervisor URL, SSH port |
| **Multi-doc attachments** | Multiple titled Markdown documents per asset (v2.0) |
| **Credentials vault** | AES-GCM + PBKDF2-SHA256, shared admin passphrase, audit-logged reveals |
| **SSH-link buttons** | Per-credential `ssh://user@host:port` link + Copy button |
| **Agentless devices** | Manual records for switches, APs, printers, IPMI, cameras — same CMDB / vault / SSH-link as agented devices |
| **In-app docs** | Curated documentation page in the dashboard with substring search across all topics (v2.0) |

### Authentication & access

| Feature | Notes |
|---|---|
| **bcrypt** | Password hashing with transparent SHA-256 upgrade on login |
| **TOTP 2FA** | Per-user, scan-QR setup; required to disable |
| **LDAP / AD** | Optional bind-mode auth; auto-creates local user record |
| **Roles** | Admin (full access) and Viewer (read-only) per user |
| **PIN enrolment** | 6-digit, single-use, 10-minute expiry |
| **API enrolment tokens** | One-time-use tokens for Ansible / cloud-init / golden images. Default group + tags applied at enrolment (v1.11.10) |
| **API keys** | Named non-expiring keys for scripts and CI |
| **Rate limiting** | Per-IP login throttle, prevents brute force |
| **Read-only demo mode** | Config flag rejects all mutations with a friendly error. For public sandboxes (v2.0) |

### Operational quality

| Feature | Notes |
|---|---|
| **Agent self-update** | SHA-256 verified, atomic replace, no SSH needed |
| **Agent integrity** | `integrity` subcommand compares binary SHA-256 vs server |
| **Re-enrolment** | Preserves device history, tags, group, and notes |
| **Backup export** | One-click ZIP of all data JSON files |
| **Hardened persistence** | flock-serialised writes, per-process unique tmp, fsync, rolling .bak fallback (v1.12.1). Recovery script for damaged files |
| **Audit log** | Every admin action logged with actor, IP, timestamp |
| **Prometheus metrics** | `/api/metrics` endpoint for Grafana scraping |
| **Digest endpoint** | `/api/digest` for cron-driven email summaries |
| **Swagger / OpenAPI** | OpenAPI 3.1 spec at `/api/openapi.json`, interactive UI at `/swagger.html` with auto-injected session token |

### UX

| Feature | Notes |
|---|---|
| **Dark/light mode** | Toggle in header, persisted per browser |
| **Tags & groups** | Tag devices and namespace by group (e.g. `dc1/prod`, `homelab`); filter and batch by either |
| **Device notes** | Free-text per device, shown as tooltip |
| **Filter & sort everywhere** | Substring filter + clickable headers on every fleet table; multi-key sort with Shift-click |
| **Density modes** | Minimal (table), Compact, Comfortable, Spacious — synced per user |
| **Multi-select** | Batch actions on cards or minimal table; selection survives density switching (v1.12.1) |
| **Collapsible sidebar** | Main / Security / Planning / Admin / Help groups; state persists per browser (v2.0) |
| **Real branding** | Favicon + header logo, clickable logo returns home, full-size logo on login (v2.0) |

### AI assistant *(v2.1.3)*

| Feature | Notes |
|---|---|
| **LLM integration** | Optional. Five providers: Ollama, LocalAI, Anthropic (Claude), OpenAI, DeepSeek. Pure stdlib HTTP — no pip deps (v2.1.3) |
| **Context-aware buttons** | Investigate device, Explain command output, Find the problem (journal), Diagnose service, Triage CVE, Triage TLS, Prioritise patches, Explain/Generate/Audit scripts, Explain webhook events (v2.1.3–v2.1.5) |
| **Secret redaction** | Regex-based pre-flight strips bearer tokens, AWS keys, long hex strings before any request leaves the process. Privacy toggles for hostnames, IPs, journal content |
| **Rate limiting** | Per-user daily request cap + per-response max-token cap, both configurable in Settings |
| **Free-form chat** | Multi-turn chat page (Help → AI Assistant) with model picker and local conversation history |
| **Local-model support** | Ollama and LocalAI providers — no external egress, no API key. Shows loaded models and VRAM use |

Full reference: **[ai.md](ai.md)**.

### MCP server *(v2.2.1)*

| Feature | Notes |
|---|---|
| **MCP server** | Read-only Model Context Protocol server. 12 tools: `list_devices`, `get_device`, `get_journal`, `get_services`, `get_containers`, `get_cves`, `get_drift`, `get_recent_commands`, `get_runbook`, `get_patches`, `get_tls`, `search_devices` |
| **No write tools** | `run_command`, `reboot_device`, etc. are intentionally absent. Write tools require server-side allow-list + per-token roles, deferred to a future release |


---

### Container awareness *(v1.11.0, alerts in v1.11.4)*
Every agent v1.11.0+ detects Docker, Podman, and kubectl-accessible Kubernetes pods on its host and posts a normalised list to the server every ~5 minutes. The Containers tab in the sidebar shows fleet-wide status; per-device drill-down shows image, tag, ports, restart count, and namespace. Read-only — RemotePower surfaces what's running, doesn't manage it.

**v1.11.4** adds three webhook events: `container_stopped` (running container vanished or transitioned to exited), `container_restarting` (restart count climbed since last report — Kubernetes-only in practice), and `containers_stale` (no fresh report within `container_stale_ttl`, default 15 min). Stale rows in the UI now get an amber `STALE` pill so old data is impossible to mistake for current data. Reference: **[containers.md](containers.md)**.

### Network map *(v1.11.0)*
Set `connected_to` on each device (Edit links button on the Network page) to record what plugs into what. The map renders nodes coloured by online/offline status and outlined by agent vs. agentless. Manual topology only — no auto-discovery. Reference: **[network-map.md](network-map.md)**.

### Agentless devices *(v1.11.0)*
"+ Agentless device" on the Devices toolbar adds a record for things that can't run the agent — switches, APs, printers, IPMI cards, cameras, smart plugs. Same CMDB metadata, vault credentials, SSH link as agented devices. Status is whatever you set it to. Reference: **[agentless-devices.md](agentless-devices.md)**.

### TLS / DNS expiry monitor *(v1.11.0)*
Add hostnames to the TLS / DNS page. The server runs a probe via `cgi-bin/remotepower-tls-check` (cron, every 6 hours suggested) or "Scan now" from the page. Default thresholds: warn at 14 days, critical at 3 days. Stdlib-only — no extra dependencies. Reference: **[tls-monitor.md](tls-monitor.md)**.

### API documentation (Swagger)
Click **API Docs** in the sidebar to open `/swagger.html` — Swagger UI rendering the OpenAPI 3.1 spec for every public endpoint. The page auto-injects your existing session token, so "Try it out" works without an Authorize step. The raw spec is at `/api/openapi.json`. Reference: **[swagger.md](swagger.md)**.

### SSH from credentials
Set the per-asset SSH port on the CMDB asset modal (Properties tab). Each credential row in the Credentials tab gets an SSH button that opens `ssh://user@host:port` in your default handler, plus a Copy button for the equivalent `ssh user@host -p port` command. Passwords are deliberately not in the URI.

### Update history
The device dropdown menu has an "Update history" link that opens the rolling buffer of the last 10 package-upgrade runs on that device — full output, exit codes, timestamps. Output is captured automatically on the next heartbeat after a run completes (~60s). Reference: **[update-history.md](update-history.md)**.

### CMDB & credential vault
The **CMDB** tab gives every enrolled device an asset record: free-text asset ID, server function (web, db, dc…) with autocomplete, optional hypervisor URL, and Markdown documentation up to 64 KB. Underneath that sits an opt-in encrypted credential vault: AES-GCM 256-bit, PBKDF2-SHA256 key derivation, shared admin passphrase, audit-logged reveals.

Setup is a one-time **Set up vault** click on the CMDB page. The passphrase is never persisted server-side — the derived key lives in the browser tab and clears on logout or page reload.

Full reference, threat model, API examples, and backup story: **[cmdb.md](cmdb.md)**.

### Device Groups
Assign a namespace to a device via the group button () on the device card. Groups like `dc1/prod`, `homelab`, `office` cause the device grid to sort and visually group by namespace. Batch commands (`device_ids`, `tag`, or `group` field) can target an entire group at once.

### Device Notes
Click the button on any device card to add free-text notes. Notes are shown as a tooltip on the device name. Useful for documenting quirks: "NAS in basement - WoL unreliable", "kids' PC - check before rebooting".

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
For higher-security devices, lock down which commands can be run via exec. Click the button on a device card, enter one command per line. When the list is non-empty, only those exact commands are accepted; all others return 403.

### Metrics (CPU / RAM / Disk)
Install `psutil` on client machines for automatic metrics collection:

```bash
pip install psutil --break-system-packages
sudo systemctl restart remotepower-agent
```

The server stores up to 1440 snapshots (~24 h at 60 s intervals) in `metrics.json`. Click the button on a device card to see sparkline charts.

### Adjustable Poll Interval
Click the button on a device card to change how often the agent checks in (10–3600 s). The new interval is queued as a `poll_interval:<n>` command and applied on the agent's next heartbeat - no restart needed.

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
# OK - ok
# or: MISMATCH: local=abc123… server=def456…
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
{ "event": "device_offline", "name": "mypc", "last_seen": 1712345678 }
{ "event": "device_online", "name": "mypc" }
{ "event": "patch_alert", "name": "mypc", "upgradable": 15, "threshold": 10 }
{ "event": "command_queued", "name": "mypc", "command": "reboot", "actor": "admin" }
{ "event": "command_executed", "name": "mypc", "command": "exec:df -h" }
```

Compatible with Ntfy, Gotify, Slack, Discord, n8n, Home Assistant.

---

## Added in 2.2.x – 2.6.x

The features below were added across the 2.2 – 2.6 release series.
Full per-release notes — including the bug-fix releases not listed
here — are in [`CHANGELOG.md`](../CHANGELOG.md).

### Host configuration management *(v2.6.0)*
Declare the desired state of each host server-side across ten sections:
package repos, netplan, NetworkManager (nmcli), resolv.conf, /etc/hosts,
enabled systemd services, local users + SSH authorized_keys, groups,
sudoers rules, and the MOTD banner.
The agent applies changes on the next heartbeat (~60 s) and reports
current state every 15 minutes for drift detection. Drift fires a
`config_drift` webhook edge-triggered (once on first divergence, not
every heartbeat). Audit-only — the agent never auto-remediates.
Reference: **[host-config.md](host-config.md)**.

### Custom monitoring scripts *(v2.5.0)*
Define bash health checks server-side and assign them to devices.
The agent runs each check every 5 minutes; exit 0 = OK, anything
else = FAIL. Fleet-wide results on the Custom Scripts page, plus
edge-triggered `custom_script_fail` / `custom_script_recover`
webhook events. Inline AI generation in the create modal. No agent
update required to start using the feature — scripts are pushed
via the existing heartbeat channel. Reference:
**[custom-scripts.md](custom-scripts.md)**.

### Pending Reboot indicator on Patches page *(v2.4.14)*
When a Debian/Ubuntu host has a pending-reboot marker
(`/run/reboot-required`) the agent reports `reboot_required: true`
in its heartbeat. The Patches page now surfaces this as a small amber
**⟳ Reboot** badge inline with the hostname so you can see at a
glance which patched hosts still need a restart — without opening
each device individually. The badge shows a tooltip identifying the
source file. No agent change is required; the flag has been in the
heartbeat since v1.x. The patch-report API (`/api/patch-report`) also
exposes the field for external consumers.

### Configuration drift detection *(v2.2.0)*
RemotePower hashes a watch-list of critical config files on every
host — `sshd_config`, `sudoers`, and similar — and flags any change
against an accepted baseline. View a diff, accept a new baseline, or
mark an expected difference as ignored (per-file) so it stops raising
a red status. Watched-file lists are pushed to the agent in the
heartbeat. Drifted files surface on the dashboard and in the fleet
event log.

### MCP server *(v2.2.1)*
RemotePower ships an MCP (Model Context Protocol) server, letting an
MCP-capable AI client query fleet state through defined tools. Read
-oriented in this release.

### Dedicated fleet event log *(v2.2.7)*
A fleet-wide activity log — enrolments, commands, drift, Proxmox
actions, alert state changes — separate from per-device command
history.

### Proxmox virtualization *(v2.3.0)*
Connect one Proxmox VE node (Settings → Proxmox; uses a scoped API
token). The Virtualization page lists the node's QEMU virtual
machines with start / shutdown actions. Server-to-API — no agent runs
on the Proxmox node. Configure with a scoped token, not a
full-access one.

### Salted password hashing *(v2.3.2)*
Passwords are stored with PBKDF2 (600k iterations, per-user salt),
replacing the legacy unsalted-SHA-256 fallback. A default-password
warning banner prompts a change on first login. See
`docs/security-review-2.3.2.md`.

### Proxmox LXC containers *(v2.3.0)* and snapshots *(v2.4.0)*
LXC containers on the Proxmox node appear on the Containers page with
the same start / shutdown actions. Every Proxmox guest — QEMU and LXC
— has a Snapshots panel: create, list, roll back, and delete
snapshots. Rollback is destructive and requires typing the guest name
to confirm; delete does not affect the running guest. Disk-only
snapshots (no RAM state).

### CVE severity accuracy *(v2.3.4, v2.4.0, v2.4.1)*
CVE findings are scored with the real CVSS v3.1 formula, and each
finding records its severity source. Debian Security Tracker
`urgency` — a patching-priority signal, not a CVSS severity — is
capped at `medium` and never reported as high/critical. Stale cache
entries from before this work are detected and re-classified
automatically.

### Default SSH username + quick SSH link *(v2.4.2)*
Set a default SSH username per user (Settings → Security → SSH
preferences). Each device row on the Devices page gets an SSH icon
that builds an `ssh://user@host` link (device IP, or hostname as
fallback) and copies the `ssh user@host` command to the clipboard.

### Mailbox monitor *(v2.4.3, fixed v2.4.4)*
A lightweight mailbox monitor with no IMAP/SMTP. Configure a device
with one or more directory paths (Settings → Mailbox monitor); the
agent counts the regular files in each — for a Maildir `new/` folder
that file count is the unread-message count — and reports the numbers
in its heartbeat. Promote a device to add an "Unread mail" tile to
the Home dashboard. No email content is read, only files counted.

### On-demand package scan *(v2.4.5)*
"Scan packages now" in the device action menu sets a one-shot flag;
the device sends a fresh package inventory and patch count within a
heartbeat or two, instead of waiting for the periodic scan. Useful
right after patching a host.

### Update-available notice *(v2.4.6)*
RemotePower checks the project's GitHub repository for newer releases
and shows an in-app notice — with the commands to update — when the
running version is behind. Detection only; RemotePower never modifies
its own code.

### Needs Attention digest *(v2.4.7)*
The Home dashboard has a single ranked list that merges every
fleet-wide signal — offline devices, critical/high CVEs, configuration
drift, pending-patch pileups, mailbox threshold breaches — into one
prioritised view. Computed server-side (`/api/attention`); unmonitored
devices are excluded, the same gate the alert pipeline uses.

### Mailbox threshold alerting *(v2.4.7)*
A device's mailbox monitor can carry an alert threshold. When a
counted mailbox reaches it, RemotePower fires the `mailbox_threshold`
webhook — the same Discord / ntfy / Slack / JSON delivery used by
every other alert. The check is edge-triggered: it fires once on the
crossing, re-arms when the count drops back below.

### Status endpoint *(v2.4.7)*
A machine-readable fleet summary at `/api/status` for external
dashboards — Uptime Kuma, Homepage, Grafana. Authenticated by a
dedicated status token (generated in Settings), not a login session,
so a monitoring tool can poll it — but it is not public. Returns a
rolled-up health word, device online/offline counts, and attention
counts by severity.

### Newer offline webhook events
In addition to the events listed above, recent releases emit:

```json
{ "event": "drift_detected", "name": "mypc", "files": 2 }
{ "event": "cve_found", "name": "mypc", "severity": "high" }
{ "event": "proxmox_action", "guest_type": "qemu", "vmid": 100, "action": "snapshot_create" }
{ "event": "mailbox_threshold", "name": "mail01", "path": "...", "count": 51, "threshold": 50 }
```

---

## v3.3.0 additions

### Channel routing matrix
Settings → Dashboard exposes a single matrix that controls, per
event kind, which four surfaces an event reaches: **Needs Attention**
(home priority cards), **Recent Activity** (home feed), **Alerts**
(inbox), **Webhook** (external delivery). Replaces the prior pair of
hide-this-kind toggles plus implicit per-event webhook gating. Legacy
`dashboard_hidden_*` config auto-migrates on first read.

Several events that fired webhooks but never reached the Alerts inbox
in prior releases — `brute_force_detected`, `backup_stale`,
`snapshot_old`, `reboot_required`, `new_port_detected`,
`ssh_key_added`, `monitor_down` — now have `_ALERT_RULES` entries.
`monitor_up` auto-resolves the matching `monitor_down` row via
label+target sub-match.

### Hash-driven agent self-update
Agents compare their own binary `sha256` against the server's
canonical hash. Mismatch in either direction triggers a download.
Version strings stay in the response and the logs but the *decision*
is hash-based — same-version rebuilds and operator-initiated
re-pushes now reliably update. The server caches the canonical hash
to a sidecar `.sha256` file so CGI requests don't re-hash on every
poll.

### Log-alert improvements
- Sample-in-summary: Needs Attention cards, Alerts-inbox titles, and
  webhook subjects for `log_alert` now show the matched log line
  (truncated) rather than the rule regex. Hover the NA card to see
  the full pattern plus up to three captured matches.
- Per-rule `display_template` field with `{device}`, `{unit}`,
  `{pattern}`, `{count}`, `{sample}`, `{sample0..2}` placeholders.
- Per-rule `exclude_pattern` (regex) silences matching lines before
  the threshold count.
- Inline NA card actions: 24-hour snooze + "Open in Logs" deep link
  to the device + unit.

### Per-IP rate limits
`POST /api/enroll/register` is throttled at 10/min/IP (the 10⁶ PIN
namespace was brute-forceable from one IP in a few minutes).
`POST /api/login` is throttled at 20/min/IP on top of the existing
per-username lockout — blocks credential-stuffing across many
usernames from one source.

### SSRF defaults flipped
`webhook_block_local` now defaults to **true**, blocking link-local
targets (`169.254.169.254` cloud metadata) and unspecified addresses.
Loopback (`127.0.0.1`, `::1`) is still allowed by default via the
new `webhook_allow_loopback` flag so homelab Gotify/ntfy sidecars
keep working.

### Admin-only alert mutation (opt-in)
`viewers_can_ack_alerts` (default true for back-compat). When false,
`ack` / `unack` / `resolve` on alerts requires admin role.

### IP allowlist
Settings → Security gains a per-IP/CIDR allowlist (off by default).
Loopback always allowed (MCP-safe). Agent paths exempted
(`/api/heartbeat`, enrollment, agent download, CSP report,
public-info, health, `/api/metrics`, `/api/status`). The save handler
refuses to enable the gate if the caller's IP isn't already in the
list — operators can't lock themselves out with one click.

### Uninstall agent
Devices drawer → "Uninstall agent" queues an `uninstall` command.
Agent stops + disables its systemd unit, removes credentials + state
+ binary, exits via a detached trampoline. Device record stays. The
row shows "agent uninstalled" until a fresh heartbeat (operator
re-installed) clears it.

### Prometheus metrics: status-token auth
The existing `/api/metrics` Prometheus exposition endpoint now
accepts the status token via `?token=…` in addition to session
bearer. Compatible with stock `prometheus.yml` scrape configs:

```yaml
- job_name: 'remotepower'
  metrics_path: /api/metrics
  params:
    token: ['<status token>']
  static_configs:
    - targets: ['remote.example.com']
  scheme: https
```

### Healthchecks.io watchdog
Server pings a configurable URL on a fixed cadence (default 60 s,
min 30) so an external monitor flips red when RemotePower itself
stops responding. Settings → Notifications → "Healthchecks.io
watchdog". Off by default. The HTTP call has a 5 s timeout and
never raises into the request pipeline.

### GitHub issues as a webhook format
New `github` destination format. Card grows a single GitHub PAT
field (fine-grained, `issues:write` scope). Issue body shows the
human-readable alert on top with the raw payload in a `<details>`
JSON block. Labels = `["remotepower", "<event>", "<severity>"]`.

### Central ACME DNS-01 credentials
TLS / DNS page → "DNS provider credentials" — operator stores
Cloudflare / Hetzner / Route 53 / DigitalOcean / Gandi / OVH /
Porkbun / Hurricane Electric / deSEC / Namecheap / NameSilo /
RFC 2136 / acme-dns API tokens on the server. Values are injected as
env vars into the queued `acme.sh --issue` command — no more hand-
editing `~/.acme.sh/account.conf` on every device.
`_scrub_acme_credentials()` redacts the secrets from the audit log
and any UI surface that displays the queued command.

### Edit buttons everywhere
Log alert rules (per-device + global), maintenance windows,
monitors, TLS targets, backup monitors, command snippets, scheduled
jobs, inbound webhook tokens (label + scope), users (role),
log-ignore patterns — every operator-managed list now supports
Edit alongside Add and Delete.

### Mobile UX polish
Two media-query blocks (≤ 720 px and ≤ 480 px) bring touch targets
up to ~44 px, modals go full-viewport with a sticky action row,
device drawer action grid becomes 2-up (1-up under 480 px), settings
tabs wrap into a 3-up grid, all `.table-card` tables get horizontal
scroll with `-webkit-overflow-scrolling: touch`, form inputs use
16 px font size so iOS Safari doesn't zoom on focus.

### Audit-driven correctness fixes
- `process_service_report` + `_record_service_transition` now
  serialise their read-modify-write under `_LockedUpdate`. Two
  concurrent agent heartbeats can no longer lose service transitions
  or fire duplicate webhooks.
- `/api/status` "high load" flag was always firing when `os.cpu_count()`
  returned None — operator-precedence bug, fixed.
- `handle_device_delete` cleanup paths all use `_LockedUpdate`.
- `_compute_attention` loads `CONFIG_FILE` once per call instead of
  four times.
- TLS expiry events now land in the Alerts inbox (`tls_expiring`
  typo in `_ALERT_RULES` renamed to `tls_expiry`).
- `_wireHeaders` is idempotent — fixes the Monitoring → Processes
  browser-freeze where the static `<thead>` accumulated click
  handlers exponentially.
- Offline check exempts the device currently heartbeating — kills
  the false-positive `OFFLINE → ONLINE` flap that fired at the TTL
  boundary.
- Dashboard CVE tile now honours the operator's CVE ignore list
  (was: showed 3 critical while the CVE page showed 0).

### Dashboard performance
- `/api/home`: one endpoint serves slim devices, drift summary, CVE
  counts, fleet events, mailwatch, links, attention payload, and the
  handful of config flags the home renderer reads. Replaces seven
  parallel `/api/*` calls.
- `?slim=1` on `/api/devices` omits sysinfo / listening_ports / SNMP
  metrics / brute_force_active.
- `/api/devices/sysinfo?ids=a,b,c` batches the Monitoring page's
  per-device sysinfo pulls (was 1 + N requests).
- File-backed 10 s cache for `/api/attention` shared across CGI
  workers; busts when any underlying state file is newer than the
  cache.

---

## v3.3.1 & v3.3.2 additions

### OFFLINE detection hardening
The per-request offline sweep no longer marks a device down on a single
sample crossing the TTL — a late beat or a stale read used to produce an
`OFFLINE` → `ONLINE` flap in the same second. The cutoff is now
per-device, `max(global ttl, poll_interval * OFFLINE_MISSED_POLLS) +
grace`, and OFFLINE is debounced through an `offline_pending` candidate:
it fires only if a later sweep (≥1 poll interval on) still sees the
device silent. Recovery stays immediate. The bar is 5 missed polls
(300 s at the default 60 s poll). `offline_pending` is cleared wherever
`offline_notified` is, including on device delete.

### Maintenance windows show the hostname
A device-scoped maintenance window's Target column resolves the device
id to its name server-side (`target_name`) instead of showing the opaque
id.

### UI consistency + PWA polish
- Action buttons aligned across pages: paired Edit/Delete/Revoke buttons
  share one size class and icon style; the ACME force-renew button gets
  its missing refresh icon.
- Devices table no longer renders stray `…` dots: under
  `table-layout: fixed` a too-narrow container shrinks columns until
  Chrome paints an ellipsis on the clipped cell (Firefox clips
  silently). Cells now use `text-overflow: clip`, and the table sheds
  low-priority columns ~200 px earlier while the sidebar is docked
  (browser and installed PWA alike).
- PWA manifest defaults to `minimal-ui`; the docked-sidebar layout no
  longer clips the device table or the "MCP Confirmations" nav badge.
- "Did you know?" tips on the About page surface lesser-known features.
- The TOTP enrollment QR renders as a data-URL `<img>` so it doesn't
  trip the strict `style-src 'self'` CSP.

### Bug fixes
- Agent patch status no longer false-warns `pacman sync failed` on a
  fully-patched Arch/CachyOS host (`-Sy` and `-Qu` are now in separate
  try blocks).
- `/api/home` CVE and drift tiles match the detail pages — stale records
  for deleted devices no longer inflate the counts.
- Settings toggles reflect real runtime defaults even when the v3.3.0
  flags were never explicitly set (notably `webhook_block_local`).
- `/api/fleet/events` honours the `?event=` filter.

## v3.4.0 additions

### Hardware & health (SMART / kernel / inventory)
The agent runs `smartctl` on each disk and reports health plus the key
pre-fail attributes (reallocated / pending / offline-uncorrectable
sectors, temperature, power-on hours). A drive that reports a non-OK
status **or** has pre-fail sectors raises the `smart_failure` event and
a red health pill on the device card; drives `smartctl` can't assess
(USB bridges, virtual disks) report `UNKNOWN` and are *not* treated as
failures. The agent also compares the running kernel to the newest
installed one (`kernel_outdated` + livepatch status) and collects a
passive inventory — DIMMs, serial numbers, temperatures, RAID state.
Everything surfaces in the device drawer's **Health & Hardware** card.

### Resource forecasting
A compact metrics snapshot is written **once per device per UTC day**
(per-mount used/total GB, memory, swap, plus a state fingerprint) and
retained for roughly six months in `metrics_history.json`. From that
history, `GET /api/devices/<id>/forecast` fits a least-squares trend of
used-GB-over-time **per mount** and extrapolates it to the mount's
capacity, yielding a **days-to-full** estimate and a projected fill date
(e.g. *"/ fills in ~18 days"*). Notes:

- Each mount is projected independently, so a fast-growing `/var`
  surfaces even while `/` looks healthy.
- Flat or shrinking mounts report **no fill** rather than a misleading
  far-future date.
- It's a straight-line trend, not a guarantee — a log burst or a big
  install shifts it; it's meant to give you lead time, not a precise
  date. Accuracy improves as daily samples accumulate, so a freshly
  added host shows little until it has a few days of history.
- The drawer's forecast view colour-codes urgency (under ~14 days,
  under ~45 days) and offers a one-click, context-prefilled AI runbook
  for an imminent fill.

### What changed (drift over time)
`GET /api/devices/<id>/changes?days=1|7` diffs the oldest snapshot in
the window against the latest and reports package deltas, opened/closed
listening ports, failed/recovered units, reboot edges, and per-mount
disk growth — a quick "what moved on this host since yesterday/last
week" without trawling logs.

### On-demand diagnostics
A one-click **network speed test** (librespeed → Mbps, with live
feedback) and a **LAN discovery** sweep (passive ARP table or an nmap
scan) that lists hosts on the device's network and flags ones not yet
managed by RemotePower.

### Device quarantine
A per-device admin switch that disables exec / reboot / every action,
enforced server-side at the command-dispatch chokepoint (not just hidden
in the UI) and audited. Freeze a suspect or sensitive host in one click,
then release it the same way.

### Compliance reports
`GET /api/compliance?frameworks=pci,hipaa,soc2` maps PCI DSS / HIPAA /
SOC 2 controls to data RemotePower already collects (patching, CVEs,
TLS, MFA, audit logging, backups, listening-port change detection, …)
and scores each **pass / fail / N-A** with evidence and remediation. The
score is pass ÷ (pass + fail), ignoring N-A — an honest "of what we can
measure, how much passes." An audit-prep aid, never a formal
attestation, and never a false pass.

### Helm release status
Where a host has Helm and a kubeconfig, RemotePower surfaces Helm
release status (visibility only — it doesn't install or upgrade).

### On-demand AI insights
All opt-in and disabled until you configure a provider:
- **Fleet anomaly scan** (`POST /api/ai/anomaly`) — ranks unusual
  signals across the fleet (odd ports, drift, failing disks) for review.
- **Cron builder** (`POST /api/ai/cron`) — plain-English → a cron
  expression, with the next run times previewed by local validation.
- **Runbook suggestions** (`POST /api/devices/<id>/runbook`) and **CMDB
  doc drafts** (`POST /api/devices/<id>/doc-draft`) — RAG-aware,
  pre-fillable from a finding (a failing disk, an imminent fill).

### RAG over your infrastructure
The AI assistant retrieves the most relevant facts from *your* fleet —
device state, watched services, CVEs, containers, CMDB metadata & asset
docs, per-device runbooks, recent commands and alerts, plus the
RemotePower product docs — and injects them into each request as a cited
`<retrieved_context>` block, so answers reference your hosts and cite
sources by id (e.g. `[live/web01#cves]`). Retrieval is **lexical-first**
(BM25, pure stdlib) so it works with every provider including Anthropic;
with an embedding-capable provider you can enable **semantic search**,
fused with lexical via Reciprocal Rank Fusion. Privacy by construction:
the encrypted credentials vault is never indexed (metadata + docs only),
history is redacted at index time, and embeddings egress is opt-in.
Managed under **Settings → AI → Knowledge index** (source toggles,
**Rebuild index**, and a **Test retrieval** box). See [rag.md](rag.md).

### Proxmox LXC create & delete
Beyond start / shutdown / snapshots, the Containers page → LXC section
gets a **Create container** wizard (live templates, root-disk storages,
Linux/OVS bridges, next free VMID; hostname, disk/cores/memory/swap,
DHCP or static network, root password and/or SSH key, start & on-boot
toggles) and a **Delete** button with a type-to-confirm guard that
force-stops a running container before removing it (no purge). Both are
admin-only, validated server-side, and audited.

### Security & hardening
`remotepower-passwd` and the installer use salted PBKDF2-HMAC-SHA256
when bcrypt isn't present (never bare SHA-256), and the server no longer
accepts legacy pre-2.3.2 unsalted-SHA-256 hashes (bcrypt/PBKDF2
auto-upgrade to bcrypt on login). A server-wide cap keeps a flapping
monitor from flooding webhook channels. Native browser pop-ups are
replaced with the app's own keyboard-friendly dialogs.

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
