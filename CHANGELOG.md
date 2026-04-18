# Changelog

## v1.4.0 — 2026-04-17

### New features

**Recurring scheduled commands**
- Schedule tab now accepts a cron expression (5-field: `min hour dom mon dow`) in addition to a one-shot datetime
- Recurring jobs stay in the queue and fire every time the cron expression matches (checked on every API request, minute precision)
- Dashboard shows `↻ <cron>` for recurring jobs vs a timestamp for one-shot jobs

**Batch commands (multi-device)**
- Click the device icon on any card to select it (turns into a checkmark)
- A batch action bar appears with Shut down all / Reboot all / Update all buttons
- API also accepts `device_ids: [...]`, `tag: "servers"`, or `group: "homelab"` on all command endpoints

**Device groups / namespaces**
- New `group` field per device (`PATCH /api/devices/:id/group`)
- Device grid sorts by group then name; group badge shown on the hostname line
- Batch commands can target an entire group

**Per-device notes**
- Free-text `notes` field per device (`PATCH /api/devices/:id/notes`, max 1024 chars)
- 📝 indicator on device name when notes are set; tooltip shows the text
- Dedicated Notes modal accessible from the device card

**Adjustable heartbeat interval per device**
- `PATCH /api/devices/:id/poll_interval` (10–3600 s)
- Server queues a `poll_interval:<n>` command; agent picks it up on next heartbeat and adjusts its sleep interval dynamically (no restart needed)
- Current interval shown in device meta row

**Agent health / offline reason**
- `offline_reason` field in device list: `missed_polls` (offline <5 min) vs `offline`
- `missed_polls` counter exposed in API and shown as an amber badge on offline cards
- Agent now reports `executed_command` field in heartbeat so the server can fire command-executed webhooks

**Re-enrollment without wipe**
- `sudo remotepower-agent re-enroll` sends the existing `device_id` in the registration payload
- Server detects a matching ID, updates the record in-place, and returns `reregistered: true`
- History, tags, group, and notes are all preserved on re-enroll

**Saved command library**
- New Command Library page (nav: Library) for named shell snippets
- `GET/POST /api/cmd-library`, `DELETE /api/cmd-library/:id`
- Exec modal now has a "pick from library" dropdown that pastes the command into the input
- Snippets shared across all admin users

**Command allowlist per device**
- `GET/POST /api/devices/:id/allowlist` — set an explicit list of allowed shell commands
- When non-empty, only listed commands can be run via exec on that device (403 otherwise)
- Empty list = unrestricted (backward-compatible with existing behaviour)
- Allowlist modal accessible from the device card (🔒 button)

**Basic metrics history (CPU / RAM / Disk)**
- Agent optionally collects `cpu_percent`, `mem_percent`, `disk_percent` via `psutil` (gracefully skipped if not installed)
- Server stores up to 1440 snapshots per device in `metrics.json` (roughly 24 h at 60 s intervals)
- Metrics modal per device with sparkline bars for CPU, RAM, and Disk
- New endpoint: `GET /api/devices/:id/metrics`

**Named API keys**
- New API Keys page (nav: API Keys)
- `GET/POST /api/apikeys`, `DELETE /api/apikeys/:id`
- Non-expiring keys authenticated via `X-Token` header (same as session tokens)
- Each key has a `role` (admin or viewer) — viewer keys are read-only
- Key value shown once at creation; not stored in any response thereafter

**Role-based access (viewer accounts)**
- Users now have a `role` field: `admin` (default) or `viewer`
- Viewer role: can see the dashboard, devices, sysinfo, history, monitor — but cannot queue commands, change config, manage users, or create API keys
- Role shown in Users table; role selector in Add User modal
- Login response now returns `role` and `username`

**Dashboard export / backup**
- `GET /api/export` streams a ZIP of all `*.json` data files (excluding `tokens.json`)
- "Export backup" button added to Settings page; uses fetch + blob for in-browser download

**Webhook on command execution**
- `command_queued` and `command_executed` webhook events added alongside the existing `device_offline`, `device_online`, and `patch_alert` events
- `command_executed` fires when the agent reports back that it ran a command (via the `executed_command` field in the heartbeat)

**Long-poll exec (terminal-in-browser foundation)**
- `POST /api/exec/wait` — queues an exec command and holds the HTTP connection open (default 90 s, max 120 s) polling for output
- When the agent's next heartbeat delivers the output, the response is flushed immediately
- Falls back with `timeout: true` if output doesn't arrive; client can then poll `/output` as before
- `longpoll.json` tracks pending waiters per device

**Digest endpoint**
- `GET /api/digest` — JSON summary: total/online/offline devices, total pending patches, last 10 commands
- Designed for cron-driven email digests or dashboard status boards; no polling infrastructure needed

**Agent integrity check**
- `sudo remotepower-agent integrity` — hashes the running binary, compares to server's known-good SHA-256
- Exits 0 if match, 1 if mismatch (suitable for cron alerting)

### Changed
- `GET /api/devices` response now includes `group`, `notes`, `offline_reason`, `missed_polls`, `poll_interval`
- `GET /api/users` response now includes `role` per user
- `POST /api/users` now accepts optional `role` field (default: `admin`)
- Login response now returns `role` and `username`
- Heartbeat response now includes `poll_interval` hint for the agent
- `_queue_command` now fires a `command_queued` webhook on every queued action
- `check_offline_webhooks` now fires `device_online` webhook when a device comes back
- Devices sorted by group then name (was: name only)
- Schedule table shows `↻ <cron>` for recurring jobs

### New data files
- `metrics.json` — per-device CPU/RAM/disk time-series (last 1440 points)
- `cmd_library.json` — saved command snippets
- `longpoll.json` — pending long-poll output slots
- `apikeys.json` — named API keys (key values stored here; never returned after creation)

### New API endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `PATCH` | `/api/devices/:id/notes` | admin | Set device notes |
| `PATCH` | `/api/devices/:id/group` | admin | Set device group |
| `PATCH` | `/api/devices/:id/poll_interval` | admin | Set poll interval hint |
| `GET` | `/api/devices/:id/metrics` | ✓ | CPU/RAM/disk time-series |
| `GET/POST` | `/api/devices/:id/allowlist` | admin | Get/set command allowlist |
| `GET` | `/api/cmd-library` | ✓ | List command snippets |
| `POST` | `/api/cmd-library` | admin | Add command snippet |
| `DELETE` | `/api/cmd-library/:id` | admin | Delete command snippet |
| `GET` | `/api/apikeys` | admin | List API keys (no values) |
| `POST` | `/api/apikeys` | admin | Create API key (value shown once) |
| `DELETE` | `/api/apikeys/:id` | admin | Delete API key |
| `GET` | `/api/export` | admin | Download ZIP backup |
| `GET` | `/api/digest` | ✓ | Summary for cron/email |
| `POST` | `/api/exec/wait` | admin | Long-poll exec (up to 120 s) |

---

## v1.3.1 — 2026-04-17

- Version bump; minor packaging fixes

---

## v1.3.0 — 2026-04-16

### New features
- Tag editor — set and edit device tags directly from the dashboard
- Tag group filtering — filter device grid by tag with one click
- Scheduled commands — queue shutdown or reboot at a specific date and time
- Custom shell commands — run arbitrary commands on devices, output returned via next heartbeat (~60s)
- Monitor history — uptime percentage, sparkline, last 50 check results per target
- Patch alert webhook — fires when a device exceeds a configurable pending update threshold
- Uptime tracking — online/offline state changes stored per device in uptime.json
- Command history page — every action logged with actor, device, and timestamp
- About page — server version, agent version, latest GitHub release check
- Dark/light mode toggle — persisted per browser in localStorage
- Force agent update from dashboard — queue update command like shutdown/reboot
- Network info — agent reports all interfaces, not just primary IP

### Fixed
- Nginx blocking PATCH method — tag API would return 405
- QUERY_STRING not forwarded to CGI — monitor history label lookup always returned empty
- Poller cadence was broken — sysinfo/journal now every 10 polls (~10min), patches every 180 polls (~3hr)
- First-poll sysinfo — agent now sends data immediately on startup instead of waiting
- Exec button shown on offline devices — now dimmed with tooltip
- Tag API existed but no UI to set tags
- Custom command output stored on server but never displayed

---

## v1.2.0 — 2026-04-16

### New features
- Agent self-update — SHA-256 verified, atomic replace, systemctl restart, no SSH needed
- Force update from dashboard — queue update command alongside shutdown/reboot
- Dark/light mode toggle
- Server version check against GitHub releases — amber banner when update available
- WoL unicast fix — sends to device's last known IP for routed/VPN networks, broadcast fallback

### Fixed
- Agent log file permission error when running as non-root
- Poller frequency — patches split from sysinfo (patches every 3hr, sysinfo every 10min)

---

## v1.1.2 — 2026-04-15
- Fixed agent self-update download URL (static file instead of CGI)
- Fixed agent log file permission for non-root users
- Reduced sysinfo/patch poll frequency to reduce load

## v1.1.1 — 2026-04-15
- Fixed agent log file permission for non-root users
- Fixed agent self-update download URL (static file instead of CGI)

## v1.1.0 — 2026-04-15
- bcrypt password hashing with silent SHA-256 auto-upgrade
- Wake-on-LAN support, MAC reported at enroll time
- Reboot command alongside shutdown
- Multiple admin users with full CRUD in dashboard
- Offline webhook (Ntfy/Gotify/Slack/Discord)
- Patch info via apt/dnf/pacman (dry-run only)
- Uptime + journalctl per device with noise filtering
- Ping/TCP/HTTP service monitoring from server
- Agent self-update — SHA-256 verified, atomic replace
- Multi-distro install scripts (apt/dnf/pacman)
- deploy-server.sh for fast redeploys

## v1.0.0 — 2026-04-14
- Initial release
- Remote shutdown over HTTPS
- PIN enrollment
- No inbound firewall rules on clients
- Flat JSON storage, Nginx + Python CGI
