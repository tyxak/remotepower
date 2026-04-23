# Changelog

## v1.7.0 - 2026-04-23

### New features

**CVE Scanner (via OSV.dev)**
- New "CVEs" page in the dashboard showing aggregate severity counts (critical/high/medium/low) across the fleet, per-device breakdown, and per-vulnerability drill-down
- Agent enumerates installed packages (`dpkg-query` / `rpm` / `pacman` / `apk`) every 6 hours and submits via new `/api/packages` endpoint; hash-gated so it only resubmits when the package list actually changes
- Server queries OSV.dev's batch endpoint (up to 500 packages per request) and caches vulnerability details for 7 days
- Supported ecosystems: Debian, Ubuntu, Rocky Linux, AlmaLinux, Red Hat, Alpine, Arch Linux
- Fixed-version information shown in the drill-down when OSV provides it
- Ignore list: mark a CVE as accepted risk globally or for a specific device; ignored findings are excluded from counts and alerts but remain visible (dimmed)
- New webhook event `cve_found` fires (priority 5 — urgent) when new critical/high CVEs appear that weren't in the previous scan

**Prometheus `/metrics` endpoint**
- Standard Prometheus text exposition at `GET /api/metrics`
- Auth via session token or API key — Prometheus's native `bearer_token` scrape config works unchanged
- Device count, online state, cpu/mem/disk percentages, upgradable package counts, CVE findings by severity, monitor state, command queue depth, webhook delivery counters

### New endpoints

- `POST /api/packages` — agent submits installed package list (device-authenticated)
- `POST /api/cve/scan` — admin triggers CVE scan (one device or all)
- `GET  /api/cve/findings` — aggregate CVE report
- `GET  /api/devices/{id}/cve` — per-device CVE findings
- `GET  /api/cve/ignore` — list active ignore entries
- `POST /api/cve/ignore` — mark a CVE as accepted risk
- `DELETE /api/cve/ignore/{vuln_id}` — remove an ignore
- `GET  /api/metrics` — Prometheus scrape endpoint

### Changed

- All version strings bumped to 1.7.0 (server, Linux agent, Windows agent)
- Linux agent gains `PACKAGE_LIST_EVERY = 360` and `MAX_PACKAGES_SEND = 10000` constants
- Linux agent gains six new functions (`get_os_release`, `get_package_list`, `send_package_list`, three hash-cache helpers) + a sidecar file `/etc/remotepower/pkg_hash`
- Webhook event helpers extended for `cve_found`

### Config keys added

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `cve_webhook_enabled` | bool | `true` | Whether to fire `cve_found` webhooks on new critical/high findings |

### New data files

- `packages.json` — per-device installed package list + hash
- `cve_findings.json` — per-device scan results
- `cve_ignore.json` — global/per-device CVE ignore list
- `cve_details_cache.json` — OSV vulnerability detail cache (7-day TTL)

### Notes

- Fedora is not reliably covered by OSV and is marked `unsupported`. Extend `cve_scanner.detect_ecosystem()` to add custom mappings.
- First-time CVE scan on a heavy Debian host can take 30–60 seconds while per-vulnerability details are hydrated; subsequent scans hit the cache and are near-instant.
- Windows agents submit no package data (OSV ecosystems don't cover Windows well). Windows devices show as `unsupported` in the CVE UI.
- Package list submission is bandwidth-efficient: ~120 KB per device per change event, zero bytes when nothing changed (hash-gated client-side).

---

## v1.6.0 - 2026-04-21

### New features

**Webhook overhaul**
- Webhook URL is now visible and editable in the Settings UI (previously hidden after save)
- Webhook payloads now include `title`, `message`, and `priority` fields for human-readable push notifications
- Push-compatible headers added: `X-Title`, `X-Priority`, `X-Tags` — works out of the box with Ntfy, Gotify, Pushover, Slack, and Discord
- Per-event emoji tags for Ntfy (`X-Tags` header) — e.g. `red_circle,computer` for offline, `warning,package` for patch alerts
- Per-event priority levels (3=normal, 4=high) for push services
- `User-Agent` header now includes server version (`RemotePower/1.6.0`)

**Monitor webhook alerts**
- New `monitor_down` event fires when a monitor target goes from up to down
- New `monitor_up` event fires when a monitor target recovers
- State-change tracking prevents duplicate alerts (only fires on transitions)
- Toggle on/off via Settings checkbox ("Monitor alerts")

**Offline webhook toggle**
- New toggle in Settings to enable/disable device offline/online webhook alerts
- Allows keeping the webhook URL configured for other events (patch alerts, commands, monitors) while disabling offline noise

**Patch alert improvements**
- Threshold can now be cleared (set to 0 or empty) to disable patch alerts via the UI
- Clearing the threshold also resets tracked alert state

### Changed

- `GET /api/config` now returns `webhook_url`, `offline_webhook_enabled`, and `monitor_webhook_enabled` (webhook URL was previously hidden from the API response)
- `POST /api/config` accepts `offline_webhook_enabled` (bool) and `monitor_webhook_enabled` (bool)
- `POST /api/config` accepts `patch_alert_threshold: 0` or `null` to clear the threshold
- Settings UI reorganised: "Webhooks" section replaces "Offline Webhook", with toggles and visible URL
- All version strings bumped to 1.6.0 (server, Linux agent, Windows agent, Dockerfile, docker-compose, README badge)
- Webhook `fire_webhook()` rewritten with richer payloads and push headers

### Config keys added

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `offline_webhook_enabled` | bool | `true` | Enable/disable device offline/online webhook alerts |
| `monitor_webhook_enabled` | bool | `true` | Enable/disable monitor up/down webhook alerts |
| `monitor_notified` | object | `{}` | Internal state tracking for monitor alert deduplication |

### Webhook events

| Event | Priority | When |
|-------|----------|------|
| `device_offline` | 4 (high) | Device misses heartbeats beyond ONLINE_TTL |
| `device_online` | 3 | Device comes back online |
| `monitor_down` | 4 (high) | Monitor target transitions from up to down |
| `monitor_up` | 3 | Monitor target recovers |
| `patch_alert` | 4 (high) | Device exceeds pending update threshold |
| `command_queued` | 3 | Command queued for a device |
| `command_executed` | 3 | Device reports command execution |

---

## v1.5.1 - 2026-04-20

### New features

**Windows agent**
- New `client/remotepower-agent.py` - full-featured Windows client agent
- Same heartbeat protocol and API as the Linux agent - enrolls the same way
- Power control via `shutdown.exe /s` and `/r` with 30-second grace period
- Patch info via Windows Update COM API (PowerShell)
- System journal via `wevtutil` (Windows System event log)
- CPU/RAM/disk metrics via psutil (optional, same as Linux)
- Boot reason tracking via `%ProgramData%\RemotePower\last_cmd.txt`
- Adjustable poll interval via config file (same mechanism as Linux)
- Runs as a Windows Service via NSSM, or interactively for testing
- `install-client.ps1` PowerShell installer: checks Python, installs psutil, enrolls, downloads NSSM, registers service
- Supports `enroll`, `re-enroll`, `status`, `integrity` subcommands
- Agent self-update is logged but not applied automatically on Windows (manual update recommended)

**Docker support**
- `Dockerfile` and `docker-compose.yml` for containerized server deployment
- Based on `python:3.12-slim` with nginx + fcgiwrap + bcrypt + reportlab
- Admin user created automatically via `RP_ADMIN_USER` / `RP_ADMIN_PASS` environment variables
- Data persisted in `/var/lib/remotepower` volume
- Healthcheck built in (HTTP probe every 60s)
- Docker-specific nginx config on port 8080 (put a reverse proxy in front for HTTPS)
- `docker/entrypoint.sh` handles fcgiwrap startup, user creation, and version config
- `.dockerignore` to keep image lean

### Changed

- Agent version bumped to 1.5.1
- Server version bumped to 1.5.1
- README updated with Windows client docs, Docker quick start, updated architecture diagram
- Platform badge updated to `Linux | Windows`
- File layout updated with new files

### New files

| File | Description |
|------|-------------|
| `client/remotepower-agent.py` | Windows agent (Python 3) |
| `install-client.ps1` | Windows client installer (PowerShell) |
| `Dockerfile` | Server container image |
| `docker-compose.yml` | Compose file for quick deployment |
| `.dockerignore` | Docker build exclusions |
| `docker/nginx-docker.conf` | Nginx config for Docker |
| `docker/entrypoint.sh` | Container entrypoint script |

---

## v1.5.0 - 2026-04-19

### New features

**Patch Report page**
- New Patches nav tab with dedicated patch overview across all devices
- Summary cards: total devices, fully patched, patches pending, total pending count, patch rate %
- Device table with per-device patch status, pkg manager, recent patch commands
- Export as CSV (`GET /api/patch-report/csv`)
- Export as XML (`GET /api/patch-report/xml`)
- Export as PDF (`GET /api/patch-report/pdf`) - formatted with ReportLab, color-coded status

**Audit log with IP tracking**
- New Audit Log nav tab showing security-relevant events
- Tracks: logins (success + failed), exec commands, session revocations, user-agent + source IP
- `GET /api/audit-log` endpoint (admin only)
- Stored in `audit_log.json` (last 500 entries)

**API key expiration**
- `POST /api/apikeys` now accepts optional `expires_at` (unix timestamp)
- Expired keys are silently rejected during authentication
- Keys without `expires_at` remain non-expiring (backward compatible)

**Bulk exec**
- `POST /api/exec` now accepts `device_ids`, `tag`, or `group` targets (same as shutdown/reboot)
- Run arbitrary commands across multiple devices in one API call
- Allowlist is checked per-device; partial failures return per-device results

**Increased exec timeout**
- Agent exec timeout raised from 30s to 300s (5 min) for long-running commands like `apt upgrade`

**Boot reason tracking**
- Agent records the last command before shutdown/reboot in `/tmp/remotepower-last-cmd`
- First heartbeat after restart includes `boot_reason` field
- Helps distinguish scheduled reboots from unexpected restarts

**Device search and filtering**
- Search bar on Devices page - filter by name, hostname, IP, OS, group, or tags
- Status filter dropdown (All / Online / Offline)
- Group filter dropdown (auto-populated from device groups)
- All filters combine with existing tag filter

**Browser notifications**
- Web Notifications API integration for device online/offline state changes
- Permission requested on first login; notifications fire on status transitions
- No server-side changes needed - purely client-side

**Session token revocation**
- `POST /api/sessions/revoke` - revoke all sessions or sessions for a specific user
- "Revoke all sessions" button on Audit Log page
- Admin-only; preserves the requester's current session when revoking all

**Two-Factor Authentication (TOTP)**
- TOTP-based 2FA compatible with Google Authenticator, Authy, etc.
- Setup flow: `POST /api/totp/setup` → scan secret → `POST /api/totp/confirm` with code
- Login prompts for authenticator code when 2FA is enabled
- Disable with password confirmation via `POST /api/totp/disable`
- Status check: `GET /api/totp/status`
- 2FA section added to Settings page with enable/disable UI

**Per-device patch report**
- `GET /api/patch-report/device/:id` - detailed patch info for a single device
- Includes patch command history, OS, uptime, agent version, metrics
- "Detail" button on each row in the Patches table opens a modal

**Clear history**
- Clear button on Command History page (`DELETE /api/history`)
- Clear button on Audit Log page (`DELETE /api/audit-log`)
- Both require admin role and are themselves audit-logged

**Filtered patch export**
- Group and device filter dropdowns on Patches page
- CSV/XML/PDF exports respect the active filter via `?group=X` and `?device_id=Y` query params
- Summary cards update live based on filtered set

### Changed
- `POST /api/exec` now supports batch targets (device_ids, tag, group) in addition to single device_id
- Agent exec timeout increased from 30s to 300s
- Agent sends `boot_reason` on first heartbeat after restart
- Audit events logged for logins, failed logins, exec commands, session revocations
- Patch percentage now excludes offline/no-data devices (only counts online with known state)
- Nav bar wraps on smaller screens, reduced padding for 11 tabs
- CSV/XML/PDF exports flush stdout properly for CGI binary output
- XML export produces valid well-formed XML

### New data files
- `audit_log.json` - security audit trail (last 500 entries)
- `sessions_meta.json` - session metadata for revocation tracking

### New API endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/patch-report` | ✓ | Full patch report (JSON) |
| `GET` | `/api/patch-report/csv` | ✓ | Patch report as CSV download |
| `GET` | `/api/patch-report/xml` | ✓ | Patch report as XML download |
| `GET` | `/api/patch-report/pdf` | ✓ | Patch report as PDF download |
| `GET` | `/api/audit-log` | admin | Security audit log |
| `POST` | `/api/sessions/revoke` | admin | Revoke user sessions |
| `GET` | `/api/patch-report/device/:id` | ✓ | Per-device patch detail |
| `POST` | `/api/totp/setup` | ✓ | Generate TOTP secret |
| `POST` | `/api/totp/confirm` | ✓ | Confirm & enable 2FA |
| `POST` | `/api/totp/disable` | ✓ | Disable 2FA (requires password) |
| `GET` | `/api/totp/status` | ✓ | Check if 2FA is enabled |
| `DELETE` | `/api/history` | admin | Clear command history |
| `DELETE` | `/api/audit-log` | admin | Clear audit log |

---

## v1.4.0 - 2026-04-17

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
- `GET/POST /api/devices/:id/allowlist` - set an explicit list of allowed shell commands
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
- Each key has a `role` (admin or viewer) - viewer keys are read-only
- Key value shown once at creation; not stored in any response thereafter

**Role-based access (viewer accounts)**
- Users now have a `role` field: `admin` (default) or `viewer`
- Viewer role: can see the dashboard, devices, sysinfo, history, monitor - but cannot queue commands, change config, manage users, or create API keys
- Role shown in Users table; role selector in Add User modal
- Login response now returns `role` and `username`

**Dashboard export / backup**
- `GET /api/export` streams a ZIP of all `*.json` data files (excluding `tokens.json`)
- "Export backup" button added to Settings page; uses fetch + blob for in-browser download

**Webhook on command execution**
- `command_queued` and `command_executed` webhook events added alongside the existing `device_offline`, `device_online`, and `patch_alert` events
- `command_executed` fires when the agent reports back that it ran a command (via the `executed_command` field in the heartbeat)

**Long-poll exec (terminal-in-browser foundation)**
- `POST /api/exec/wait` - queues an exec command and holds the HTTP connection open (default 90 s, max 120 s) polling for output
- When the agent's next heartbeat delivers the output, the response is flushed immediately
- Falls back with `timeout: true` if output doesn't arrive; client can then poll `/output` as before
- `longpoll.json` tracks pending waiters per device

**Digest endpoint**
- `GET /api/digest` - JSON summary: total/online/offline devices, total pending patches, last 10 commands
- Designed for cron-driven email digests or dashboard status boards; no polling infrastructure needed

**Agent integrity check**
- `sudo remotepower-agent integrity` - hashes the running binary, compares to server's known-good SHA-256
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
- `metrics.json` - per-device CPU/RAM/disk time-series (last 1440 points)
- `cmd_library.json` - saved command snippets
- `longpoll.json` - pending long-poll output slots
- `apikeys.json` - named API keys (key values stored here; never returned after creation)

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

## v1.3.1 - 2026-04-17

- Version bump; minor packaging fixes

---

## v1.3.0 - 2026-04-16

### New features
- Tag editor - set and edit device tags directly from the dashboard
- Tag group filtering - filter device grid by tag with one click
- Scheduled commands - queue shutdown or reboot at a specific date and time
- Custom shell commands - run arbitrary commands on devices, output returned via next heartbeat (~60s)
- Monitor history - uptime percentage, sparkline, last 50 check results per target
- Patch alert webhook - fires when a device exceeds a configurable pending update threshold
- Uptime tracking - online/offline state changes stored per device in uptime.json
- Command history page - every action logged with actor, device, and timestamp
- About page - server version, agent version, latest GitHub release check
- Dark/light mode toggle - persisted per browser in localStorage
- Force agent update from dashboard - queue update command like shutdown/reboot
- Network info - agent reports all interfaces, not just primary IP

### Fixed
- Nginx blocking PATCH method - tag API would return 405
- QUERY_STRING not forwarded to CGI - monitor history label lookup always returned empty
- Poller cadence was broken - sysinfo/journal now every 10 polls (~10min), patches every 180 polls (~3hr)
- First-poll sysinfo - agent now sends data immediately on startup instead of waiting
- Exec button shown on offline devices - now dimmed with tooltip
- Tag API existed but no UI to set tags
- Custom command output stored on server but never displayed

---

## v1.2.0 - 2026-04-16

### New features
- Agent self-update - SHA-256 verified, atomic replace, systemctl restart, no SSH needed
- Force update from dashboard - queue update command alongside shutdown/reboot
- Dark/light mode toggle
- Server version check against GitHub releases - amber banner when update available
- WoL unicast fix - sends to device's last known IP for routed/VPN networks, broadcast fallback

### Fixed
- Agent log file permission error when running as non-root
- Poller frequency - patches split from sysinfo (patches every 3hr, sysinfo every 10min)

---

## v1.1.2 - 2026-04-15
- Fixed agent self-update download URL (static file instead of CGI)
- Fixed agent log file permission for non-root users
- Reduced sysinfo/patch poll frequency to reduce load

## v1.1.1 - 2026-04-15
- Fixed agent log file permission for non-root users
- Fixed agent self-update download URL (static file instead of CGI)

## v1.1.0 - 2026-04-15
- bcrypt password hashing with silent SHA-256 auto-upgrade
- Wake-on-LAN support, MAC reported at enroll time
- Reboot command alongside shutdown
- Multiple admin users with full CRUD in dashboard
- Offline webhook (Ntfy/Gotify/Slack/Discord)
- Patch info via apt/dnf/pacman (dry-run only)
- Uptime + journalctl per device with noise filtering
- Ping/TCP/HTTP service monitoring from server
- Agent self-update - SHA-256 verified, atomic replace
- Multi-distro install scripts (apt/dnf/pacman)
- deploy-server.sh for fast redeploys

## v1.0.0 - 2026-04-14
- Initial release
- Remote shutdown over HTTPS
- PIN enrollment
- No inbound firewall rules on clients
- Flat JSON storage, Nginx + Python CGI
