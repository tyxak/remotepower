# Changelog

## v1.6.3 — 2026-04-22

### Fixed
- Bulk "Upgrade packages" rejected freshly-restarted devices with
  `Unknown or unreported package manager: none`. Root cause: the server
  looked up `sysinfo.packages.manager` on the device record, but `packages`
  is only populated after a patch-info poll — which runs every `PATCH_EVERY`
  (180) polls, i.e. roughly 3 hours after agent restart. On any device that
  had been restarted recently (every Debian box the 1.6.1 service-file fix
  was deployed to) the upgrade button was effectively broken.

  The dispatcher no longer relies on server-side sysinfo at all. It now
  queues a single self-detecting shell snippet that runs `command -v
  apt-get` / `dnf` / `pacman` on the device at execution time and picks
  the right one. This also simplifies the server code — one command, no
  per-device dispatch, no stale-cache failure modes.

### Changed
- `POST /api/upgrade-device` response no longer includes the `manager`
  field (the server doesn't know in advance anymore). The queued exec
  output — visible on the next heartbeat — still shows which manager ran.
- All version strings bumped to 1.6.3.

### Note on custom `apt` commands
The Custom Command dialog runs whatever string you type verbatim. If you
manually type `apt update && apt upgrade -y …` on a box that still has
`NoNewPrivileges=yes` in its agent service file, you'll still see the
`seteuid 105 failed` error — that's expected, and the fix is to deploy
the 1.6.1 service file and do `systemctl daemon-reload && systemctl
restart remotepower-agent` on that host. The bulk "Upgrade packages"
button works around this automatically via the APT_CONFIG override;
custom commands don't, by design.
---
 
## v1.6.2 — 2026-04-22

### Fixed
- Bulk "Upgrade packages" still failed on Debian/Ubuntu with
  `E: seteuid 105 failed - seteuid (1: Operation not permitted)` because the
  `-o APT::Sandbox::User=root` flag was only applied to `apt-get upgrade`.
  But `apt-get update` is the call that actually opens network sockets and
  drops to the `_apt` user — so under systemd hardening (`NoNewPrivileges=yes`,
  restricted cgroups, user namespaces), `apt-get update` returned rc=100 and
  short-circuited the `&&` chain before upgrade ever ran.

  The fix writes a one-line apt config to a tempfile, points `APT_CONFIG` at
  it, and exports that env var for the whole chain. Every `apt-get` call in
  the chain (`update`, `upgrade`, `autoremove`, `clean`) now inherits
  `APT::Sandbox::User "root"` plus the `Dpkg::Options` conffile handling, and
  a `trap` cleans up the tempfile even if any step fails.

  **Server-only fix** — agents don't need to be restarted to pick this up,
  since the command is constructed server-side and dispatched via the
  existing `exec:` channel. Just redeploy the server.

### Changed
- All version strings bumped to 1.6.2.
---
 
## v1.6.1 — 2026-04-22

### Fixed
- Bulk-action icons in the selection bar rendered as oversized default-styled
  buttons — `.btn-shutdown` and `.btn-reboot` had no CSS defined, so SVGs were
  unconstrained. Added matching red/amber/purple button styles with proper 14px
  SVG sizing so the batch bar visually matches the rest of the UI.
- Device "…" dropdown menu was pierced by sibling cards' menu buttons due to
  each `.device-card` sharing a stacking context with `z-index: 20`. The open
  dropdown's parent card is now lifted via `:has(.device-dropdown.active)` plus
  an explicit `z-index: 9999` on the active dropdown wrapper as a fallback.
- Agent `exec:` commands running apt failed with
  `seteuid 105 failed - seteuid (1: Operation not permitted)` because
  `NoNewPrivileges=yes` in `remotepower-agent.service` blocked apt's drop to
  the `_apt` user. Removed the directive — the agent runs as root by design,
  so this hardening was cosmetic. Defence-in-depth added in the new upgrade
  path via `-o APT::Sandbox::User=root`.

### New features
- Bulk "Upgrade packages" action — select multiple devices and run apt/dnf/
  pacman upgrade across all of them in one click. Server dispatches the right
  command per device based on the package manager reported in sysinfo:
  - apt:    `apt-get update && apt-get upgrade -y && apt-get autoremove -y && apt-get clean`
            (with `APT::Sandbox::User=root` and non-interactive dpkg conffile handling)
  - dnf:    `dnf -y upgrade`
  - pacman: `pacman -Syu --noconfirm`
  Output arrives on the next heartbeat (~60s) via the existing `exec:` pipe.
- "Update all" button renamed to "Update agent" with a clarifying tooltip so
  it isn't confused with package upgrades.

### New API
- `POST /api/upgrade-device` — body `{device_ids: [...]}` or `{device_id: "..."}`.
  Returns per-device results including the detected package manager, or an
  error if the manager is unknown/unreported.

### Changed
- All version strings bumped to 1.6.1.
---
 
## v1.6.0 — 2026-04-21
 
### New features
- Webhook URL visible and editable in Settings UI — no longer hidden after save
- Webhook payloads include `title`, `message`, `priority` for push-friendly notifications
- Push headers (`X-Title`, `X-Priority`, `X-Tags`) for Ntfy, Gotify, Pushover compatibility
- Monitor webhook alerts — `monitor_down` / `monitor_up` events on state change
- Toggle on/off for device offline/online webhook alerts in Settings
- Toggle on/off for monitor webhook alerts in Settings
- Patch alert threshold can be cleared (set to 0 or empty) to disable
- Clear webhook URL button in Settings UI
### Changed
- `GET /api/config` now returns `webhook_url` (was hidden), `offline_webhook_enabled`, `monitor_webhook_enabled`
- Settings page reorganised: "Webhooks" section with toggles replaces "Offline Webhook"
- `fire_webhook()` rewritten with richer payloads, human-readable messages, and push headers
- All version strings bumped to 1.6.0
### New config keys
- `offline_webhook_enabled` (bool, default: true) — toggle offline/online alerts
- `monitor_webhook_enabled` (bool, default: true) — toggle monitor alerts
- `monitor_notified` (internal) — state tracking for monitor alert deduplication
---
 
## v1.6.0 — 2026-04-21
 
### New features
- Webhook URL visible and editable in Settings UI — no longer hidden after save
- Webhook payloads include `title`, `message`, `priority` for push-friendly notifications
- Push headers (`X-Title`, `X-Priority`, `X-Tags`) for Ntfy, Gotify, Pushover compatibility
- Monitor webhook alerts — `monitor_down` / `monitor_up` events on state change
- Toggle on/off for device offline/online webhook alerts in Settings
- Toggle on/off for monitor webhook alerts in Settings
- Patch alert threshold can be cleared (set to 0 or empty) to disable
- Clear webhook URL button in Settings UI
### Changed
- `GET /api/config` now returns `webhook_url` (was hidden), `offline_webhook_enabled`, `monitor_webhook_enabled`
- Settings page reorganised: "Webhooks" section with toggles replaces "Offline Webhook"
- `fire_webhook()` rewritten with richer payloads, human-readable messages, and push headers
- All version strings bumped to 1.6.0
### New config keys
- `offline_webhook_enabled` (bool, default: true) — toggle offline/online alerts
- `monitor_webhook_enabled` (bool, default: true) — toggle monitor alerts
- `monitor_notified` (internal) — state tracking for monitor alert deduplication
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
### New data files
- `history.json` — command log (last 200 entries)
- `schedule.json` — scheduled jobs
- `uptime.json` — online/offline state changes per device
- `monitor_history.json` — check results per monitor target (last 50)
- `cmd_output.json` — custom command output per device (last 100)
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
- Agent version bump to 1.2.0
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
