# Changelog
 
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
