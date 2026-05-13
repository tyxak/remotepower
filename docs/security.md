# Security notes

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

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
