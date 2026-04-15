# Changes from v1.0.0

All changes are additive — the existing data format, API contract, and agent
credential format are fully preserved.

---

## api.py

### Modified functions
| Function | Change |
|---|---|
| `handle_login()` | Calls `maybe_rehash()` to silently upgrade SHA-256 → bcrypt on next login |
| `handle_devices_list()` | Now includes `mac` and `sysinfo` fields in response |
| `handle_device_delete()` | Also purges queued commands for the deleted device |
| `handle_enroll_register()` | Accepts and stores `mac` from agent |
| `handle_heartbeat()` | Stores `sysinfo` and `journal` from agent payload when present; uses `hmac.compare_digest` for token comparison |
| `require_auth()` | Now returns `username` string (was void) |

### New functions
| Function | Description |
|---|---|
| `hash_password()` / `verify_password()` / `maybe_rehash()` | bcrypt with SHA-256 fallback; auto-upgrades on login |
| `fire_webhook()` | POST JSON to configured webhook URL; silent on failure |
| `check_offline_webhooks()` | Runs on every API request; fires `device_offline` / `device_online` events, stores state in `config.json` |
| `handle_reboot()` | Queue `reboot` command (`POST /api/reboot`) |
| `handle_wol()` | Send magic packet via UDP broadcast (`POST /api/wol`) |
| `handle_sysinfo(dev_id)` | Return cached sysinfo + journal for a device (`GET /api/devices/:id/sysinfo`) |
| `handle_monitor_run()` | Ping/TCP/HTTP checks (`GET /api/monitor`) |
| `handle_config_get()` / `handle_config_save()` | Read/write `config.json`: webhook URL, WoL settings, monitor list |
| `handle_users_list()` / `handle_user_create()` / `handle_user_delete()` / `handle_user_passwd()` | Multi-admin CRUD |
| `handle_agent_version()` | Return server-side agent version + SHA-256 (`GET /api/agent/version`) |
| `handle_agent_download()` | Serve agent binary for self-update (`GET /api/agent/download`) |

### New data file
`config.json` — stores: `webhook_url`, `wol_broadcast`, `wol_port`, `monitors[]`, `offline_notified{}`

### Backward compatibility
- `users.json` key is still `password_hash` — existing SHA-256 hashes work; upgraded silently
- `commands.json` still stores plain strings (`'shutdown'`) — agent `resp.get('command')` unchanged
- `devices.json` gains two optional new keys: `mac`, `sysinfo`, `journal` — old entries without them work fine

---

## remotepower-agent

### Modified
| Section | Change |
|---|---|
| `VERSION` | Bumped to `1.1.0` |
| `enroll_interactive()` | Now sends `mac` field via `get_mac()` |
| `execute_command()` | Added `reboot` command → `systemctl reboot` |
| `heartbeat()` | Every 10th poll sends `sysinfo` (uptime, patch info, platform) and `journal` (100 lines); every 60th poll checks for self-update |
| `main()` | Added `update` action for manual update trigger |

### New functions
| Function | Description |
|---|---|
| `get_mac()` | Reads MAC from `/sys/class/net/<iface>/address` via `ip route get` |
| `get_uptime()` | `uptime -p` |
| `get_journal(n)` | `journalctl -n N --no-pager --output=short-iso` |
| `get_patch_info()` | Dry-run update check: apt / dnf / pacman. Nothing is installed. |
| `check_for_update()` | Fetch `/api/agent/version`, compare with `VERSION`, download if newer, verify SHA-256, atomic replace, `systemctl restart` |
| `http_get()` / `http_get_binary()` | GET helpers alongside existing `http_post()` |

### Sysinfo poll cadence
Sysinfo (including `dnf check-update` / `apt --simulate upgrade`) runs every **10th poll**
(~10 minutes at 60s interval) to avoid being spammy on slow package managers.

---

## remotepower-passwd

Rewritten as a proper interactive menu:
- Option 1: Change password (existing user)
- Option 2: Add user (new)
- Option 3: Delete user (protected: cannot delete last admin)
- Option 4: List users (shows hash type: bcrypt vs sha256)

Data format unchanged — still `password_hash` key.

---

## remotepower.conf (Nginx)

Added a separate `location /api/agent/download` block with `fastcgi_read_timeout 60s`
to handle the larger binary payload without timing out.

---

## Deploying the self-update feature

1. Copy the updated agent to the server:
   ```bash
   sudo mkdir -p /var/www/remotepower/agent
   sudo install -m 755 client/remotepower-agent /var/www/remotepower/agent/remotepower-agent
   ```

2. Set the version in config.json:
   ```bash
   sudo python3 -c "
   import json; from pathlib import Path
   p = Path('/var/lib/remotepower/config.json')
   c = json.loads(p.read_text()) if p.exists() else {}
   c['agent_version'] = '1.1.0'
   p.write_text(json.dumps(c, indent=2))
   print('Done')
   "
   ```

3. When you want to push an update, increment `VERSION` in the agent source,
   copy the new binary to `/var/www/remotepower/agent/remotepower-agent`,
   and update `agent_version` in config.json. All running agents will pick it
   up within ~1 hour automatically.
