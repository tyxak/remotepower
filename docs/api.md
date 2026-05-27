# API reference

All authenticated endpoints require: `X-Token: <session_token_or_api_key>`

### Devices
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/devices` | | List enrolled devices |
| `DELETE` | `/api/devices/:id` | admin | Remove a device |
| `PATCH` | `/api/devices/:id/tags` | admin | Set device tags |
| `PATCH` | `/api/devices/:id/notes` | admin | Set device notes |
| `PATCH` | `/api/devices/:id/group` | admin | Set device group |
| `PATCH` | `/api/devices/:id/poll_interval` | admin | Set poll interval hint |
| `GET` | `/api/devices/:id/sysinfo` | | Cached sysinfo + journal |
| `GET` | `/api/devices/:id/uptime` | | Uptime event history |
| `GET` | `/api/devices/:id/output` | | Custom command output |
| `GET` | `/api/devices/:id/metrics` | | CPU/RAM/disk time-series |
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
| `GET` | `/api/schedule` | | List scheduled jobs |
| `POST` | `/api/schedule` | admin | Add job (`run_at` or `cron`) |
| `DELETE` | `/api/schedule/:id` | admin | Cancel scheduled job |

### Monitor
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/monitor` | | Run ping/TCP/HTTP checks |
| `GET` | `/api/monitor/history?label=X` | | Check history for a target |

### Users & Auth
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/users` | | List admin users (with role) |
| `POST` | `/api/users` | admin | Create user (pass `role`: admin\|viewer) |
| `DELETE` | `/api/users/:name` | admin | Delete user |
| `POST` | `/api/users/passwd` | | Change password |

### API Keys
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/apikeys` | admin | List API keys |
| `POST` | `/api/apikeys` | admin | Create API key (value shown once) |
| `DELETE` | `/api/apikeys/:id` | admin | Delete API key |

### Command Library
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/cmd-library` | | List command snippets |
| `POST` | `/api/cmd-library` | admin | Add command snippet |
| `DELETE` | `/api/cmd-library/:id` | admin | Delete command snippet |

### Misc
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/history` | | Command history log |
| `GET` | `/api/config` | | Get config |
| `POST` | `/api/config` | admin | Save config |
| `GET` | `/api/agent/version` | - | Agent version + SHA-256 |
| `GET` | `/api/version` | | Server version + GitHub check |
| `GET` | `/api/export` | admin | Download ZIP backup |
| `GET` | `/api/digest` | | Summary (total, online, patches, recent cmds) |
| `GET` | `/api/patch-report` | | Full patch report (JSON) |
| `GET` | `/api/patch-report/csv` | | Patch report as CSV (`?group=X&device_id=Y`) |
| `GET` | `/api/patch-report/xml` | | Patch report as XML (`?group=X&device_id=Y`) |
| `GET` | `/api/patch-report/pdf` | | Patch report as PDF (`?group=X&device_id=Y`) |
| `GET` | `/api/patch-report/device/:id` | | Per-device patch detail |
| `DELETE` | `/api/history` | admin | Clear command history |
| `GET` | `/api/audit-log` | admin | Security audit log |
| `DELETE` | `/api/audit-log` | admin | Clear audit log |
| `POST` | `/api/sessions/revoke` | admin | Revoke user sessions |
| `POST` | `/api/totp/setup` | | Generate TOTP secret for 2FA |
| `POST` | `/api/totp/confirm` | | Confirm & enable 2FA |
| `POST` | `/api/totp/disable` | | Disable 2FA (requires password) |
| `GET` | `/api/totp/status` | | Check if 2FA is enabled |

---

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
