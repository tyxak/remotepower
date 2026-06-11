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
| `GET` | `/api/monitor` | | Run ping/TCP/HTTP/DNS/ICMP/DB checks |
| `GET` | `/api/monitor/history?label=X` | | Check history for a target |

### Checks (CheckMK-style per-host health) — v4.1.0
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/checks` | | Fleet check matrix (OK/WARN/CRIT/UNKNOWN per host; `?status=critical\|warning`) |
| `GET` | `/api/devices/:id/checks` | | Check list + summary for one host |
| `POST` | `/api/checks/toggle` | admin | Mute/unmute a check on a host (`{device_id, check, enabled}`) |
| `GET` | `/api/checks/custom` | | List custom-check definitions |
| `POST` | `/api/checks/custom` | admin | Add/update a custom check (process/port/file/job/log; host/tag/group target) |
| `POST` | `/api/checks/custom/delete` | admin | Remove a custom check (`{id}`) |
| `GET` | `/api/nav-counts` | | Per-sidebar-group attention counts (offline / monitors-down / critical CVEs) |

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
| `GET` | `/api/patch-report/device/:id` | | Per-device patch detail |
| `DELETE` | `/api/history` | admin | Clear command history |
| `GET` | `/api/audit-log` | admin | Security audit log |
| `DELETE` | `/api/audit-log` | admin | Clear audit log |
| `POST` | `/api/sessions/revoke` | admin | Revoke user sessions |
| `POST` | `/api/totp/setup` | | Generate TOTP secret for 2FA |
| `POST` | `/api/totp/confirm` | | Confirm & enable 2FA |
| `POST` | `/api/totp/disable` | | Disable 2FA (requires password) |
| `GET` | `/api/totp/status` | | Check if 2FA is enabled |

### Security (v4.2.0)
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/webauthn/available` | | Is the passkey feature available + enabled |
| `POST` | `/api/webauthn/register/begin` | | Start passkey registration (returns options) |
| `POST` | `/api/webauthn/register/complete` | | Finish passkey registration |
| `GET` | `/api/webauthn/credentials` | | List your registered passkeys |
| `DELETE` | `/api/webauthn/credentials/:id` | | Remove one of your passkeys |
| `POST` | `/api/webauthn/login/begin` | - | Start a passkey sign-in (rate-limited) |
| `POST` | `/api/webauthn/login/complete` | - | Finish a passkey sign-in → session token |
| `GET` | `/api/saml/available` | - | Is SAML SSO configured (boolean only) |
| `GET` | `/api/saml/metadata` | - | SP metadata XML for your IdP |
| `GET` | `/api/audit-log/verify` | admin | Walk the audit hash-chain; report tampering |
| `GET` | `/api/security-posture` | admin | Graded secure-defaults self-check |
| `GET` | `/api/scans` | scan | List security scans |
| `POST` | `/api/scans` | admin | Queue a scan (tool, profile, intensity, target) |
| `GET` | `/api/scans/:id` | scan | Scan detail + findings |
| `DELETE` | `/api/scans/:id` | admin | Delete a scan record |
| `POST` | `/api/scans/clear` | admin | Clear finished scans |
| `GET` | `/api/scan-targets` | scan | Registered non-enrolled scan targets |
| `POST` | `/api/scan-targets` | admin | Register a target (returns ownership proof) |
| `POST` | `/api/scan-targets/:id/verify` | admin | Verify ownership (DNS TXT or /.well-known) |
| `DELETE` | `/api/scan-targets/:id` | admin | Remove a scan target |
| `GET` | `/api/scan-schedules` | scan | List scheduled scans |
| `POST` | `/api/scan-schedules` | admin | Create a recurring (cron) scan |
| `POST` | `/api/scan-schedules/:id/run` | admin | Run a scheduled scan now |
| `DELETE` | `/api/scan-schedules/:id` | admin | Delete a schedule |

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
