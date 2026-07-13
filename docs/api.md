# API reference

> **This page is a curated tour of the most-used endpoints, not the full surface.**
> RemotePower exposes **576 paths**. The complete, always-current reference is
> generated from the live route table — browse it interactively at
> **`/swagger.html`**, or fetch the OpenAPI 3.1 document at
> **`/api/openapi.json`**. Anything shipped is in there; this page is hand-written
> and covers roughly the first ninety you're likely to reach for.

All authenticated endpoints require: `X-Token: <session_token_or_api_key>`.
Every route is also reachable under the permanent `/api/v1/...` alias.

## Behaviour that applies to every endpoint

- **Request bodies are validated.** A malformed body returns **400** with the
  offending field, before the handler runs.
- **A disabled module 404s its whole API prefix.** Switching a module off under
  Settings → Advanced → Optional modules (Alerts, Tickets, Billing, Knowledge base,
  Compliance, Pentest) makes every route under its prefix return **404** at the
  dispatcher — e.g. all of `/api/tickets/*` with Tickets off. The module is
  genuinely off, not merely hidden from the sidebar.
- **Tenant isolation.** Where tenancy is enforced, a device id belonging to another
  tenant returns **404** (not 403 — a 403 would confirm the id exists), and every
  fleet-wide aggregate is filtered to your tenant.
- **Write contention returns a retryable 503**, never a 500. Back off and retry.
- **Conditional GET.** Some read endpoints honour `If-None-Match` and answer **304**
  when nothing changed.

### Devices
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/devices` | | List enrolled devices |
| `DELETE` | `/api/devices/:id` | admin | Remove a device |
| `PATCH` | `/api/devices/:id/tags` | admin | Set device tags |
| `PATCH` | `/api/devices/:id/notes` | admin | Set device notes |
| `PATCH` | `/api/devices/:id/group` | admin | Set device group |
| `PATCH` | `/api/devices/:id/poll_interval` | admin | Set poll interval hint |
| `PATCH` | `/api/devices/:id/alert-delay` | admin | Per-device extra grace (minutes) before a device_offline alert (0=default, ≤1440) |
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
| `POST` | `/api/users` | admin | Create user (pass `role` — a built-in role or any custom role you've defined) |
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
| `GET` | `/api/audit-log/archive` | admin | Download the gzipped archive of evicted audit entries |
| `GET` | `/api/diagnostics` | admin | Download a JSON support bundle (versions, backend, fleet, cadence-job staleness, audit/chain status, optional-dep presence; secrets scrubbed) |
| `GET` | `/api/security-posture` | admin | Graded secure-defaults self-check (each warn names its fix tab) |
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

### Fleet & server control (v5.0.0)
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/devices/bulk-delete` | admin | Delete many devices by id list |
| `POST` | `/api/devices/bulk-tags` | admin | Add and/or remove tags across a selection |
| `PATCH` | `/api/devices/:id/decommissioned` | admin | Retire/restore an asset (forces `monitored=false`) |
| `GET` | `/api/board` | | NOC status-board rollups (`?by=group\|site\|tag`) |
| `GET` | `/api/network-metrics` | | Per-device RX/TX throughput (`?by=fleet\|group\|tag\|site`) |
| `GET` | `/api/network-map` | | Topology; supports `?site=&group=&tag=` scope filter |
| `GET`/`POST` | `/api/maintenance-mode` | get any / set admin | Read or toggle runtime maintenance mode |
| `POST` | `/api/server/self-update` | admin | Run the configured update script |
| `POST` | `/api/self/backup-encrypt` | admin | Encrypt existing plaintext backup archives |
| `GET`/`POST`/`DELETE` | `/api/webhook/dlq` (+ `/retry`) | admin | Webhook dead-letter queue: list / retry / clear |
| `POST` | `/api/webhook/replay` | admin | Replay past fleet events to a destination |
| `GET` | `/api/version` | | Current vs latest release + update-available |

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
