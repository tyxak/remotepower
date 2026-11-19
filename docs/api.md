# API reference

> **This page is a curated tour of the most-used endpoints, not the full surface.**
> RemotePower exposes **791 paths**. The complete, always-current reference is
> generated from the live route table — browse it interactively at
> **`/swagger.html`**, or fetch the OpenAPI 3.1 document at
> **`/api/openapi.json`**. Everything shipped is in there; this page is hand-written
> and covers the roughly 100 you're likely to reach for.

All authenticated endpoints require: `X-Token: <session_token_or_api_key>`.
Every route is also reachable under the permanent `/api/v1/...` alias.

## Behaviour that applies to every endpoint

- **Request bodies are validated.** A malformed body returns **400** with the
  offending field, before the handler runs.
- **A disabled module 404s its whole API prefix.** Switching a module off under
  Settings → Advanced → Optional modules (Alerts, Tickets, Billing, Knowledge base,
  Compliance, Pentest, AI executor, Autonomy, SSH gateway) makes every route under its prefix return **404** at the
  dispatcher — e.g. all of `/api/tickets/*` with Tickets off. The module is
  off, not merely hidden from the sidebar.
- **Tenant isolation.** Where tenancy is enforced, a host id belonging to another
  tenant returns **404** (not 403 — a 403 would confirm the id exists), and every
  fleet-wide aggregate is filtered to your tenant.
- **A key with a host scope hands out only what it has.** An administrator key that is limited to some groups, tags or sites can create and
  change keys, roles and accounts that stay inside them, and nothing wider: a request for more (a scope of `all`, another kind of scope, a role
  that reaches every host) is a **403** with `code: "beyond_key_scope"`. A key made without a scope gets the scope of the key that made it.
- **Write contention returns a retryable 503**, never a 500. Back off and retry.
- **Conditional GET.** Some read endpoints honour `If-None-Match` and answer **304**
  when nothing changed.

### Hosts
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/devices` | | List enrolled hosts |
| `DELETE` | `/api/devices/:id` | admin | Remove a host |
| `PATCH` | `/api/devices/:id/tags` | admin | Set host tags |
| `PATCH` | `/api/devices/:id/notes` | admin | Set host notes |
| `PATCH` | `/api/devices/:id/group` | admin | Set host group |
| `PATCH` | `/api/devices/:id/poll_interval` | admin | Set poll interval hint |
| `PATCH` | `/api/devices/:id/alert-delay` | admin | Per-host extra grace (minutes) before a device_offline alert (0=default, ≤1440) |
| `GET` | `/api/devices/:id/sysinfo` | | Cached sysinfo + journal |
| `GET` | `/api/devices/:id/capabilities` | | What a Linux agent can see on its host: root or not, container mode, each tool it uses as present, missing, not needed or not available in a container (with the feature that needs it and a fix hint), and the logs the threat sensor can open. `{"reported": false}` until the agent has sent it. See [troubleshooting.md](troubleshooting.md) |
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
| `POST` | `/api/enroll/register` | - | Register host with a PIN or an enrollment token (pass `device_id` for re-enroll) |
| `POST` | `/api/enrollment-tokens` | admin | Make an enrollment token. Body: `expires_in`, `default_group`, `default_tags`, `label`, `allowed_cidrs`, `max_uses` (1 to 1000 hosts, default 1) |
| `GET` | `/api/enrollment-tokens` | admin | List the open tokens: `prefix`, `uses`, `max_uses`, `uses_left`, time left (never the token) |
| `DELETE` | `/api/enrollment-tokens/{prefix}` | admin | Revoke a token by the prefix the list shows |
| `POST` | `/api/heartbeat` | host | Client keepalive + fetch commands |

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
| `GET` | `/api/checks` | | Fleet check matrix (OK/WARN/CRIT/UNKNOWN per host; `?status=critical\|warning`). `?problems=1` adds `problem` (`state`, `alerts_open`, `resolved_by`, `resolved_at`) to each failing check whose host and kind have alerts |
| `GET` | `/api/devices/:id/checks` | | Check list + summary for one host |
| `POST` | `/api/checks/toggle` | admin | Mute/unmute a check on a host (`{device_id, check, enabled}`) |
| `GET` | `/api/checks/custom` | | List custom-check definitions |
| `POST` | `/api/checks/custom` | admin | Add/update a custom check (process/port/file/job/log; host/tag/group target) |
| `POST` | `/api/checks/custom/delete` | admin | Remove a custom check (`{id}`) |
| `GET` | `/api/nav-counts` | | Per-sidebar-group attention counts (offline / monitors-down / critical CVEs) |

### Problems (Alerts, Needs attention and Checks, joined)
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/problems` | | One row per host and kind of problem, with the alerts, Needs attention items and failing checks under it and a `state`: `failing`, `host_clear`, `waiting_for_report`, `resolved_but_failing`, `resolved` or `recovered`. `?state=active\|all\|<state>` (default `active`), `source=alert\|attention\|check`, `device_id=`, `q=`, `days=` (how far back a resolved alert counts; default 7, at most 30), `limit=`, `offset=`. `counts` covers everything the caller may see, before the filters, and carries `active_sources` (the active problems each of `alert`, `attention` and `check` holds). A row names what can be done to it: `open_ids` (the open alerts a resolve closes), `mute_events` (the events a mute covers), `attention[].ignore_key` (what an ignore or snooze needs), `checks[].key` (what a switch-off needs) and `fix` (the playbook a fix opens) |
| `GET` | `/api/problems/history` | | Everything that happened to one problem, newest first: each alert of it raised (and how often it came again), acknowledged and resolved, by whom and how, with the resolve note. `?device_id=&family=` (a row's `device_id` and `family`), `detail=` for a problem with no host, `days=` (default 90, at most 365). Only the alerts the caller may see |

### Users & Auth
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/users` | | List users (with role, MFA state, sign-in source and last sign-in) |
| `POST` | `/api/users` | admin | Create user (pass `role` — a built-in role or any custom role you've defined). A password over 72 bytes is a 400. A key that has a host scope can create only an account whose role stays inside that scope |
| `PATCH` | `/api/users/:name` | admin | Change an account's role. Making someone an administrator asks for the step-up, and a key with a host scope can only move an account to a role inside its scope |
| `DELETE` | `/api/users/:name` | admin | Delete user |
| `POST` | `/api/users/passwd` | | Change a password: your own with `old_password`, or another account's as an administrator who has confirmed their own password in the last ten minutes (`POST /api/auth/step-up`). An API key cannot, so it gets a 403 with `step_up_required`. A password the account used recently is a 400 when `password_history` is set, and more than ten such checks a minute from one caller is a 429. A new password over 72 bytes is a 400 |

### API Keys
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/apikeys` | admin | List API keys |
| `POST` | `/api/apikeys` | admin | Create API key (value shown once). Pass `scope` (`{"type": "groups", "values": ["prod"]}`; `tags` and `sites` work the same) to limit it to part of the fleet. A key that has a scope creates only keys inside its own |
| `PATCH` | `/api/apikeys/:id` | admin | Change a key's name, role, scope, source-IP allowlist, expiry or rate limit. The secret stays. A key that has a scope cannot widen or clear its own, or change a key that reaches more than it does |
| `POST` | `/api/apikeys/:id/rotate` | admin | Make a replacement key with the same settings and turn the old one off (value shown once) |
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
| `POST` | `/api/config` | admin | Save config. `password_history` (0 to 24) and `password_max_age_days` (0 to 3650) are whole numbers, 0 is off, and a value outside the range is a 400 that saves none of the body |
| `GET` | `/api/agent/version` | - | Agent version + SHA-256 |
| `GET` | `/api/version` | | Server version + GitHub check |
| `GET` | `/api/export` | admin | Download ZIP backup (redacted: no API key values, no secrets in the settings, no account credentials). With tenant isolation on, the platform operator only |
| `GET` | `/api/digest` | | Summary (total, online, patches, recent cmds) |
| `GET` | `/api/patch-report` | | Full patch report (JSON) |
| `GET` | `/api/patch-report/csv` | | Patch report as CSV (`?group=X&device_id=Y`) |
| `GET` | `/api/patch-report/xml` | | Patch report as XML (`?group=X&device_id=Y`) |
| `GET` | `/api/patch-report/device/:id` | | Per-host patch detail |
| `DELETE` | `/api/history` | admin | Clear command history |
| `GET` | `/api/audit-log` | admin/auditor | Security audit log |
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
| `GET` | `/api/saml/available` | any | Is SAML SSO configured (boolean only) |
| `GET` | `/api/saml/metadata` | - | SP metadata XML for your IdP |
| `GET` | `/api/audit-log/verify` | admin/auditor | Walk the audit hash-chain; report tampering |
| `GET` | `/api/audit-log/archive` | admin/auditor | Download the gzipped archive of evicted audit entries |
| `GET` | `/api/diagnostics` | admin | Download a JSON support bundle (versions, backend, fleet, cadence-job staleness, audit/chain status, optional-dep presence; secrets scrubbed) |
| `GET` | `/api/security-posture` | admin/auditor | Graded secure-defaults self-check (each warn names its fix tab) |
| `GET` | `/api/scans` | scan | List security scans |
| `POST` | `/api/scans` | scan | Queue a scan (tool, profile, intensity, target) |
| `GET` | `/api/scans/:id` | scan | Scan detail + findings |
| `DELETE` | `/api/scans/:id` | scan | Delete a scan record |
| `POST` | `/api/scans/clear` | scan | Clear finished scans |
| `GET` | `/api/scan-targets` | scan | Registered non-enrolled scan targets |
| `POST` | `/api/scan-targets` | admin | Register a target (returns ownership proof) |
| `POST` | `/api/scan-targets/:id/verify` | admin | Verify ownership (DNS TXT or /.well-known) |
| `DELETE` | `/api/scan-targets/:id` | admin | Remove a scan target |
| `GET` | `/api/scan-schedules` | scan | List scheduled scans |
| `POST` | `/api/scan-schedules` | scan | Create a recurring (cron) scan |
| `POST` | `/api/scan-schedules/:id/run` | scan | Run a scheduled scan now |
| `DELETE` | `/api/scan-schedules/:id` | scan | Delete a schedule |

### Fleet & server control (v5.0.0)
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/devices/bulk-delete` | admin | Delete many hosts by id list |
| `POST` | `/api/devices/bulk-tags` | admin | Add and/or remove tags across a selection |
| `PATCH` | `/api/devices/:id/decommissioned` | admin | Retire/restore an asset (forces `monitored=false`) |
| `GET` | `/api/board` | | NOC status-board rollups (`?by=group\|site\|tag`) |
| `GET`/`POST` | `/api/business-services` | get any / create admin | Business services with the live state of each part *(7.4.9)* |
| `GET`/`PUT`/`DELETE` | `/api/business-services/:id` | get any / change admin | One service with its history and 30-day availability *(7.4.9)* |
| `GET` | `/api/business-services/impact` | | The services that depend on a host (`?device_id=`) *(7.4.9)* |
| `POST` | `/api/alerts/:id/assign` | ack policy | Assign an alert to an account, or take it back with an empty `user` *(7.4.9)* |
| `GET` | `/api/network-metrics` | | Per-host RX/TX throughput (`?by=fleet\|group\|tag\|site`) |
| `GET` | `/api/network-map` | | Topology; supports `?site=&group=&tag=` scope filter |
| `GET`/`POST` | `/api/maintenance-mode` | get any / set admin | Read or toggle runtime maintenance mode |
| `POST` | `/api/server/self-update` | admin | Run the configured update script |
| `POST` | `/api/self/backup-encrypt` | admin | Encrypt existing plaintext backup archives |
| `GET`/`POST`/`DELETE` | `/api/webhook/dlq` (+ `/retry`) | admin | Webhook dead-letter queue: list / retry / clear |
| `POST` | `/api/webhook/replay` | admin | Replay past fleet events to a destination |
| `GET` | `/api/version` | | Current vs latest release + update-available |

### Ingest, key custody & liveness (v6.3.1–v6.4.1)
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/health` | - | Unauthenticated liveness probe. Returns `{"status":"ok"}` and **no version** *(v6.4.1)* — for orchestrators and load balancers |
| `GET` | `/api/security/advisory` | | "What to fix first" — the prioritized cross-layer list; `?scope=` for fleet / group / tag / host. See [security-advisory.md](security-advisory.md) |
| `POST` | `/api/security/advisory/brief` | | Server-side-redacted brief for the optional AI ordering pass (titles/severities/counts only — never evidence) |
| `POST` | `/api/devices/:id/snmp/walk` | admin | SNMP **OID browser** — walk any subtree with the host's stored credentials; audited, capped per walk *(v6.4.1)*. See [monitors.md](monitors.md) |
| `POST` | `/api/devices/:id` | | Save host settings from the drawer, including the display **name** *(rename, v6.4.1)* |
| `GET` | `/api/devices/:id/settings` | admin | What the drawer's Host settings form edits, under the names the save takes: `watched_services`, `watched_files`, `log_watch`, `cmd_allowlist`, `reachability`, `manual_status`, `ssh_user`, `ssh_port` and `quarantined`. The host list does not carry them *(8.0.0)* |
| `GET` | `/api/devices/:id/flows` | | NetFlow/IPFIX top talkers, conversations and protocol breakdown. See [flow.md](flow.md) |
| `POST` | `/api/flow/in/:token` | token | Flow ingest from the `remotepower-flowd` receiver |
| `GET`/`POST` | `/api/kmip/*` | admin | The KMIP key server — status, config, clients (issue / revoke / re-issue / delete), key inventory, activity log, export / import / reset. See [kmip.md](kmip.md) *(v6.4.1)* |

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
