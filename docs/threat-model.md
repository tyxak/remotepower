# Threat model (STRIDE)

A structured inventory of RemotePower's trust boundaries and the concrete
mitigation each one relies on, organized by [STRIDE](https://en.wikipedia.org/wiki/STRIDE_(security))
(Spoofing, Tampering, Repudiation, Information disclosure, Denial of service,
Elevation of privilege). This complements [security.md](security.md) — that
doc is a narrative list of controls; this one is the structured threat/
mitigation matrix an auditor or a new contributor would want, organized by
attacker goal rather than by feature. Every mitigation cited here is a real,
shipped control — this is not an aspirational design doc.

## Scope and actors

- **Operator (human)** — logs in with a password (+ optional TOTP/WebAuthn),
  holds a role (`admin`, `viewer`, `auditor`, `finance`, or a custom role with
  a granular permission set and an optional device-group scope).
- **API key / service account** — a bearer token with its own role, optional
  device scope, optional per-key rate limit and source-IP allowlist. As of
  v6.1.1 also carries its own `tenant_id`, set at creation from the creating
  admin's real tenant (see the Elevation of Privilege section — this was a
  real gap, fixed this session).
- **MCP / AI client** — an API key with the `mcp` role, additionally gated by
  a per-action allowlist and (for write actions against a device flagged
  `require_confirmation`) a human-approved confirmation queue.
- **Agent** — a per-device bearer token minted at enrollment; optionally
  upgraded to mutual-TLS (a CA-verified client certificate pinned per
  device).
- **Relay satellite** — forwards agents' heartbeats from a segmented network;
  authenticates to the server with its own token.
- **External IdP** (OIDC/SAML/LDAP) — federated login; group→role mapping is
  admin-configured.
- **Trust boundary**: everything left of `gunicorn + Flask (wsgi.py)` in
  [architecture.md](architecture.md)'s diagram is untrusted input. Nginx
  terminates TLS; the app process is the first thing that parses
  attacker-controlled bytes.

## Spoofing (impersonating a legitimate identity)

| Threat | Mitigation |
|---|---|
| Stolen session token replayed from another host | Idle/sliding session timeout (`idle_timeout_minutes`), absolute TTL, a configurable max-sessions-per-user cap enforced at *validation* time (not just mint time), session list + revoke UI. Tokens are hashed at rest (SHA-256 keyed `tokens.json`) so a leaked datastore read yields no usable session. |
| Stolen/leaked API key reused indefinitely | Per-key expiry (`expires_at`), an optional `rotate_after_days` policy surfaced as a dashboard reminder, guided one-click rotation (`POST /api/apikeys/{id}/rotate`), per-key rate limiting and source-IP allowlist. Keys are stored as a SHA-256 hash, never plaintext. |
| Agent impersonation (forged heartbeat) | Bearer token per device at minimum; optional mutual TLS with a CA-verified, per-device-pinned client certificate for a stronger guarantee than a bearer secret alone. Agent binary integrity is separately attested (below, Tampering). |
| SSO/IdP response spoofing | Standard OIDC/SAML validation (issuer, audience, signature) via the IdP library; `sso_only` mode can mandate federated login, with an explicit `local_login: true` break-glass exemption on a specific account so enabling it can never fully lock everyone out. |
| Login brute force | Per-IP and per-account throttling with configurable thresholds; a `brute_force_detected` event/alert with active-attempt tracking (`_bf_active`) surfaced per device. |
| CSRF-style cross-origin request forgery | The API is bearer-token authenticated (no ambient cookie auth for state-changing calls), so a cross-origin page cannot forge a request without already possessing the token. |

## Tampering (unauthorized modification of data or code in transit/at rest)

| Threat | Mitigation |
|---|---|
| Audit log entries altered or deleted after the fact | Each `audit_log()` entry is hash-chained (`_hash` links to the previous entry's hash, HMAC-keyed, with automatic key-generation rotation — `audit_hmac_auto_rotate_days`); a chain break is detectable. An optional WORM forward sink (`audit_worm_path`) appends every entry to an external file the app itself never rotates or prunes, for a copy the operator can harden with `chattr +a` or an object-lock-backed mount, independent of the live (bounded, rotated) log. |
| Config or firewall rules tampered with via the API | Every firewall/cron/config-file edit path is validated against a strict character allowlist, routed through the audited, permission-gated command queue, and skipped on quarantined/audit-mode hosts — there is no path from the UI to a command the operator couldn't already run directly with that permission. Config changes are audit-logged with the *names* of changed keys (never values, so secrets can't leak into the audit trail). |
| Agent binary tampered with (supply-chain / on-host) | Agent self-update requires a validly-signed release (the agent refuses to apply an update that isn't signed by the operator's key); each agent additionally reports its own binary hash, attested against the canonical published build, flagging a mismatch (tampering, corruption, or a partial update) on the current version. |
| Man-in-the-middle on agent↔server or agent↔satellite | TLS end-to-end (HTTPS), with every hop refusing TLS below 1.2; agents verify the server's certificate (`CERT_REQUIRED` + hostname check), with an internal CA addable via `RP_CA_BUNDLE` *in addition to* the system trust store, never as a replacement. |
| CSP bypass injecting attacker script into the dashboard | `script-src 'self'; style-src 'self'` with **no** `unsafe-inline`, verified live — zero inline `on*=` handlers, inline `style=` attributes, or inline `<script>` anywhere, in static HTML or in JS-built `innerHTML`. `/api/csp-report` logs violations for regression detection. |
| SSRF via an operator-configured outbound integration (Proxmox, AI provider, homelab connector, DNS/webhook target) | A shared pre-flight (`_url_targets_local_or_meta`) blocks loopback/link-local/metadata targets before the request is made; a connect-time peer-IP recheck (`tls_monitor._addr_blocked` and the equivalent for `_SSRFIntegrationClient`) closes the DNS-rebind TOCTOU window by connecting to the specific vetted IP literal, not the hostname; outbound calls are no-redirect so a 3xx can't replay a token/API-key to a rebound host. |

## Repudiation (denying an action was taken)

| Threat | Mitigation |
|---|---|
| An admin denies having performed a destructive or sensitive action | Every mutating handler audit-logs actor, source IP, user agent, and action detail; the hash chain (above) makes a post-hoc edit to the trail itself detectable. MCP/AI-initiated actions additionally record the originating AI host and the natural-language prompt that led to the action. |
| A break-glass credential reveal is disputed | Two-person rule: the requester and the approving admin are both recorded, and the full request/approval/reveal exchange is immutably audit-logged and raises a `vault_break_glass` alert — no single account can both request and approve. |
| A litigation hold's start/end is disputed | `litigation_hold` config carries `started_at`/`started_by`/`reason`, and both enabling and disabling are independently audit-logged (lifting a hold is treated as equally consequential as starting one). |

## Information disclosure (exposing data to an unauthorized party)

| Threat | Mitigation |
|---|---|
| CMDB credentials (passwords, IPMI, service-account secrets) read by an unauthorized party | AES-GCM encryption with a PBKDF2-derived key; the vault passphrase is never persisted server-side, so a stolen datastore alone yields no plaintext. Every reveal requires the vault key on that specific request (not just a valid session) and is audit-logged with actor/IP/asset/label. |
| A tenant sees another tenant's devices/data when multi-tenancy is enabled | App-layer scoping (`_tenant_gate`/`_scope_filter_devices`) confines a tenant admin to their own tenant's devices; an optional Postgres row-level-security layer (`tenancy_rls`) enforces the same boundary at the database level as defense-in-depth. `GET /api/tenancy/readiness` gives an operator a static-but-accurate report of exactly which stores are (and, just as importantly, are **not**) tenant-isolated, so enabling tenancy never implies more coverage than actually exists. |
| A config field holding a secret (webhook URL, OIDC client secret, AI API key) is echoed back on a plain `GET` | `handle_config_get` redacts every secret-named field to a `*_set`/`*_configured` boolean for everyone, admins included — re-entry is required to change it, it is never echoed back. A recursive scrubber additionally catches any *newly added* secret-named key by substring match (`password`, `token`, `api_key`, `secret`, `community`, `bearer`, `webhook`, `vault`, `cred`, …), not an exact, easily-outdated name list. |
| An operator-authored free-form field (a CMDB note, a custom facet) containing a pasted secret ends up in the AI/RAG embedding store, and from there potentially a cloud embedding provider | Every RAG corpus builder filters secret-*named* keys by the same case-insensitive substring match before the text is embedded, applied uniformly across every free-form source, not a source-by-source allowlist that could drift. |
| An API key created by a tenant's admin turns out to have cross-tenant (superadmin-equivalent) visibility | **Fixed this session, a real bypass**: an API key's tenant used to be resolved via its free-text `user` display field (which defaults to the literal string `'api'`, matching no real account) — falling through to the default tenant, which made the key superadmin-equivalent regardless of who created it. The key now carries its own `tenant_id`, stamped from the creating admin's real tenant at mint time, and every tenant-boundary check resolves through that. See `_caller_effective_tenant` in `api.py`. |
| Secrets in a shipped release tarball | The release build excludes `.claude/`, internal docs (`*-internal.md`), `.git`, design assets, deploy scripts, and encrypted/credential files by an explicit exclude list, verified on every release ("tarball leak-check"). |

## Denial of service (degrading availability)

| Threat | Mitigation |
|---|---|
| A runaway or leaked API key exhausts server capacity | Per-key rate limiting (`rate_limit`, requests/minute), enforced independently of the per-IP login throttle, so one key's misbehavior can't starve every other caller. |
| Unbounded growth of an append-only store (audit log, history, alerts) exhausts disk | Every append-log has both a count cap and an age-based retention sweep (independently configurable, whichever fires first); litigation hold suspends the age-based half deliberately (a legal-preservation feature, not a DoS gap) but the count caps remain in force, so live-log size is still bounded even during a hold. |
| A malformed or oversized request body crashes a handler | `get_json_obj()` coerces any non-dict top-level JSON (an array, `null`, a bare string) to `{}` instead of raising into the ~hundreds of `body.get(...)` call sites; string/list fields are length- and count-capped throughout (`_sanitize_str`, per-field list-size limits). |
| A single scheduled sweep (patch/rollout/backup) run against the whole fleet at once saturates the network or the agents | Ringed rollouts (canary → pilot → broad, each ring health-gated before the next fires); maintenance windows suppress alert noise during planned work; per-device poll-interval tuning. |

## Elevation of privilege (gaining more access than granted)

| Threat | Mitigation |
|---|---|
| A read-only role (viewer/mcp/auditor/finance) reaches a state-mutating handler gated only by `require_auth()` | `require_write_role()` — admin OR a role holding at least one action permission — is the correct gate for any mutating handler; a bare `require_auth()` on a write path is a recurring bug class this project actively greps for on every release sweep. |
| A custom operator role (neither literally `'admin'` nor `'viewer'`) slips through a denylist-style role check | Every admin gate resolves the role record (`_resolve_role(role).get('admin')`) rather than string-matching against `('viewer', 'mcp')` — a custom role is correctly `admin: False` by construction, closing the class of bug where a denylist check silently treats "not a known non-admin role" as "must be admin". |
| A hijacked admin session is used to quietly mint a backdoor admin account, or promote an existing low-privilege account to admin | **Step-up re-authentication** (added this session): `POST /api/auth/step-up` re-verifies the caller's own password or TOTP and stamps the session with a short-lived (10-minute) freshness marker; `require_step_up()` gates the two clearest privilege-escalation actions (creating a new admin account, promoting an existing user to admin) on that fresh stamp, on top of the existing admin-role check. Demotions and lateral role moves are unaffected — the friction is scoped to the actual escalation case. |
| A tenant admin escalates to platform-operator (superadmin) scope | `require_superadmin_auth()` gates `/api/tenants*`; a tenant-scoped admin passing the plain admin role check is explicitly insufficient there (a tenant admin could otherwise move itself into the default tenant and become a de facto superadmin). |
| An MCP/AI client executes a write action a human never approved | The MCP action allowlist is opt-in per action; any write against a device flagged `require_confirmation` (the default) queues for human approval instead of executing immediately, visible in the pending-confirmations UI with the originating AI host and prompt attached. |
| A CMDB vault operation is performed with a stale/wrong key, or the vault key itself is guessed | `verify_key`/`VaultKeyError`/`VaultLockedError` distinguish "not configured" / "locked" / "wrong key" (400/401/403 respectively) rather than a single ambiguous failure, and the vault key is required per-request, not cached in the session. |

## Maintaining this doc

Update the relevant row (or add one) whenever a security-relevant control
lands or changes — the `docs/security-review-<version>.md` release write-ups
are the detailed, point-in-time record of *what changed and why*; this doc
is the durable, always-current *what protects against what* reference. If a
row's cited mechanism is renamed or removed, fix the row in the same change
— a stale citation here is worse than no citation, since it implies a
protection that no longer exists.
