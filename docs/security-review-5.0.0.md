# Security review — v5.0.0 "CTRLMatters"

RemotePower is reviewed for security on every release. This document summarises
the v5.0.0 pass. The bar we hold ourselves to is simple and explicit:

> **No Critical, High, or Medium severity finding ships.** Anything that could be
> exploited is fixed before release, on both the server and the agent.

## Scope

A whole-project review — not just the new code — covering:

- **Server** (`api.py` and its sibling modules: backup encryption, RAG/AI, CVE
  scanner, integrations, DNS, resolver health, IP reputation, storage backends).
- **Agent** (Linux/Windows/macOS collectors, command execution, self-update,
  containerized mode).
- **Frontend** (Content-Security-Policy compliance, output escaping / XSS,
  event dispatch).

The new attack surface this release received focused attention:

- **Mutual-TLS agent authentication** — optional fleet-wide enforcement plus a
  per-device pinned client-certificate fingerprint.
- **At-rest backup encryption** — AES-256-GCM with a passphrase taken only from
  the environment.
- **Two-person "break-glass" approval** for revealing stored credentials.
- **Per-API-key rate limits**, a **webhook dead-letter queue** with replay, a
  runtime **maintenance mode**, and a server **disk-space watchdog**.

## Method

The code was audited by hand across the axes that matter for this codebase —
authentication / RBAC, command and argument injection, SSRF, alert/lock
integrity, secret handling, and the containerized-agent host boundary — and
exercised with the static and dynamic tooling we use every cycle: **bandit,
semgrep, gitleaks, njsscan, nuclei and pip-audit**, plus manual probing against
a live instance.

## Result

**No Critical, High, or Medium findings.** The release bar is met.

The new control-plane features are safe by construction:

- **Mutual-TLS headers cannot be forged.** The verified client-certificate
  identity is taken from server-set request parameters that the reverse proxy
  overwrites on every request, so a client cannot inject its own "verified"
  header. When enforcement is on and a device has a pinned fingerprint, the
  presented certificate must match it (constant-time compare), binding a
  certificate to a single host.
- **Backup encryption** uses a fresh random salt and nonce per backup, an
  authenticated GCM tag verified before any plaintext is written, and a
  passphrase that is never persisted to the data directory the backup protects.
- **Break-glass** enforces a genuine two-person rule: the requester cannot
  approve their own reveal, and every reveal is audit-logged.
- **Webhook replay** re-dispatches only the exact stored destination — it does
  not accept an attacker-chosen URL, so it adds no SSRF surface.

## Hardening applied this cycle

Small, defence-in-depth improvements made during the review (none rose to a
shipped vulnerability):

- The backup decryptor now **bounds the key-derivation iteration count** read
  from a file header, so a crafted or corrupt header cannot pin a CPU on restore.
- The macOS agent **tightens its data directory to owner-only** (the credential
  file was already `0600`).
- The webhook dead-letter retry path now **persists the per-entry attempt
  counter** correctly.
- Request handlers **coerce a malformed top-level JSON body** to an empty object
  instead of returning a server error.

## Follow-up sweep (post-release hardening)

A second whole-project pass — six parallel audit streams (binding, bug-hunt,
UI, performance, localization, docs) plus a live, authorized probe of a running
instance and the usual SAST tooling (Bandit, Semgrep, gitleaks) — produced no
Critical, High, or Medium findings. The items it did surface were fixed:

- **Legacy webhook URL no longer returned by the config API.** Slack / Discord /
  Teams webhook URLs embed a secret token in their path, so the URL *is* a
  credential. The newer multi-webhook destinations were already redacted, but the
  legacy single `webhook_url` field was still returned to admin callers of
  `GET /api/config`. It is now withheld from everyone — the response carries only
  a `webhook_configured` boolean, and an admin re-enters the URL to change it
  (the same pattern used for the AI provider key). *(Low — admin-gated, but a
  reusable secret should not travel in a response body. If you used the legacy
  field, rotate that webhook once after upgrading.)*
- **Trend/history writes are durable on the SQLite backend.** Per-disk SMART,
  per-GPU and hottest-temperature trend samples were being written from inside an
  outer table lock; because the SQLite backend shares one connection per data
  directory, that nested transaction could be rolled back and the sample lost.
  The samples are now captured under the lock and written after it commits.
- The live probe confirmed the standing posture below end-to-end: a strict CSP
  with no `unsafe-inline`, HSTS with preload, `frame-ancestors 'none'`,
  unauthenticated API calls rejected, TLS 1.3, and no secrets in error responses.

## Standing posture

CSP remains fully migrated (`script-src 'self'; style-src 'self'`, no
`unsafe-inline`); there are no inline event handlers or inline styles. Secrets
are redacted from configuration reads and never logged. Outbound features keep
their SSRF preflight-and-connect-time guards. The agent's command execution is
admin-authenticated, audited, and can be disabled per host with read-only audit
mode.
