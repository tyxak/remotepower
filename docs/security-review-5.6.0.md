# Security review — v5.6.0 "ProvisionMatters"

*Date: 2026-07-01. Authorized review of the maintainer's own codebase.*

This cycle ran a broad pentest of the product: the full committed SAST stack plus
a 5-dimension manual review (auth/RBAC, injection/SSRF, XSS/CSP, secrets/crypto,
the agent root channel + this release's new code). Every reported finding was
hand-verified before fixing. **No Critical / High / Medium issues.** A handful of
Low (mostly defense-in-depth) findings were fixed; the rest were confirmed safe.

## Tooling

| Tool | Result |
| --- | --- |
| **CodeQL** (GitHub default suites, python + javascript) | **0 results** |
| **bandit** (`-b .bandit-baseline.json`) | 0 new High/Medium |
| **gitleaks** | no leaks |
| **semgrep** (security-audit / python / javascript / secrets) | 2 `use-defused-xml` — mitigated false positives (see below) |
| **njsscan** | only string-match false positives |
| **pip-audit** | no dependency CVEs (the server is stdlib-first) |

## Findings fixed (all Low)

1. **Credential leak via webhook-DLQ host redaction.** `_redact_url_to_host()`
   reduced a URL with `urlsplit().netloc`, which keeps `user:pass@` userinfo — so a
   webhook whose secret lives in HTTP basic-auth (rather than the path) was shown
   in the admin DLQ list. Now built from `hostname` (+ port).

2. **Secret-bearing URLs in the "no secrets" diagnostics bundle.** The support
   bundle explicitly pops secret-named-miss URLs but omitted **`healthchecks_url`**
   (the ping UUID is a credential) and **`metrics_push.url`** (may embed basic-auth).
   Both are now popped from the bundle.

3. **`metrics_push.url` returned to non-admins** on `GET /api/config`. Now
   withheld (indicator only) for non-admins, like the webhook URLs.

4. **Read-only roles could perform editorial writes.** `handle_runbook_delete`
   and the CMDB metadata/doc handlers (`handle_cmdb_update`, `handle_cmdb_doc_*`)
   were gated only by `require_auth()`, so a `viewer`/`auditor`/`finance`/`mcp`
   principal could edit CMDB fields or delete runbooks. Added `require_write_role()`
   — admin **or** a role with at least one action permission (a scoped operator);
   permission-based, not a role-string denylist.

5. **`systemctl` argument injection (agent).** Several agent calls passed a
   config-supplied unit name as a positional argument with no `--` end-of-options
   guard, so a unit beginning with `-` could be read as a `systemctl` option (e.g.
   `-H <host>`). Added `--` to all six call sites and the new `systemd_unit` check.
   (Admin-only paths, hence Low — but the canonical guard now blocks it regardless.)

6. **`useradd`/`usermod` argument injection (agent).** Host-config user-management
   passed the username positionally without `--`; now validated against the POSIX
   username pattern and passed after `--`.

7. **RouterOS / OPNsense SSRF (connect-time).** These two REST clients used a bare
   `urlopen` with resolve-time-only SSRF checks and followed redirects — leaving a
   DNS-rebinding window (the live fetch is triggered by any authenticated user, and
   admin-stored creds are then sent to the rebound peer). Both now use a
   connect-time peer-IP guard + no-redirect opener (mirroring the Proxmox/AI/image
   clients). RFC1918/LAN targets stay allowed (these devices live on the LAN).

## Confirmed safe (verified, not changed)

- **XSS / CSP:** clean. `renderMarkdown` escapes the whole input first and emits no
  `<a href>`/raw HTML, so the all-roles-readable **knowledge base** has no stored-XSS
  vector. No inline `on*=`/`style=` in HTML or `innerHTML` strings; no `eval`/`new
  Function`. Every dynamic field in the new pages goes through `escHtml`/`escAttr`.
- **Agent C2 channel:** audit/read-only mode guards every mutating path; the only
  `shell=True` is the by-design, token-authed, audit-gated `exec:` channel; mTLS is
  `CERT_REQUIRED` + `check_hostname` with no insecure escape hatch.
- **Crypto / secrets:** AES-256-GCM DR backups + CMDB vault (PBKDF2 600k), session
  tokens / API keys / device tokens hashed at rest with constant-time compare, all
  security IDs from `secrets.*`. Break-glass two-person rule holds.
- **Injection:** SQL fully parameterized; request-derived paths are
  regex-sanitized / realpath-contained; the file manager confines on the agent.
- **This release's new code** (KB, automation actions, recover events, check
  catalog / `systemd_unit`, site-health): authz correct, inputs bounded, no
  lock-nesting, recover-event match keys present in the alert whitelist.
- **semgrep `use-defused-xml`** (cloud-import, DMARC): both reject `<!DOCTYPE`/
  `<!ENTITY>` before parsing and stock ElementTree disables external entities, so
  XXE / billion-laughs is not reachable.

## Residuals (accepted, low)

- SMTP / LDAP / SNMP outbound to admin-configured internal hosts (internal targets
  are the feature; no HTTP-redirect/metadata-credential primitive).
- `_avatar_path` allows `.` in the filename char class — not exploitable (`/` is
  stripped, fixed `.img` suffix) and stripping it would break dotted usernames'
  avatars.
