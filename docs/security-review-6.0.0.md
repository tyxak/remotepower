# Security review — v6.0.0 "ClarityMatters"

*Date: 2026-07-05. Authorized review of the maintainer's own codebase and
infrastructure.*

This cycle ran a whole-project security pass over the product — not just the
release's changes. It combined the full committed SAST stack, a parallel manual
audit across every recurring vulnerability class (server auth/RBAC, SSRF,
injection, XSS/CSP, secrets/crypto, the agent root channel, data-binding, and
dependencies), a review of both the server and all three agents, and a live
authenticated header/TLS/behaviour review of the maintainer's own running
instance. Every reported finding was hand-verified before fixing.

**No Critical or High issues were found.** Three Medium findings and a set of
Low / defense-in-depth items were fixed before promotion. **Nothing Critical,
High, or Medium ships.**

## Tooling

| Tool | Result |
| --- | --- |
| **CodeQL** (GitHub default suites, python + javascript) | **0 results** |
| **bandit** (`-b .bandit-baseline.json`) | 0 new — 0 High |
| **gitleaks** (git history + working tree) | no leaks |
| **Live header/TLS review** (production instance) | strict CSP (no `unsafe-inline`), HSTS preload, `X-Frame-Options: DENY`, `nosniff`, COOP/CORP `same-origin`, `Permissions-Policy`, CSP reporting — all present |

The public "Code scanning" surface on GitHub stays clean: CodeQL reports zero
open alerts across both languages.

## Findings fixed

### Medium

- **Read-only roles could modify the shared Calendar and Tasks boards.** The six
  create/update/delete handlers for the team calendar and kanban board gated on a
  bare authentication check rather than the write-permission check used
  everywhere else, so a read-only account (viewer / auditor / finance / an MCP
  token) could add, edit or delete shared items. All six now require a role with
  write permission; the read-only *list* endpoints are unchanged. Every mutation
  was already audit-logged.
- **Two stored-value display paths did not escape agent-reported data.** A
  group-id field in the host-configuration editor and file-hash strings in the
  configuration-drift views were interpolated into the page without HTML-escaping,
  while every neighbouring field was escaped. Because the server treats agent
  input as untrusted, a compromised or malicious agent could have returned a
  crafted value that executed script in an operator's browser. Both now use the
  standard escaping helper. (The strict Content-Security-Policy is a second layer
  that already blocks inline script; this closes the source as well.)

### Low / defense-in-depth

- The shared outbound HTTP client for homelab integrations now rejects an
  absolute URL supplied as a request path, so a request can never be retargeted
  away from the validated provider host (no live caller could reach this, but it
  removes the footgun class).
- DNS-provider record and zone identifiers are now URL-quoted as single path
  segments before being placed in an API path.
- A configuration timestamp write was moved under the standard file lock to close
  a lost-update race with concurrent settings saves.

### Documented deployment hardening (by design, opt-in)

Agent self-update verifies a server-supplied SHA-256 by default and can
additionally enforce a **pinned GPG signature** — the strongest protection. That
enforcement is opt-in (it requires pinning the release public key on the host).
Operators running in higher-trust environments should enable signed-update
enforcement; the Windows and macOS agents do not self-update at all.

## Areas verified clean

The manual pass confirmed the product is hardened against every recurring class
it checks for, including: permission-gated writes across the handler surface;
admin checks resolved through the role model (no denylist gaps); no lock-nesting
or storage-backend-blind state gates; SSRF guards (connect-time peer-IP recheck,
no-redirect, blocked metadata/loopback) on every outbound feature, with
attacker-influenceable identifiers reduced to safe URL segments; request bodies
coerced so a non-object body cannot fault a handler; the agent's host reads and
outbound HTTP routed through the safe wrappers, and its file-manager path
handling closed against symlink races; and the external customer-portal perimeter
(session expiry/revocation, allow-listed fields, site-scoped access, rate-limited
magic links). Secrets are withheld from configuration reads (indicators only,
even for admins) and are excluded from the AI/RAG corpus by a substring match on
secret-named fields.

## Transparency

Security matters here, and we want that to be visible. This product is scanned on
every release by CodeQL (the results are public under the repository's Code
scanning tab), and by bandit and gitleaks locally before every push. Each release
gets a whole-project manual audit and a live review of the running instance, and
the outcome is written up in one of these public notes. If you find a security
issue, please report it — see `SECURITY.md`.
