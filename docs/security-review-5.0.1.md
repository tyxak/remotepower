# Security review — v5.0.1 "TemperMatters"

RemotePower holds every release to a simple bar: **no Critical, High, or Medium
finding ships, and nothing exploitable ships.** This is the record of the
whole-project server + agent security review for v5.0.1, so you can see exactly
what was checked, what was found, and how it was handled. Security matters here,
and we want that to be visible.

## How it was reviewed

- **Manual code audit** of the full server (`server/cgi-bin/`, ~67k lines) and
  all three agents (Linux/Windows/macOS), covering the OWASP-style classes:
  injection (shell/SQL/template), SSRF, path traversal, authn/authz & IDOR,
  secret handling, XSS/XXE, crypto, and the project's own recurring-bug classes.
- **Static analysis (SAST):** Bandit (Python), gitleaks (secret scanning), and a
  **CodeQL** code-scanning pass (the same default query suites GitHub runs)
  across Python and JavaScript.
- **Live checks** against a running instance: response headers/CSP, auth gating
  on every sensitive endpoint, method/verb handling, and traversal probes.

## Outcome

**No Critical, High, or Medium finding ships.** The findings below were fixed in
this release; the static-analysis residue is a reviewed set of by-design false
positives, documented for transparency.

### Fixed in v5.0.1

- **Escalation dead-letter reliability (High).** A failed delivery of an alert
  *escalation* could, under the SQLite/PostgreSQL backend, fail to record its
  dead-letter-queue entry due to nested transactional locking — making a missed
  escalation invisible and un-retryable. The webhook send was moved outside the
  lock so the DLQ entry always records.
- **Support-bundle secret hygiene (High).** The downloadable diagnostics bundle
  scrubbed config by key *name*; a few secrets whose key name doesn't match the
  pattern (an SSH key, webhook URLs with tokens in the path, a git token) could
  slip through. The bundle now applies the same explicit redactions the
  `/api/config` view does.
- **Cross-scope access (Medium ×2 — IDOR).** Two endpoints (one ACME cleanup
  action, one per-site report) didn't fully enforce the caller's RBAC scope,
  letting a scoped operator touch or read another scope's data. Both now enforce
  scope.
- **Credential-reveal role check.** Revealing a scope-shared credential now
  requires an admin or an operator role with action permissions — a read-only
  viewer can no longer reveal, even with the vault key.
- **CVE accuracy.** The fallback version comparator no longer treats a
  prerelease (e.g. `1.2.0-beta`) as equal to its release, so it stops suppressing
  a real finding; and Alpine package data now keys the vulnerability database by
  the correct `major.minor` series.

### Static-analysis: reviewed false positives

A handful of SAST rules are inherent false positives for an application of this
kind; each was triaged against the source and is **not exploitable**. They are
scoped out of code scanning with the reason recorded in
`.github/codeql/codeql-config.yml`, while all injection / XSS / SSRF / auth
queries stay fully active:

- **Clear-text storage/logging of "passwords."** The server persists *hashed*
  (bcrypt/PBKDF2) and *encrypted* (AES-256-GCM) secrets to `0600` files by
  design; static analysis can't tell a hash from plaintext.
- **"Insecure TLS protocol."** The TLS *monitor* deliberately offers legacy
  protocol versions so it can probe and report on old servers' certificates — a
  monitoring probe, never a connection that carries our data.
- **"Weak hashing."** The two hits are an HMAC-SHA256 audit-chain MAC and a
  non-security dedup fingerprint (`usedforsecurity=False`) — neither is password
  hashing (passwords use bcrypt/PBKDF2).
- **Client request "forgery."** The browser API client only calls the app's own
  origin (the Content-Security-Policy `connect-src 'self'` blocks anything else).
- **JavaScript XSS flags** in the audited code were genuine false positives
  (values *are* escaped via the app's HTML/attribute encoders) and were either
  refactored to a form the analyzer trusts or hardened with an input guard, so
  the XSS queries now report clean with no rule disabled.

Bandit reports zero High findings; its remaining Medium/Low items (subprocess
use by an agent that runs admin-authorized commands, defensive `try/except`,
config key-name strings) are captured in a reviewed baseline. gitleaks scans
clean (its hits were build artifacts and documentation examples). CodeQL reports
zero.

## Reporting

Found something? Please report it **privately** via GitHub's
["Report a vulnerability"](https://github.com/tyxak/remotepower/security/advisories/new).
See [SECURITY.md](../SECURITY.md) and [security.md](security.md) for the full
policy, crypto details, and the standing security posture.
