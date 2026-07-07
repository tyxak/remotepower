# Security review — v6.0.1 "RefineMatters"

RemotePower is a defensive fleet-management product. Every release goes through a
security pass before it ships; this note is the public record for v6.0.1. The bar
is simple and non-negotiable: **no Critical, High or Medium finding — and nothing
exploitable — ships.**

## What was reviewed

A whole-project pass over the server and all three agents (Linux, Windows, macOS),
not just the release diff:

- **Static analysis (SAST).** CodeQL (the GitHub `security-extended` Python +
  JavaScript suites), Bandit and Gitleaks all run locally before every push and
  report **clean** (zero new findings; the small set of rule-level exclusions are
  documented, individually triaged false positives — never any injection, SSRF,
  XSS or auth rule).
- **Manual audit.** Authentication and session handling, role-based authorization
  on every state-changing endpoint, secret storage and redaction, SSRF guards on
  every outbound request, command/SQL/path-traversal injection, cross-site
  scripting sinks, the agents' update path, and third-party dependencies.
- **Dynamic testing.** Standard web-app scanners (OWASP ZAP, Nikto, Nuclei,
  Wapiti, WhatWeb) against a running instance, plus authenticated probing of the
  live API surface.
- **Content-Security-Policy.** The production policy is
  `default-src 'self'` with `script-src 'self'` and `style-src 'self'` — no
  `unsafe-inline` — verified live, alongside HSTS (preload), `X-Frame-Options:
  DENY`, `X-Content-Type-Options: nosniff`, a locked-down `Permissions-Policy`
  and a `report-uri` for violations. The shipped HTML/JS contains zero inline
  event handlers, inline styles or inline scripts.

## Findings

**No Critical, High or Medium finding.** The recurring high-risk classes
(authorization gaps, SSRF, injection, XSS, secret exposure, auth/MFA bypass) were
each traced end-to-end and land at an existing guard.

Two **Medium correctness** issues in alert handling were found and fixed — not
security vulnerabilities, but they could hide a real problem from an operator:
recovering one watched process (or one storage pool) on a host could clear the
still-open alerts for the others. Both now match on the specific process/pool.

A small number of **Low**, defence-in-depth hardening items were fixed rather than
merely noted, to keep the surface tight:

- Outbound vulnerability-database lookups (OSV, the Debian security tracker) now
  use a no-redirect opener and URL-quote every identifier — a poisoned DNS answer
  or redirect can't bounce the request elsewhere. No credential is ever sent on
  these and the response is never reflected.
- The container-image-registry client now *requires* the SSRF-safe opener (it
  fails closed instead of falling back to a default one).
- A read-only role can no longer clear a ticket's "unread reply" badge — a
  read-only token must not nudge shared state.

## Posture in brief

bcrypt-hashed passwords (with a PBKDF2-HMAC-SHA256 fallback) behind rate-limited
login; TOTP two-factor with one-time recovery codes; constant-time token
comparison; per-endpoint authorization resolved from role permissions (not a role
name allowlist); secrets redacted from every read API and encrypted at rest;
every outbound integration behind a connect-time SSRF guard with no redirects; the
agents post their telemetry over a no-redirect opener so a token can never be
replayed or downgraded.

Security is a feature here, and we'd rather over-share the process than under-test
the product. If you find something, please open a report.
