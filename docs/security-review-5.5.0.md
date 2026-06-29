# Security review — v5.5.0 "ScaleMatters"

_Last updated: 2026-06-29. This is a public summary of the security work done for the
v5.5.0 release. RemotePower is reviewed every release; older summaries live in
`docs/security-review-*.md` (the three most recent are kept) and the complete history
is in [CHANGELOG.md](../CHANGELOG.md)._

## Bar

**No Critical, High, or Medium severity issue ships — and nothing exploitable.** Where
a static-analysis tool flags a by-design pattern, the finding is triaged, justified,
and recorded so the scanners stay green and real regressions stand out. Findings at or
above Medium are fixed before release; Low / informational items are fixed when cheap
and otherwise documented as accepted residuals with their rationale.

## How this release was reviewed

- **Multi-pass code audit** of the server (`api.py` and its helper modules) and all
  three agents (Linux, Windows, macOS), covering authentication/authorization, SSRF,
  injection (shell / SQL / XML / path traversal), cross-site scripting, secret
  handling and storage, response headers / CSP, lock-safety, and the agent command and
  self-update channels.
- **Static analysis**: `bandit` (Python), `gitleaks` (secrets), `semgrep`, and a local
  **CodeQL** run using the same default query suites GitHub Code Scanning runs — all
  expected to report **clean** (committed configuration records the triaged by-design
  patterns so genuine findings are never masked).
- **Live authenticated penetration testing** against the production instance: header
  posture, unauthenticated rejection, authorization boundaries, and malformed-input
  handling.

## Findings fixed in this release

| Severity | Area | Summary | Status |
|---|---|---|---|
| High | Authorization | One device-action endpoint (drift content fetch) authenticated the caller but did not enforce the **command permission and device scope** its sibling endpoints do, so a read-only or out-of-scope token could queue a read on a watched file. Now gated exactly like the other drift mutations. | **Fixed** |
| Medium | Denial of service | The DMARC aggregate-report parser rejects reports carrying a document-type/entity declaration (entity-expansion defense), but the check scanned only the start of the document, so a padded prolog could slip past it. The whole (size-capped) report is now scanned. | **Fixed** |
| Medium | SSRF | The AI-provider client re-validated the peer IP at connect time only for HTTPS endpoints; a plain-HTTP endpoint could be re-pointed to an internal address after the initial check. The same connect-time guard now applies to HTTP. | **Fixed** |
| Low | Secret exposure | A monitoring ping URL containing a secret path token was returned in the config API to non-admin (read-only) tokens. It is now withheld from non-admins, matching how other secret-bearing URLs are handled. | **Fixed** |

## Accepted low-severity residuals (documented, not exploitable)

- Two optional firewall integrations (RouterOS / OPNsense) and the IMAP/SMTP mail
  paths validate their target at configuration time but not again at connect time.
  All are **admin-configured** endpoints (an admin already has privileged access), so
  the residual risk is a misconfiguration aid, not a remote exploit. Connect-time
  re-validation is tracked as defense-in-depth.
- The committed nginx templates and Docker image are being aligned with the hardened
  production header set (the live instance already serves the full set — see below).

## Verified strong

The live instance returns a complete hardened header set — Content-Security-Policy
with no `unsafe-inline` (`script-src 'self'; style-src 'self'`), HSTS with preload,
`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`,
`Cross-Origin-Opener-Policy`, and `Cross-Origin-Resource-Policy` — rejects
unauthenticated API calls, and returns clean JSON for malformed input. The audit
additionally confirmed clean: the role model fails closed for unknown/custom roles;
two-person break-glass credential reveals cannot be single-party bypassed; the
strict-mode alert-state guard holds on every path; the config API reduces every
token / password / secret-bearing URL to a boolean indicator; sessions, API keys,
device tokens and enrollment tokens are stored hashed, passwords with bcrypt, and
backups encrypted (AES-256-GCM, verify-before-use); all outbound integrations apply
preflight + connect-time SSRF guards with no credential-replaying redirects; SQL is
fully parameterized and request-derived data is consistently HTML-escaped; and every
agent command channel honors read-only "audit mode" with symlink-safe credential
writes and signed/checksum-verified self-update.

## Transparency

Security matters here, and this project is pentested as much as we can manage every
release. If you find something, please open a report — responsible disclosure is
welcomed and credited.
