# Security review — v6.2.3 "Un1fyMatters"

RemotePower is a defensive fleet-management product. Every release goes through a
security pass before it ships; this note is the public record for v6.2.3. The bar
is simple and non-negotiable: **no Critical, High or Medium finding — and nothing
exploitable — ships, on the server or the agent.**

v6.2.3 is a consolidation and tidy-up release. Its security-relevant changes are
internal refactors — a single shared request-body validation helper wired into
~240 handlers, one shared traversal behind the two config-secret redactors, and a
thin-wrapper unification of the HTML-escaping and formatting helpers — plus an
optional WireGuard tunnel listen-port field. Because refactors of shared,
security-touching helpers are exactly where a subtle regression hides, this
release also ran an **exhaustive, whole-codebase security audit** rather than a
changes-only pass.

## What was reviewed

- **Static analysis (SAST).** CodeQL (GitHub default Python + JavaScript security
  suites, run through the same config the production scan uses), Bandit and
  Gitleaks all report **clean**: CodeQL **zero results** across Python and
  JavaScript; Bandit **zero new issues** against its reviewed baseline (the
  remaining Low/Medium items are the long-standing by-design set — `try/except`
  cleanup paths, `0.0.0.0` bind strings, the agent's deliberate root command
  channel — each annotated at its line); Gitleaks reports no leaks across the
  full git history and the working tree. Semgrep's Python/JavaScript/secrets rule
  packs were also run; every result was triaged to a false positive or a
  by-design construct (the SNMPv3 AES-CFB privacy mode is the protocol standard;
  the flagged HTML sinks all pass through the escaping helpers; the file-mode
  findings are `0o700` restrictive directories or the deliberately-annotated
  scanner work directory; the subprocess findings use list-argv with
  internally-generated names). The CodeQL rule-level exclusions are the same
  documented, individually-triaged false positives as prior releases (persisting
  hashed/encrypted secrets to a 0600 file, a legacy-TLS prober, an HMAC chain, a
  same-origin fetch under CSP); no injection, SSRF, XSS or auth rule is ever
  suppressed.

- **Adversarial review across six dimensions.** Independent deep passes over:
  the session's own refactors (regression hunt); authentication, RBAC and
  multi-tenant isolation; server-side request forgery; injection (command, SQL,
  path, XML, header); frontend cross-site scripting and CSP integrity; and
  secrets, cryptography and token handling. Findings were confirmed by driving
  the real code paths, not by reading alone.

## What the refactors were confirmed not to break

- **Config-secret redaction.** The two redactors (one drops secret-named keys,
  one masks them) now share a single recursive traversal. A property test drove
  20,000 randomly-nested configurations through both the new and the previous
  implementation: **zero divergence** in either the dropped-key set or the masked
  output. `GET /api/config` still returns every secret as a configured/not-set
  boolean for all roles, including admins.
- **HTML escaping.** The escaping helper unification is byte-for-byte equivalent
  on every input (including `null`/`undefined` and the full metacharacter set);
  no escaping was weakened, and the strict production CSP (`script-src 'self'`,
  no `unsafe-inline`) remains intact with zero inline handlers or styles.
- **Request-body validation.** The ~240-handler helper is a mechanical
  equivalent of the previous inline pre-check; no authentication or authorization
  call was added, removed or reordered relative to validation.

## Findings fixed before release

The audit surfaced a set of **pre-existing** issues (not v6.2.3 regressions) in
the multi-tenant and off-box-export code paths. All were fixed and covered with
regression tests before this release:

- **Tenant / scope isolation on request-body device targets.** A handful of
  handlers resolved a device identifier from the request body and sat outside the
  path prefix that the pre-dispatch scope enforcement covers, so on a
  multi-tenant or role-scoped install a privileged caller could act on or read a
  device outside their tenant/scope. These were routed through the same
  scope-and-tenant filter the rest of the command and fleet-aggregate surface
  already uses (a no-op on a single-tenant, unscoped install). This closed a
  cross-tenant command path, a bulk host-inventory read, a bulk alert-clear, a
  fleet host-config collect, and several fleet-aggregate report views.
- **Off-box export redaction unified.** The support diagnostics bundle, the
  backup archive and the declarative config export each carried their own list of
  the credential-bearing fields whose key *name* is not secret-shaped (URLs that
  embed basic-auth userinfo, a cloud secret access key, a third-party client id).
  Those lists had drifted, so each surface redacted a slightly different set. They
  now share one redaction list, so every off-box artifact strips the full set and
  the lists cannot diverge again.
- **Internal webhook peer check.** A loopback-only internal endpoint verified the
  peer with a value that, behind the shipped reverse-proxy topology, always reads
  as loopback. It now uses the same trusted-peer resolution the IP allowlist and
  audit trail rely on.
- **Two small correctness nits** in the release's own new code (a malformed tunnel
  port value returned a 500 instead of a clean 400; a defensive confirmation
  fallback had become self-referential) were also fixed.

## Bottom line

SAST is clean across all four tools; the six adversarial passes found no
remaining exploitable issue; and the pre-existing isolation and export-redaction
gaps the audit surfaced were fixed and regression-tested before release. No
Critical, High or Medium finding ships in v6.2.3.
