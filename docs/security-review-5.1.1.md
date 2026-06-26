# Security review — v5.1.1 "ClusterMatters"

Status: released. No breaking changes.

## Scope

v5.1.1 is a small follow-up to v5.1.0 plus the first round of community-reported
fixes and a whole-project finalize sweep. This review covers the new and changed
code — Proxmox cluster-wide guest listing (#9), URL-hash routing on refresh (#12),
LocalAI API keys (#10), a separate embedding service (#11) — and the broad audit
and hardening sweep that accompanied the release.

## Tooling

A clean run of all three static-analysis tools was required to ship, plus a live
authenticated penetration test of the production deployment.

- **CodeQL** (the GitHub default `python` + `javascript` security suites, run
  locally via `tools/codeql-local.sh`, honouring the committed
  `.github/codeql/codeql-config.yml`): **0 results** across both languages.
- **bandit** (`-r server/cgi-bin client -b .bandit-baseline.json`): **0 new
  findings** beyond the triaged baseline; no HIGH introduced.
- **gitleaks** (`-c .gitleaks.toml`, current tree + full history, and
  `--no-git`): **no leaks**.
- **Live pentest** (authenticated, against the production site): security
  response headers verified on both the app shell and API responses — a full
  Content-Security-Policy with **no `unsafe-inline`** (`script-src 'self'`,
  `style-src 'self'`), HSTS with `preload`, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Cross-Origin-Opener-Policy` and
  `Cross-Origin-Resource-Policy`, and a referrer/permissions policy. Unauthenticated
  API calls return `401`; an invalid token returns `401` (not a `500`); unknown
  routes return a clean JSON `404` with no stack trace; and a malformed
  (non-object) request body is handled gracefully rather than producing a server
  error.
- **Unit gate**: the full suite passes on **both** the JSON and SQLite storage
  backends (`make test` and `make test-sqlite`).

## Findings fixed

No Critical, High or Medium findings. The items below are Low-severity
defence-in-depth and robustness fixes that were nonetheless addressed before
release, so that automated code scanning stays clean and there is nothing
exploitable.

### CMDB note rendering — attribute escaping (Low)
The small Markdown renderer used for CMDB asset notes escaped `<`, `>` and `&`
but not quotes. A crafted link URL could therefore break out of the `href`
attribute it was placed in. In practice this was already neutralised by the live
CSP (an injected inline event handler cannot execute, and is reported to the
violation endpoint) and the renderer only accepts `http(s)://` URLs, so script
execution was not possible. The renderer now also escapes `"` and `'`, closing
the attribute-injection entirely.

### Request-body robustness (Low)
Several administrator-only endpoints (bulk device actions and a number of
configuration validators) assumed a JSON **object** body. A top-level JSON
**array** slipped past the existing guard and could cause a server error before
the request was fully processed. All affected handlers now coerce a non-object
body to an empty object and return a normal validation response instead. These
endpoints are authenticated and admin-gated; the impact was robustness, not data
exposure.

### Outbound request safety for the new embedding service (#11)
The optional "separate embedding service" added in this release lets an operator
point semantic-search embeddings at a different endpoint than the chat provider.
That endpoint is subject to the **same** safeguards as every other outbound
integration: a set-time pre-flight that rejects loopback / link-local / cloud
metadata targets (loopback is permitted only for the explicitly local providers),
a connect-time peer-address re-check, and a no-redirect policy so a credential can
never be replayed to a rebound host. The embedding API key is withheld and masked
on read like every other stored secret, and changing the provider, URL or model
invalidates the cached vectors.

## Posture

The control-plane and data-plane safeguards documented in previous reviews remain
in place: mutual-TLS agent authentication with per-device certificate pinning,
AES-256-GCM encrypted disaster-recovery backups, two-person break-glass credential
reveals, an audited and permission-gated command queue with read-only "audit mode"
for agents, secrets withheld on read for everyone (administrators included), and a
fleet-wide outbound-request (SSRF) guard applied to every integration.

## Verdict

No Critical, High or Medium findings. Nothing exploitable was identified in code
review, automated scanning, or the live penetration test. The release is
considered safe to ship.
