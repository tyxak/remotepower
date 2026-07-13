# Security review — v6.1.1 "HardenMatters"

RemotePower is a defensive fleet-management product. Every release goes through a
security pass before it ships; this note is the public record for v6.1.1. The bar
is simple and non-negotiable: **no Critical, High or Medium finding — and nothing
exploitable — ships.**

v6.1.1 is a broad correctness-and-hardening pass over the whole product rather
than one big new subsystem. Because it lands on top of the large v6.1.0 transport
cutover (CGI → gunicorn/Flask) and the multi-tenancy work, this review paid
particular attention to two classes of regression: incomplete tenant-isolation
sweeps (a device-keyed store that a later feature added but an earlier isolation
pass never covered), and off-box artifacts that could carry a secret.

## What was reviewed

- **Static analysis (SAST).** CodeQL (the GitHub default Python + JavaScript
  security suites), Bandit and Gitleaks all run locally and report **clean** —
  zero new findings. The small set of rule-level CodeQL exclusions are the same
  documented, individually-triaged false positives as prior releases (persisting
  hashed/encrypted secrets to a 0600 file, a legacy-TLS prober, an HMAC chain);
  no injection, SSRF, XSS or auth rule is ever suppressed. Bandit runs against a
  reviewed baseline with **zero High**; Gitleaks reports no leaks across the full
  history and the working tree.
- **Multi-agent code review.** A structured, independently-verified security
  review across the whole server and agent surface — six parallel threat-class
  hunters (SSRF, cross-tenant/IDOR, auth-gating, XSS, injection, secret handling,
  plus an agent-side pass), each finding re-verified against the source before
  any fix. Three findings warranting a fix were confirmed (below); everything
  else was clean or by-design.
- **Manual audit + live probe.** The maintainer's own running instance was probed
  (read-only, with a maintainer-supplied one-time token) to confirm the live
  posture: every API endpoint enforces authentication (unauthenticated requests
  are rejected), the server banner discloses no version, and the security headers
  match the documented policy.
- **Content-Security-Policy.** Unchanged and verified live: `default-src 'self'`
  with `script-src 'self'` and `style-src 'self'`, **no `unsafe-inline`**,
  alongside HSTS (preload), `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, a locked-down `Permissions-Policy`,
  cross-origin isolation (COOP/CORP) and a `report-uri` for violations.

## Findings

All findings below were caught and fixed **before** this line was promoted to
production — none shipped. They're recorded in full because the bar is "nothing
exploitable ships," not "nothing was ever found."

**High — the Alerts subsystem was missing tenant isolation.** RemotePower's
optional multi-tenancy confines each tenant's admins to their own devices. The
v6.1.0/v6.1.1 tenancy work gated the device-keyed *confirmations* store, but the
structurally-identical *alerts* store was missed: with tenancy enforced, a
tenant-scoped admin could list another tenant's alerts (device names, hostnames,
CVE ids, event detail) and acknowledge or resolve them — reading, and
suppressing, another tenant's security signal. Fixed: a shared visibility filter
now scopes the alerts list and the sidebar badge counts, and every mutation
(ack / unack / resolve, bulk ack / resolve, and mute) is tenant-gated, returning
"not found" for an out-of-tenant alert id so its existence isn't even confirmed.
Fleet-level (device-less) alerts stay visible, matching the existing behaviour.
This affects only deployments that have turned tenancy on.

**High — the same tenant-isolation gap existed in six other fleet-wide views.**
A follow-up pass asked the obvious next question: if the alerts store was missed,
what other fleet-aggregate endpoints filter only by role scope and never consult
the tenant gate? A tenant admin resolves to the "all devices" role scope, so any
handler that checks *only* that scope sees the whole fleet. Six did: the OpenSCAP
compliance overview, the fleet-wide privileged-command (sudo) search, the activity
/event feed, the authorized-scan list **and its bulk-clear**, the per-asset risk
overview, and the fleet health rollup. With tenancy enforced, a tenant admin could
read another tenant's compliance scores, privileged-command history, device
activity, scan findings and risk/health posture — and, via scan-clear, delete
another tenant's finished scan records. Fixed: each now routes its device set
through the shared scope-and-tenant filter (the same helper the already-correct
container / drift / command-queue overviews use), so out-of-tenant devices are
dropped before anything is read or mutated; the two conditionally-cached views
(risk, events) also fold the tenant into their cache key so two tenant admins can
no longer share a cached response. This affects only deployments with tenancy on.

**Medium — sidebar badge counts could cross tenants via a shared cache.** The
per-sidebar "needs attention" badge counts are cached briefly, keyed by the
caller's role scope. Two different tenant admins both resolve to the same
"all devices" scope, so they shared one cache entry — and the underlying
alerts / pending-confirmations / pending-commands counts were computed over the
whole fleet without a tenant filter. Fixed: the cache key now includes the
caller's tenant, and each of those counts is restricted to the caller's own
devices.

**Medium — the downloadable diagnostics bundle could carry an integration
credential.** The support bundle is scrubbed of secrets before it leaves the box,
and already stripped the known secret-bearing-but-not-secret-named fields
(webhook URLs, health-check ping URLs, metrics-push URLs, git tokens). An
integration instance URL can also embed HTTP basic-auth credentials
(`https://user:pass@host`); the live config view already redacts it, but the
bundle did not. Fixed: integration URLs are now stripped from the bundle too.

**Lower-severity hardening (fixed in the same pass).** Two smaller items were
tightened even though neither was exploitable: an AI-analysis endpoint that only
required a valid login now requires a role with write permission, so a strictly
read-only role can no longer trigger a paid AI-provider call; and the optional
agent-push (wake-nudge) daemon now reads device credentials through the same
storage backend the app uses. On the default Postgres/SQLite backend the daemon
previously looked for on-disk JSON files that no longer exist, so it failed
closed and the (opt-in, off-by-default) push channel was silently inert — a
functional bug rather than an exposure, but one that left a feature quietly
non-working.

## Coverage confidence — checked and clean

The review explicitly confirmed the recurring bug classes this codebase tracks
are clean this release: outbound HTTP for operator-supplied URLs all runs through
the SSRF-safe path (connect-time peer-IP recheck, no redirects, metadata/loopback
blocked, attacker-controlled ids reduced to a single URL segment); every
attacker-influenceable field rendered in the UI is HTML-escaped or set as text,
and every dynamic link goes through the protocol allowlist; admin decisions use a
permission check, never a role-name denylist, and state-mutating handlers require
a write role; database access is fully parameterised; file download / export /
attachment paths are traversal-guarded; and config fields holding a token,
password or secret-bearing URL are withheld on read (a boolean indicator only,
admins included) and kept out of the AI/RAG corpus. The agent posts only over
no-redirect HTTPS and reads host facts through its host-path shim.

## The standing posture

The durable, always-current security posture — architecture, controls, the SAST
configuration and the triaged false-positive list — lives in
[`security.md`](security.md). This file is the point-in-time record for v6.1.1;
the previous passes are [`security-review-6.1.0.md`](security-review-6.1.0.md) and
the earlier reviews, retained in `CHANGELOG.md` and the release history.
