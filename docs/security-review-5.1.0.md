# Security review — v5.1.0 "UnityMatters"

Status: test (origin/main), pre-promotion. No breaking changes.

## Scope

This release adds a first-class `fail2ban_ban` webhook/alert event, Arabic
right-to-left layout CSS, and an i18n string batch. The review covers that new
code plus the standard SAST sweep.

## Tooling

- **bandit** (`-r server/cgi-bin client -b .bandit-baseline.json`): **0 new
  findings** beyond the triaged baseline. No HIGH introduced.
- **gitleaks** (`-c .gitleaks.toml`): **no leaks** (current tree + history).
- **Targeted unit gate**: every module touched by the change passes on **both**
  the JSON and SQLite backends — event registries (`test_v184`, `test_v223`,
  `test_v225`, `test_v510_features`), version surface (`test_v510`, loosened
  `test_v501`/`test_v500`), the brittle source-window pins (`test_v248`,
  `test_v250`, `test_v260`, `test_v224`), JS parse (`test_jsload`), i18n
  (`test_themes_i18n`, `test_v430_i18n_gate`), the heartbeat contract
  (`test_heartbeat_contract`), and alert machinery (`test_v500_sweep`,
  `test_v490_resolver_health`).
- **CodeQL**: the committed `.github/codeql/codeql-config.yml` (paths-ignore +
  inherent-FP query-filters) is unchanged; the full local CodeQL run was not
  executed in this constrained environment — the production CodeQL default-setup
  run on the promotion push is the gate, and the change introduces no new query
  surface (see below).

## New-code review

### `fail2ban_ban` event (server `api.py`)
- **No new sink.** The event reuses the existing `fire_webhook` / `_record_alert`
  / `_record_fleet_event` path; no shell, SQL, `eval`, deserialization or
  filesystem write is introduced. The agent-reported jail/IP data is already
  sanitised by the existing heartbeat sanitiser (`_sanitize_str`, length-capped,
  `[:50]` jails / `[:200]` IPs) before any of it reaches the new code.
- **Lock-safety.** Bans are buffered in `_fail2ban_pending` **inside** the
  `_DeviceUpdate` lock and fired **after** it releases — `fire_webhook` takes its
  own lock, so this avoids the B2 lock-nesting class (verified green on the SQLite
  backend, where nesting would silently drop the alert).
- **Edge-trigger + flood control.** Bans fire only against the previous heartbeat
  snapshot (first snapshot seeded silently); new bans are capped per beat
  (`[:50]`) and per jail; repeat bans on a host **coalesce** into one open alert
  (`_alert_identity` carries no per-IP field by design), so a brute-force burst
  cannot flood the inbox while each ban still reaches webhook/SIEM destinations.
- **No secret in payload.** The payload carries device id/name, jail name and
  banned IPs only — no credential or token. Output is rendered through the
  existing escaping in the alert/feed renderers.
- **XSS.** The dashboard feed routes the event via `_homeActivityAttrs` using the
  same `escAttr`-guarded base as every other event; no new innerHTML sink.

### Arabic RTL CSS (`styles.css`)
- Purely additive `[dir="rtl"]` layout overrides; no script, no behavioural
  change, brace-balanced.

### i18n batch (`i18n.js`)
- Additive DICT keys (curated block) for existing English source strings; no
  logic change. The translate-by-source-text engine is unchanged.

### `av_infected` event (server `api.py`)
- Same shape as `fail2ban_ban`: reuses `fire_webhook` / `_record_alert`, no new
  sink. Fired from `_ingest_av` in the **post-lock** heartbeat ingest section
  (like `_ingest_hardware`), so no lock-nesting. Edge-triggered on the rising
  infected-count edge (re-reports don't re-fire); payload carries device id/name,
  tool and count only. No recover event — a malware finding stays actionable.

## Finalize sweep

Beyond the new-feature review above, v5.1.0 received a whole-project finalize
sweep — a structured audit of the **entire** codebase (server, agent, frontend,
docs), not just the changed lines, run as several independent review passes plus
a live authenticated pentest of the production deployment and the local SAST
suite. Headline result: the live security posture is strong — the production
site serves a strict Content-Security-Policy with **no** `unsafe-inline`
(`script-src 'self'; style-src 'self'`), HSTS with preload, `X-Frame-Options:
DENY`, `nosniff`, cross-origin opener/resource isolation and `frame-ancestors
'none'`; every unauthenticated API call returns `401`. The agent audit found no
Critical/High/Medium issues (every command channel is audit-mode-gated, the
self-update is signature/checksum-verified and fail-closed, TLS is strict on all
three agents, and every host-fact read is rootfs-mapped for the containerised
agent). Two real issues were found and **fixed in this release**:

- **(High) Webhook dead-letter queue leaked a secret-bearing destination URL.**
  The admin `GET /api/webhook/dlq` listing scrubbed the destination object but
  still echoed a convenience top-level `url`; for Slack/Discord/Teams the token
  is embedded in the URL path (the same class closed for `webhook_url` in v5.0.0).
  The listing now redacts the URL to `scheme://host`, dropping the secret path.
- **(Medium) AI-provider HTTP lacked a connect-time peer-IP recheck.** The cloud
  provider base URL was validated only when saved; a DNS-rebinding window between
  save and call could have replayed the API key to a loopback / link-local /
  cloud-metadata address. The AI HTTP client now re-validates the peer IP at
  connect (mirroring the Proxmox client), rejecting those ranges; loopback is
  permitted only for an explicitly internal/self-signed endpoint.

A handful of low-severity hardening notes (connect-time rechecks on a couple of
other admin-configured outbound integrations, response byte caps) are tracked for
a later pass; none is exploitable in the shipped configuration.

## Bar

No Critical / High / Medium findings ship. The two issues above were fixed in
this release; nothing exploitable remains in the reviewed code.
