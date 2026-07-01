# Security review — v5.6.0 "HeapMatters"

*Date: 2026-07-01. Authorized review of the maintainer's own codebase.*

This cycle ran a broad pentest of the product: the full committed SAST stack plus
a 5-dimension manual review (auth/RBAC, injection/SSRF, XSS/CSP, secrets/crypto,
the agent root channel + this release's new code). Every reported finding was
hand-verified before fixing. The main sweep found no Critical/High/Medium issues;
a later pre-production bug hunt (see the final section) found **one Medium** (an
AI-path SSRF) and a ship-blocking Postgres data-correctness bug, both fixed before
promotion. **Nothing Critical/High/Medium ships.** The remaining findings were Low
(mostly defense-in-depth) and fixed; the rest were confirmed safe.

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

## Follow-up sweep (2026-07-01)

A second, deeper pass (parallel per-dimension audits of the server core, the
side modules, and the agent, plus CodeQL/bandit/gitleaks and an authenticated
live review of the running site) surfaced **one Medium and a few Low** items,
all fixed. CodeQL (python + javascript) = **0 results**; bandit 0-new; gitleaks
clean; the live site presents a full CSP (no `unsafe-inline`), HSTS preload,
COOP/CORP, `401` on unauthenticated/bad-token requests, and correctly scrubs
config secrets (only `*_set`/`*_configured` indicators returned).

1. **Medium — CMDB → RAG corpus secret exposure.** The denylist that keeps
   credential-named fields out of the AI/embedding corpus was an *exact* name set
   (`credentials/secrets/vault/password`) that missed the common secret names
   (`api_key`, `token`, `passphrase`, `private_key`, `community`, `bearer`, …). An
   operator-added free-form CMDB field like `api_key: …` could be embedded into
   the vector store and, with a cloud embedding provider, sent off-box. Fixed with
   a case-insensitive substring matcher applied to CMDB metadata **and** the
   generic facet formatter.
2. **Low — cloud-metadata SSRF completeness.** The SSRF peer classifiers blocked
   IPv4 `169.254.169.254` (link-local) but not the IPv6/other metadata endpoints
   (`fd00:ec2::254`, `100.100.100.200`, `192.0.0.192`); now explicitly denied.
3. **Low — CVE-scanner response size cap.** Upstream OSV/Debian reads are now
   bounded (32 MiB) against a hostile/MITM'd upstream.
4. **Low — agent file-manager write TOCTOU.** The temp write now uses
   `O_EXCL|O_NOFOLLOW` so a pre-placed symlink can't redirect it.
5. **Low — storage file perms.** The SQLite `snapshot()` DB copy and the JSON
   `_write_json_atomic()` dump (both can carry hashed creds / tokens / encrypted
   config secrets) are now created **0600 from creation with `O_NOFOLLOW`** — no
   world-readable window, no symlink-follow (they were briefly ~0644 before).

Optional-feature hardening (Postgres RLS — opt-in `tenancy_rls`, default off, and
layered *under* the app-layer `tenancy_enforced` filter which is the independent
primary tenant isolation): the per-request tenant GUC now **fails closed** to a
deny sentinel if it can't be set, so a pooled thread connection can never carry a
prior request's tenant. Row-level-security policies currently harden the `devices`
roster table; the other per-tenant stores rely on the app-layer filter — extending
DB-level RLS to those tables is a tracked roadmap item, not a default-deployment
exposure.

Accepted low residuals (documented, not remotely exploitable by an unprivileged
party): the agent file-manager *read* op follows the documented "audit mode blocks
mutation, not reads" model (a fully-trusted server can read host files); the
`dns_resolve`/`resolver_health` helpers rely on their callers' fixed public-resolver
allowlist rather than an internal guard.

## Pre-production bug hunt (2026-07-01)

A final exhaustive bug hunt + pentest before the v5.6.0 prod prep (two independent
adversarial passes over the diff + a live authenticated review) surfaced three real
issues, all fixed and regression-tested. SAST re-verified clean afterwards: CodeQL
python **0** / javascript **0**, bandit 0-new, gitleaks clean; `make check` green on
both backends (JSON + SQLite, 4883 tests each); lint clean.

1. **Ship-blocker (correctness, Postgres-only) — cold→entity migration omitted from
   the Postgres backend.** The v5.6.0 promotion of `posture_state`/`port_baseline`/
   `av_status`/`ssh_key_baseline` from cold blobs to per-row entities was wired into
   the SQLite backend but not its Postgres twin — and `make test-both` only exercises
   JSON + SQLite, so it was invisible. **Production runs Postgres**, so it would never
   split those four files' cold blob; once the first entity row was written, a
   full-fleet `load()` would silently drop every un-migrated device. Fixed:
   parametrized `_migrate_cold_to_entity_pg(conn, files)`, bumped the Postgres schema
   counter 2→3, gated the V4 migration at `db_ver < 3` (a prod DB at v2 skips the
   already-run V3 and runs V4). A guardrail now asserts the Postgres backend migrates
   every `_COLD_TO_ENTITY_Vn` tuple the SQLite backend defines, so the two can't drift
   again without a live database.
2. **Medium — AI/embedding SSRF via IPv6-embedded IPv4 (metadata key-exfil).** The
   AI/embedding HTTP path (which carries the Bearer API key) did a connect-time
   peer-IP recheck but did **not** unwrap IPv6 forms embedding an IPv4, so a provider
   `base_url` resolving to `::ffff:169.254.169.254`, `2002:a9fe:a9fe::` (6to4) or
   `64:ff9b::a9fe:a9fe` (NAT64) rebound to the cloud metadata service and could
   exfiltrate the key. `ai_provider._peer_ip_blocked` now unwraps v4-mapped/6to4/NAT64
   and adds `is_multicast`/`is_reserved`, mirroring the shared `api._ip_class_blocked`.
   (Private LAN and the opt-in loopback path stay allowed — a local LLM is a
   legitimate provider target.)
3. **Low — agent file-manager write could wedge (supersedes Finding 4 above).** The
   temp write used `O_EXCL`, so a stale `.rp-tmp` left by an earlier crashed write
   blocked every future write to that path. It now uses `O_TRUNC` (keeping
   `O_NOFOLLOW` for the symlink-TOCTOU guard), matching the server's
   `_write_json_atomic`.
