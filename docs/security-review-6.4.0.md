# Security review — v6.4.0 "Sh1eldMatters"

A thorough bug-hunt / security sweep across the project, weighted toward the
freshly-written v6.4.0 code (the agentic log-sweep + triage, the NetFlow/IPFIX/
sFlow flow receiver, and this cycle's three "top-pick" additions: flow-verified
service dependencies, cross-fleet incident outcome memory, and the detection
self-test). Method: deterministic SAST plus three independent adversarial
reviewers, each owning a dimension; every finding was reproduced before being
fixed.

## Process

- **SAST** — `ruff --select F821` (agent + all `*_handlers.py` modules + the flow
  parser: **0**; the ~155 hits in `api.py` are the documented bound-handler
  false-positive class), `gitleaks` (**no leaks**, 1447 commits), `bandit` on the
  new code (3 Mediums, all by-design — a `0.0.0.0` UDP bind and an operator-config
  `urlopen` in the flow sidecar, byte-identical to the already-accepted syslog
  daemon, plus a `0.0.0.0` string inside a test datagram builder).
- **Adversarial reviewers** — three parallel passes: (1) cross-tenant / RBAC-scope
  / IDOR isolation; (2) injection / XSS / SSRF / untrusted-parser safety; (3)
  auth/write-gate, logic-correctness, and dead-feature bugs. Each reviewer drove
  the real code paths with live repros under a scratch data dir.

## Second pass — deep adversarial audit (multi-vector)

A second, wider sweep ran eight independent adversarial reviewers in parallel
(cross-tenant / IDOR, SSRF, XSS / DOM injection, auth / RBAC / session,
command-injection / RCE, secret leakage, XML / SQL / path / deserialization, and
logic-correctness), alongside the full local SAST stack (Bandit, gitleaks,
`ruff --select F821`, and a config-honoring CodeQL run matching production's
advanced-setup scan — **0 results, Python and JavaScript**). Every reported
finding was reproduced against the real code path before being fixed, and each
carries a regression test. All fixes landed **before release** — the affected
subsystems never shipped in this state.

The most serious was a **cross-tenant authorization gap in the staged-rollout /
auto-patch subsystem**: those two device-targeting paths did not pass through
the same tenant/scope filter the rest of the command surface uses, so on a
multi-tenant deployment a tenant administrator could have directed a patch /
reboot / script action beyond their own tenant. Fixed by stamping the creator's
tenant scope onto the rollout or policy at creation and enforcing it wherever
the target set is resolved; a guardrail test now drives the real dispatch path
for both. (Multi-tenant isolation is an opt-in enterprise mode, off by default.)

The remaining items were lower-severity hardening, all fixed: free-form
documentation / ticket / knowledge-base bodies are now run through the same
inline-secret scrubber as script bodies before they can reach an AI context;
alert acknowledge / resolve now honours a scoped operator's device scope (not
just their tenant); a threshold that was meant to disable an alert at `0` now
does; the storage-maintenance argument validator was tightened to reject spaces
and leading dashes; operator-authored log-alert regexes are screened for
catastrophic-backtracking (ReDoS) shapes at save time; and the satellite
scanner's XML parse gained the same DTD/entity guard the agent already uses.

The SSRF, XSS, command-injection, SQL, XXE and deserialization reviews found
**no exploitable issue** — the outbound-request guard (connect-time peer-IP
re-validation, no-redirect, metadata-range blocking) and the escape-everything
frontend discipline held across the board.

## Findings (first pass — all fixed; all LOW)

The new code was found to be notably well-hardened — the recurring bug classes
this project tracks had clearly been designed against. Three genuine low-severity
defects were found and fixed:

1. **Cross-tenant AI-triage scoreboard leak** (`handle_ai_stats`, api.py). The
   v6.4.0 triage scoreboard counted `triaged` / `auto` / `feedback_up` / `down`
   over the **raw** alert list, so a tenant admin (or any read-only role) saw
   fleet-wide aggregates across tenants — ironically the `incident_memory` count
   added right beside it was already tenant-filtered. Fixed by routing the alert
   list through `_filter_alerts_for_caller` (RBAC scope + tenant gate), matching
   every other alert read path. Aggregate counts only — no names/content — hence
   LOW. Guard: `test_v631_incident_memory.TestAiStatsScoreboardTenantIsolation`.

2. **Unbounded `unknown_seen` map → flow-sidecar DoS** (`remotepower-flowd.py`).
   NetFlow/IPFIX is connectionless UDP with a spoofable source address; the
   daemon's log-throttle map was keyed on the unmapped-exporter source IP and
   never pruned, so a flood of spoofed sources could grow it without bound and
   OOM the process. (`buckets`/`templates` are keyed only after a successful
   token match, so they stay bounded by the enrolled-device count — this map was
   the sole unbounded structure, keyed precisely on the untrusted set.) Fixed
   with a size cap that clears on overflow (matching `TemplateCache._MAX`);
   clearing loses only throttle timestamps. The binary parser itself was
   confirmed comprehensively bounds-checked (no OOB read, no count/length-driven
   hang or OOM across v5/v9/IPFIX/sFlow). Guard:
   `test_v631_flow.TestDaemonAggregate.test_unknown_seen_is_bounded`.

3. **AI daily-cap debited before validation** (`handle_alert_ai_triage`,
   `handle_log_sweep_diagnose`). The per-user daily AI-request counter was
   incremented before the 404/400 existence checks, so a request that made
   **zero** provider calls (unknown alert, missing device, no sweep yet) still
   spent the caller's quota. Fixed by moving the debit to after the validation
   checks, immediately before the actual provider call. Per-user only, no
   cross-user impact. Guard: `test_v631.TestAiRateLimitAfterValidation`.

## Verified clean (no exploitable issue)

- **Tenant isolation** across all new modules: `handle_dependency_health`
  (`_scope_filter_devices`), `handle_ai_incident_memory` + `_similar_incidents`
  (`_tenant_gate` / per-alert `_device_tenant`), `handle_alert_ai_triage` /
  `_feedback` (`_filter_alerts_for_caller` + under-lock re-check),
  `handle_remediation_log` (`_scope_filter_devices`), `_compliance_facts`
  (already scoped in the v6.4.0 fix), the signed-command channel, and
  `handle_flow_in` (capability-token = device scope). `handle_detection_selftest`
  exposes only global notification config (consistent with `handle_config_get`).
- **Parser safety**: `flow_parse.py` bounds every packet-declared count/length,
  reads through a range-checked `_u()` (no OOB), caps the template cache, and
  canonicalizes IPs through `ipaddress` (so flow fields reaching the UI carry no
  HTML metacharacters). Adversarial datagrams (absurd counts, huge template
  lengths, zero-length fields, IPFIX var-length `0xffff`) all yield bounded
  results, none hang/OOM.
- **XSS**: every UI render path for polled/agent/exporter/LLM-supplied data
  (`app.js` flows modal + detection self-test, `app-network.js` dependency
  health, `app-alerts.js` triage verdict + ATT&CK chips, `app-ai.js` log-sweep)
  escapes at the sink; `_clean_attack_techniques` validates technique ids
  server-side; `renderMarkdown` escapes HTML first.
- **Logic/correctness**: all three features driven end-to-end
  (`dependency_missing`/`_restored` fire + auto-resolve with a whitelisted
  `dep_edge` sub_match; incident-memory harvest idempotent via the seen-ring;
  detection self-test false-positive-free). All four new cadence sweeps are in
  **both** `main()` and `scheduler.CADENCE`; config keys persist through
  save/model/get; no success `respond()` under `except Exception`; no
  `.exists()` on a storage key; write-gates correct.

## Finalize / hardening pass (whole-project, not just new code)

A second sweep across the entire project accompanied the release finalize:

- **SAST, all three tools clean.** `bandit -r server/cgi-bin client` — 0 High,
  0 Medium (the one Medium found, the macOS agent writing its replaced binary
  world-executable during self-update, was fixed — see below; remaining
  findings are by-design Lows: shell-less subprocess, best-effort try/except).
  `gitleaks` — no leaks across full history and the working tree. `ruff
  --select F821` on both agents — clean. **CodeQL** (the config-honoring pass
  that matches production's advanced-setup scan) — **0 results across Python
  and JavaScript**.
- **macOS agent self-update hardened.** The mac agent replaced its own binary
  with mode `0o755` (world-readable/executable) — inconsistent with the Linux
  agent (`0o700`) and needlessly broad, since the launchd daemon runs as root.
  Tightened to `0o700` (owner-only). No exploitability, but least-privilege
  parity across agents.
- **Live probing of the maintainer's own instance** (authorized internal
  testing) confirmed a strong external posture: a strict Content-Security-Policy
  with no `unsafe-inline` (`default-src 'self'`; script/style `'self'`;
  `frame-ancestors 'none'`), HSTS with preload, `X-Frame-Options: DENY`,
  `nosniff`, cross-origin opener/resource policies, and a locked
  permissions-policy. Unauthenticated API requests are rejected with a terse
  `401`/`404` (no stack traces, no version-dependent error text); unexpected
  methods and path-traversal attempts are handled (`405`/`403`/`404`); the only
  unauthenticated endpoint is a minimal health check. No information disclosure
  beyond the product version.

No Critical / High / Medium issue ships; nothing exploitable. The full local
SAST suite (Bandit, gitleaks, CodeQL) reports clean.
