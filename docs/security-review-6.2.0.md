# Security review — v6.2.0 "Daem0nMatters"

RemotePower is a defensive fleet-management product. Every release goes through a
security pass before it ships; this note is the public record for v6.2.0. The bar
is simple and non-negotiable: **no Critical, High or Medium finding — and nothing
exploitable — ships, on the server or the agent.**

v6.2.0 makes the agent a first-class supervised service on every OS (a Windows
service via pywin32, launchd `KeepAlive` on macOS, systemd on Linux), completes a
Windows-agent parity buildout, and adds a set of gap-closing capabilities: a
governed AI executor, a PII scan, EDR coverage reporting, DNS-blocker control, JIT
credential checkout, and quotes. Because the headline surfaces are a
privileged-by-nature service supervisor and an AI that proposes remediation
commands, this review paid particular attention to two questions: can the new
endpoints be reached by a caller who shouldn't reach them, and can the AI executor
be steered into running something an operator didn't sanction.

## What was reviewed

- **Static analysis (SAST).** CodeQL (the GitHub default Python + JavaScript
  security suites), Bandit and Gitleaks all run locally and report **clean**:
  CodeQL returns **zero results** across Python and JavaScript; Bandit reports
  **zero High** against its reviewed baseline (the remaining Low/Medium items are
  the long-standing by-design set — `try/except/pass` cleanup paths, `0.0.0.0`
  bind strings, the agent's deliberate root command channel — each annotated at its
  line); Gitleaks reports no leaks across the full git history and the working tree.
  The small set of rule-level CodeQL exclusions are the same documented,
  individually-triaged false positives as prior releases (persisting
  hashed/encrypted secrets to a 0600 file, a legacy-TLS prober, an HMAC chain, a
  same-origin fetch under CSP); no injection, SSRF, XSS or auth rule is ever
  suppressed.
- **Undefined-name analysis on the agents.** A `ruff --select F821` pass over all
  three agents (Linux, Windows, macOS) reports zero undefined names — the class
  that shipped a dead code path in a prior release.
- **Authorization on the new attack surface.** Every new v6.2.0 endpoint was read
  for its gate and tenant behaviour (below).
- **Prompt-injection resistance of the governed AI executor** (below).

## New-surface authorization — audited, all gated

Each new endpoint enforces the right gate for what it does, and device-scoped
endpoints resolve a cross-tenant/out-of-scope id to a 404 (never confirming the id
exists):

| Endpoint | Gate | Notes |
|---|---|---|
| `GET /api/ai-exec/catalog` | `require_auth` | read-only list of operator-authored actions |
| `POST /api/ai-exec/propose` | `require_write_role` | **executes nothing** — returns a pending confirmation id |
| `GET /api/pii` | `require_auth` | read |
| `POST /api/pii/scan` | `require_write_role('exec')` | mutating — write-role, not bare auth |
| `GET /api/edr/coverage` | `require_auth` | read |
| `POST /api/vault/checkout` | `require_admin_auth` | sensitive credential reveal |
| `POST /api/vault/checkout/{id}/revoke` | `require_admin_auth` | admin-only |

DNS-blocker control (pause blocking for a bounded window) is admin-only and
audit-logged, with a hard maximum window and a self-re-enabling timer, so a debug
pause cannot silently become a permanent hole. All outbound integration traffic —
including the new EDR connectors — rides the same connect-time SSRF guard as every
other outbound feature (loopback / link-local / cloud-metadata refused, peer IP
re-validated, no redirects).

## The governed AI executor is injection-resistant by construction

`POST /api/ai-exec/propose` does not let the model author a command. It is handed a
catalog of **operator-saved actions** and instructed to choose **at most one, by
its exact id**, or answer `NONE` — it "may not invent an action, and may not write
a command." The proposal produces a pending confirmation that then flows through
the same approval + command-validation gate as every other queued command. So a
hostile string in the device context can, at worst, cause the model to pick an
already-approved catalog action or nothing — there is no path from model output to
an arbitrary shell command. Execution remains write-role-gated and audit-logged.

## Findings fixed before release

This release's reported issues were **correctness/robustness**, not privilege or
data-exposure vulnerabilities, but two are worth recording because they belong to a
class the project actively tracks:

- **Opaque ids must be non-numeric by construction.** A scheduled job carries a
  `token_hex` id; an id that reads as scientific notation (`1e5…`) was coerced to
  `Infinity` by the frontend's `data-arg` dispatcher, so its delete request hit
  `/api/schedule/Infinity` and 404'd — an un-deletable job. The schedule and
  maintenance delete controls now pass the raw id through `data-action-btn`/
  `data-id`, which is never number-coerced, and auto-patch-managed windows are
  minted with a prefixed `ap_<id>` id. No cross-user impact — a caller could only
  ever fail to delete *their own* fleet's row — but it is the same id-coercion
  class the project treats as a defect wherever it appears.
- **Auto-patch maintenance windows were written incomplete** (no id/scope), so they
  could not be deleted from the UI. The sync now writes the full window record and
  the list endpoint backfills any legacy window missing an id.

## Standing posture

The durable controls are unchanged and were re-verified: a strict
Content-Security-Policy with no `unsafe-inline`; the full security-header set;
same-origin enforcement on state-changing requests; session tokens hashed at rest;
bcrypt password hashing; per-API-key rate limiting; the connect-time SSRF guard on
every outbound feature; tenant isolation on device-keyed stores and fleet
aggregates; and `O_NOFOLLOW` on agent state-file I/O. The new supervised-service
installers run with the privileges the OS service model requires and nothing more,
and the Windows agent's self-update verifies a SHA-256 (and a signature when signed
updates are enabled) before applying.

**Result: no Critical, High or Medium finding ships in v6.2.0.**
