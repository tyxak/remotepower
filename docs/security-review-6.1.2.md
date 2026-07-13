# Security review — v6.1.2 "AfterglowMatters"

RemotePower is a defensive fleet-management product. Every release goes through a
security pass before it ships; this note is the public record for v6.1.2. The bar
is simple and non-negotiable: **no Critical, High or Medium finding — and nothing
exploitable — ships.**

v6.1.2 is a correctness-and-fit release: it surfaces telemetry the agents already
collected, adds optional-module kill switches, completes the pydantic request-body
validation rollout, and works through a wide bug hunt. Because most of the changes
touch data that had been *collected but never acted on*, this review paid particular
attention to two things: that a signal newly wired into an alert or the AI corpus
carries no data it shouldn't, and that the tamper signals being surfaced (a refused
agent self-update, a changed SSH host key) are trustworthy rather than noise.

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
- **Undefined-name analysis on the agents.** A stdlib `symtable` pass over all
  three agents (`ruff --select F821` covers the same class) — because a swallowed
  `NameError` in the agent silently disables whatever feature it lived in, and a
  security guard that never executes is worse than none.
- **Property and fuzz testing.** The Hypothesis suites
  (`tests/test_hypothesis_*.py`) drive thousands of generated inputs at the parsers,
  normalisers, sanitizers and the crypto round-trip, and assert JSON≡SQLite storage
  agreement.
- **Full test gate.** The complete suite runs against both the JSON and SQLite
  backends — every change in this release ships green on both.

## Findings fixed before release

Nothing Critical, High or Medium remained open at ship. The security-relevant items
this pass found and closed:

### A username-validation guard that never ran (agent)

The agent's `apply_host_config` validated each requested Linux username against a
POSIX pattern before handing it to `useradd`/`usermod` — the guard that stops a name
like `-x` being read as a command-line option. But it called `_re.fullmatch(...)`
while the agent imports `re`; `_re` was never defined at module scope, so the guard
raised `NameError` on the first user and the surrounding `except Exception` swallowed
it. The whole host-config apply then aborted (silently taking groups, sudoers, motd,
logrotate and cron with it), and the username was never actually validated.

It survived every prior check because the tests for this code path are all
source-text greps — they saw the line present and passed without ever running it,
and the v5.6.0 pentest test even pinned the literal broken string, certifying a
guard that could not execute. Fixed to use the real `re` module; a new static
guardrail now fails the build on *any* undefined name in any of the three agents.

### Tamper signals promoted from a settings page to Needs-Attention

A **refused agent self-update** — the agent declining an unsigned or tampered
self-update — was stored by the server but rendered only as a table on the
agent-signing settings page. It never reached Needs-Attention, so it never affected
a host's or the fleet's health score and no alert could fire: a supply-chain tamper
signal you would only find by opening one specific settings page. It is now a
critical Needs-Attention item, deliberately independent of whether the server can
hash its own copy of the agent build (the agent already made the judgement).

### Local certificate expiry never reached the AI corpus

The RAG live-state corpus builder read local TLS certificate inventory from
`sysinfo.cert_files`, but that data is stored in the hardware record, not sysinfo —
so the field was always empty and the AI advisor never saw local cert expiry despite
being documented to. Corrected to read the hardware store. This is a completeness
fix rather than a leak; the corpus's secret-field filtering (case-insensitive
substring match over operator-authored fields) is unchanged and was re-confirmed.

### Silent failure signals wired to alerts

Two hardware signals the agents collected were excluded from every verdict, so a
real failure was invisible: an NVMe drive that had exhausted its spare reserve
(the drive's own "about to go read-only" indicator) and a NIC accumulating
errors/drops (a failing cable or port). Both now feed the disk-health verdict and
the per-host Checks engine respectively. The NIC check reasons about the
per-heartbeat *delta*, not the cumulative-since-boot total, so a long-lived host's
historical count cannot raise a false alarm; interface CRC errors are surfaced as
their own "check the cable" reason rather than scored as drive failure.

### Test isolation could touch a live install

Four test modules imported `api.py` without first pointing `RP_DATA_DIR` at a
temporary directory. Because importing the module runs `ensure_default_user()`,
running the suite on a host where `/var/lib/remotepower` is writable could have
overwritten a live install's admin user. Fixed at every site; two leaked
`respond()` monkeypatches that had been turning assertions into false greens were
also closed.

## Standing posture

The controls that carry across releases remain in force and were re-confirmed here:

- **Outbound SSRF defence** — connect-time peer-IP recheck against the vetted IP
  literal (closing the DNS-rebind window), no-redirect openers on every
  token/API-key-bearing outbound call (integrations, AI/embedding providers,
  Proxmox, the scanner and push satellites, and all three agents), and
  metadata/link-local/unspecified blocking.
- **Tenant isolation** — device-keyed stores and fleet aggregates are filtered by
  the caller's tenant, cross-tenant ids return 404, and the command-queue family
  filters body-supplied device ids through the scope filter at a single chokepoint.
- **Untrusted XML** — routed through `safe_xml.fromstring`, which rejects any
  DTD/entity declaration over the whole buffer (billion-laughs defence; stdlib does
  not resolve external entities, so no XXE).
- **CSP** — production serves `script-src 'self'; style-src 'self'` with no
  `unsafe-inline`; there are no inline event handlers or style attributes in the
  static HTML or in any JavaScript `innerHTML` string.
- **Secrets** — never echoed back on read (a boolean indicator only), redacted from
  diagnostics bundles and the RAG corpus, and stored hashed/encrypted at rest in
  0600 files.

No Critical, High or Medium finding ships in v6.1.2, and nothing found in this pass
is exploitable.
