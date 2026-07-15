# Security review — v6.2.2 "Pu1seMatters"

RemotePower is a defensive fleet-management product. Every release goes through a
security pass before it ships; this note is the public record for v6.2.2. The bar
is simple and non-negotiable: **no Critical, High or Medium finding — and nothing
exploitable — ships, on the server or the agent.**

v6.2.2 is a performance-and-polish release built around the agent heartbeat. The
changes with a security surface are: a new agent→server delta protocol (the agent
omits unchanged inventory and the server merges its stored copy back in), agent
HTTP connection reuse, an in-place installer upgrade path, and a set of frontend
interaction features (keyboard alert inbox, device hover cards, deep links). This
review paid particular attention to the two questions those raise: can the delta
protocol be steered into serving stale or cross-device data, and does the reused
transport weaken any of the guarantees the per-request transport gave.

## What was reviewed

- **Static analysis (SAST).** CodeQL (the GitHub default Python + JavaScript
  security suites), Bandit and Gitleaks all run locally and report **clean**:
  Bandit reports **zero new issues** against its reviewed baseline (the remaining
  Low/Medium items are the long-standing by-design set — `try/except/pass` cleanup
  paths, `0.0.0.0` bind strings, the agent's deliberate root command channel —
  each annotated at its line); Gitleaks reports no leaks across the full git
  history and the working tree. The CodeQL rule-level exclusions are the same
  documented, individually-triaged false positives as prior releases (persisting
  hashed/encrypted secrets to a 0600 file, a legacy-TLS prober, an HMAC chain, a
  same-origin fetch under CSP); no injection, SSRF, XSS or auth rule is ever
  suppressed.
- **Undefined-name analysis on the agents.** A `ruff --select F821` pass over all
  three agents (Linux, Windows, macOS) reports zero undefined names.
- **Third-party pattern scan (Semgrep).** A `semgrep` pass over the server and
  agents was run in addition to the committed gates. Its findings were reviewed
  individually; all are non-exploitable and are recorded below in the interest of
  transparency — one led to a real hardening change, the rest are constant-value
  or by-design patterns.
- **Live posture check.** The production TLS endpoint was checked for response
  headers and authentication behaviour (below).
- **Delta protocol, transport reuse and the new frontend surface** were read for
  their trust boundaries (below).

## The one change made from the scan

- **Billion-laughs guard on the agent's XML parse.** The agent parses one XML
  document — the OpenSCAP (XCCDF) results file produced locally by `oscap`. It
  used the standard-library parser directly. The standard library resolves **no**
  external entities (so there is no XXE), but it *does* expand internal entities,
  which a crafted file could use to exhaust memory. The file is generated locally
  by a trusted tool, so real-world risk was minimal — but the agent runs with
  elevated privilege and a document-type declaration there is never legitimate, so
  the parse now rejects any DTD/entity declaration before parsing, mirroring the
  guard the server already applies to all untrusted XML. Defense-in-depth, applied
  because the bar is "nothing exploitable," not "nothing likely."

## Delta sysinfo — no stale or cross-device exposure

The heartbeat delta protocol lets the agent omit inventory fields whose content
is unchanged; the server fills them back in from what it already stored for **that
device**. Three properties were verified by reading the ingest path and driving it
with tests:

- **The merge is per-device and whitelisted.** Omitted fields are merged only from
  the *same* device's previously stored `sysinfo`, and only for a fixed allow-list
  of field names. A field the server has never stored is not fabricated — it is
  listed back to the agent for a full resend. There is no path by which one
  device's data lands on another.
- **Capability is server-advertised.** The agent only begins omitting fields after
  the server signals support in a heartbeat response, so a new agent against an
  older server always sends complete data, and a downgraded server heals on the
  next beat.
- **State is only trusted when confirmed.** The agent updates its "already sent"
  bookkeeping only on a response the server actually committed (not a busy/dropped
  beat), so a lost write can never leave the server serving a value the agent has
  stopped sending.

The delta body is still run through the same sanitizer (`safe_si`) as a full body;
nothing about the protocol bypasses field validation.

## Transport reuse — same guarantees, verified

The agent now reuses one HTTPS connection across heartbeats instead of a fresh
handshake each time. The persistent connection uses the **same** TLS context as
before — certificate verification required, hostname checking on, self-signed-CA
bundle and mTLS client certificate honoured — and `http.client` never follows
redirects, so the "never replay the token-bearing POST to a 3xx target" guarantee
holds by construction, exactly as the no-redirect opener gave it. Proxied
environments and an explicit opt-out fall back to the previous per-request path.

## New frontend surface

The keyboard alert inbox, device hover cards and deep links were read for injection
and authorization:

- Hover cards and inbox rows render device fields through the existing
  escaping helpers and build DOM with `textContent`/`appendChild`, never an
  `innerHTML` string; the hover card lives at document body level and is
  purely presentational. Device ids are charset-validated before use.
- Deep links (`#device/<id>/<tab>`) drive the same drawer the UI already opens;
  the id is validated against the device-id charset and the tab against a fixed
  set. No new server endpoint and no new authorization path is introduced —
  every action still passes the same server-side gate it always did.

## Reviewed third-party-scanner findings (non-exploitable)

For transparency, the Semgrep pass surfaced these; each was traced to its source
and is not reachable by untrusted input:

- **SQL built with an f-string (server storage layer).** These interpolate
  **table and column identifiers from a fixed literal set in the source** into DDL
  and the row-level-security migration. SQL cannot bind an identifier as a
  parameter, so identifier interpolation is unavoidable; the values are
  compile-time constants with no user input. Data values everywhere use bound
  parameters.
- **Relaxed cipher floor on two LAN-appliance integrations** (RouterOS, OPNsense).
  These target self-signed appliances on the local network under the same
  "trusted LAN + API credentials" model as `curl -k`; the channel stays encrypted
  (TLS 1.2 minimum) and the outbound request is SSRF-guarded and admin-configured.
  A deliberate compatibility trade-off for local network gear, not an internet
  path.
- **`shell=True` on the agent command channel.** This *is* the product: an
  authenticated, audited, allow-list/four-eyes/quarantine-gated operator command
  run as root. Annotated by design.
- **Plain-WebSocket option for a relay satellite** and file-mode constants on
  agent state files: both by design (a satellite on a trusted segment may serve
  plaintext; agent state files are 0600 with `O_NOFOLLOW`), documented at their
  lines.

## Live posture (production endpoint)

The production TLS endpoint was checked without and with credentials:

- **Response headers:** a strict Content-Security-Policy with no `unsafe-inline`
  and a CSP report endpoint; HSTS with a two-year max-age, `includeSubDomains` and
  `preload`; `X-Frame-Options: DENY`; `X-Content-Type-Options: nosniff`;
  `Referrer-Policy: strict-origin-when-cross-origin`; and a restrictive
  `Permissions-Policy`.
- **Authentication boundary:** an unauthenticated API request and a request with an
  invalid token both return `401`; the public status endpoint rejects a
  non-status token. No information leak in the error responses; the server banner
  carries no version or stack detail.

## Standing posture

The durable controls are unchanged and were re-verified: the strict CSP; the full
security-header set; same-origin enforcement on state-changing requests; session
tokens and device tokens hashed at rest; bcrypt password hashing; per-API-key rate
limiting; the connect-time SSRF guard on every outbound feature; tenant isolation
on device-keyed stores and fleet aggregates; and `O_NOFOLLOW` on agent state-file
I/O. The v6.2.2 backup change (skip an unreadable file rather than abort) and the
Postgres schema advisory lock are robustness fixes with no privilege or
data-exposure surface.

**Result: no Critical, High or Medium finding ships in v6.2.2.**
