# Under the Hood: how RemotePower is built

Most of the docs here tell you *what* RemotePower does and *how to use it*. This
one is for the curious — and for anyone hacking on the code. It's the engineering
tour: the shape of the codebase, the decisions behind it, and the load-bearing
patterns that hold ~96,000 lines of server Python together without a framework in
sight.

If you just want to run the thing, start with [install.md](install.md) and
[architecture.md](architecture.md) (which covers the deployment topology and the
heartbeat → command → response cycle). This page picks up where that one stops:
inside the process.

---

## The philosophy: boring on purpose

RemotePower is deliberately built out of the least exciting technology that will
do the job. The guiding rules:

- **Near-stdlib.** The server runs on Python's standard library plus a short list
  of well-worn, optional-where-possible dependencies. There is no ORM, no task
  queue, no message broker, no Redis, no Celery. A background job is a function
  that a scheduler calls; a queue is a JSON list under a lock.
- **No build step for the frontend.** The dashboard is hand-written HTML, CSS and
  JavaScript. There is no webpack, no bundler, no transpiler, no `node_modules`.
  You can `curl` the page, read it, and understand it. Edit a file, reload, done.
- **One big module, many small ones.** The API is one large file
  (`server/cgi-bin/api.py`, ~64k lines) that owns routing, auth, and the request
  lifecycle, surrounded by ~56 focused sibling modules that each do one thing
  (DNS, SNMP, TLS monitoring, hypervisor drivers, the RAG index, …).
- **Everything degrades.** Optional dependencies are guarded behind
  `try: import …`. No `bcrypt`? Fall back to PBKDF2. No `pydantic`? Request
  validation short-circuits and the hand-rolled checks still run. The product
  keeps working with a smaller feature set rather than failing to boot.

The payoff is that the whole thing is *legible*. A single engineer can hold the
request path in their head, and a new contributor can trace a feature from the URL
to the byte on disk without learning a framework first.

By the numbers (v6.1.2):

| Thing | Count |
|---|---|
| Server Python (`server/cgi-bin/`) | ~96,000 lines |
| The main API module (`api.py`) | ~64,000 lines |
| Focused sibling modules | 56 |
| HTTP routes (exact + templated) | ~419 exact, ~329 pattern |
| Request handlers (`handle_*`) | ~674 |
| Typed request-body models | 243 |
| Homelab integration connectors | 40 |
| Background maintenance sweeps | ~43 |
| Frontend JS files (no bundler) | 38 |
| Test methods across 301 files | ~6,600 |

---

## The backend: one process, one router

Since v6.1.0 the server is a real WSGI app. `server/cgi-bin/wsgi.py` is a tiny
Flask shell — `application = Flask(__name__)` with a single catch-all route — and
gunicorn runs it (`gunicorn wsgi:application`). That's the *entire* transport
layer. What happens next is the interesting part.

The Flask route does almost nothing: it copies the WSGI environ into a
thread-local request context (`_RCTX`) and calls `api.main()` — the same
`main()` that has existed since the project's CGI days. The whole dispatch table,
the auth and CSRF enforcement, the read-only-role gate, the ~43 maintenance
sweeps: all unchanged. Only the shell around them changed.

That's not an accident. Before v6.1.0 the server ran as CGI behind fcgiwrap (one
process per request) and later an SCGI prefork worker. The cutover to gunicorn +
Flask was designed as *"swap the entry point, keep the handlers,"* which was only
cheap because the dispatcher had already been refactored from a giant `if/elif`
chain into a **table-driven router**. Handlers write their response the old way —
`print()`, `respond()`, raw `sys.stdout.buffer.write()` for downloads — and
`wsgi.py` captures that into a per-request buffer and wraps it in a real
`flask.Response`. The ~20 streaming/export handlers needed *zero* changes.

### A request's journey

When `main()` runs, a request flows through a fixed pipeline before it ever
reaches your handler:

1. **Context** — method, path, query, headers and body are read from `_RCTX`
   (never bare `os.environ`, which under a persistent server would be
   process-global, not per-request).
2. **Routing** — the path is matched against `_EXACT_ROUTES` (a dict of
   `(method, path) → handler`) first, then `_PATTERN_ROUTE_DEFS` for templated
   paths like `/api/devices/{id}/checks`. Exact wins; patterns fill in the
   `{id}`-shaped gaps.
3. **Auth** — the handler calls `require_auth()`, `require_admin_auth()`,
   `require_perm('containers', [dev_id])`, or `require_write_role('tickets')`
   depending on what it does. Read-only roles (viewer, auditor, finance, the MCP
   bridge) are admitted by `require_auth()` but rejected by
   `require_write_role()` — so any state-mutating handler must gate on the latter.
4. **Module gate** — `_enforce_module_gate()` 404s an entire API prefix if the
   operator switched that module off (Settings → Advanced). The UI is never the
   enforcement boundary; the API is.
5. **Tenant scope** — in a multi-tenant install, `_enforce_device_scope()` and the
   per-handler `_scope_filter_devices()` confine a tenant admin to their own
   devices, even for fleet-wide aggregate views.
6. **Dispatch** — your handler runs and produces a response via `respond(status,
   dict)`, which raises an `HTTPError` that unwinds the stack cleanly. (A neat
   consequence: a success `respond()` inside a `try/except Exception` gets *caught*
   and rewritten to a 500 — so we never do that.)

Every handler is documented for the OpenAPI/Swagger spec automatically: the spec
builder parses the route table and the dispatcher source to reconstruct templated
paths, so `/swagger.html` covers the whole surface without a hand-maintained
spec file.

---

## Storage: one API, three backends

The single most important abstraction in the codebase is the storage layer.
Everything persistent is a **logical storage key** — a `DATA_DIR`-relative name
like `devices.json` — and every read and write goes through the same handful of
functions:

- `load(KEY)` — read and deserialize. Memoized per request in a thread-local
  `_LOAD_CACHE`.
- `save(KEY, value)` — serialize and persist atomically.
- `with _LockedUpdate(KEY) as doc:` — the read-modify-write primitive. Acquire the
  lock, hand you the current value, write it back when the block exits.
- `backend_exists(KEY)` — the storage-aware existence check.

Underneath, three backends implement that contract:

- **Flat JSON** (`storage.py`, the fallback default) — one file per key, written
  atomically with an `flock` and a rolling `.bak` sibling for crash recovery.
  Simple, greppable, zero setup.
- **SQLite** — WAL mode, stdlib `sqlite3`. Hot entities are stored **row per
  entity**, so a heartbeat updates one device's row instead of rewriting a whole
  file. In-place, reversible migration from the file backend.
- **PostgreSQL** (the single-node default since v6.1.0) — multi-host DSN failover,
  optional read replicas, a PgBouncer pooler, and — if you turn it on — row-level
  security keyed on a per-request GUC as DB-enforced tenant isolation beneath the
  app layer.

The abstraction is why the same code runs on a Raspberry Pi with a flat file and
on a multi-node cluster with Postgres. It's also where the subtle bugs live, and
the codebase has learned some hard rules the hard way:

- **Gate on `backend_exists()`, never `Path.exists()`.** Under SQLite/Postgres a
  logical key is a DB row, not a file, so `Path.exists()` is always false for it.
  A throttle keyed on `if F.exists()` silently never fires — which once turned a
  daily backup into an every-heartbeat backup.
- **In a poll loop, bust the load cache each iteration.** `load()` is memoized per
  request; a long-poll waiting for *another process* to write a key must
  invalidate the cache or it re-reads its own first snapshot forever.
- **Any standalone daemon reads through the backend, too.** The push daemon and
  scanner satellite are separate processes; they can't just `open()` a `.json`
  that lives in Postgres.

### Locking, and effects that must wait

`_LockedUpdate` (and its single-row cousin `_DeviceUpdate`) serialize writes. The
trap is *nesting*: under a DB backend the whole data dir shares one connection, so
taking a second lock inside an open one deadlocks. The codebase solves this two
ways. The three audit-style recorders (`fire_webhook`, `audit_log`,
`log_command`) auto-defer — if you call them inside a lock, they queue and fire
right after the outermost lock releases, in order, and are discarded if the block
aborts. Other self-locking helpers (the history samplers) follow the manual rule:
collect the data inside the lock, act on it after the block exits.

Lock semantics are also kept at **parity across backends** — `non_blocking=True`
gives a contended lock the same brief grace on JSON (retry ~100 ms), SQLite
(`busy_timeout`) and Postgres (retrying advisory-lock), and an uncaught
`LockBusy` renders as a retryable **503**, not a 500. A handler that works on two
backends and 500s on the third is the bug we design against.

---

## The maintenance sweeps

RemotePower has ~43 periodic jobs: poll integrations, check disk headroom, expire
confirmations, sample SMART/GPU history, run scheduled backups, re-scan for CVEs,
and so on. There is no cron inside the app and no external job runner. Each sweep
is a `run_<x>_if_due()` function with a cheap "is it time yet?" gate backed by a
persisted timestamp.

By default (since v6.1.0) a dedicated, leader-elected
`remotepower-scheduler.service` process runs them out of band — one leader across
a cluster, chosen by file-lock or `pg_advisory_lock`. With `--no-scheduler` the
sweeps fall back to their original home: piggy-backing on request traffic, where
`main()` runs the due ones at the tail of a request. Either way the "is it due?"
check reads a lightweight config snapshot (`_config_ro()`) so a not-due sweep
costs almost nothing — important when it runs on every request.

---

## Request-body validation: pydantic as a safety net

A recurring bug class in any JSON API is the request body: a field silently
missed, an integer arriving as a string, a top-level array where a dict was
expected (which 500s the first `.get()`). RemotePower's answer is
`server/cgi-bin/request_models.py` — a pydantic v2 layer wired into 243 handlers.

The design choice worth calling out is that it's **additive and never
narrowing**. A model validates the body as a *superset* of what the handler
already accepted: every field is optional with a loose `mode='before'` coercer
that mirrors the handler's own `str()`/`int(x or N)`/`bool()` dance, and unknown
keys are ignored (rejecting them would break existing API clients). The handler
keeps its own extraction; the model just runs first to turn a clearly-malformed
body into a clean, structured 400 — never echoing the submitted value back, since
bodies can carry secrets. If pydantic isn't installed, validation short-circuits
and the hand-rolled checks run unchanged.

There's a genuinely subtle rule baked in here: if the old code *clamped* an
out-of-range number (`max(1, min(43200, n))`), the model must **not** add a
`le=43200` bound, because that would reject a value the old code accepted — a
breaking change. Faithfulness to existing behavior beats theoretical strictness.

---

## The agent: a polite polling daemon

The client (`client/remotepower-agent.py`, with a byte-identical extensionless
copy, plus separate `remotepower-agent-win.py` / `remotepower-agent-mac.py`
implementations that speak the same protocol) is a small Python daemon that POSTs
to `/api/heartbeat` every N seconds
(default 60). The heartbeat is the whole protocol: the agent sends telemetry, the
server's response carries any pending command (`shutdown`, `reboot`,
`exec:<cmd>`, `poll_interval:<n>`, …). Expensive facts are sent on slower
cadences — full sysinfo every ~10 polls, patch counts every ~3 hours — so the hot
path stays cheap.

Two properties are load-bearing:

- **No redirects, ever.** The agent posts its token and telemetry, so a 3xx
  response must never be followed (it could replay the token to a rebound host).
  All agent HTTP goes through a no-redirect opener.
- **Container-aware reads.** The agent can run in a container to monitor its
  Docker host. Every host fact is read through `host_path()`, which is the
  identity function natively but maps to the bind-mounted host root inside a
  container — so the agent reads the *host's* `/proc`, not the slim image's.

Whatever the agent sends is only trusted after passing through a server-side
sanitizer that whitelists and bounds each field before it ever reaches a check or
the UI.

---

## The frontend: a framework you can read

The dashboard is one `index.html` (~9,600 lines), one main `app.js` (~25,000
lines), and ~37 supporting JS modules — all vanilla, all served as-is. No
framework, no build, no bundler. State lives in a few module-scoped objects;
rendering is `innerHTML` with escaped values plus targeted DOM updates.

The parts that make this scale without a framework:

- **Event delegation, not inline handlers.** The Content-Security-Policy is fully
  locked down — `script-src 'self'; style-src 'self'`, no `unsafe-inline`. That
  means *zero* inline `onclick=` attributes and *zero* `style="…"` strings, in
  the static HTML and in every `innerHTML` template. Interactivity is wired
  through `data-action` / `data-home-act` attributes dispatched from a small
  number of top-level listeners. An inline handler would silently die under the
  CSP, so the rule is enforced by convention and tests.
- **Escape at the sink.** Untrusted values go through `escHtml`/`escAttr` (or
  `textContent`/`appendChild`) before touching the DOM, and operator-authored
  URLs go through a scheme allowlist helper before landing in an `href`. The CSP
  is the backstop; escaping is the primary defense.
- **A translation observer.** Six languages are handled without a framework: a
  `MutationObserver` translates page text as it's rendered, and a dictionary
  handles the short labels. Adding UI text means adding a dictionary entry, not
  wiring a pipeline.
- **Guardrails against overflow.** Every panel that renders a variable number of
  rows caps its height and scrolls internally via shared CSS utilities, so a host
  with 400 open ports can't push a card off the screen. Every sortable table
  wires the same sort helper. These are enforced in code review because they've
  regressed before.

None of this is clever. That's the point — you can open the file and see exactly
what happens when you click a button.

---

## Security engineering (the defensive posture)

Security in RemotePower is defensive engineering, and the interesting parts are
the *defenses*, not any single feature:

- **Defense in depth against SSRF.** Every outbound request to an
  operator-supplied target (integration connectors, hypervisor drivers, TLS
  monitoring, AI providers) runs through a guarded client: it re-resolves the
  hostname, connects to the specific vetted IP literal (closing the DNS-rebind
  window), refuses redirects (so a token can't be replayed to a rebound host),
  and blocks link-local / metadata / unspecified addresses. Attacker-influenceable
  IDs that get interpolated into an outbound URL are reduced to a single
  URL-encoded path segment so they can't smuggle in an absolute URL.
- **Tenant isolation as a chokepoint.** Rather than sprinkle checks everywhere,
  device resolution funnels through `_scope_filter_devices()`, which folds in both
  role scope and tenant filtering — even for a tenant admin who otherwise resolves
  to "no scope." Fleet-wide aggregate views route their device set through it, and
  per-scope caches include the tenant in their key.
- **RBAC that fails closed.** Roles are resolved through a single helper; a custom
  operator role that is neither "viewer" nor "admin" is gated on its actual
  permission bits, not on a denylist. State-mutating handlers require a write
  role, not merely authentication.
- **Tamper-evident audit log.** Audit entries are chained with a hash of the prior
  entry, so an edit or a dropped record breaks the chain and is detectable.
- **Secrets never echoed.** Config fields that hold a token or a
  secret-bearing URL are redacted to a boolean `*_configured` indicator on read —
  for admins too — and must be re-entered to change. A recursive scrubber catches
  secret-named keys in diagnostics bundles and the RAG corpus, so an
  operator-authored `api_key` field never gets embedded or shipped off-box.
- **XML without the footguns.** Untrusted XML (DMARC reports, cloud exports) is
  parsed through a hardening wrapper that refuses any DTD/entity declaration
  anywhere in the buffer — the entity-expansion ("billion laughs") vector — before
  the stdlib parser (which doesn't resolve external entities) ever sees it.

The bar the project holds itself to: nothing exploitable ships, and the whole
codebase scans clean under CodeQL, Bandit and Gitleaks on every release.

---

## Testing and release engineering

The test suite is ~6,600 methods across 301 files, and the real gate runs the
*entire* suite twice — once on the JSON backend, once on SQLite — because the
cross-backend bugs are the ones that reach production. (Production CI adds a third
dimension: it runs on the Python version the servers ship with, which has caught
version-specific breakage a local run couldn't.)

A few testing patterns are unusual and worth knowing about:

- **Source-inspection tests.** Some tests read the source of a handler and assert
  it *contains* a security-relevant call — that it audits, re-verifies a password,
  or gates an incompatible update. They're brittle to line shifts (a fixed-size
  window pins the check), but they catch a whole class of "someone deleted the
  audit call" regression that behavioral tests miss.
- **Property-based + fuzz testing.** Hypothesis generates thousands of adversarial
  inputs to prove invariants — that a sanitizer never crashes, that the two
  storage backends always agree on a round-trip, that request validation turns
  *any* body into either a value or a clean rejection.
- **Static analysis as a gate.** CodeQL (the exact GitHub default suites), Bandit
  and Gitleaks run locally before every push and again in CI, all expected to
  report zero. False-positive rules are filtered with a documented, triaged
  reason; injection / SSRF / XSS / auth queries stay active.

Releases are cut as signed git tags. The build produces a reproducible tarball
with a SHA-256 and a detached GPG signature (signed locally — the key never
touches CI), and publishing a GitHub release triggers a multi-arch
(`amd64` + `arm64`) container image push to the registry. The same version is
also packaged for the AUR, built from the signed, PGP-verified tarball.

---

## Where to look next

- [architecture.md](architecture.md) — deployment topology and the
  heartbeat → command → response cycle.
- [wsgi.md](wsgi.md) — the gunicorn/Flask entry point in detail.
- [scaling.md](scaling.md) — the Postgres backend, worker pool, multi-node,
  satellites and retention for large fleets.
- [writing-a-connector.md](writing-a-connector.md) — add your own integration in
  one function.
- [api.md](api.md) — the REST surface (or just open `/swagger.html`).

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
