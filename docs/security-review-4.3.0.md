# RemotePower — Security Review (v4.3.0 "ImprovementMatters")

Date: 2026-06-12. Scope: a focused review of the v4.3.0 delta over the
v4.2.0 review, covering the three batches in this release — the refinement
batch (diagnostics bundle, audit-archive download, slow-request ring,
rate-limit coverage on the unauthenticated auth callbacks, per-device alert
delay, monitor flap dampening), the **performance batch** (the new persistent
SCGI API worker `server/cgi-bin/api_worker.py`, app-level gzip on selected
endpoints, the fleet-checks server cache), and the **UX/robustness batch**
(device deep links, the connectivity banner, the heartbeat rate floor,
deploy-script snapshots/rollback, the accessibility sweep) — against the
standing brief: authentication/authorization, command execution, input
handling, secrets, transport, SSRF, path traversal, and the front-end.

**No CRITICAL or HIGH issues were found.** Two **Low** hardenings were
identified during this review and fixed in the same release (below). All
v4.2.0-review fixes were untouched by this release's changes and spot-verified
intact (SSRF anti-rebinding, config secret scrub, hashed session tokens,
scan-schedule scoping).

## Independent scanning

- **bandit** (Python static analysis) was run against the new/changed modules
  (`api_worker.py`, `tools/bump_version.py`, `tests/e2e_harness.py`): no
  HIGH findings. The remaining LOW/MEDIUM flags were each reviewed and are
  intentional: best-effort `try/except pass` in the worker's per-request
  cleanup path (flush/close must never mask the response), the deliberate
  `0o660` unix-socket mode (group access is how nginx connects — see below),
  and fixed-argv `subprocess` calls in the test harness.
- The full DAST stack (wapiti / nikto / nuclei / OWASP ZAP) was last run
  clean against v4.2.0. The v4.3.0 web-facing surface delta is small (no new
  routes accept new user input; the worker sits behind the same nginx
  front), but **re-running the in-product Pentest passive profile against the
  test instance before production promotion is recommended**, particularly if
  the SCGI worker is enabled there.

---

## Fixed during this review (both shipped in v4.3.0)

- **[Low] SCGI worker: unbounded header-block allocation.** The netstring
  parser accepted any advertised length, so a local process with socket
  access could make a request child attempt a multi-GB allocation
  (memory-DoS; not reachable through nginx, which generates the headers
  itself). Fixed: length digits capped and the header block limited to 1 MB
  (`MAX_HEADER_BYTES`), with a regression test
  (`test_oversized_header_block_refused`).
- **[Low] Deploy snapshots written to a world-readable directory.**
  `/var/backups/remotepower-deploys/` was created with default permissions.
  The snapshots contain only the deployed code tree (no data dir, no
  secrets), but the directory is now created/tightened to `0700` as
  defence-in-depth.

---

## New surface review

### Persistent SCGI worker (`api_worker.py`) — the main new attack surface

- **Trust model unchanged from fcgiwrap.** The worker listens on a unix
  socket (`0660`, inside `RuntimeDirectory=remotepower`, mode `0750`,
  `www-data:www-data`) — exactly the same local-trust posture as
  `/run/fcgiwrap.socket`. Whoever can write to the socket can issue
  arbitrary API requests with forged CGI variables (including
  `REMOTE_ADDR`); that set is root and `www-data`, i.e. nginx — the same
  parties that could already do this under CGI. **Recommendation kept in the
  shipped config comments: use the unix socket; if TCP mode is ever used,
  bind loopback only** (a reachable TCP port would let any local user forge
  request metadata).
- **Process isolation preserved.** Fork-per-request with copy-on-write means
  each request runs in a pristine copy of the imported module — no
  cross-request state, token, or cache leakage by construction. The three
  fork-hygiene rules (SQLite connections closed pre-fork; `_LOAD_CACHE`
  cleared per child; `SIGCHLD` reset in the child) are documented as
  load-bearing in the module docstring and exercised by the end-to-end
  worker tests (request isolation is asserted directly).
- **PRNG hygiene**: the child reseeds `random` post-fork. Token generation
  uses `secrets` (urandom-backed), which is fork-safe regardless.
- **Resource limits**: per-request `SIGALRM` backstop (default 900 s),
  soft child cap (`RP_WORKER_MAX`, default 32), kernel backlog beyond that.
  A hung handler dies by alarm; nginx's `scgi_read_timeout` gives up first.
- **systemd unit hardening**: `NoNewPrivileges`, `ProtectSystem=full`,
  `ProtectHome`, `PrivateTmp`, `ReadWritePaths` limited to the data dir;
  runs as `www-data` like the CGI did.

### App-level gzip (`_render_response`)

BREACH was the reason nginx never gzipped JSON; that reasoning still stands
and is now enforced **per endpoint** instead of globally. The whitelist
(`_GZIP_SAFE_GET_PATHS`: home, devices, attention, alerts, checks) contains
only GET endpoints whose responses carry no session tokens and reflect no
request-supplied data, so there is no secret+reflection pair to oracle.
Compression also requires `Accept-Encoding: gzip` and a ≥1400-byte body.
A guardrail test (`test_whitelist_has_no_secret_bearing_endpoints`) fails if
a token-ish path is ever added to the list. Alert payloads can contain
log-derived text from monitored hosts (low-trust input), but those responses
contain no secret, so compressing them is not a BREACH vector.

### Fleet-checks cache

The cache stores **unscoped** host rows in the server's data dir; RBAC scope
and the `?status` filter are applied per request *after* the cache. The
scope property is pinned by a test (`test_scope_filter_applies_after_cache`):
a viewer cannot be served another scope's hosts from a cache an admin warmed.
The cache file lives in `RP_DATA_DIR` with the same protection as
`devices.json` itself (which contains strictly more data).

### Heartbeat rate floor

The 429 path runs **after** the constant-time device-token check
(`hmac.compare_digest`), so unauthenticated callers cannot use it to probe
device ids, and the response writes nothing (same early-exit mechanics as the
403). Default off; enabling it is an availability decision, not a
confidentiality one. An attacker holding a valid device token gains nothing
new — they could already write that device's state.

### Device deep links (`#device/<id>`)

The fragment never reaches the server. No tokens or secrets enter the URL —
only device ids, which are not sensitive identifiers in this model. The id
from the hash is `decodeURIComponent`-ed and then only ever (a) re-encoded
with `encodeURIComponent` for the API path and `replaceState`, and (b)
rendered via `textContent` (never `innerHTML`) in the drawer header — no
DOM-XSS sink. CSP posture (`script-src 'self'`, no inline handlers) is
unchanged; the v2.3.2 CSP fidelity suite passes against this release.

### Connectivity banner / accessibility sweep

Static markup + delegated `data-action` handlers (CSP-clean, verified by the
existing 35-test CSP suite). `role`/`aria-*` attributes have no security
effect. The banner triggers only on fetch-level failures and renders no
dynamic content.

### Deploy snapshots / rollback

Root-only script (existing requirement), backups under a root-owned `0700`
directory, restore extracts a tarball the same root created — no new
privilege boundary is crossed. Rollback restores code only; the
schema-newer-than-code warning (storage.py) closes the silent-data-divergence
gap that rollbacks previously had.

### Release/test tooling

`tools/bump_version.py` (regex rewrites of tracked files, dry-run default in
tests) and the Playwright harness (binds `127.0.0.1`, throwaway data dir,
fixed-argv subprocesses) introduce no production surface.

---

## Carried-forward observations (unchanged, tracked)

- Session tokens remain readable by JavaScript (header-token design,
  localStorage/sessionStorage). Mitigated by the strict no-inline CSP; an
  httpOnly migration would be an architecture change. Unchanged this release.
- The audit log's write path still rewrites the whole document per entry
  (the deferred `list_append` rewrite) — integrity is unaffected (hash chain
  intact and verified in the diagnostics bundle).

**Posture: strong; release-over-release hardening continues.** The durable
summary of RemotePower's security model lives in `docs/security.md`.
