# RemotePower — Security Review (v3.9.0)

Date: 2026-06-03. Scope: a focused re-review on top of the v3.8.0 pass,
covering the v3.9.0 sweep (bind-it-together, alerting/patch-verification
fixes, front-end polish) plus an independent re-trace of the high-risk
sinks. Both the **server** (`server/cgi-bin/api.py` and helper modules)
and the **agent** (`client/remotepower-agent.py`) were reviewed against
the standing brief: authentication/authorization, command execution,
input handling, secrets, transport, SSRF, path traversal, and the
front-end.

The posture remains **strong and hardened release-over-release**. The
v3.8.0 review closed the DNS-rebinding TOCTOU across the webhook,
audit-forward, and OIDC back-channels; this release closes the **one
remaining outbound fetch that was not routed through that guard** — the
HTTP uptime monitor — and tightens inbound alert-link handling.
Everything else re-checked was confirmed defended.

---

## Summary

v3.9.0 adds no new high-privilege machinery. The review therefore
concentrated on (a) the one new/changed outbound fetch path, (b) the new
data-binding paths that move agent-reported fields into storage and the
UI, and (c) regression-checking the v3.8.0 hardening is intact. One
medium-severity SSRF gap was found and fixed; one low-severity
defence-in-depth inconsistency was tightened. No critical or high issues.

| ID | Severity | Status | Title |
|----|----------|--------|-------|
| F1 | Medium   | Fixed  | HTTP uptime-monitor SSRF (string blocklist + no connect-time recheck) |
| F2 | Low      | Fixed  | Inbound-webhook alert links not scheme-validated |

---

## Fixed in 3.9.0

### F1 — HTTP uptime-monitor SSRF closed  (severity: medium)

**Where:** `_sanitize_monitor_target()` (the `http` branch) and the
`mtype == 'http'` check inside `_execute_monitor_checks()`.

**Before:** an `http`/`https` monitor target was validated only by a
literal string-prefix blocklist (`'127.'`, `'10.'`, `'169.254.'`,
`'192.168.'`, `'172.'`, …) tested against `parsed.hostname`, and then
fetched with a bare `urllib.request.urlopen(req, …)`. That is the exact
class of outbound fetch v3.8.0 (F1) hardened for the other channels, but
the monitor leg was missed. Three concrete weaknesses:

1. **No connect-time peer recheck (DNS rebinding).** A target
   `http://attacker.example/` whose DNS resolves to a public address for
   the pre-flight check but to `169.254.169.254` / `127.0.0.1` at fetch
   time would pass the string check and connect to the internal address.
   `urlopen` also follows 3xx by default, widening the surface.
2. **Encoding bypasses of the literal blocklist.** IPv6 loopback
   (`http://[::1]/`), and alternately-encoded IPv4
   (`http://2130706433/` = 127.0.0.1, plus octal/hex) are not matched by
   the prefix list.
3. **Over- and under-blocking.** `'172.'` blocks public 172.32+ while the
   real RFC1918 boundary is 172.16/12; meanwhile the LAN ranges the
   product is *designed* to monitor were blocked unless the operator
   flipped an opt-in.

**After:** the monitor now uses the same shared SSRF machinery as every
other back-channel:

- The sanitizer pre-flights with `_url_targets_local_or_meta(parsed,
  allow_loopback=<allow_internal_monitors>)`, which resolves the host and
  runs the per-IP classifier (`_ip_class_blocked`) — covering IPv6, the
  integer/octal/hex IPv4 encodings, and DNS names.
- The fetch goes through `_ssrf_safe_opener(allow_loopback=…,
  no_redirect=True)`, so the **connected peer IP is re-classified**
  (anti-rebinding) and redirects are refused.
- Cloud-metadata / link-local (`169.254.0.0/16`) and the unspecified
  address are **always** blocked; loopback is blocked unless the operator
  sets `allow_internal_monitors`. RFC1918 private LAN ranges stay allowed
  by design — monitoring an internal service is the normal case, and is
  consistent with how `_ip_class_blocked` treats every other channel.

Verified functionally: the sanitizer now returns `None` for
`169.254.169.254`, `[::1]`, `2130706433`, `127.0.0.1`, and non-`http`
schemes, while accepting public and RFC1918 targets (`tests/test_v390.py
::TestV390MonitorSSRF`).

### F2 — Inbound-webhook alert links scheme-validated  (severity: low, defence-in-depth)

**Where:** the inbound-alert ingest path that stores `links[].url`.

**Before:** an inbound alert's link URLs were stored after only
`_sanitize_str` (length truncation) — unlike the operator quick-links and
CVE reference-links, which use the dedicated `_validate_link_url`
(`http(s)`-only, rejects `javascript:`/`file:` and quote characters).

**Not live-exploitable today** — the Alerts table HTML-escapes every
field and never emits `payload.links` as an `<a href>`, and the strict
CSP (`script-src 'self'`, no `unsafe-inline`) would neutralize a
`javascript:` URI anyway. It was a latent inconsistency: a future
renderer that *did* make these clickable could reintroduce the issue.

**After:** inbound `links[].url` runs through the same `_validate_link_url`
validator; a link whose URL fails validation is dropped rather than
stored.

---

## Re-checked and found defended (no new findings)

The v3.8.0 hardening was re-verified intact, and the high-risk sinks were
re-traced independently:

- **Command injection** — no `shell=True` in `api.py`; every
  `subprocess.run` is argv-based (ping uses `-- target`, GPG batch argv,
  `bash -n` via stdin, Ansible argv with `0600` extra-vars/key files).
  The agent's `exec:` runs a shell by design (server-trusted, allowlist
  enforced server-side) — unchanged.
- **SSRF (other channels)** — webhook sender, audit→SIEM forwarder, and
  OIDC discovery/token fetches still re-validate the connected peer IP via
  `_ssrf_safe_opener` / `_SSRFGuard*Connection`, with `enforce_ip`
  mirroring each path's opt-out. F1 brings the monitor into the same
  model.
- **Tokens / crypto** — device, enrollment, and inbound tokens all compare
  with `hmac.compare_digest`; the query-string token sites use
  `_ct_token_eq`. No new boundary uses `==`.
- **Authorization / IDOR** — device-scoped endpoints honour the caller
  scope (`_caller_scope` / `_device_in_scope`); inbound resolution honours
  a pinned `scope_device_id`. The new `metrics-history` CPU-load series
  reuses the existing scoped `handle_device_metrics_history` (no new
  unauthenticated read).
- **Client IP** — `_get_client_ip` reads only the nginx-set `REMOTE_ADDR`,
  not a client-controlled forwarded header, so rate-limit / IP-allowlist
  decisions can't be spoofed.
- **New bind paths** — the added fields (`canonical`, `loadavg_1m`,
  `cpu_count`, `swap`, rkhunter `last_run_ts`, livepatch `state`) are all
  sanitized on ingest: `canonical` re-uses `_sanitize_unit_name`; the
  numeric series fields are type-checked before use; the rkhunter/livepatch
  fields were already length-sanitized in `_ingest_av` / the kernel
  ingest. No new untrusted value reaches a sink.
- **Front-end** — every dynamically-rendered value in the new/changed
  renderers (services canonical hint, rkhunter pill, livepatch pill, the
  sortable rows) is `escHtml`/`escAttr`-escaped; no new inline handlers or
  styles, so the strict CSP is unaffected.
- **No** `eval` / `exec` / `pickle` / `yaml.load` / unsafe-XML /
  deserialization sinks were introduced.
- **Agent** — strict TLS context (`CERT_REQUIRED`, `check_hostname=True`);
  self-update verifies sha256 with `compare_digest` then an optional
  fail-closed GPG signature; state/cred files `0600`, dirs `0700`,
  `O_NOFOLLOW` reads. Unchanged this release.

---

## Accepted limitations (carried over, unchanged)

These are the same documented acceptances as the v3.8.0 review; nothing in
v3.9.0 changes their status.

- **L1 — `_url_targets_local_or_meta` fails open on DNS-resolution
  failure.** A name that can't be resolved is allowed through (the request
  then fails with a network error). The connect-time peer recheck still
  applies once a connection is actually made, so a name that resolves at
  connect time to a blocked address is still refused. Accepted.
- **L2 — Secrets in `config.json`.** Webhook URLs, SMTP/OIDC credentials,
  etc. are stored in the data dir (root/`www-data`-readable, `0600`
  files). Encryption-at-rest remains out of scope. Unchanged.
- **L3 — Agent command execution runs a shell.** The L3 trust model: a
  device trusts its server; the server-side per-device allowlist and the
  catastrophic-command denylist are the control. Unchanged.
- **L4 — CSRF posture.** State-changing endpoints require the bearer
  token (header), not a cookie sent ambiently, so classic CSRF doesn't
  apply. Unchanged.

---

## Tests

`tests/test_v390.py` pins the F1/F2 fixes and the v3.9.0 behaviour:

- `TestV390MonitorSSRF` — sanitizer blocks metadata / IPv6 / integer-IP /
  loopback / non-http, allows public + RFC1918; the execute path uses
  `_ssrf_safe_opener(..., no_redirect=True)` and no bare `urlopen`.
- `TestV390InboundLinks` — inbound link ingest calls `_validate_link_url`.
- The fix/bind/polish suites pin the patch-verify, metric-threshold, and
  tls_expiry corrections and the new bound fields.

The full suite (`make test`) passes.

---

## What "thorough" means in this review

The findings are file-and-flow specific, traced from untrusted input to
sink rather than asserted from the changelog. F1 was confirmed by
exercising the sanitizer against the bypass encodings; the "re-checked"
list reflects sinks actually re-read this pass, not a restatement of the
prior review. The single new outbound fetch path in the release was the
primary target, and it is now consistent with the rest of the codebase's
SSRF model.
