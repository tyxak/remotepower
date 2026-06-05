# RemotePower — Security Review (v3.13.0)

Date: 2026-06-04. Scope: a focused re-review on top of the v3.8.0 → v3.12.0
passes, covering the v3.13.0 "bind it together" sweep plus an independent
re-trace of the high-risk sinks across the **server** (`server/cgi-bin/api.py`
and helper modules) and the **agent** (`client/remotepower-agent.py`), against
the standing brief: authentication/authorization, command execution, input
handling, secrets, transport, SSRF, path traversal, deserialization, and the
front-end.

The posture remains **strong and hardened release-over-release**. No new
CRITICAL or HIGH server- or agent-side issues were found. Prior-review fixes
(SSRF anti-rebinding across webhooks / audit-forward / OIDC / monitors,
image-registry SSRF + credential exfiltration, the `/api/config` secret scrub,
the TCP-monitor IP-class check) were all verified intact. This release tightens
four defence-in-depth gaps and confirms the rest of the surface defended.

---

## Summary

The review concentrated on (a) the paths that render or serve
agent-/IdP-supplied content to an operator's browser; (b) the OIDC back-channel
token handling; and (c) the remaining raw-socket outbound path. Four MED/LOW
items were addressed; the front-end CSP migration was confirmed complete
(production already serves `script-src 'self'; style-src 'self'` with no
`unsafe-inline`), and the agent's command channel, self-update verification, and
container-management paths were re-checked clean.

---

## Findings addressed

### 1. (MED) Agent-supplied SCAP report served inline without a self-contained CSP
`server/cgi-bin/api.py` — `handle_scap_report_download`.

A device submits an arbitrary OpenSCAP/usg HTML report (`report_html_gz`,
authenticated by device id + token); it is stored verbatim and later served to
an operator at `GET /api/scap/<id>/report` as `text/html`,
`Content-Disposition: inline`, on the application origin. A compromised agent (or
anyone holding a device token) could embed `<script>` and have it execute in the
operator's session. Exploitation was blocked only by the **global** nginx CSP —
which a future deployment change or a location that sets its own `add_header`
(silently dropping inherited headers) could remove.

**Fix.** The handler now emits a **self-contained sandboxed CSP** for the report
response — `default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline';
font-src data:; sandbox;` — plus `X-Frame-Options: DENY`. The report renders
normally (it is static tables with inline CSS), but scripts, forms, and
same-origin access are neutralised regardless of the upstream policy. The defence
no longer depends on the global CSP.

### 2. (LOW) OIDC `id_token` accepted without standard claim checks
`server/cgi-bin/api.py` — OIDC callback.

The confidential-client back-channel posture (TLS + `client_secret` + SSRF-
guarded fetch + state/nonce) is sound and matches RFC 6749 §10.12, but the
`id_token` was consumed with no `exp` / `iss` / `aud` validation, leaving a
narrow window for replay of a leaked token or cross-relying-party token
confusion (both already requiring the one-time `state`).

**Fix.** After the nonce check the callback now rejects an **expired** token
(120 s clock-skew allowance), an **issuer** that doesn't match the configured
`oidc_issuer`, and an **audience** that isn't this `oidc_client_id` (string or
list form). These are cheap claim checks layered on top of — not a replacement
for — the existing channel trust.

### 3. (LOW) Syslog audit-forward re-resolved its target after the SSRF check (TOCTOU)
`server/cgi-bin/api.py` — `_audit_forward`, `mode == 'syslog'`.

The SSRF guard resolved and classified the configured syslog host, then
`socket.create_connection` / `sendto` re-resolved it independently — a DNS-
rebinding window the HTTP forwarder closes with connect-time peer revalidation
but the raw-socket path did not. The destination is admin-configured (low
practical risk) and the path only *sends* a log line.

**Fix.** The forwarder now resolves the target **once** via `getaddrinfo`,
classifies that literal IP with the existing `_url_targets_local_or_meta` guard,
and connects to the literal IP (correct address family for UDP) — no second,
unchecked resolution.

---

### 4. (LOW) SSRF IP classifier missed IPv6-embedded IPv4 and multicast/reserved
`server/cgi-bin/api.py` — `_ip_class_blocked`.

The shared per-IP SSRF classifier blocked link-local (so the
`169.254.169.254` cloud-metadata address was covered), unspecified, and
loopback, but did not unwrap IPv6 forms that *embed* an IPv4 address — 6to4
(`2002::/16`) and the NAT64 well-known prefix (`64:ff9b::/96`) — so a target
such as `64:ff9b::a9fe:a9fe` (169.254.169.254 wrapped) was classified global
and allowed. Exploitation required an environment that actually routes those
prefixes to the metadata service, and `getaddrinfo` to return such an address,
so practical risk was low — but it is a real gap in defence-in-depth.

**Fix.** `_ip_class_blocked` now unwraps v4-mapped (`::ffff:a.b.c.d`), 6to4 and
NAT64-embedded IPv4 and re-classifies the inner address, and additionally
rejects multicast and reserved ranges. Loopback is decided first (so a
deliberately-allowed loopback target is unaffected — `::1` is itself
`is_reserved`), and RFC1918 private ranges remain allowed by design for LAN
fleets.

---

## Verified clean (no change)

- **CSP migration complete.** Production serves a strict CSP with no
  `unsafe-inline` in `script-src` or `style-src`; the front-end ships zero inline
  scripts/styles/handlers (all behaviour is delegated via `data-action`). A
  full scan found no inline `on*=` attributes, `javascript:` URLs, `eval`,
  `new Function`, or string-argument timers.
- **Command execution.** No `shell=True` / `os.system` reachable from attacker
  input on the server; Ansible argv is built from validated fields; `ssh_exec`
  retains its `-`-prefix argv-injection guard; agent container/compose actions
  are regex-validated and never use the shell.
- **Agent trust boundary.** Strict TLS (`CERT_REQUIRED` + `check_hostname`,
  HTTPS-only); self-update verifies sha256 with `hmac.compare_digest` and an
  optional fail-closed GPG signature.
- **AuthZ.** RBAC enforced at the dispatch chokepoint plus per-handler scope
  checks; device-token endpoints use constant-time compares and verify device
  ownership (no IDOR). `GET /api/users/<u>/avatar` is `require_auth`-gated and
  serves only non-secret images.
- **Secrets / crypto / path handling / deserialization.** `_scrub_config_secrets`
  recursive scrub intact; bcrypt-12 / PBKDF2-600k, `secrets` tokens,
  `compare_digest`, AES-GCM vault; all user/agent-influenced path segments
  sanitised; no `pickle` / `yaml.load` / `eval` of untrusted data.

---

## Front-end hardening (defence-in-depth, shipped this release)

- `escHtml` now also escapes single quotes, matching the other escape helpers.
- The update-banner release-notes link is scheme-validated (http/https only)
  before render.

No outstanding issues. The reviewed surface is consistent with the strong
posture of prior releases.

---

## Addendum — v3.13.0 new-surface audit + external scan

The large v3.13.0 feature set added new endpoints that were given a dedicated
review: the controller **backup/restore**, fleet **host-config collect/export**,
the **software-center** inventory catalog, **drift profiles** CRUD, the
fleet-risk cache, the network-mount collectors, and the targeted **AI buttons**
(which send a raw system-prompt to `/api/ai/chat`).

**Result: no CRITICAL or HIGH issues.** Highlights verified clean: restore
extraction rejects symlinks/hardlinks/devices, absolute paths, `..`, and any
realpath that escapes the data dir, and takes a pre-restore safety snapshot;
collect-all queues a fixed command (no injection) and is admin-only; export and
the inventory catalog are RBAC scope-filtered; drift-profile mutations are
admin-only with absolute-path validation; agent collectors use fixed argv
subprocess calls (no shell). Two **LOW** items were fixed:

- **Restore decompression-bomb guard** — the uploaded tarball is capped at 50 MB
  compressed, but the *uncompressed* size was unbounded; a crafted gzip could
  fill the data-dir filesystem. Restore now rejects archives whose cumulative
  uncompressed size or member count exceeds a bound (admin-only either way).
- **AI-chat RBAC isolation** — `/api/ai/chat` injected an unscoped fleet snapshot
  and RAG corpus, so a scoped/viewer role could pull out-of-scope device data
  into the AI context. The fleet snapshot is now scope-filtered to the caller,
  and RAG retrieval is restricted to full-access (admin) callers.

Two non-cryptographic SHA-1 *fingerprint* hashes (log-line and attention-item
dedupe keys) flagged by static analysis were annotated `usedforsecurity=False`
(they were never used for security; the digest is unchanged).

## External SAST + DAST scan

A full combined scan was run against a deployed instance and the source:

- **SAST:** Bandit over the server + agent Python.
- **DAST:** OWASP ZAP full active scan, Nikto, Nuclei, Wapiti, WhatWeb.

**Outcome: no exploitable findings.** Nuclei and the dependency-CVE check were
empty; ZAP's single "High" (a cloud-metadata probe) was a false positive — the
probed path returns a plain 404 and there is no `proxy_pass $host` upstream, so
metadata SSRF is structurally impossible; the remaining items were informational
(CSP notices, unix-timestamp and internal-IP disclosures inherent to a fleet
dashboard). Bandit surfaced only the fingerprint-hash nits above plus the
expected, accepted patterns (SSRF-guarded outbound clients, argv subprocess
calls). A separate operational note (not a code issue): keep source backups out
of the web-served `cgi-bin/` directory.
