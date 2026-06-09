# RemotePower — Security Review (v4.1.0 "VisualMatters")

Date: 2026-06-09. Scope: a focused re-review on top of the v3.8.0 → v4.0.0
passes, covering the v4.1.0 feature work — the per-host Checks engine, custom
checks (server- and agent-evaluated), the expanded active monitors (DNS / ICMP /
HTTP-assertion / credential-less DB liveness), the composable dashboard, the
host-grouped alert inbox, and the agent's mail-queue probe — plus an independent
re-trace of the high-risk sinks across the **server** (`server/cgi-bin/api.py`
and helper modules) and the **agent** (`client/remotepower-agent.py` and
`client/remotepower-satellite.py`), against the standing brief:
authentication/authorization, command execution, input handling, secrets,
transport, SSRF, path traversal, deserialization, and the front-end.

The posture remains **strong and hardened release-over-release**. **No CRITICAL
or HIGH server- or agent-side issues were found.** Prior-review fixes (SSRF
anti-rebinding across webhooks / audit-forward / OIDC / monitors, image-registry
SSRF + credential exfiltration, the `/api/config` secret scrub, the TCP-monitor
IP-class check, session tokens hashed at rest) were all verified intact. This
release tightens transport and one defence-in-depth gap and confirms the new
surface defended.

## Independent scanning

This release was independently scanned and passed **clean**:

- **wapiti** — black-box web application scanner
- **nikto** — web server / misconfiguration scanner
- **nuclei** — templated vulnerability scanner
- **bandit** — Python static analysis (server + agent source)
- **OWASP ZAP** — active + passive web scan

No exploitable findings were reported by the above tooling against the running
application or the source.

---

## What was tightened in v4.1.0

- **TLS 1.2 floor on every hop.** The relay **satellite** now pins
  `minimum_version = TLSv1_2` on both the agent→satellite listener and the
  satellite→server upstream context; the **agent** pins it on its
  server/satellite connection (on top of `CERT_REQUIRED` + hostname check); and
  the **server's** outbound HTTPS context (`_get_ssl_context`) pins it too.
  Obsolete TLS 1.0/1.1 can no longer be negotiated even where the platform still
  offers them.
- **SSH argv builder hardening (defence-in-depth).** `ssh_agent.build_ssh_argv`
  now rejects a host/user beginning with `-`, mirroring `ssh_exec`, so a stored
  value can never be smuggled as an ssh option. (Not exploitable before — the
  value was joined into a single `user@host` token — but now consistent.)

## New surface reviewed clean

- **Agent-side custom checks** (`eval_agent_checks` / `_eval_one_agent_check`):
  file checks only `os.path.exists` / `os.stat` (never read file content); the
  log-error check passes the operator pattern as a single `journalctl -g` value
  (list form — it can never become a flag) and sanitises the optional unit to
  `[A-Za-z0-9_.@-]`. Definitions are admin-gated server-side, control chars are
  stripped, file/job checks require an absolute path, and numeric extras are
  clamped.
- **DB-liveness monitor** speaks only enough of each wire protocol to confirm the
  server answers — **no credentials are sent or stored** — and reuses the same
  SSRF guard (connect-time peer-IP recheck, `allow_internal_monitors` gate) as
  the TCP monitor.
- **mail-queue probe** is a read-only argv-list invocation with a 1-hour
  back-off when the MTA is broken (no shell, no flood).
- **Dashboard widgets / `/api/home`** add only read-only aggregation; the
  `?w=` enabled-widget hint is validated against the known widget set.

## Standing posture (verified intact)

- **AuthZ**: every state-changing handler enforces auth/admin/permission or a
  constant-time status token; RBAC scope-filtering applied to alerts, checks and
  device views.
- **Crypto/session**: bcrypt cost 12 / PBKDF2-SHA256 600k; legacy unsalted
  SHA-256 rejected; all token comparisons constant-time; header-only auth (no
  cookies) makes CSRF structurally impossible.
- **CSP**: `script-src 'self'; style-src 'self'` with no `unsafe-inline`,
  verified live; zero inline `on*=`/`style=`/`<script>` in shipped HTML or in
  app.js `innerHTML` strings; violations reported to `/api/csp-report`.
- **No** `eval`/`exec`/`pickle`/`yaml` on input; JSON only.
- **Secrets** scrubbed from `/api/config`; webhook tokens redacted; the agent
  ships only redacted previews + fingerprints from its secrets scan.

No outstanding CRITICAL/HIGH/MEDIUM items.
