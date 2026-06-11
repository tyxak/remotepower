# RemotePower — Security Review (v4.2.0 "5ecur1tyM4tter5")

Date: 2026-06-10. Scope: a focused security re-review on top of the
v4.0.0 → v4.1.0 passes, covering the v4.2.0 feature work — **authorized
vulnerability scanning** (the scan orchestration engine, scanner satellites, the
sandboxed tool runners in `client/remotepower-scanner.py`, the ACME-style domain
ownership verification, and the active-tier gating), **passkeys / WebAuthn**
(`server/cgi-bin/webauthn_auth.py`), **SAML 2.0 SSO** (`server/cgi-bin/saml_auth.py`),
the **tamper-evident audit log** hash-chain, and the account guardrails (MFA
enforcement, session caps, API-key expiry, the posture self-check) — plus an
independent re-trace of the high-risk sinks across the **server**
(`server/cgi-bin/api.py` and helper modules) and the **agent**
(`client/remotepower-agent.py`, `client/remotepower-satellite.py`,
`client/remotepower-scanner.py`), against the standing brief:
authentication/authorization, command execution, input handling, secrets,
transport, SSRF, path traversal, deserialization, and the front-end.

The posture remains **strong and hardened release-over-release**. **No CRITICAL
or HIGH server- or agent-side issues were found.** One **Medium**
authorization gap was found and fixed in this release (below). Prior-review
fixes (SSRF anti-rebinding across webhooks / audit-forward / OIDC / monitors /
scan-domain verification, image-registry SSRF + credential exfiltration, the
`/api/config` recursive secret scrub, IP-class checks, session tokens hashed at
rest) were all verified intact.

## Independent scanning

This release was independently scanned and passed **clean**:

- **wapiti** — black-box web application scanner
- **nikto** — web server / misconfiguration scanner
- **nuclei** — templated vulnerability scanner
- **bandit** — Python static analysis (server + agent source)
- **OWASP ZAP** — active + passive web scan

No exploitable findings were reported by the above tooling against the running
application or the source — only informational items and false positives.

---

## Fixed in v4.2.0

- **[Medium] Scan-schedule endpoints were not role-scope enforced.** A custom
  role holding the (independently scopeable) `scan` permission restricted to a
  device subset could list, run-now, or delete recurring scan schedules that
  targeted hosts **outside** its scope (the one-off scan path was already scoped;
  the three schedule handlers gated only on the bare `scan` permission). Fixed by
  threading the caller's scope through `handle_scan_schedules_list` (filter),
  `handle_scan_schedule_run` and `handle_scan_schedule_delete` (refuse with 403)
  via a shared `_scan_sched_in_scope` helper that mirrors the create-path rule:
  an all-scope caller sees everything; a scoped caller may only act on a
  device-targeted schedule whose host is in scope, never a domain/scan-target
  schedule. Not remotely exploitable (requires an authenticated, partially
  privileged operator), and the scan target is still always derived server-side,
  so the worst pre-fix outcome was a scoped operator scheduling a scan of an
  in-fleet host outside their slice — now closed.

## Fixed in the post-release sweep (2026-06-11)

A second adversarial pass over the v4.2.0 surface (and a whole-project
re-trace) found and fixed the following. All were fixed the same day:

- **[High] Passkey-only accounts could sign in with a password alone.** The
  password-login path enforced a second factor only when a TOTP secret was
  enrolled; a user whose sole MFA was a passkey received a full session from
  username+password — silently defeating the per-role MFA policy for exactly
  the users who chose the phishing-resistant option (and the posture page
  showed them as fully protected). `handle_login` now refuses to mint a
  session for an account with registered passkeys until a WebAuthn assertion
  completes (the UI hands off to the passkey ceremony automatically); a
  one-time recovery code remains the break-glass fallback, and if the
  WebAuthn library is removed the login degrades rather than locking everyone
  out.
- **[Medium] `webauthn_enabled` gated nothing.** Setting the flag to false
  did not disable passkey registration or passwordless login — the kill
  switch was cosmetic. Every ceremony handler now honours the flag (default
  ON when the library is present); disabling it revokes passwordless login
  immediately, and the login-page button is shown only when the server
  confirms support.
- **[Low] Scan-target file verification allowed loopback.** The
  `/.well-known` ownership probe used the SSRF-safe opener with
  `allow_loopback=True`, leaving a blind, admin-only boolean oracle against
  services on the server's own loopback. Now `allow_loopback=False`, matching
  the scan-time denylist (and the documented behaviour).
- **[Low] Passkey login-begin enumerated accounts.** The unauthenticated
  `/api/webauthn/login/begin` returned a distinguishable 404 for unknown /
  passkey-less usernames and had no rate limit. It now shares the password
  login's per-IP rate bucket and returns a normal-looking challenge with an
  empty allow-list for unknown users (no challenge is stored, so the ceremony
  can never complete).
- **[Hardening] Audit writes are now atomic.** `audit_log()` did an unlocked
  load→append→save; two concurrent requests could silently drop an entry —
  indistinguishable from the tampering the hash-chain exists to detect. The
  whole read-hash-append-prune is now one `_LockedUpdate` unit (and the few
  call sites that held another lock were rearranged to audit after release).
  Session minting on login and scan-schedule deletion got the same treatment.
- **[Hardening] Chain integrity is now ambient, not click-only.** The Audit
  page verifies the hash-chain on load and shows a persistent intact/tamper
  badge, and the security-posture self-check gained an `audit_chain` row — a
  broken chain now surfaces without an operator thinking to press "Verify".

Accurate scope note for the tamper-evidence guarantee: the chain detects
modification or deletion of retained, chained entries; deletion of a contiguous
*prefix* (or the whole file, by an attacker with filesystem access to the
per-install HMAC key) is outside the threat model — the recommended mitigation
for that class is `audit_forward_enabled` to an external SIEM, which the
posture self-check already scores.

## New surface reviewed clean

- **Authorized scanning — authorization is server-side and cannot be forged.**
  The scan target is never client-supplied: for an enrolled device it is the
  validated IP from the device record (`_scan_target_for_device`, `_sanitize_ip`
  + `_ip_class_blocked` denylist); for a domain/vhost it must match an
  ownership-**verified** scan target whose value passed the anchored
  `_classify_scan_target` regex (so it cannot begin with `-` — no tool
  option-injection). Domain ownership is proven ACME-style (DNS TXT or a fixed
  `.well-known` path fetched through the connect-time anti-rebinding
  `_ssrf_safe_opener`, `no_redirect=True`). Private/loopback ranges are refused.
- **Scanner satellite trust.** The claim/results endpoints authenticate with
  `hmac.compare_digest` against a token stored only as a SHA-256 hash, require
  the `scanner` capability, derive the target server-side, and accept results
  only for a job the satellite actually claimed (`claimed_by`) — a satellite
  cannot choose its own target or complete someone else's job.
- **Tool sandboxing.** Every tool runs as an argv list (no shell, no string
  interpolation) in a container with `--cap-drop ALL`, `--no-new-privileges`,
  `--pids-limit`, `--rm` and a unique `--name`, force-removed on timeout, with an
  orphan sweep — closing the container-leak class seen in pre-release testing.
- **WebAuthn / passkeys.** No hand-rolled crypto (the vetted `py_webauthn`
  library); registration/authentication challenges are one-time and TTL-bounded;
  a sign-count regression (cloned-authenticator signal) is refused before any
  session is minted; only the public key is stored.
- **SAML 2.0.** No hand-rolled XML/signature handling (`pysaml2` + `xmlsec1`);
  signature, audience and validity-window checks are delegated to the library and
  RemotePower adds `InResponseTo` + one-time-use replay protection; the SP holds
  no private key (the stored `saml_idp_x509_cert` is the IdP's public cert); the
  IdP entity-id/SSO-URL/cert never leak pre-login (only a `saml_enabled` boolean
  on `/api/public-info`).
- **Tamper-evident audit log.** Each entry is HMAC-SHA256-chained to its
  predecessor; `/api/audit-log/verify` reports the first break; the log can only
  be cleared after an admin password re-prompt, and a clear writes an immutable
  pre-wipe archive first.
- **Account guardrails.** MFA enforcement, session caps, and API-key default
  expiry are all enforced server-side (the cap in both session-mint sites, the
  key expiry in `verify_token`, the MFA gate in dispatch), not cosmetic.

## Standing posture (verified intact)

bcrypt (cost 12, PBKDF2-HMAC-SHA256 fallback at OWASP-2023 parameters) behind
rate-limited login with a lockout ladder; TOTP **and now passkeys** for MFA;
256-bit header-based session tokens (CSRF-safe by construction), hashed at rest;
a strict CSP with **no `'unsafe-inline'`** (`script-src`/`style-src 'self'`,
verified live); AES-GCM CMDB vault (fresh nonce per encrypt); mandatory TLS
verification with a TLS 1.2 floor and connect-time anti-rebinding on every
server-initiated fetch; `O_NOFOLLOW` agent state files; recursive `/api/config`
secret scrub. No deserialization of untrusted input (JSON only).

---

The full standing posture and threat model live in
[security.md](security.md).
