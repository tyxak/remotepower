# RemotePower — Security Review (v4.4.0 "FortifyMatters")

Date: 2026-06-13. Scope: a full read of every server handler (`api.py` and all
sibling modules) and all three agents (Linux, Windows, macOS) against the
standing brief — authentication/authorization, command execution, input
handling, secrets, transport, SSRF, path traversal, and the front-end — rather
than only the release delta. This was the security-themed release, so the audit
was deliberately broad.

**One CRITICAL and several HIGH issues were found and fixed in this same
release** (below). The rest of the surface was confirmed clean, including the
v4.2.0 passkey/MFA-bypass fix, path-traversal containment on every user-named
file operation, constant-time token comparison, and the recursive config secret
scrub.

## Independent scanning

- **Independently pentested clean.** The web-facing surface was scanned with
  **wapiti, nikto, nuclei, bandit and OWASP ZAP**. No exploitable findings —
  only informational items (standard headers are already present: CSP without
  `unsafe-inline`, HSTS, `X-Frame-Options: DENY`, `X-Content-Type-Options`,
  Referrer-Policy, Permissions-Policy). The production CSP was verified live to
  serve `script-src 'self'; style-src 'self'` with no inline allowance.
- **bandit** was run across the changed modules; no HIGH findings. The
  remaining LOW flags are intentional and reviewed (best-effort `try/except
  pass` in cleanup paths, fixed-argv `subprocess` calls).

---

## Fixed during this review (all shipped in v4.4.0)

- **[CRITICAL] Custom-role privilege escalation through the admin gate.**
  `require_auth(require_admin=True)` enforced admin-only access with a string
  denylist — `role in ('viewer', 'mcp')`. A **custom operator role** (a shipped,
  admin-creatable RBAC feature, assignable to a login account) is neither
  `viewer` nor `mcp`, so it passed the gate and reached every admin-only
  endpoint: user creation/promotion, role and API-key management, config save,
  and — most seriously — the agent-update **signing-key** generation endpoint
  (a path to fleet-wide code execution). Fixed by gating on the *resolved* role
  record (`_resolve_role(role)['admin']`), which marks only the built-in admin
  role as admin. Built-in `viewer`/`mcp` behaviour is unchanged; custom roles
  are now correctly confined to their granted permissions and device scope. This
  is the single highest-impact fix in the release.
- **[HIGH] Cross-scope read on the mitigation diagnostic routes.** The
  mitigation *status* (returns up to 256 KB of captured command output) and
  *AI-analysis* endpoints live outside the `/api/devices/` prefix, so the
  central `_enforce_device_scope` guard didn't apply, and they gated on
  `require_auth()` only. A scoped operator/viewer could read another scope's
  diagnostic capture. Both now call `_scope_block_device(dev_id)`, matching the
  read-scoping the rest of the per-device API already had.
- **[HIGH] Shell-quoting break-out on queued commands.** The drift "fetch file
  content" action built `exec:cat '<path>'` with naive single-quoting around a
  device `watched_files` path that has no metacharacter filter at ingestion — a
  path containing a quote broke out into agent RCE for anyone holding the
  device-update privilege. The ACME issue/renew/revoke commands interpolated the
  agent-reported `home` directory the same way. Both now use `shlex.quote`.
- **[HIGH] Agent local privilege escalation via predictable tempfile.** The
  on-host lynis posture audit (runs as root) wrote its report to a fixed
  `/tmp/rp-lynis-report.dat`; a local unprivileged user could pre-plant a
  symlink there and have the root agent clobber an arbitrary file. Now uses
  `tempfile.mkstemp` (unpredictable, `O_EXCL`) and unlinks after parsing.
- **[HIGH] Windows/macOS agents accepted plain HTTP.** Unlike the Linux agent,
  the Windows and macOS agents did not reject `http://` server URLs and used the
  default TLS context (verifies certs, but permits TLS 1.0/1.1). A misconfigured
  or downgraded `--server` could send the device token and command output in
  cleartext and let a MITM inject commands the agent runs as SYSTEM/root. Both
  now refuse non-HTTPS URLs and pin a TLS 1.2 floor, matching the Linux agent.
- **[MEDIUM] RouterOS REST SSRF.** The RouterOS integration (reachable by any
  authenticated user) fetched its device-configured host with no anti-rebinding
  check. A pre-flight now blocks loopback and link-local/cloud-metadata
  addresses while still allowing the RFC1918 LAN address a real router uses.
- **[MEDIUM] Metrics scrape availability.** `/api/metrics` had no exception
  guard around exposition generation, so one malformed store record 500-ed the
  entire scrape and broke Prometheus monitoring fleet-wide. It now degrades to a
  minimal valid payload plus a `remotepower_scrape_error` gauge, and per-record
  loops skip non-dict entries.

---

## Reviewed clean (no action)

- **Passkey / MFA-bypass (v4.2.0 fix) holds.** Password-only login for a
  passkey-only user returns `webauthn_required` and never mints a token;
  SAML/OIDC/LDAP all derive role from server-side group mapping with a
  viewer-default (no IdP-attribute→admin spoof); WebAuthn enforces challenge
  single-use, origin/RP-ID binding, user-handle binding, and sign-count
  regression.
- **Path traversal.** Avatar, SCAP, ACME, IaC and backup-restore all sanitize
  the user-supplied component (strict regex or `_validate_id`) or use
  realpath-containment before joining — no traversal found.
- **Token comparison.** Sessions are SHA-256-keyed dict lookups; API keys use a
  full-scan `hmac.compare_digest` (no early-exit timing oracle); the status
  token uses a constant-time compare.
- **Config secret leakage.** Explicit per-key redaction plus a recursive
  backstop scrub; webhook URLs are blanked for non-admins; the AI API key is
  admin-only and masked. No MCP-readable usable secret.
- **Subprocess surface.** No `shell=True`/`os.system` on the server outside the
  intended, now-quoted command channel; argv lists throughout; ssh_exec rejects
  `-`-prefixed host/user (option-injection). The agent's `exec:` channel is the
  documented, device-token-authenticated operator command path, not a vuln.
- **Agent update integrity.** sha256 checked with `hmac.compare_digest`; opt-in
  signed-updates verify a detached GPG signature against a pinned local key in
  an ephemeral `0700` keyring and fail closed; the binary is written via
  `mkstemp` + atomic move.

---

## Carried-forward observations (tracked, unchanged)

- Session tokens remain readable by JavaScript (header-token design). Mitigated
  by the strict no-inline CSP; an httpOnly migration would be an architecture
  change.
- A few admin-only integration fetches (Proxmox, OPNsense, the AI provider
  base-URL, SNMP) connect to operator-configured destinations without the full
  anti-rebinding recheck. They are admin-configured (not arbitrary user input)
  and lower-risk than the now-fixed viewer-reachable RouterOS path; threading
  the shared SSRF opener through these sibling modules is tracked as a
  follow-up.
- TOTP codes are accepted without recording a used-counter, so a code is
  replayable within its ~60–90 s window. Low impact (rate-limited login, short
  window); a used-counter check is tracked for a future release.

**Posture: strong. The critical class is closed and the agents are at transport
parity across all three platforms.** The durable summary of RemotePower's
security model lives in `docs/security.md`.
