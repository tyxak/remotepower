# RemotePower — Security Review (v3.8.0)

Date: 2026-06-02. Scope: a focused security re-review covering the
features added since the v3.0.5 review — v3.5.0 (SBOM, lifecycle
expiry, VNC-over-SSH, sites/teams), v3.6.0 (host file/backup/user/SSH-key/
firewall/AV/auto-patch actions, Proxmox backup), v3.7.0 (2FA recovery
codes, audit→SIEM forwarding, credential rotation, config enforce,
maker-checker change approval, Proxmox VM create, Ansible runner), and
v3.8.0 (security hardening + AI-investigate breadth). Both the **server**
(`server/cgi-bin/api.py` and the helper modules) and the **agent**
(`client/remotepower-agent.py`) were reviewed, with the same brief as
prior passes — auth, command execution, input handling, secrets,
transport, SSRF, path traversal, and the frontend.

This release found the posture **strong and clearly hardened
release-over-release**. The genuinely exploitable surface is small: one
residual SSRF gap (DNS-rebinding TOCTOU) is **closed in this release**,
and the agent self-update fail-open window now has an opt-in fail-closed
control. Everything else reviewed was confirmed defended.

---

## Summary

The new v3.5–v3.7 surface adds a lot of high-privilege machinery
(remote file/user/firewall mutation, a back-channel SIEM forwarder, an
OIDC client, an Ansible runner, Proxmox provisioning). The review
checked each for injection, SSRF, IDOR/missing-authz, path traversal,
deserialization, race conditions, and secret handling.

- **One finding fixed in this release** (M1 — SSRF DNS-rebinding TOCTOU
  in the three outbound back-channels).
- **Two defence-in-depth fixes** shipped alongside it (audit-forward TLS
  context, maker-checker device-state recheck).
- **One agent hardening control** added (opt-in mandatory signed
  updates).
- The remaining items are accepted-with-rationale, unchanged in
  substance from prior reviews (L3 — agent runs a shell by design; L4 —
  CSRF posture; secrets-at-rest).

---

## Fixed in 3.8.0

### F1 — SSRF DNS-rebinding (TOCTOU) closed across all outbound back-channels  (severity: medium)

**Was:** `_url_targets_local_or_meta()` resolved the configured hostname
via `getaddrinfo` and classified the IPs (rejecting link-local /
metadata / unspecified, and loopback when configured), but the
subsequent `urllib` request **re-resolved the hostname independently**.
An attacker controlling DNS for a configured host — or running a
rebinding name server — could return a public IP during the pre-flight
check and `169.254.169.254` / loopback during the actual fetch. The
check and the fetch were not pinned to the same address.

Affected three back-channels:

- **Webhook sender** (`fire_webhook` → `_send_one_webhook`) — admin-
  configured target, but still a leak path for cloud-metadata
  credentials into a webhook body.
- **Audit→SIEM forwarder** (`_forward_audit`, http mode) — same.
- **OIDC discovery + token exchange** (`_oidc_discover`, callback token
  POST) — the more interesting vector, because the **IdP** (not the
  admin) supplies the `token_endpoint`/`userinfo_endpoint`/`jwks_uri`
  URLs in the discovery document, lowering the bar to a hostile or
  compromised IdP.

v3.8.0 had already closed the *redirect-based* bypass (a `_NoRedirect`
opener handler) and added SSRF guards to the syslog and OIDC paths, so
this DNS-rebinding window was the residual.

**Fixed:** added connect-time peer-IP re-validation. Two
`http.client` connection subclasses (`_SSRFGuardHTTPConnection`,
`_SSRFGuardHTTPSConnection`) override `connect()` to re-classify the
*actual* peer address after the socket connects, aborting with an
`OSError` if it lands on a blocked class. A `_ssrf_safe_opener(...)`
helper builds a `urllib` opener wired with these connections, the pinned
(verified) TLS context, and — with `no_redirect=True` — the existing
`_NoRedirect` handler. All three back-channels now route through it.

Because the guard runs on the connected socket (not a fresh DNS
lookup), a rebinding attacker that returns a public IP for the
pre-flight check and an internal IP for the fetch is caught at connect
time. Crucially, the connection is still made *by hostname*, so normal
TLS verification (SNI + certificate chain) is untouched — the fix adds
a check, it does not weaken transport security. The IP classifier was
refactored into a shared `_ip_class_blocked(ip, allow_loopback)` used by
both the pre-flight DNS check and the connect-time recheck, so the two
can't drift apart.

### F2 — Audit-forward HTTPS now pins the verified TLS context  (severity: low)

**Was:** `_forward_audit` (http mode) computed `ctx = _get_ssl_context()`
for HTTPS targets but then built the opener **without** passing it —
a dead variable. Verification still happened (urllib's default opener
uses a strict default context), but the code diverged from the
established pattern at every other outbound HTTPS call site and read as
if it pinned a context it dropped.

**Fixed:** the audit forwarder now goes through `_ssrf_safe_opener(...)`,
which pins the verified context onto the `HTTPSHandler` consistently
with the webhook and OIDC paths.

### F3 — Maker-checker approval re-checks device state  (severity: low)

**Was:** when a parked `exec_command` / `reboot_device` /
`run_saved_script` confirmation was approved, `_mcp_execute` re-checked
the per-device exec allowlist only `if device_id in devs`. If the device
was **deleted** between request and approval the branch fell through and
still queued the command (an orphaned queue entry); and a device that
became **quarantined** after the request was parked would still receive
the approved command (the immediate-exec path's quarantine check was not
mirrored on the approval path).

**Fixed:** `_mcp_execute` now rejects the device-targeting actions up
front when the device no longer exists or is quarantined, returning a
clear error instead of queuing. This closes the gap on both the
maker-checker approval path and the direct MCP-tool path.

---

## Agent hardening

### F4 — Opt-in mandatory signed self-updates  (severity: low / by-design)

The agent self-update verifies the downloaded binary against the
server-advertised sha256 and, **if a `release.pub` is pinned**, also
requires a valid detached GPG signature (fail-closed, ephemeral
keyring, `VALIDSIG` required). With no key pinned — the default on a
fresh install — verification is sha256-only, and since the server
dictates both the binary and its expected hash, a compromised server
could push root RCE to every enrolled agent. This is the documented L3
trust model (the server is trusted), not a new vulnerability, but the
signing being off-by-default is the single highest-leverage hardening
item.

**Added:** a `require-signed-updates` opt-in. Touch
`/etc/remotepower/require-signed-updates` on a host and the agent
refuses to install **any** update unless a `release.pub` is pinned and
the download carries a valid signature — flipping the fail-open default
to fail-closed even when no key file is present. The update-rejection is
recorded to the agent state dir (surfaced as the existing
`agent_update_rejected` signal). Recommendation for production: ship
`release.pub` in the installer and set the marker on sensitive hosts.

---

## Accepted limitations / recommendations (state in 3.8.0)

### L1 — `_url_targets_local_or_meta` fails open on resolution failure — accepted

On `socket.gaierror` the pre-flight check returns `False` ("don't block
what we can't classify — it'll fail at connect anyway"). With F1's
connect-time peer re-validation now in place, this pre-flight is an
early-out optimisation, not the security boundary: a name that fails the
pre-flight resolve but later connects to an internal address is still
caught on the connected socket. No change required.

### L2 — Secrets in `config.json` — unchanged

Env-var overrides (`RP_PROXMOX_TOKEN_SECRET`, `RP_SMTP_PASSWORD`,
`RP_LDAP_BIND_PASSWORD`) remain available, the file stays `0600`, and
the backup export redacts secrets. The v3.7.0 credential vault
(`cmdb_vault`) is a positive addition here: PBKDF2-SHA256 @ 600k
iterations, AES-GCM with a fresh random nonce per encrypt, passphrase
never persisted, canary verified with `hmac.compare_digest`, rotation
re-encrypts and persists atomically. Encryption-at-rest for
`config.json` itself remains larger work, not called for unless
deployment context changes.

### L3 — Agent command execution runs a shell — unchanged

Inherent to what RemotePower is — a remote command runner. The
per-device `allowed_commands` allowlist is a strict membership check;
the denylist fallback is a small substring list and is **not** the
security boundary. The boundary is `require_perm('exec')` + the audit
log, plus (v3.7.0/v3.8.0) maker-checker change approval with
separation-of-duties (`change_approval_no_self`). v3.8.0 correctly
re-applies the allowlist at both the park step and the approval step, so
enabling the governance control can't smuggle a denied command through
the queue. No change recommended.

### L4 — CSRF posture — unchanged

Same trade-off: the session token lives in `localStorage` /
`sessionStorage` and is sent via a custom header, so cookie-borne CSRF
doesn't apply, and the strict CSP (from v3.0.5, re-confirmed below)
mitigates the XSS exposure of token storage.

---

## Reviewed and found defended (posture documentation)

Re-verified line-by-line in this pass:

- **Exec allowlist / maker-checker** — allowlist re-checked at park *and*
  approval (v3.8.0); approval flips status under the file lock before
  out-of-lock execution; already-decided entries 409; self-approval
  blocked.
- **2FA recovery codes** — 40-bit random, bcrypt-hashed, consumed
  **atomically under a file lock** (v3.8.0) so concurrent logins can't
  double-spend one code; failures feed the per-username lockout +
  per-IP limit + timing-defence delay.
- **Ansible runner** — no `shell=True`; argv list; host alias and IP
  regex-sanitised into the inventory; SSH password passed via a `0600`
  JSON extra-vars file (not the INI — closes a host-vars injection
  vector); SSH key in a `0600` tempfile; workdir always `rmtree`'d;
  skips quarantined devices; `exec`-gated.
- **Proxmox VM/LXC create** — every field regex/range-validated; body
  `urlencode`'d (no shell); admin-only + audited; `verify_tls` defaults
  on; token never logged; an action allowlist blocks
  migrate/clone/delete.
- **Host user / SSH-key / firewall actions** — username and pubkey
  validated against strict regexes with no shell metacharacters in the
  allowed charset; firewall port int-validated, proto/action/backend
  allowlisted. No injection.
- **`ssh_exec` / VNC-over-SSH** — argv list, never `shell=True`; explicit
  leading-`-` guard against `-oProxyCommand=` argv injection; key in a
  `0600` tempfile; password via `$SSHPASS` env, not argv.
- **LDAP auth** — filter assertion value RFC-4515-escaped before
  formatting; transient vs denied errors don't leak directory
  availability to the client.
- **Audit→SIEM forwarder** — SSRF-guarded (now incl. F1), redirect
  bypass blocked, syslog target also guarded, payload length-capped,
  fully wrapped so a forwarding outage can't break audit logging.
- **CSP report endpoint** — unauthenticated by necessity
  (browser-originated) but body-size capped, per-IP throttled, written
  through `audit_log` which JSON-encodes and length-truncates every
  field (no log injection, no unbounded growth).
- **SNMP client** — pure-stdlib BER parser over untrusted UDP; Python
  slicing is memory-safe, so a malicious responder yields a caught
  exception, not corruption.
- **Auth core** — 256-bit session tokens; API-key scan fully
  constant-time with no early exit; role re-read from the live user
  record each request (demotion is immediate); TTL enforced; login
  per-IP and per-username rate-limited with dummy-hash timing defence;
  bcrypt cost 12 with PBKDF2 600k fallback; `_validate_id` blocks path
  traversal in every id-addressed file op.
- **MCP write path** — gated by an mcp-role-only server-side action
  allowlist; destructive actions honour per-device confirmation; params
  validated before parking; client-supplied `X-MCP-*` headers used only
  as truncated audit strings, never as a boundary.
- **Frontend / CSP** — re-scanned: no inline scripts, no inline event
  handlers, no inline `style=` attributes injected via `innerHTML`, no
  `<style>` injection, no `javascript:` URIs, no `eval` / `new
  Function`. The strict CSP (`script-src 'self'; style-src 'self'`, no
  `'unsafe-inline'`) remains intact on the live deployment, with HSTS
  now enabled (`max-age=63072000; includeSubDomains; preload`).
- **Agent self-update** — when a key is pinned the verification is sound
  (ephemeral keyring, `VALIDSIG` required, fail-closed, atomic
  `mkstemp`+`chmod`+`move` install).

No injection, IDOR, auth-bypass, deserialization, or path-traversal
issue was found in the new v3.5–v3.8 surface.

---

## Tests

`tests/test_v380.py` carries the v3.8.0 security regressions:

- `test_audit_forward_no_redirect_and_syslog_ssrf` — verifies the
  audit-forward http path uses the connect-time SSRF-guarded opener with
  no-redirect-follow, and the syslog target is SSRF-checked.
- `test_ssrf_connect_time_peer_revalidation` — verifies the
  `_SSRFGuard*Connection` peer recheck and `_ssrf_safe_opener` exist and
  are wired into the webhook / audit / OIDC senders (anti-rebinding).
- `test_require_signed_updates_fail_closed` — verifies the agent refuses
  an unsigned update when `require-signed-updates` is set and no key is
  pinned.
- `test_makerchecker_rejects_deleted_or_quarantined_device` — verifies
  the approval path rejects device-targeting actions for a
  missing/quarantined device.

The earlier per-feature security tests (2FA recovery atomicity,
allowlist re-check on approval, Ansible extra-vars hardening, SFTP
size-before-decode) continue to pass. Full suite green.

---

## What "thorough" means in this review

This pass enumerated every new high-privilege code path added since
v3.0.5 and traced it end-to-end:

| Surface | State |
|---|---|
| Webhook / audit-forward / OIDC back-channels | F1 fixed (anti-rebinding) |
| Maker-checker change approval | F3 fixed (device-state recheck) |
| Ansible runner | clean (argv, sanitised inventory, 0600 secrets) |
| Proxmox VM/LXC create | clean (validated, urlencoded, allowlisted) |
| Host file/user/key/firewall/AV actions | clean (validated, no shell injection) |
| Credential vault (`cmdb_vault`) | clean (AES-GCM, fresh nonce, atomic rotate) |
| 2FA recovery codes | clean (bcrypt, atomic consume) |
| Agent self-update | F4 hardening control added |
| Agent exec / trust boundary | unchanged-by-design (L3) |
| Frontend / CSP | clean (re-confirmed strict, no `unsafe-inline`) |
