# RemotePower — Security Review (v2.3.2)

Date: 2026-05-17. Scope: a focused review of the security-sensitive
surfaces of the RemotePower server, agent, and frontend. This is not
an exhaustive line-by-line audit — it concentrates on authentication,
command execution, input handling, secrets, transport, and the
frontend.

This release (2.3.2) applies the two clear, low-risk fixes the
review found. The remaining findings are documented here with
recommendations rather than rushed fixes.

---

## Summary

The overall posture is reasonably good. Earlier releases built in a
number of solid controls — login rate limiting with lockout,
constant-time credential comparison, a username-timing-oracle
defence, TOTP 2FA, agent-to-server TLS verification, an SSRF guard on
monitor targets, secret masking for the SMTP/LDAP/Proxmox
credentials, `0600` data files, and a full set of HTTP security
headers (including a CSP) on both nginx configs.

The review found **two genuine weaknesses worth fixing** and a
small number of **accepted limitations** worth recording.

---

## Fixed in 2.3.2

### F1 — Unsalted SHA-256 password fallback  (severity: medium)

**Was:** when the `bcrypt` library was not installed, `hash_password`
fell back to a bare, unsalted `hashlib.sha256` of the password. The
seeded default admin user was likewise stored as
`sha256(b'remotepower')`. Unsalted SHA-256 is fast and has no
per-hash salt, so a stolen `users.json` is vulnerable to
rainbow-table and high-speed offline cracking.

In practice `bcrypt` is present in the Docker image and the
documented bare-metal install — so this was a fallback path — but a
fallback that silently downgrades password security to "trivially
crackable if the file leaks" is not acceptable.

**Fixed:** the fallback is now salted **PBKDF2-HMAC-SHA256** with a
random 16-byte per-hash salt and 600,000 iterations (the OWASP
floor). It is pure stdlib — no new dependency. Hashes are
self-describing (`pbkdf2$<iters>$<salt>$<digest>`).

Backward compatible: legacy unsalted SHA-256 hashes still verify, and
`maybe_rehash()` now upgrades them — to bcrypt if available, else to
PBKDF2 — on the user's next successful login. Previously a
bcrypt-less server left legacy hashes in place forever.

### F2 — Default password on bare-metal installs  (severity: medium)

**Was:** a fresh bare-metal install seeds an `admin` account with the
well-known password `remotepower`. (The Docker path was fixed in
2.2.6 — it generates a random password and prints it once.) A
bare-metal install left on the default is fully exposed.

**Fixed (partial — see caveat):** the seeded admin is now created
with a proper salted hash (via F1) instead of a bare SHA-256, and is
flagged `must_change_password`. The login response carries this
flag, and the UI shows a persistent red warning banner — "This
account is using the default password, change it now" — linking to
the password-change form. The flag (and banner) clear automatically
once the password is changed.

This does not *prevent* running on the default password — it makes
it impossible to miss. A hard forced-change-before-anything-else flow
was considered but not shipped: it's a larger change with lockout
edge cases, and couldn't be browser-tested here. The loud banner is
the safe, non-breaking nudge. A forced-change flow is a reasonable
future hardening.

---

## Accepted limitations / recommendations (not changed in 2.3.2)

### L1 — CSP uses `'unsafe-inline'` for scripts and styles

The Content-Security-Policy on both nginx configs is solid in most
respects (`default-src 'self'`, `frame-ancestors 'none'`,
`object-src 'none'`, `base-uri 'self'`, `form-action 'self'`) but
`script-src` and `style-src` both include `'unsafe-inline'`.

This is **required** by the current frontend: `index.html` uses ~210
inline `onclick=` handlers and ~470 inline `style=` attributes.
Without `'unsafe-inline'` the app would not function.

Consequence: the CSP blocks *external* malicious scripts, framing,
`<base>` hijacking, and plugin objects — but it does not block an
*injected inline* `<script>` or `onclick`. The defence against that
remains the frontend's `escHtml` / `escAttr` escaping, which is used
consistently (≈244 call sites).

**Recommendation (larger future work):** migrate inline `onclick`
handlers to `addEventListener` registrations and inline styles to
CSS classes, then drop `'unsafe-inline'`. This is a sizeable refactor
and should be its own project — it is explicitly not a quick fix.

### L2 — Secrets are plaintext in `config.json`

The SMTP password, LDAP bind password, and (when not supplied via
the environment variable added in 2.3.1) the Proxmox API token live
in `config.json` in plaintext. The file is `0600` and 2.3.1 made the
backup export redact them, so the realistic leak paths are closed —
but the live file is unencrypted.

**Recommendation:** extend the 2.3.1 `RP_PROXMOX_TOKEN_SECRET`
environment-variable pattern to the SMTP and LDAP passwords
(`RP_SMTP_PASSWORD`, `RP_LDAP_BIND_PASSWORD`). Encryption at rest, or
an OS-level secret store (systemd credentials), is a larger piece of
work. As noted in the 2.3.1 notes, any scheme where the server uses
the secret unattended has the secret recoverable on the host — the
goal is defence against partial access (a leaked file, a backup),
not against full host compromise.

### L3 — Agent command execution runs a shell

The agent executes server-dispatched commands via
`subprocess.run(cmd, shell=True)`. This is inherent to what
RemotePower *is* — a remote command runner — and is not a bug. The
security boundary is the **server side**: the `/api/exec` paths are
admin-gated (`require_admin_auth`), length-capped, and pass through
`_check_exec_allowlist`. That boundary was reviewed and looks sound.

**Recommendation:** none required. Worth keeping in mind that anyone
with an admin token has, by design, full command execution on every
enrolled host — so admin token hygiene and the audit log are the
controls that matter. The audit log does record every exec.

### L4 — CSRF posture

State-changing endpoints are not protected by a CSRF token — but the
session token is sent in a custom `X-Token` header, not a cookie. A
cross-origin attacker's page cannot set a custom header on a request
the browser makes automatically, so classic CSRF does not apply. The
trade-off is the standard one: the token lives in `localStorage` /
`sessionStorage` and is therefore exposed to XSS instead. This is a
reasonable and deliberate design; no change recommended, but it
should be a conscious choice — recorded here so it stays one.

### L5 — Reviewed and found OK

For completeness, areas reviewed that did **not** turn up issues:

- **Login flow** — rate-limited with a 10-minute lockout, constant-
  time password comparison, a dummy-hash verify so a missing
  username can't be timed, TOTP 2FA support, a 0.5s failure delay,
  full audit logging.
- **Token verification** — session tokens are 256-bit
  `secrets.token_urlsafe`; API-key matching does a full constant-time
  scan with no early exit (no timing oracle on key prefixes).
- **Agent transport** — verifies the server's TLS certificate
  (`CERT_REQUIRED`, hostname checking on); credentials file is
  `0600`.
- **SSRF** — monitor HTTP targets are checked against private /
  loopback / link-local ranges, with an explicit opt-in config flag
  for intentional internal monitoring.
- **Path traversal** — resource IDs are validated against a strict
  `^[A-Za-z0-9_\-]{1,64}$` allowlist.
- **Data file permissions** — JSON data files are created `0600`.
- **HTTP security headers** — both nginx configs ship
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy`, `Permissions-Policy`, and a CSP (see L1 for the
  one caveat). HSTS is present but commented out — enable it once
  the deployment is HTTPS-only.

---

## Tests

`tests/test_v232.py` (11 tests): PBKDF2 round-trip, salting (two
hashes of the same password differ), iteration-count floor, legacy
SHA-256 backward compatibility, `hash_password` never emits a bare
digest, garbage/corrupt-hash handling, default user re-seed format
and `must_change_password` flag, frontend banner present, both nginx
configs still carry the security headers.

Total: **940 tests, all passing.**
