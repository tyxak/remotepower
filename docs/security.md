# Security notes

For a structured threat/mitigation matrix organized by attacker goal
(spoofing, tampering, repudiation, information disclosure, denial of
service, elevation of privilege) rather than by feature, see
[threat-model.md](threat-model.md).

- Use HTTPS for anything internet-facing
- Session tokens are configurable (default 30-day remember-me / 24-hour standard); API keys default to never-expire — set a per-key expiry, or rotate manually if compromised
- Enrollment PINs are single-use, expire after 10 minutes
- Device tokens are 256-bit random secrets
- Passwords hashed with **bcrypt** (cost 12), with a **PBKDF2-HMAC-SHA256** (600 000 iterations, OWASP 2023 minimum) fallback where bcrypt is unavailable; legacy hashes auto-upgraded on next login
- Webhook URLs (legacy single + multi-destination) stored server-side only, redacted from backup exports
- CMDB vault uses AES-GCM with PBKDF2-derived keys; passphrase never persisted server-side
- Custom commands run as root - use the per-device command allowlist for untrusted operators
- Viewer role users cannot queue commands, change config, or access API keys
- `apikeys.json`, `tokens.json`, and `users.json` are owned by the app-server user mode `700` - protect your server
- Agent state files (`/var/lib/remotepower/` mode `0700`) use `O_NOFOLLOW` on every read/write to defeat symlink attacks from local non-root users
- **Session tokens are hashed at rest** — `tokens.json` is keyed by the SHA-256 of the bearer token, never the token itself, so a leaked file yields no usable session
- Agents verify the server's TLS certificate (`CERT_REQUIRED` + hostname check); an internal CA can be trusted via `RP_CA_BUNDLE` *in addition to* the system store, never instead of it. The agent→satellite relay hop can also run over HTTPS

## Independent security testing

**The bar: no Critical, High, or Medium severity finding ships.** Anything that
could be exploited is fixed before release, on both the server and the agent.

Every release is reviewed as a whole project rather than as a diff, because
most of what a review finds is older than the release it ships in. Each review
reads the server, the agents, the sidecars, the installers, the container image
and the shipped web-server configuration; runs the static analysers (CodeQL,
semgrep, bandit, gitleaks, an undefined-name check); scans nginx running the
shipped configuration with nmap, nikto, nuclei and wapiti; and runs the full
test suite on every storage backend. The write-ups for the last three releases
are kept:

- [security-review-7.1.0.md](security-review-7.1.0.md) — eleven issues, among
  them a tenant admin able to change install-wide state on multi-tenant
  installs, signed alert-email links that took their address from the request,
  a crafted SSH user name that could make threat intel blame an address of the
  attacker's choosing, and the agent's WebSocket channels following redirects
  with the device token. Also a functional bug the web-server scans turned up:
  the shipped nginx configuration refused every dashboard edit sent with PUT.
- [security-review-7.0.3.md](security-review-7.0.3.md) — fourteen issues: three
  ways one tenant could reach another, a browser terminal that sent the
  operator's SSH password to a host it had not verified, two agent channels
  that ran commands in read-only mode, and an API token that could ride a
  redirect.
- [security-review-7.0.2.md](security-review-7.0.2.md) — thirty-six issues from
  a whole-project pass, and two guards found to be measuring nothing.

Each review found real defects, and every one of them was fixed before the
release went out.

The **Security → Firewall** page (view/edit
nftables/iptables/ufw/firewalld rules and fail2ban jails), is safe by
construction: every edit is **server-validated, permission-gated, written to the
audited command queue, and skipped on quarantined hosts** — a rule you add is
checked against a strict character allowlist, and a rule you delete is parsed
into tokens and quoted, so an existing rule's comment or negation reaches the
host as an inert argument. There is no path from the UI to a command the operator
could not already run with that permission.

### Control-plane hardening

The trust boundary around the agents and the secrets store:

- **Mutual-TLS agent authentication.** Agents can present a CA-verified **client
  certificate** on every connection, pinned per device, so the server accepts
  heartbeats only from a known agent — not merely from anyone holding an
  enrolment token. Optional and additive; enable it per device or enforce it
  fleet-wide once every agent has a certificate.
- **Encrypted disaster-recovery backups.** Data backups can be encrypted **at
  rest with AES-256-GCM**, with the key derived via **PBKDF2-SHA256** from a
  passphrase supplied in the environment — the passphrase is never written to
  disk. Restore is symmetric.
- **Break-glass credential reveals.** Revealing a stored credential can require a
  **two-person rule**: one operator requests, a second admin approves, and the
  full exchange is written to the immutable audit log and raises a
  `vault_break_glass` alert — so no single account can read the most sensitive
  secrets alone.
- **Per-API-key rate limiting.** Each named API key carries its own request
  budget, enforced independently of the per-IP login throttle, so a leaked or
  runaway automation key can't exhaust the server.
- **Guided self-update with no shell.** The optional server self-update runs an
  absolute script path that an admin configures by hand; it is run directly (never
  through a shell), admin-only, and audit-logged, and stays disabled until set.
- **Login banner / security notice.** An optional plain-text notice shown above
  the sign-in form (for example "Authorized use only. Activity is monitored."),
  surfaced before authentication.

Every outbound feature — integrations, DNS providers, AI providers, web-push and
the monitors — reuses the same connect-time SSRF guard (loopback / link-local /
cloud-metadata refused, peer IP re-validated, no redirects), with credentials
redacted from API responses and raw URLs kept admin-only. The strict
Content-Security-Policy (`default-src 'self'`, no `unsafe-inline`), full
security-header set (HSTS preload, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy, COOP/CORP), same-origin enforcement on
state-changing requests, and the SSRF-safe fetch path are verified against a
running instance in each review.

### Further hardening

- Session tokens hashed at rest (above).
- OIDC token-exchange failures log only the HTTP status + OAuth error code, never the IdP response body (which can echo a client secret).
- Webhook-host classification is anchored to the apex / a real subdomain, so look-alike hosts (`discord.com.attacker.tld`) aren't trusted.
- AWS cloud-import validates the region against the AWS region shape, fetches through the anti-rebinding, no-redirect opener, and refuses any EC2 response carrying a DTD / entity declarations before parsing (XXE / entity-expansion hardening).
- Ansible runs trust host keys on first use (`accept-new` + a per-run `known_hosts`) instead of disabling host-key checking.

> **Defense-in-depth note:** agent self-update enforces a signature only when an
> operator pins a release public key and enables *require-signed-updates*
> (opt-in). On its own the server-supplied SHA-256 is an integrity check, not an
> authenticity one — so a server compromise could push a binary. Enable signed
> updates on internet-exposed or multi-tenant deployments. Devices managed over
> RouterOS/MikroTik default to the vendor self-signed cert (TLS verification is a
> per-device opt-in, `routeros.verify`); enable it where the device has a trusted cert.

---

Under the flat-JSON backend, state lives in `/var/lib/remotepower/` (owned by
the app-server user — `www-data` / `nginx` / `http`, depending on distro — mode
`700`). Under the default PostgreSQL backend (and under SQLite) the same logical
keys are database rows rather than files. The most security-relevant of them:

| File | Contents |
|------|----------|
| `users.json` | Admin accounts + bcrypt hashes + roles |
| `devices.json` | Enrolled devices, MAC, group, notes, cached sysinfo + journal |
| `tokens.json` | Active browser sessions (24 h standard / 30 d remember-me TTL), keyed by SHA-256 of the token |
| `apikeys.json` | Named API keys — stored as a SHA-256 `key_hash` (the raw key is shown once at creation and never persisted) |
| `pins.json` | Pending enrollment PINs |
| `commands.json` | Pending command queue per device |
| `config.json` | Webhook URL, WoL settings, monitor targets, patch threshold |
| `history.json` | Command log (last 200 entries by default; tunable) |
| `schedule.json` | Scheduled jobs (one-shot + recurring cron) |
| `uptime.json` | Online/offline state changes per device |
| `monitor_history.json` | Check results per monitor target (last 300 by default; tunable) |
| `cmd_output.json` | Custom command output per device (last 100) |
| `metrics.json` | CPU/RAM/disk snapshots per device (last 1440) |
| `cmd_library.json` | Saved command snippets |
| `longpoll.json` | Pending long-poll output slots (transient) |

**Backup:**
```bash
sudo tar czf remotepower-backup-$(date +%F).tar.gz /var/lib/remotepower/
# Or via dashboard: Settings → Backups → Export backup
```

---

## Compliance frameworks (SOC 2 / ISO 27001)

For a mapping of RemotePower's built-in controls (RBAC, MFA/SSO, encryption at
rest + in transit, the hash-chained + WORM audit log, signed evidence exports,
vulnerability management, backup/DR, …) to **SOC 2** Trust Services Criteria and
**ISO/IEC 27001:2022** Annex A controls — plus what stays the operator's
responsibility — see [compliance.md](compliance.md). It's a mapping aid for
audit prep, not a certification claim.

## Security posture

RemotePower has been audited end-to-end across multiple releases — the server
(`api.py`, helper modules, nginx config), the agent (`remotepower-agent`), and
the extended subsystems (WebTerm handshake, CMDB vault, LDAP, TOTP, API keys, AI
provider, Proxmox/OPNsense/RouterOS integrations, SSRF-guarded outbound calls,
backup/restore, host-config, and the RBAC scope model). The full reviews live in
`docs/security-review-*.md`; the latest is
[security-review-7.1.0.md](security-review-7.1.0.md). The codebase is also
scanned with a combined **SAST + DAST** pipeline (see *Security testing* below):
CodeQL reports zero in both languages under the configuration production runs,
Bandit reports nothing new against its baseline and no high-severity finding,
and gitleaks is clean over the full history. Where a finding
is by design it carries an inline suppression **with its reason** next to the
code, rather than being filtered out of sight. Summary of the
defences in place (kept current):

### Authentication

- **Session tokens** are 256-bit, generated with `secrets.token_urlsafe(32)`,
  carried in the `X-Token` HTTP header. **Not cookies** — this means cross-site
  requests cannot forge state-changing API calls without a CORS preflight that
  the server never permits.
- **Passwords** are hashed with **bcrypt** (cost 12); where bcrypt is unavailable
  the server falls back to PBKDF2-HMAC-SHA256 at 600 000 iterations (OWASP minimum)
  with per-account salts. Legacy hashes are auto-upgraded on next login.
- **Login rate limiting** uses an exponential backoff ladder
  (10 s → 1 min → 5 min → 30 min → 2 h) and a dummy-verify on missing users to
  prevent timing-based account enumeration.
- **TOTP** secrets are 160-bit (RFC 4226); a code window of ±1 step
  accommodates clock skew. TOTP failures count against the login rate limit.
- **Passkeys (WebAuthn, v4.2)** offer phishing-resistant, passwordless sign-in
  via the vetted `py_webauthn` library; a cloned-authenticator sign-count
  regression is refused, only the public key is stored, and a passkey satisfies
  the MFA-required policy.
- **SAML 2.0 SSO (v4.2)** delegates signature / audience / validity checks to
  `pysaml2` + `xmlsec1` and adds `InResponseTo` + one-time-use replay protection;
  the SP holds no private key.
- **Account guardrails (v4.2):** optionally **enforce MFA** (TOTP or passkey) per
  role, **cap concurrent sessions** per user, set a **default API-key expiry**,
  and read a graded **security-posture self-check** on the Audit page. The audit
  log is **hash-chained** (tamper-evident) with a one-click integrity verify.
- **API keys** are 320-bit, **stored hashed at rest** (SHA-256 `key_hash`; a
  legacy plaintext key is migrated to a hash on first use) and compared by hash
  with `hmac.compare_digest`, shown to the operator only at creation, support
  per-key expiry, an optional per-key device scope and a source-IP allowlist, and
  are capped at 50 per server.
- **LDAP** binds use `CERT_REQUIRED` TLS verification by default; opt-out
  exists for self-signed CAs.
- **`Authorization: Bearer`** is accepted alongside `X-Token`. The token verification path is
  identical — same TTL, same role lookup, same admin gate. `X-Token`
  takes priority when both headers are present, so a stray
  `Authorization` header injected by a transparent proxy can't override
  the dashboard's session token. Bearer was generalised for the bundled
  MCP server, which sends it per RFC 6750. Operator note: `Authorization`
  headers tend to be logged by more middleware than the non-standard
  `X-Token` — if you suspect Bearer-bearing requests have been logged
  upstream, rotate the affected API keys.

### CSRF / cross-origin

- The `X-Token` header scheme is CSRF-safe by construction: custom headers
  force a CORS preflight, and RemotePower serves no permissive
  `Access-Control-Allow-Origin`. Browsers cannot forge cross-origin
  state-changing requests.
- Defence-in-depth: every state-changing request (`POST`/`PUT`/`PATCH`/`DELETE`)
  passes an Origin/Referer same-origin check before route dispatch. CLI and
  agent clients (which send no Origin) are unaffected; evil-site form posts get
  a 403.

### XSS

- All user-derived content is escaped via `escHtml` / `escAttr` before
  `innerHTML` assignment.
- AI assistant output is rendered through an escape-first Markdown renderer:
  the entire response is HTML-escaped, then transforms operate only on safe
  ground. Code fences are extracted and re-inserted without further interpretation.
- Toast notifications escape their message string.

### Webhook destinations

- Outbound webhook URLs are validated for `http`/`https` scheme.
- Per-event toggles, CVE severity filters, maintenance-window suppression, and
  per-device "unmonitored" gating all apply uniformly to legacy single-URL and
  multi-destination configurations.
- The `webhook_block_local` setting (on by default, in **Settings → Security**)
  refuses POSTs to link-local and unspecified addresses, which covers cloud
  metadata services at 169.254.169.254. Loopback is allowed so a notifier running
  next to the server keeps working; send `webhook_allow_loopback: false` to
  `POST /api/config` to refuse it too. RFC1918 private networks are permitted —
  homelab Gotify / ntfy on the LAN is legitimate.
- **DNS-rebinding protected.** The webhook sender, the audit→SIEM forwarder, the
  OIDC discovery / token-exchange fetches, and the HTTP uptime
  monitor re-validate the *actual* peer IP at connect time, not just the address
  resolved during the pre-flight check — so a hostname that resolves to a
  permitted address for the check but an internal/metadata address for the real
  request is caught and refused. TLS verification (server name + certificate
  chain) is unaffected; the audit forwarder pins the verified TLS context for the
  connection it validated.
- **HTTP monitor SSRF.** The uptime monitor's `http`/`https` check
  validates its target through the shared per-IP classifier instead of a literal
  string-prefix blocklist (which missed IPv6 `[::1]`, integer/octal/hex-encoded
  IPv4, and DNS rebinding) and fetches through the connect-time SSRF guard above.
  Cloud-metadata / link-local is always blocked; loopback only when
  `allow_internal_monitors` is set; RFC1918 LAN stays allowed by design. See
  the latest `docs/security-review-*.md`.

### CMDB vault

- AES-GCM with PBKDF2-HMAC-SHA256 600 000 iterations, 256-bit salts,
  96-bit nonces, canary blob for key verification without leaking ciphertext.
- The vault passphrase is **never persisted server-side**. The derived key is
  returned to the browser, sent back on every operation in the `X-RP-Vault-Key`
  header, and used to encrypt/decrypt in a single request scope.
- Vault keys do not appear in audit logs, debug logs, or backup exports.

### Agent

- Runs as root by design (needs `dpkg` / `pacman` / `systemctl`), but every
  subprocess invocation uses the argv-list form — no shell injection — except
  the considered `exec:` command path, which is the agent's product feature.
- TLS verification is mandatory: `CERT_REQUIRED` + `check_hostname=True`;
  `http_post()` rejects non-HTTPS URLs at the function head.
- Self-updates are SHA-256 verified with `hmac.compare_digest` and applied
  atomically via `mkstemp` + `shutil.move`.
- **Opt-in mandatory signed updates**: create the marker file
  `/etc/remotepower/require-signed-updates` and the agent fails *closed* — it
  refuses any self-update unless a release public key is pinned *and* the download
  carries a valid signature. Without the marker the default is fail-open (an
  unsigned update is allowed when no key is configured), so this flips the
  posture for hosts that demand signed updates.
- Agent state files live in `/var/lib/remotepower/` (mode `0700`) with
  `O_NOFOLLOW` on every read and write. A `/tmp/` fallback exists for non-root
  deploys and uses the same anti-symlink hardening.
- Enrollment credentials are written with `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW`
  at mode `0600` atomically — no race between create and chmod.
- Server-pushed log-watch paths are passed through a deny list (`/etc/shadow`,
  `/root/.ssh/`, `/proc/`, `/sys/`, `/dev/`, etc.) with `realpath()` resolution
  so symlinks cannot bypass.

### Backup export

- Backup exports redact every secret field: webhook URLs, Pushover tokens,
  SMTP passwords, LDAP bind passwords, Proxmox API tokens, AI provider keys.
  The redacted backup can be safely shared with support.

### nginx hardening (shipped config)

- Strict security headers: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` denying
  geolocation/camera/microphone, `Cross-Origin-Opener-Policy` and
  `Cross-Origin-Resource-Policy: same-origin`,
  `X-Permitted-Cross-Domain-Policies: none`, `X-XSS-Protection: 0` (the legacy
  filter off, as OWASP recommends) and `frame-ancestors 'none'` in CSP.
- `server_tokens off` — no nginx version in responses or error pages.
- Unknown paths return 404 rather than the dashboard (the dashboard navigates by
  `#fragment`, so no route needs a catch-all).
- Methods on `/api/` restricted to `GET POST PUT DELETE PATCH`.
- Request body capped at 2 MB.
- Static `.json` and `.tmp` files denied (defence against accidental data-dir exposure).
- The `/cgi-bin/` path is denied as a static location (defence in depth — the
  Python backend lives there but is only ever imported by gunicorn, never
  served over HTTP, so its URL should never resolve to a static file).
- HSTS commented out — uncomment after HTTPS is fully tested.

### Internet-facing access control

Authentication (session token / API key, rate-limited login, optional 2FA) is
the primary control on every API call. If the instance is reachable from the
public internet, consider **also** restricting `/api/` by source IP — or
fronting it with a VPN / SSO proxy. The static dashboard shell can stay public;
`/api/` is the sensitive surface. Keep an allowlist in an include file and pull
it into each `/api/` location:

```nginx
# /etc/nginx/snippets/rp-allowlist.conf
allow 203.0.113.7;     # admin IP
allow 10.0.0.0/24;     # LAN / VPN range
deny  all;
```

**Caveat:** agents POST to `/api/heartbeat` (and enroll / download), so the
allowlist **must include every agent's source IP** (your LAN/VPN) or they stop
reporting. If agents roam on arbitrary public IPs, don't blanket-allowlist
`/api/` — rely on the built-in per-device token auth and put the admin surface
behind a VPN/SSO instead. Never IP-restrict `/api/csp-report` (you'd lose CSP
reports from real browsers). The shipped `server/conf/remotepower.conf` carries
this guidance inline.

## Security testing

RemotePower is reviewed and scanned on an ongoing basis:

- **Manual security reviews** of the server and agent every release
  (see the `docs/security-review-*.md` files; latest:
  [security-review-7.1.0.md](security-review-7.1.0.md)).
- **SAST** — **CodeQL** with GitHub's query suites (also run on every push),
  [Bandit](https://bandit.readthedocs.io/), [semgrep](https://semgrep.dev/),
  [gitleaks](https://github.com/gitleaks/gitleaks) and an undefined-name check.
- **DAST** — [nmap](https://nmap.org/), [Nikto](https://github.com/sullo/nikto),
  [Nuclei](https://github.com/projectdiscovery/nuclei) and
  [Wapiti](https://wapiti-scanner.github.io/) against nginx running the shipped
  configuration; earlier releases also ran [OWASP ZAP](https://www.zaproxy.org/).

The most recent run reported **no exploitable findings** after the fixes in
that release's review — only informational results and scanner false positives,
such as technology fingerprints matching product names in the interface text.

If you find a security issue, please report it **privately** via GitHub's
[**"Report a vulnerability"**](https://github.com/tyxak/remotepower/security/advisories/new)
(see [SECURITY.md](../SECURITY.md) for the full policy and response window) —
rather than opening a public issue.

**Supply chain.** Release tarballs are published with a SHA-256 checksum and a
detached **GPG signature** (`.tar.gz.asc`); the signing key fingerprint is
`E7B5AD456728B8462A8B54BFD488AF115D2CCDBF`. AUR packages PGP-verify that
signature at build time, and the agent self-update can be pinned to require a
signed binary (fail-closed).

The **container images** are signed too — for most people the image is what
actually runs. They use **cosign keyless
signing** (Sigstore) rather than a key, because the reason the GPG key is kept
local is that CI must not hold a signing key, and putting a cosign key in CI
would reintroduce exactly that. The signature is bound to the release workflow's
OIDC identity, so verification asserts *which workflow in which repository*
built the image:

```bash
cosign verify ghcr.io/tyxak/remotepower:latest \
  --certificate-identity-regexp '^https://github.com/tyxak/remotepower/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Both flags matter. A bare `cosign verify` accepts a signature from *any*
identity, which for a keyless signature means anyone with a GitHub account —
it proves the image was signed, not by whom, which is not a check. Images are
signed **by digest**, so the `latest` and `X.Y` tags resolve to the same signed
digest as the exact version; the images also carry SLSA build provenance.

## Threat model

**In scope:**

- Anonymous internet attackers reaching the dashboard
- Cross-site attackers attempting CSRF / XSS / framing
- Local non-root users on a managed host attempting privilege escalation via
  the agent
- Compromised or malicious server attempting silent exfiltration via
  agent-side controlled inputs (log-watch paths, etc.)
- MITM attackers attempting to inject into agent ↔ server traffic
- Cred-stuffing / brute-force against login and admin-password re-prompt

**Out of scope:**

- A fully compromised server with root access — by design, the operator has
  shell-level control over every agent. Root-on-server = root-on-agents. We
  defend against silent-exfil pivots, not against intentional misuse.
- A fully compromised admin session — once an attacker has a valid `X-Token`,
  they are the admin. We log everything to the audit log so the operator can
  see what happened, and the WebTerm flow requires admin-password re-prompt to
  raise the bar for that specific privileged action.

## Operator hardening checklist

Recommended for production deployments beyond the secure defaults:

- [ ] Run behind HTTPS with a valid certificate (Let's Encrypt is fine).
- [ ] If internet-facing, restrict `/api/` by source IP (allowlist include) or
      front it with a VPN/SSO — see "Internet-facing access control" above.
      Include your agents' source IPs in the allowlist.
- [ ] Uncomment the `Strict-Transport-Security` header in
      `server/conf/remotepower.conf` once HTTPS is verified.
- [ ] Enable the `limit_req` rate-limit zones at the nginx level — the config
      ships with commented-out examples.
- [ ] Change the default admin password on first login (a banner reminds you).
- [ ] Enable TOTP 2FA for every admin account: **Settings → Security → TOTP**.
- [ ] Rotate or expire any API keys you no longer use.
- [ ] If your deployment must never POST webhooks to the server's own loopback
      address, send `webhook_allow_loopback: false` to `POST /api/config`
      (`webhook_block_local`, which covers cloud metadata, is already on).
- [ ] Configure a daily backup destination (built-in scheduled backup,
      **Settings → Backups**) and verify the redacted export can be restored.
- [ ] Review the audit log on a schedule — `/api/audit-log` or
      **Settings → Security → Audit log**.
- [ ] If using LDAP/AD, set `ldap_tls_verify: true` and provide a trusted CA;
      only set to `false` for known-self-signed internal directories.
- [ ] If using the CMDB vault, set a passphrase that meets the complexity
      gate (≥ 12 characters, 2 of 4 character classes) and **store it
      separately** — RemotePower cannot recover it.
- [ ] **Encrypt the control-plane host's own disk.** The data directory holds
      every device token, the CMDB credential vault, API-key hashes and the
      backups — a stolen or decommissioned disk hands over the fleet, and no
      application-level control can undo that. **Settings → Security posture**
      reports the state of the volume `RP_DATA_DIR` sits on; a host
      that cannot see device-mapper — a container, typically — reports
      "cannot be determined" rather than a finding, so check the underlying
      host yourself in that case.

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
