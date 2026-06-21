# Security notes

- Use HTTPS for anything internet-facing
- Session tokens are configurable (default 7-day remember-me / 8-hour standard); API keys default to never-expire — set a per-key expiry, or rotate manually if compromised
- Enrollment PINs are single-use, expire after 10 minutes
- Device tokens are 256-bit random secrets
- Passwords stored as **PBKDF2-HMAC-SHA256** (600 000 iterations, OWASP 2023 minimum); legacy SHA-256 hashes auto-upgraded on next login
- Webhook URLs (legacy single + multi-destination) stored server-side only, redacted from backup exports
- CMDB vault uses AES-GCM with PBKDF2-derived keys; passphrase never persisted server-side
- Custom commands run as root - use the per-device command allowlist for untrusted operators
- Viewer role users cannot queue commands, change config, or access API keys
- `apikeys.json`, `tokens.json`, and `users.json` are owned by the CGI user mode `700` - protect your server
- Agent state files (`/var/lib/remotepower/` mode `0700`) use `O_NOFOLLOW` on every read/write to defeat symlink attacks from local non-root users
- **Session tokens are hashed at rest** — `tokens.json` is keyed by the SHA-256 of the bearer token, never the token itself, so a leaked file yields no usable session
- Agents verify the server's TLS certificate (`CERT_REQUIRED` + hostname check); an internal CA can be trusted via `RP_CA_BUNDLE` *in addition to* the system store, never instead of it. The agent→satellite relay hop can also run over HTTPS

## Independent security testing

**The bar: no Critical, High, or Medium severity finding ships.** Anything that
could be exploited is fixed before release, on both the server and the agent.

Each release is reviewed for security at the code level and scanned with an
external toolchain in addition to the CI guardrails. The current release,
**v5.0.0**, underwent a whole-project server + agent security review with SAST
tooling, held to the same bar — **no Critical, High, or Medium finding ships** —
see [security-review-5.0.0.md](security-review-5.0.0.md). The previous release,
**v4.10.0**, had the same whole-project audit and **passed clean** — see
[security-review-4.10.0.md](security-review-4.10.0.md). The v4.10.0
headline surface, the **Security → Firewall** page (view/edit
nftables/iptables/ufw/firewalld rules and fail2ban jails), is safe by
construction: every edit is **server-validated against a strict character
allowlist, permission-gated, written to the audited command queue, and skipped on
quarantined hosts** — there is no path from the UI to a command the operator could
not already run with that permission.

### Control-plane hardening (v5.0.0)

v5.0.0 strengthens the trust boundary around the agents and the secrets store:

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

Recent releases were independently penetration-tested with
[wapiti](https://wapiti-scanner.github.io/), [nikto](https://github.com/sullo/nikto),
[nuclei](https://github.com/projectdiscovery/nuclei), [bandit](https://github.com/PyCQA/bandit),
[semgrep](https://semgrep.dev/), [gitleaks](https://github.com/gitleaks/gitleaks)
and [OWASP ZAP](https://www.zaproxy.org/), each passing clean: **v4.7.0** (homelab
integrations + containerized agent), **v4.8.0** (onboarding + DMARC monitor),
**v4.9.0** (DNS dashboard + resolver health), **v4.10.0** (firewall/fail2ban) and
**v5.0.0** (control-plane hardening + scale).
Every outbound feature — integrations, DNS providers, AI providers, web-push and
the monitors — reuses the same connect-time SSRF guard (loopback / link-local /
cloud-metadata refused, peer IP re-validated, no redirects), with credentials
redacted from API responses and raw URLs kept admin-only. The strict
Content-Security-Policy (`default-src 'self'`, no `unsafe-inline`), full
security-header set (HSTS preload, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy, COOP/CORP), same-origin enforcement on
state-changing requests, and the SSRF-safe fetch path were all verified live. A
durable, release-over-release summary lives in the
[`security-review-*.md`](security-review-4.10.0.md) files.

### v4.0.0 hardening pass

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

All data in `/var/lib/remotepower/` (owned by `www-data`, mode `700`):

| File | Contents |
|------|----------|
| `users.json` | Admin accounts + bcrypt hashes + roles |
| `devices.json` | Enrolled devices, MAC, group, notes, cached sysinfo + journal |
| `tokens.json` | Active browser sessions (7-day TTL), keyed by SHA-256 of the token |
| `apikeys.json` | Named API keys (values stored here) |
| `pins.json` | Pending enrollment PINs |
| `commands.json` | Pending command queue per device |
| `config.json` | Webhook URL, WoL settings, monitor targets, patch threshold |
| `history.json` | Command log (last 200 entries) |
| `schedule.json` | Scheduled jobs (one-shot + recurring cron) |
| `uptime.json` | Online/offline state changes per device |
| `monitor_history.json` | Check results per monitor target (last 50) |
| `cmd_output.json` | Custom command output per device (last 100) |
| `metrics.json` | CPU/RAM/disk snapshots per device (last 1440) |
| `cmd_library.json` | Saved command snippets |
| `longpoll.json` | Pending long-poll output slots (transient) |

**Backup:**
```bash
sudo tar czf remotepower-backup-$(date +%F).tar.gz /var/lib/remotepower/
# Or via dashboard: Settings → Export backup
```

---

## Security posture

RemotePower has been audited end-to-end across multiple releases — the server
(`api.py`, helper modules, nginx config), the agent (`remotepower-agent`), and
the extended subsystems (WebTerm handshake, CMDB vault, LDAP, TOTP, API keys, AI
provider, Proxmox/OPNsense/RouterOS integrations, SSRF-guarded outbound calls,
backup/restore, host-config, and the RBAC scope model). The full reviews live in
`docs/security-review-*.md`; each release-over-release pass is
summarised in the latest, [security-review-4.10.0.md](security-review-4.10.0.md).
The codebase is also scanned with a combined **SAST + DAST** pipeline (Bandit;
OWASP ZAP, Nikto, Nuclei, Wapiti, WhatWeb) — the most recent full run reported
**no exploitable findings** (see *Security testing* below). Summary of the
defences in place (kept current):

### Authentication

- **Session tokens** are 256-bit, generated with `secrets.token_urlsafe(32)`,
  carried in the `X-Token` HTTP header. **Not cookies** — this means cross-site
  requests cannot forge state-changing API calls without a CORS preflight that
  the server never permits.
- **Passwords** are PBKDF2-HMAC-SHA256 at 600 000 iterations (OWASP 2023 minimum)
  with per-account salts. Legacy SHA-256 hashes are auto-upgraded on next login.
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
- **API keys** are 320-bit, compared with `hmac.compare_digest`, shown to the
  operator only at creation, support per-key expiry, capped at 50 per server.
- **LDAP** binds use `CERT_REQUIRED` TLS verification by default; opt-out
  exists for self-signed CAs.
- **`Authorization: Bearer`** is accepted alongside `X-Token` as of v3.2.0
  (was previously only `/api/metrics`). The token verification path is
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
- Optional `webhook_block_local` config flag refuses POSTs to loopback /
  link-local / unspecified IPs (covers cloud metadata services at
  169.254.169.254). RFC1918 private networks are deliberately permitted —
  homelab Gotify / ntfy on the LAN is legitimate.
- **DNS-rebinding protected.** The webhook sender, the audit→SIEM forwarder, the
  OIDC discovery / token-exchange fetches, and (since v3.9.0) the HTTP uptime
  monitor re-validate the *actual* peer IP at connect time, not just the address
  resolved during the pre-flight check — so a hostname that resolves to a
  permitted address for the check but an internal/metadata address for the real
  request is caught and refused. TLS verification (server name + certificate
  chain) is unaffected; the audit forwarder pins the verified TLS context for the
  connection it validated. (Introduced v3.8.0.)
- **HTTP monitor SSRF (v3.9.0).** The uptime monitor's `http`/`https` check now
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
  the deliberate `exec:` command path, which is the agent's product feature.
- TLS verification is mandatory: `CERT_REQUIRED` + `check_hostname=True`;
  `http_post()` rejects non-HTTPS URLs at the function head.
- Self-updates are SHA-256 verified with `hmac.compare_digest` and applied
  atomically via `mkstemp` + `shutil.move`.
- **Opt-in mandatory signed updates** (v3.8.0): create the marker file
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
  geolocation/camera/microphone, `frame-ancestors 'none'` in CSP.
- Methods restricted to `GET POST DELETE PATCH` at the location block.
- Request body capped at 64 KB.
- Static `.json` and `.tmp` files denied (defence against accidental data-dir exposure).
- The `/cgi-bin/` path is denied as a static location (defence in depth — the
  Python backend lives there but is only ever executed via `/api/` through
  fcgiwrap, so its URL should never resolve to a static file).
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

- **Manual security reviews** of the server and agent every few releases
  (see the `docs/security-review-*.md` files; latest:
  [security-review-4.10.0.md](security-review-4.10.0.md)).
- **SAST** — [Bandit](https://bandit.readthedocs.io/) static analysis of the
  Python codebase.
- **DAST** — [OWASP ZAP](https://www.zaproxy.org/) full active scan,
  [Nikto](https://github.com/sullo/nikto), [Nuclei](https://github.com/projectdiscovery/nuclei),
  [Wapiti](https://wapiti-scanner.github.io/) and WhatWeb against a running
  instance.

The most recent full SAST + DAST run reported **no exploitable findings** —
only informational results and tool false positives (e.g. a metadata-SSRF
probe against a path that simply returns a 404, and benign timestamp/internal-IP
disclosures inherent to a fleet dashboard). The few static-analysis nits it did
surface (e.g. non-cryptographic fingerprint hashes) were annotated or fixed.
**v4.8.0** was independently tested with wapiti, nikto, nuclei, bandit and OWASP
ZAP and passed clean.

If you find a security issue, please report it privately rather than opening a
public issue.

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
- [ ] If your deployment must never POST webhooks to internal IPs, enable
      `webhook_block_local` in the config.
- [ ] Configure a daily backup destination (built-in scheduled backup,
      **Settings → Backup**) and verify the redacted export can be restored.
- [ ] Review the audit log on a schedule — `/api/audit-log` or
      **Settings → Audit Log**.
- [ ] If using LDAP/AD, set `ldap_tls_verify: true` and provide a trusted CA;
      only set to `false` for known-self-signed internal directories.
- [ ] If using the CMDB vault, set a passphrase that meets the complexity
      gate (≥ 12 characters, 2 of 4 character classes) and **store it
      separately** — RemotePower cannot recover it.

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
