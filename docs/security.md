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

---

All data in `/var/lib/remotepower/` (owned by `www-data`, mode `700`):

| File | Contents |
|------|----------|
| `users.json` | Admin accounts + bcrypt hashes + roles |
| `devices.json` | Enrolled devices, MAC, group, notes, cached sysinfo + journal |
| `tokens.json` | Active browser sessions (7-day TTL) |
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

RemotePower was audited end-to-end for v3.0.2 covering the server (`api.py`,
nginx config), the agent (`remotepower-agent`), and the extended modules
(WebTerm handshake, CMDB vault, LDAP, TOTP, API keys, AI provider, Proxmox).
Summary of the defences in place:

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
- **API keys** are 320-bit, compared with `hmac.compare_digest`, shown to the
  operator only at creation, support per-key expiry, capped at 50 per server.
- **LDAP** binds use `CERT_REQUIRED` TLS verification by default; opt-out
  exists for self-signed CAs.

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
- HSTS commented out — uncomment after HTTPS is fully tested.

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
