# RemotePower — Security Review (v4.6.0 "RepellantMatters")

Date: 2026-06-14. Scope: a full read-through of the server (`api.py` + its
sibling modules), all three agents (Linux / Windows / macOS) and the frontend,
followed by an external scan of the running web surface. v4.6.0 is primarily a
visual-identity release, but it ships a project-wide hardening pass alongside.

**Verdict: clean.** No exploitable findings remain. The web surface was scanned
with **wapiti, nikto, nuclei, bandit and OWASP ZAP** with no exploitable
results. The issues found during the internal audit were fixed in this release
and are listed below. The durable description of RemotePower's security model
remains `docs/security.md`; the prior full audit is
`docs/security-review-4.4.0.md`.

---

## Fixed in this release

### SSRF parity on the appliance / integration targets
The RouterOS REST integration gained an SSRF pre-flight in v4.4.0; this release
extends the **same guard to every sibling that fetches a user/admin-supplied
host**:

- **OPNsense** REST target (was reachable by any authenticated user — the most
  significant of the set, now blocked the same way RouterOS is).
- **Proxmox** host (validated at config-save time).
- **AI provider** `base_url` (validated at config-save time; loopback is still
  allowed for the local Ollama / LocalAI providers, which legitimately run on
  `127.0.0.1`).
- **TLS-monitor** targets, including the optional `connect_address` DNS
  override.

Each blocks loopback, link-local and cloud-metadata (`169.254.169.254`) while
still allowing the RFC1918 LAN addresses these integrations legitimately use.

### Resolved-role checks on two read endpoints
Two read paths gated authorization with a string denylist (`role not in
('viewer','mcp')`) rather than the resolved role record — the exact pattern the
v4.4.0 admin-gate fix replaced everywhere else. A **custom operator role** is
neither `viewer` nor `mcp`, so it was incorrectly treated as admin and could
read admin-only config (including raw webhook destination URLs, whose path can
be a secret) and a pending-confirmation count. Both now gate on
`_resolve_role(role).get('admin')`, matching `require_auth`.

### Agent credential storage hardening
- **Windows:** `agent.json` (which holds the device bearer token) is written
  under `C:\ProgramData`, which is readable by the local `Users` group by
  default. The agent now strips inheritance and grants only `SYSTEM` +
  `Administrators` on the data directory and the file, so a non-admin local user
  can no longer read the token.
- **macOS:** the credential write is now atomic (0600 temp file → `os.replace`)
  — the previous open-write-then-`chmod` left a brief window at the process
  umask where the token was world-readable.
- **Linux:** the `pending-cmd.json` retry stash now routes through the existing
  O_NOFOLLOW state-file helpers (with a full-length read), closing a `/tmp`
  symlink-pre-plant write vector that the rest of the agent's state files were
  already hardened against.

---

## Verified clean (no findings)

- **Frontend CSP / XSS** — no inline `on*=` handlers, inline `style="…"`
  attributes or inline `<script>`; all dynamic HTML is interpolated through the
  project sanitizers (`escHtml` / `escAttr`). Production serves
  `default-src 'self'; script-src 'self'; style-src 'self'` with HSTS preload,
  `frame-ancestors 'none'`, nosniff and a referrer/permissions policy.
- **Server authN/authZ** — every state-changing endpoint is gated
  (`require_admin_auth` / `require_perm` / agent-token HMAC / loopback /
  status-token); the v4.4.0 custom-role admin-bypass remains fixed; the device
  list never serializes a device token; device scope + tenant isolation are
  enforced at the `_enforce_device_scope` chokepoint.
- **Injection / path traversal** — no `shell=True` / `os.system` on the server;
  SSH uses argv lists with an option-injection guard and 0600 keyfiles; all
  id-addressed file handlers validate the id against a strict allowlist.
- **Agent transport** — all three agents are HTTPS-only with
  `CERT_REQUIRED` + hostname checking + a TLS 1.2 floor; verification is never
  disabled.

---

← [Back to security overview](security.md) · [Back to docs index](README.md)
