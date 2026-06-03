# RemotePower — Security Review (v3.10.0)

Date: 2026-06-03. Scope: a focused re-review on top of the v3.8.0 and v3.9.0
passes, covering the v3.10.0 sweep (container restart-count binding, two
outbound-fetch / secret-disclosure fixes, alert-label corrections) plus an
independent re-trace of the high-risk sinks. Both the **server**
(`server/cgi-bin/api.py` and helper modules, including
`server/cgi-bin/image_registry.py`) and the **agent**
(`client/remotepower-agent.py`) were reviewed against the standing brief:
authentication/authorization, command execution, input handling, secrets,
transport, SSRF, path traversal, and the front-end.

The posture remains **strong and hardened release-over-release**. v3.8.0 closed
the DNS-rebinding TOCTOU across the webhook, audit-forward, and OIDC
back-channels; v3.9.0 closed it on the HTTP uptime monitor. This release closes
the **two remaining outbound fetches that were not behind that guard** — the
container image-registry client and the Healthchecks.io ping — adds an IP-class
check to the **TCP** uptime monitor, and replaces the `GET /api/config`
secret denylist with a structural recursive scrub. Everything else re-checked
was confirmed defended.

---

## Summary

The review concentrated on (a) the outbound fetch paths, since the image-update
scanner makes requests driven by host-reported container metadata; (b) the
`GET /api/config` response shape, since it is reachable by low-privilege
viewer/MCP keys; and (c) regression-checking that the v3.8.0/v3.9.0 hardening is
intact. Two high-severity issues were found and fixed (an SSRF + credential
exfiltration path in the image-registry client, and a cleartext-secret leak via
`/api/config`); one medium and one low defence-in-depth inconsistency were
tightened. No issues were found in the agent's command channel, self-update, or
container-management paths.

| ID | Severity | Status | Title |
|----|----------|--------|-------|
| F1 | High     | Fixed  | Image-registry client: redirects, DNS-rebinding, and unchecked bearer-token realm fetch (credential exfiltration) bypass the SSRF guard |
| F2 | High     | Fixed  | `GET /api/config` leaks AI `api_key` + `registry_credentials` in cleartext to viewer/MCP roles (denylist redaction gap) |
| F3 | Medium   | Fixed  | TCP uptime monitor has no IP-class SSRF check (internal port-scan oracle) |
| F4 | Low      | Fixed  | Healthchecks.io ping uses an unguarded `urlopen` (no peer recheck / redirect refusal) |

---

## F1 — Image-registry client bypasses the SSRF guard (High, fixed)

**Files:** `server/cgi-bin/image_registry.py`; caller in `server/cgi-bin/api.py`
(`_run_image_update_scan`).

The image-update scanner resolves the registry's current manifest digest for
each `repo:tag` an agent reports. The caller pre-flighted the *manifest* URL
against `_url_targets_local_or_meta`, but the client then fetched with a bare
`urllib.request.urlopen`. Three distinct bypasses:

1. **DNS-rebinding TOCTOU.** The pre-flight resolves the hostname; `urlopen`
   re-resolves at connect. Every other outbound fetch in the codebase closes
   this with the `_SSRFGuard*Connection` peer re-validation — this one did not.
2. **Redirect following.** A malicious registry could answer with
   `302 → http://169.254.169.254/latest/meta-data/…`; the bare `urlopen` follows
   it with no peer recheck on the redirect target.
3. **Unchecked token-realm fetch (the worst).** On a `401`, `_build_auth`
   parses `Www-Authenticate: Bearer realm="…"` — **fully attacker-controlled** —
   and fetched that realm URL to mint a token with **no SSRF check at all**. If
   per-registry credentials were configured, they were sent as Basic auth to the
   attacker's realm, i.e. credential exfiltration.

**Reachability.** Image references come from container metadata reported by
agents (host-controlled). A compromised or malicious managed host reports an
image whose registry it controls; the server then fetches the manifest and the
realm it dictates.

**Fix.** `remote_digest` / `_manifest_digest` / `_build_auth` now accept an
`opener` and a `url_guard`. The caller passes
`_ssrf_safe_opener(allow_loopback=not block_local, ssl_ctx=…, no_redirect=True,
enforce_ip=block_local)` and a guard wrapping `_url_targets_local_or_meta`, so
**every** fetch — manifest and token realm — re-validates the connected peer IP
and refuses redirects. `_build_auth` additionally forces the realm to HTTPS and
pre-flights it against the IP classifier before fetching (and before sending any
credentials), raising `BlockedURL` on a blocked target. When the operator has
turned off local blocking (`webhook_block_local=false`) the opener keeps the
no-redirect behaviour but skips IP enforcement, mirroring the manifest
pre-flight. RFC1918 LAN registries stay allowed by design.

## F2 — `GET /api/config` leaks secrets to viewer/MCP roles (High, fixed)

**File:** `server/cgi-bin/api.py` (`handle_config_get`).

`handle_config_get` is gated by `require_auth()` only — not admin — so `viewer`
and read-only `mcp` tokens can call it. It built the response as a wholesale copy
of the config dict and then **denylisted** specific secret keys with `pop`
(SMTP/LDAP/Proxmox/OIDC passwords, webhook tokens, status token). It never
popped:

- `cfg['ai']`, which holds the AI-provider `api_key` in cleartext (the dedicated
  `/api/ai/config` endpoint is admin-only and masks the key, but `/api/config`
  returned the whole `ai` sub-dict);
- `cfg['registry_credentials']`, the per-registry username/password map.

Both were returned in cleartext to any authenticated viewer/MCP key — a
structural denylist problem where every future secret leaks until someone
remembers to add a `pop`.

**Fix.** Two `*_set`/`*_configured` booleans replace the raw values
(`ai_configured`, `registry_credentials_set`), and a recursive
`_scrub_config_secrets(safe)` runs as a structural backstop before the response
is sent: it removes any leaf key matching
`(?:^|_)(password|passwd|secret|apikey|api_key|access_token|refresh_token|private_key|credentials|token)$`
at any nesting depth. The anchor on whole-word suffixes means every `*_set` /
`*_from_env` indicator and non-secret `*_id` field (e.g. `proxmox_token_id`,
`oidc_client_id`) is preserved, so the Settings UI still renders, while a
newly-added config secret cannot leak before it is explicitly redacted. The
scrub mutates only the per-request deep-copy that `load()` returns, so it cannot
corrupt the in-process config cache.

## F3 — TCP uptime monitor has no IP-class SSRF check (Medium, fixed)

**File:** `server/cgi-bin/api.py` (`_sanitize_monitor_target`,
`_execute_monitor_checks`).

The `http` monitor branch calls `_url_targets_local_or_meta` and the executor
re-validates the peer via the SSRF-safe opener. The **`tcp`** branch did
neither: it stripped non-`[a-zA-Z0-9.\-]` characters from the host and validated
the port, then ran `socket.create_connection` unguarded. A monitor targeting
`127.0.0.1:22`, `169.254.169.254:80`, or any RFC1918 `host:port` reported
open/closed — an internal port scanner with a boolean oracle, including
metadata-endpoint reachability probing, ignoring the `allow_internal_monitors`
opt-in that gates the http path. Monitor creation is admin-only, so this is a
guard-consistency / defence-in-depth gap rather than a privilege crossing — but
it let an admin (or a hijacked admin session) turn the server into a blind
internal scanner.

**Fix.** The tcp branch now resolves the host and runs the shared IP classifier
(respecting `allow_internal_monitors` for loopback, always blocking
link-local/metadata), returning `None` on a blocked class — mirroring the http
branch. `_execute_monitor_checks` additionally re-checks the connected peer
after `create_connection` and reports `blocked` instead of `open` if it lands on
a blocked class, closing the rebinding window.

## F4 — Healthchecks.io ping uses an unguarded `urlopen` (Low, fixed)

**File:** `server/cgi-bin/api.py` (`ping_healthchecks_if_due`).

The watchdog GET to the admin-configured `healthchecks_url` used a bare
`urllib.request.urlopen` — no peer recheck, no redirect refusal. Admin-only
config and an outbound GET whose body is discarded, so exfil/oracle value is
minimal; the concern is consistency (the last unguarded operator-supplied
outbound URL in `api.py`) and redirect-to-metadata on misconfigured infra.

**Fix.** Routed through `_ssrf_safe_opener(allow_loopback=True, ssl_ctx=…,
no_redirect=True)`. Loopback stays allowed (a local watchdog sidecar is a
legitimate target); link-local/metadata is always blocked.

---

## Re-checked and confirmed sound (no action)

- **Agent command channel.** `exec:` runs arbitrary shell as root by design;
  the trust boundary is the device token (compared with `hmac.compare_digest`),
  the transport is TLS-verified HTTPS-only, and command delivery rides the
  heartbeat. A MITM cannot impersonate the server.
- **Agent self-update.** sha256-pinned download plus the opt-in, fail-closed GPG
  signature gate (`require-signed-updates`) using an ephemeral keyring.
- **Container / compose ops.** argv-only (never `shell=True`), action
  allowlists, tight ID/stack-name regexes, compose path resolved and existence-
  checked. The new batched `docker inspect` (restart-count binding) passes only
  agent-derived container IDs as argv elements — no shell, no interpolation.
- **Host user / firewall actions.** Username and SSH-key validators forbid all
  shell metacharacters; the single-quote-wrapped interpolation is safe.
- **Front-end XSS.** Device/container/host-controlled fields are consistently
  escaped via `escHtml`/`escAttr`; the new ClamAV-scan-time and per-interface
  MAC render paths pass through `escHtml`.
- **AuthZ.** Device-token compares are constant-time; re-enrollment requires the
  existing token; inbound-webhook tokens are compared with `hmac.compare_digest`;
  RBAC `require_perm` enforces scope at the dispatch chokepoint.
- **No `pickle` / `yaml.load` / `eval` / `os.system`** anywhere; CVE/OSV fetches
  use hardcoded hostnames.
