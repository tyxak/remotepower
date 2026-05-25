# RemotePower — Security Review (v3.0.4)

Date: 2026-05-25. Scope: a focused security re-review eight months on
from the v2.3.2 review. Same brief as before — auth, command
execution, input handling, secrets, transport, and frontend — plus an
explicit check on the items that were *recommendations* in 2.3.2 to
see whether they have been addressed.

This release closes the headline open finding from 2.3.2 (L1 — CSP
`'unsafe-inline'`) and runs a thorough sweep across every
browser-facing surface. The remaining open items are unchanged in
substance from the previous review and remain accepted-with-rationale.

---

## Summary

The posture is now noticeably stronger than at the 2.3.2 mark. The
single biggest gap on the previous review — `'unsafe-inline'` in the
CSP, which left the dashboard vulnerable to *injected* inline scripts
despite the existing `escHtml`/`escAttr` discipline — is now closed.

The review found **one finding fixed in this release** and confirmed
that the remaining accepted limitations have either been partially
addressed (L2) or remain unchanged-by-design (L3, L4).

---

## Fixed in 3.0.4

### F1 — CSP `'unsafe-inline'` removed from `script-src` and `style-src`  (severity: high)

**Was:** the Content-Security-Policy on both nginx configs included
`'unsafe-inline'` in both `script-src` and `style-src`, required by
the frontend's ~210 inline `onclick=` handlers, ~470 inline `style=`
attributes, and an inline `<script>` / `<style>` block in
`index.html`. As recorded in the 2.3.2 review L1, this meant the CSP
blocked *external* malicious scripts but did **not** block an
*injected* inline `<script>` or `onclick=` — the defence rested
entirely on `escHtml` / `escAttr` discipline. A single missed escape
in any of the ~244 templating call sites was the only thing standing
between a stored XSS bug and arbitrary script execution.

**Fixed:** the full inline-code migration was carried out:

- `index.html`: 1 inline `<style>`, 1 inline `<script>`, 718 `style=`
  attributes, 367 inline event handlers, and 1 stray `javascript:` URI
  → 0 of each. Inline blocks moved to external CSS/JS, attributes
  replaced with utility classes (named + auto-generated `isl-N`),
  handlers rewired to `data-action` / `data-action-btn` event
  delegation.
- `app.js` (13 k+ lines of template-string HTML): 961 `style=` in
  innerHTML, 44 `onclick=` / 5 `onchange=` / 6 `oninput=` → 0 of
  each. A `_evtData` Map carries the args for handlers whose payload
  is too large for `data-*` attributes (JSON blobs, callbacks).
- `swagger.html`: inline `<style>`, inline `<script>`, inline
  `style=`, plus two cdnjs CDN `<link>`/`<script>` → all extracted
  and self-hosted.
- `docs/Manual.html`: inline `<style>` + `style=` → external CSS.
  Also added to the deployment paths (Dockerfile + `deploy-server.sh`
  + `install-server.sh`); the dashboard's `/Manual.html` link
  silently 404'd in production before this release.
- Three runtime sites that would have circumvented the new CSP were
  caught and refactored: a `document.createElement('style')` injection
  for the CMDB active-tab style; a `setAttribute('onclick', …)` /
  `setAttribute('oninput', …)` re-index loop in `hcRemoveUser` (which
  was also functionally broken under the new event-delegation model);
  and a QR-code fallback that built an `<img onerror="…" style="…">`
  via `innerHTML`.

Five external CDN dependencies that were always-blocked even under
the previous `'unsafe-inline'` CSP (because cross-origin is its own
axis, orthogonal to inline) were self-hosted under
`/static/vendor/`: Inter + JetBrains Mono web fonts (92 woff/woff2
subsets, ~1.4 MB on disk; the browser only fetches the latin subset
in practice), `@xterm/xterm` 5.5.0 + `addon-fit` 0.10.0,
`qrcode-generator` 1.4.4, and Swagger UI 5.17.14 (CSS + bundle JS).
The associated CDN fetches and the api.qrserver.com img-src fallback
are gone, so `script-src`, `style-src`, and `img-src` now resolve to
`'self'` only (plus `data:` for the base64 icons inside the swagger
CSS).

Both nginx configs now ship:

```
script-src 'self'; style-src 'self'; img-src 'self' data:; …
```

No `'unsafe-inline'` anywhere. The "what if I missed one escape" risk
is now mitigated by the browser, not just by escape discipline.

---

## Accepted limitations / recommendations (state in 3.0.4)

### L2 — Secrets in `config.json` — **partially fixed**

The 2.3.2 review recommended extending the `RP_PROXMOX_TOKEN_SECRET`
pattern to the SMTP and LDAP passwords. Both have shipped:
`RP_SMTP_PASSWORD` and `RP_LDAP_BIND_PASSWORD` (3.0.3 release notes).
The live `config.json` is still `0600` and the backup export still
redacts the secrets, so the realistic leak paths are closed. Setting
the env vars makes the in-file value irrelevant to the running
server.

**Status:** the recommended low-effort fix has been done. Encryption
at rest / systemd credentials remain larger work and are still not
called for unless deployment context changes.

### L3 — Agent command execution runs a shell — unchanged

Inherent to what RemotePower is — a remote command runner. The
server-side `_check_exec_allowlist` and `require_admin_auth` boundary
still looks sound on re-review. Admin token hygiene + the audit log
remain the operational controls. No change recommended.

### L4 — CSRF posture — unchanged

Same trade-off as before: the session token lives in `localStorage` /
`sessionStorage` and is sent via the custom `X-Token` header, so
classic cookie-borne CSRF doesn't apply. The XSS exposure of token
storage is now mitigated by the strict CSP (F1 above) — an injected
inline script can no longer reach `localStorage` without triggering a
CSP violation. The posture is materially better than it was in 2.3.2.

### L5 — Reviewed and found OK (re-confirmed)

Re-verified in this pass:

- **Login flow** — still rate-limited with a 10-minute lockout
  (3.0.2 added exponential backoff per the changelog), constant-time
  password comparison, dummy-hash verify on missing-user, TOTP 2FA,
  audit logged. Password hashing is bcrypt with the 2.3.2 PBKDF2
  fallback; PBKDF2 iteration count still at the OWASP floor.
- **Session tokens** — 256-bit `secrets.token_urlsafe`; API-key
  comparison is constant-time across the full set with no early
  exit.
- **Agent transport** — TLS verification on, credentials file
  `0600`.
- **SSRF** — monitor HTTP targets still go through the private/
  loopback/link-local guard; explicit opt-in flag for internal
  targets.
- **Path traversal** — resource IDs still validated against a strict
  allowlist regex.
- **Data file permissions** — `0600` on creation.
- **HTTP security headers** — both nginx configs carry
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy`, `Permissions-Policy`, and the now-strict CSP.
  HSTS still commented out — enable when HTTPS-only.
- **No `eval` / `new Function` / `setTimeout('string')`** anywhere
  in `app.js` (re-scanned). The `'unsafe-eval'` directive is
  consequently not needed and is correctly absent.
- **No `javascript:` URIs** anywhere in shipped HTML (one was found
  and removed during this review — see F1).
- **CGI surface emits pure JSON** — re-confirmed; no Python code
  path writes HTML to the response body. The MCP server is JSON-RPC,
  the webterm proxy is WebSocket, the agent runs offline of any
  browser context.

---

## Tests

`tests/test_v232.py` is now the canonical security-regression file
and has grown from 11 to 18 tests. New since 2.3.2:

- `test_csp_no_unsafe_inline` — directive integrity in both nginx
  configs (checked only against the `add_header` line, so a comment
  mentioning the string in passing doesn't trip the regex).
- `test_no_inline_scripts_in_html` / `test_no_inline_event_handlers_in_html`
  — iterate `index.html`, `swagger.html`, `Manual.html` from a
  shared `_SHIPPED_HTML` list, so adding a future page is a one-line
  edit.
- `test_no_inline_event_handlers_in_appjs` — covers the JS template
  strings (a different surface — handlers there only manifest after
  innerHTML).
- `test_no_javascript_uri_in_html` — catches the
  `href="javascript:…"` form.
- `test_no_external_cdn_in_shipped_assets` — `<script>` / `<link>` /
  `<img>` / `<iframe>` auto-loaded resources; user-clickable `<a>`
  documentation links are correctly not flagged.
- `test_vendor_libs_are_self_hosted` — guards the
  `static/vendor/*` directory so a future deploy refactor can't
  silently lose the bundled libs.

All 18 tests pass on the current tree. Full suite **940+ tests, all
passing** (no regressions from the migration).

---

## What "thorough" means in this review

The 2.3.2 review noted it was *focused, not line-by-line*. This pass
is also focused, but it ran an explicit enumeration of every
browser-facing surface:

| Surface | State |
|---|---|
| `server/html/index.html` | clean |
| `server/html/swagger.html` | clean |
| `docs/Manual.html` | clean (and now actually deployed) |
| `server/html/static/css/*` | clean — only local `@import` and `data:` images |
| `server/html/static/js/*` | clean — V8 parses, no inline event handlers in templates |
| `server/html/sw.js` | clean — no external loads |
| `server/html/manifest.json` | clean — same-origin icons only |
| `server/html/static/vendor/*` | self-hosted, no further fetches |
| `server/cgi-bin/*.py` | JSON-only API — no HTML emission |
| `mcp/`, `server/webterm/`, `client/` | not browser-served |

A new file `.gitignore` was added in passing — `__pycache__` had been
accidentally committed at one point.
