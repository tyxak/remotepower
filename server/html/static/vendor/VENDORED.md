# Vendored third-party libraries

Versions and upstreams for everything under `static/vendor/`, so updates and
CVE checks don't require source archaeology. **When you update a lib, update
this table in the same commit.** Where the bundled files carry no version
marker the version is recorded as the best evidence available — pin it
properly on the next update.

## Version check — 2026-08-06

Upstream latest vs. what is pinned below, with the practical exposure noted so a
maintainer with a browser to test in can decide:

- **swagger-ui 5.32.6 → 5.32.8 available.** 5.32.8 carries DOMPurify fixes
  (CVE-2026-41238/41239/41240). Practical exposure here is low: the API Reference
  page renders RemotePower's OWN server-generated OpenAPI spec, is admin-authed,
  and runs under `script-src 'self'` with no `unsafe-inline`, so the DOM-XSS
  class is strongly mitigated regardless. Recommended on the next cut (fetch the
  bundle from the tagged release and smoke-test the page in a browser — do not
  swap a minified bundle unverified).
- **xterm.js 5.5.0 → 6.0.0** and **xterm-addon-fit** are a MAJOR bump; defer
  until the web terminal can be exercised in a browser (breaking-change risk).
- noVNC 1.5.0, qrcode-generator, fonts: current / no security-relevant update.

| Directory | Library | Version | Upstream | Used by |
|---|---|---|---|---|
| `novnc/` | noVNC | 1.5.0 (see `novnc/VENDORED.md`) | https://github.com/novnc/noVNC | VNC console (device drawer) |
| `swagger-ui/` | Swagger UI | 5.32.6 (`VERSION` string in `swagger-ui-bundle.min.js`) | https://github.com/swagger-api/swagger-ui | API Reference page |
| `qrcode-generator/` | qrcode-generator | unversioned bundle | https://github.com/kazuhikoarase/qrcode-generator | 2FA enrollment QR |
| `xterm/` | xterm.js | 5.5.0 (`@xterm/xterm@5.5.0`) | https://github.com/xtermjs/xterm.js | Web terminal |
| `xterm-addon-fit/` | xterm fit addon | 0.10.0 (`@0.10.0`) | https://github.com/xtermjs/xterm.js | Web terminal resize |
| `fonts/` | Inter + JetBrains Mono | see `inter-jetbrains.css` | https://rsms.me/inter/ · https://www.jetbrains.com/lp/mono/ | UI / mono typography |

## Optional Python dependencies (server)

The server core is stdlib-only. These unlock optional features and are
detected at runtime (`/api/diagnostics` → `optional_deps`); absent = feature
hidden, never an error:

| Package | Feature |
|---|---|
| `webauthn` | Passkeys / WebAuthn sign-in (v4.2.0) |
| `pysaml2` (+ `xmlsec1` binary) | SAML 2.0 SSO (v4.2.0) |
| `ldap3` | LDAP authentication |
| `cryptography` | CMDB vault, agent enrollment crypto extras |
| `psycopg2` / `psycopg` | PostgreSQL storage backend |
| `reportlab` | PDF report export |
| `psutil` | richer server-status metrics |

Dev-only tooling is pinned in `pyproject.toml` / `make install-dev`
(black 26.5.1, isort 8.0.1, mypy 2.1.0) and `playwright` powers the
optional `make e2e` browser smoke suite.
