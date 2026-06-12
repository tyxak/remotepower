# Vendored third-party libraries

Versions and upstreams for everything under `static/vendor/`, so updates and
CVE checks don't require source archaeology. **When you update a lib, update
this table in the same commit.** Where the bundled files carry no version
marker the version is recorded as the best evidence available — pin it
properly on the next update.

| Directory | Library | Version | Upstream | Used by |
|---|---|---|---|---|
| `novnc/` | noVNC | 1.0.3 (from bundled source) | https://github.com/novnc/noVNC | VNC console (device drawer) |
| `swagger-ui/` | Swagger UI | 3.x bundle (marker `3.1.4`; verify on update) | https://github.com/swagger-api/swagger-ui | API Reference page |
| `qrcode-generator/` | qrcode-generator | unversioned bundle | https://github.com/kazuhikoarase/qrcode-generator | 2FA enrollment QR |
| `xterm/` | xterm.js | unversioned bundle | https://github.com/xtermjs/xterm.js | Web terminal |
| `xterm-addon-fit/` | xterm fit addon | unversioned bundle | https://github.com/xtermjs/xterm.js | Web terminal resize |
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
