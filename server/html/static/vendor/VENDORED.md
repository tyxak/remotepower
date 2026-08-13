# Vendored third-party libraries

Versions and upstreams for everything under `static/vendor/`, so updates and
CVE checks don't require source archaeology. **When you update a lib, update
this table in the same commit.** Where the bundled files carry no version
marker the version is recorded as the best evidence available — pin it
properly on the next update.

## Version check — 2026-08-13

- **swagger-ui 5.32.6 → 5.32.13 — DONE.** Closes the DOMPurify advisories
  (CVE-2026-41238/41239/41240): the bundled DOMPurify moves 3.4.0 → 3.4.13.
  Practical exposure here was always low — the API Reference renders
  RemotePower's OWN server-generated spec, is admin-authed, and runs under
  `script-src 'self'` with no `unsafe-inline` — but the fix is free and the
  advisory is real.

  Fetched from the `v5.32.13` tag, **SRI hashes recomputed** (`swagger.html`
  pins sha384 for both files), and smoke-tested in a real browser signed in:
  873 operations across 13 tag groups render, an operation expands, zero
  console errors, zero failed requests.

  This is exactly why the warning below says never to swap a minified bundle
  unverified. The first attempt replaced the files and nothing else — the stale
  SRI hashes made the browser refuse BOTH resources and the page rendered
  completely blank, with the failure visible only in the console. A file-level
  diff would have looked perfect.

- **xterm.js 5.5.0 → 6.0.0 + addon-fit 0.10.0 → 0.11.0 — DONE (2026-08-13).**
  Previously deferred on the grounds that an automated smoke test cannot type
  into a shell. It cannot reach a shell, but it can drive every boundary between
  our code and the library, which is where a major bump actually breaks — and
  that is now a permanent test rather than a one-off check
  (`tests/test_v643_vendored_terminal_boots.py`). It boots the REAL vendored
  files in Chromium with `app-remote.js`'s exact constructor options and
  asserts: the UMD globals are constructors, `fit()` sizes to the container,
  written output reaches the terminal BUFFER with the ANSI escape consumed,
  real keystrokes reach `onData` (what the websocket forwards to the remote
  shell), a resize reaches `onResize` (what keeps the remote pty's geometry
  right), and the console is clean. 5.5.0 and 6.0.0 were measured
  side by side and were identical on every one of those.

  There is **no security driver**: `@xterm/xterm` has zero advisories at any
  version, and the only `xterm` advisory is from 2019 against < 3.10.1. The
  cost is size — the bundle grows 290KB → 489KB. That is paid only when an
  operator opens the web terminal, since `app-remote.js` loads it lazily, but
  it is a real 1.7× and worth knowing before the next bump.

  Two probe traps, recorded because both produced a confident wrong answer:
  `write()` is queued and flushed on a later frame, so reading the buffer in the
  same evaluate returns `''` on every version; and the container's `innerText`
  is empty whether or not anything rendered, so asserting on it proves
  nothing.
- noVNC 1.5.0, qrcode-generator, fonts: current / no security-relevant update.

| Directory | Library | Version | Upstream | Used by |
|---|---|---|---|---|
| `novnc/` | noVNC | 1.5.0 (see `novnc/VENDORED.md`) | https://github.com/novnc/noVNC | VNC console (device drawer) |
| `swagger-ui/` | Swagger UI | 5.32.13 (bundles DOMPurify 3.4.13; SRI-pinned in `swagger.html`) | https://github.com/swagger-api/swagger-ui | API Reference page |
| `qrcode-generator/` | qrcode-generator | unversioned bundle | https://github.com/kazuhikoarase/qrcode-generator | 2FA enrollment QR |
| `xterm/` | xterm.js | 6.0.0 (`@xterm/xterm@6.0.0`; SRI-pinned in `app-remote.js`) | https://github.com/xtermjs/xterm.js | Web terminal |
| `xterm-addon-fit/` | xterm fit addon | 0.11.0 (`@xterm/addon-fit@0.11.0`) | https://github.com/xtermjs/xterm.js | Web terminal resize |
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
