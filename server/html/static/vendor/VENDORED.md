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

## v7.0.3 — 2026-09-07

- **swagger-ui 5.32.13 → 5.32.15 — DONE.** Two upstream patch releases since the
  last bump; the one that matters raises the bundled `js-yaml` past a security
  advisory. Same procedure as last time: files replaced, **both SRI hashes
  recomputed** from the new bytes, and the page booted in a real Chromium.

  Verified in both directions, because "it rendered" on its own proves less than
  it looks. The harness first reported **zero operations** — and reported zero
  for the SHIPPED 5.32.13 files too, which is what identified the harness rather
  than the bundle: `swagger-init.js` shows a "log in first" panel unless a token
  is in storage, so nothing ever fetched the spec. With a token: five operations
  render, the stylesheet applies, the console is clean. Then the pin was
  corrupted on purpose and the browser refused the bundle with an integrity
  error and rendered nothing — so the pins are doing work rather than decorating
  the tag.

- **noVNC 1.5.0 → 1.7.0 — DONE, in that order.** This was recorded as deferred
  earlier in the cycle for a reason: nothing in the suite drove the VNC console,
  and a bump you cannot watch work is how the blank Swagger page shipped. So the
  boot test came first — `tests/test_v703_vendored_vnc_boots.py`, which plays a
  real RFB 3.8 server against the vendored files and drives every call
  `app-remote.js` makes: the module's default export, the raw-channel
  `new RFB(target, channel, {})` form, the viewport setters, all four event
  listeners, `sendCredentials` and `disconnect`. It passed against the shipped
  1.5.0 first, which is what made it a measurement rather than a hope, and it
  was demonstrated failing by mutating the library two ways.

  Then the bump: `core/` and `vendor/pako/` replaced from the v1.7.0 tag,
  LICENSE.txt with them. Two new decoders arrive (`h264.js`, `zlib.js`); pako is
  byte-identical. No SRI pin to recompute — the viewer is a dynamic ES-module
  import, same-origin under `script-src 'self'`, which
  `tests/test_v232.py::test_the_unpinnable_novnc_path_is_still_the_only_one`
  holds to that one path. The whole boot test passes unchanged on 1.7.0: same
  handshake, same canvas geometry, same painted rectangle, clean console.

  A trap worth keeping, found writing the harness: pushing the server's reply
  synchronously from `send()` re-enters noVNC's receive handler mid-compaction
  and the bytes vanish, leaving the client stuck in state `Security`. That reads
  exactly like a library that stopped speaking RFB — it was the probe. Defer the
  push; a real socket is never re-entrant.

- xterm.js 6.0.0 and addon-fit 0.11.0 are the current upstream releases. fonts
  and qrcode-generator: unchanged, no security-relevant update.

## Re-verified for v7.0.0 — 2026-08-14

No changes needed. Every pinned version in the table below still matches the
bytes on disk: the two SRI hashes in `swagger.html` were recomputed from the
files and are identical to the pins, which `tests/test_v643_sri_pins_match.py`
also holds continuously. The check is recorded rather than left implicit because
a deferred verification with nothing asserting it becomes the permanent state —
the same reason the AUR publication now has `tools/aur-status.sh`.

| Directory | Library | Version | Upstream | Used by |
|---|---|---|---|---|
| `novnc/` | noVNC | 1.7.0 (see `novnc/VENDORED.md`) | https://github.com/novnc/noVNC | VNC console (device drawer) |
| `swagger-ui/` | Swagger UI | 5.32.15 (SRI-pinned in `swagger.html`) | https://github.com/swagger-api/swagger-ui | API Reference page |
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
