# Vendored third-party libraries

Versions and upstreams for everything under `static/vendor/`, so updates and
CVE checks don't require source archaeology. **When you update a lib, update
this table in the same commit.** Where the bundled files carry no version
marker the version is recorded as the best evidence available — pin it
properly on the next update.

## v8.0.0 — 2026-11-09

- **Version check — nothing to update (2026-11-09).** Against the npm registry on this date `swagger-ui-dist` 5.34.1, `@xterm/xterm` 6.0.0,
  `@xterm/addon-fit` 0.11.0, `@novnc/novnc` 1.7.0, `qrcode-generator` 2.0.4 and `@fontsource/inter`, `jetbrains-mono` and `b612` 5.3.0 are still the
  current releases, and they are the versions in this folder.
- **Three Actions have a newer release that is still inside the seven-day cooldown, so the pins stay.** `docker/login-action` 4.8.0 (published
  2026-11-05, pinned 4.7.0), `sigstore/cosign-installer` 4.1.3 (2026-11-04, pinned 4.1.2) and `github/codeql-action` 4.39.3 (committed 2026-11-04,
  pinned 4.39.2). The earliest day each can be taken is 2026-11-11 for the last two and 2026-11-12 for the first; the other seven pins are the latest
  releases. The scanner image's nuclei (3.11.1, 2026-08-08) is the latest. The server and agent images build from `python:3.14-slim`, a floating tag
  that moved on 2026-11-08.
- **The server's Python dependencies are not pinned, so what a new install gets is what `make ci-parity` resolves.** `pip-audit` over that list
  (bcrypt, cryptography, dnspython, webauthn, pysaml2, flask, gunicorn, pydantic, psycopg, mini-racer) finds no known vulnerability. The development
  machine's own copies of dnspython (2.9.0), psycopg (3.3.6) and pydantic (2.14.1) are a patch release behind the newest; ci-parity runs the suite on
  the newest in a fresh environment. The push, SSH gateway and web terminal daemons were run against `websockets` 17.4 (the newest, installed into a
  separate directory; this machine's own copy is 10.4, and the installers take the newest): the 208 tests that start them pass.

## v7.5.0 — 2026-11-04

- **Version check — nothing to update (2026-11-04).** Against the npm registry on this date: `swagger-ui-dist` 5.34.1, `@xterm/xterm` 6.0.0,
  `@xterm/addon-fit` 0.11.0, `@novnc/novnc` 1.7.0, `qrcode-generator` 2.0.4 and `@fontsource/inter`, `jetbrains-mono` and `b612` 5.3.0 are the
  current releases, and they are the versions in this folder. The pinned GitHub Actions are the latest releases except
  `sigstore/cosign-installer`, which published 4.1.3 on the day of this check and stays on 4.1.2 until it has been out for the seven days
  Dependabot's cooldown asks for; the scanner image's nuclei (3.11.1) is the latest. The server's Python dependencies are not pinned:
  `pip-audit` finds no known vulnerability in the list `make ci-parity` installs.
- **Licence texts for Inter and JetBrains Mono added.** The two families were vendored since v3.x with the SIL Open Font License 1.1
  named only in this record; B612 (v7.4.9) was the first to carry the text beside the files. The texts are the `LICENSE` files of the
  npm packages `@fontsource/inter@5.3.0` and `@fontsource/jetbrains-mono@5.3.0`, the same versions as the font files here: each
  tarball's sha512 and sha1 matched the registry's `dist` entry before anything was unpacked, and only `package/LICENSE` was read from
  it. They are `fonts/inter-OFL.txt` (copyright The Inter Project Authors, https://github.com/rsms/inter) and
  `fonts/jetbrains-mono-OFL.txt` (copyright The JetBrains Mono Project Authors, https://github.com/JetBrains/JetBrainsMono).
  `tests/test_v750_font_licences.py` pins their sha256.

## v7.4.9 — 2026-11-02

- **B612 5.3.0 added (2026-11-04), for the Typeface option.** From the npm `@fontsource/b612@5.3.0` tarball: its sha512 and sha1
  matched the registry's `dist` before anything was unpacked, it holds 28 files and no install script, and it was unpacked into a
  fresh directory. Two files were copied unchanged into `fonts/files/`: `b612-latin-400-normal.woff2` (Regular) and
  `b612-latin-700-normal.woff2` (Bold), the Latin subset (U+0000-00FF and the usual punctuation). The licence text is
  `fonts/b612-OFL.txt` (SIL Open Font License 1.1, copyright The B612 Project Authors, no reserved font name); the font's own name
  table carries the same copyright line and the licence address. B612 was drawn by Airbus and ENAC for aircraft cockpit screens.
  Nothing loads it until a person picks it under My Account → Appearance → Typeface: the `@font-face` rules are in `styles.css`, and a
  browser fetches a face only when text on the page uses it. The package's italic files and `.woff` copies were not taken, and neither
  was B612 Mono. `tests/test_v749_typeface_font.py` pins the sha256 of both files. nginx serves `/static/` for a year and marks it
  immutable, and the stylesheet names these files without a version, so a new B612 release needs new file names, not new bytes
  under the old ones.
- **swagger-ui 5.34.0 → 5.34.1 — DONE.** A bug-fix release (a non-Map value in a response no longer breaks the
  panel); no advisory. From the npm `swagger-ui-dist@5.34.1` tarball, its sha512 integrity checked against the registry.
  `swagger-ui-bundle.js` was copied as `swagger-ui-bundle.min.js`; `swagger-ui.css` is byte-identical to 5.34.0's, so only
  the bundle's SRI pin in `swagger.html` changed. Booted signed in, in Chromium, against the old bundle as a control: the
  spec loads, an operation expands, no console error and no failed request, the same on both.
- xterm.js 6.0.0, addon-fit 0.11.0, noVNC 1.7.0, qrcode-generator 2.0.4 and the Inter and JetBrains Mono fonts (5.3.0) are
  still the current releases on npm.
- The server's Python dependencies are not pinned, so a new install and the CI run resolve the newest releases; the
  CI-parity run (`make ci-parity`) is what shows a release that breaks.

## v7.4.0 — 2026-10-23

- **swagger-ui 5.33.3 → 5.34.0 — DONE.** From the npm `swagger-ui-dist@5.34.0`
  tarball, its sha512 integrity checked against the registry. `swagger-ui-bundle.js`
  and `swagger-ui.css` were copied as `swagger-ui-bundle.min.js` and
  `swagger-ui.min.css`; the stylesheet changed this time, so both SRI pins in
  `swagger.html` changed. Booted signed in, in Chromium, against the old bundle as a control: the same spec loads, an
  operation expands, no console error, same result on both.
- xterm.js 6.0.0, addon-fit 0.11.0, noVNC 1.7.0 and qrcode-generator 2.0.4 are
  still the current releases.

## v7.4.0 — 2026-10-16

- **swagger-ui 5.33.1 → 5.33.3 — DONE.** From the npm `swagger-ui-dist@5.33.3`
  tarball, its sha512 integrity checked against the registry, `swagger-ui-bundle.js`
  and `swagger-ui.css` copied unchanged (the files here were confirmed to be
  5.33.1's, byte for byte, before the swap). Upstream's stylesheet is identical
  between the two releases, so only the bundle's SRI pin in `swagger.html`
  changed. Booted signed in, in Chromium, against the old bundle as a control:
  the spec loads (954 operations, 14 tags), an operation expands, no console
  error, no failed request, the same on both.
- xterm.js 6.0.0, addon-fit 0.11.0, noVNC 1.7.0 and qrcode-generator 2.0.4 are
  the current releases.

## v7.3.0 — 2026-10-12

- **Version check — nothing to update.** Against the npm registry on this date:
  swagger-ui-dist 5.33.1, `@xterm/xterm` 6.0.0, `@xterm/addon-fit` 0.11.0,
  `@novnc/novnc` 1.7.0, `qrcode-generator` 2.0.4, `@fontsource/inter` 5.3.0 and
  `@fontsource/jetbrains-mono` 5.3.0 are each the current release, and the files
  here are those releases.
- **The server's Python dependencies were run at their latest releases**, the way
  a fresh install resolves them (webauthn 3.0.1, cryptography 50.0.2, pydantic
  2.14.1, werkzeug 3.1.9, pysaml2 7.5.5, gunicorn 26.2.0, psycopg 3.3.6, pyasn1
  0.6.4, asyncssh 2.24.1): 54 test modules that touch them pass unchanged. Nothing
  is pinned, so a new install gets these.
- **Dev tooling moved with them**: black 26.10.1, isort 9.0.2, mypy 2.4.0 and ruff
  0.17.0 produce no change to the formatted baseline and no new finding.

## v7.1.0 — 2026-10-03

- **swagger-ui 5.32.15 → 5.33.1 — DONE.** The current upstream release, taken
  from the npm `swagger-ui-dist@5.33.1` tarball (its sha512 integrity checked)
  and copied verbatim, as before. **Both SRI pins in `swagger.html`
  recomputed.** Booted signed in, in Chromium: the spec loads, operations
  render and expand, no console errors and no failed requests.
- **qrcode-generator 1.4.4 → 2.0.4 — DONE.** 2.0 adds an ES-module build and
  type definitions; the UMD API the 2FA enrolment uses (`qrcode(0, 'M')`,
  `addData`, `make`, `createDataURL`) is unchanged. Minified from
  `dist/qrcode.js` with terser, licence header kept, and **the new bundle drew
  the identical QR matrix as the old one for three inputs** (a plain
  `otpauth://` URI, one with percent-encoded UTF-8, and a 300-character
  string) before it replaced it. SRI pin in `app.js` recomputed; the code
  renders in the browser through the pin.
- **Fonts — current.** Every one of the 92 files under `fonts/files/` is
  byte-identical to `@fontsource/inter@5.3.0` and
  `@fontsource/jetbrains-mono@5.3.0`, the current releases.
- xterm.js 6.0.0, addon-fit 0.11.0 and noVNC 1.7.0 are the current upstream
  releases.

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
| `swagger-ui/` | Swagger UI | 5.33.1 (SRI-pinned in `swagger.html`) | https://github.com/swagger-api/swagger-ui | API Reference page |
| `qrcode-generator/` | qrcode-generator | 2.0.4 (minified from `dist/qrcode.js`; SRI-pinned in `app.js`) | https://github.com/kazuhikoarase/qrcode-generator | 2FA enrollment QR |
| `xterm/` | xterm.js | 6.0.0 (`@xterm/xterm@6.0.0`; SRI-pinned in `app-remote.js`) | https://github.com/xtermjs/xterm.js | Web terminal |
| `xterm-addon-fit/` | xterm fit addon | 0.11.0 (`@xterm/addon-fit@0.11.0`) | https://github.com/xtermjs/xterm.js | Web terminal resize |
| `fonts/` | Inter + JetBrains Mono + B612 | `@fontsource/inter` 5.3.0, `@fontsource/jetbrains-mono` 5.3.0, `@fontsource/b612` 5.3.0 (Regular and Bold, Latin; licence in `fonts/b612-OFL.txt`) | https://rsms.me/inter/ · https://www.jetbrains.com/lp/mono/ · https://github.com/polarsys/b612 | UI / mono typography; B612 for the Typeface option |

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
(black 26.10.1, isort 9.0.2, mypy 2.4.0, ruff 0.17.0) and `playwright` powers the
optional `make e2e` browser smoke suite.
