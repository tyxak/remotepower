# Contributing to RemotePower

Thanks for taking the time to contribute. This guide covers how to get set up,
the conventions the codebase follows, and what we look for in a pull request.

By participating you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to contribute

- **Bug reports** and **feature requests** — open an issue (templates provided).
- **Code** — fixes, features, docs, tests.
- **Security issues** — please do **not** open a public issue; see
  [SECURITY.md](SECURITY.md).

## Project layout

| Path | What |
|---|---|
| `server/cgi-bin/api.py` | The server (single CGI app). |
| `server/html/` | The dashboard — `index.html`, `static/js/app.js`, `static/css/styles.css`, `sw.js`. |
| `client/remotepower-agent.py` | The Linux agent (the canonical agent). |
| `client/remotepower-agent` | A byte-identical extensionless copy of the agent (kept in sync). |
| `client/remotepower-agent-win.py` | The minimal Windows agent. |
| `tests/` | The unittest suite (`test_*.py`). |
| `docs/` | Per-version notes, feature docs, the manual. |

## Development setup

Python 3.8+ (CI runs 3.12). The server imports a few runtime deps:

```bash
python -m pip install bcrypt cryptography dnspython   # + psutil for the agent
```

## Running the tests

The suite must pass before a PR is merged (CI enforces it). Tests respect
`RP_DATA_DIR` so they never touch a real data directory:

```bash
RP_DATA_DIR="$(mktemp -d)" python -m unittest discover -s tests -v
```

Add tests for any behaviour change. New features get a `tests/test_*.py`; bug
fixes get a regression test that fails before your change and passes after.

## Conventions (please follow — CI and review enforce these)

These rules exist because each has been broken and patched before:

- **CSP-safe UI — no inline handlers or styles.** Production serves
  `script-src 'self'; style-src 'self'` with no `unsafe-inline`. Never add an
  inline `on*=` handler or a `style="…"` attribute — in static HTML *or* inside
  an `app.js` `innerHTML` string. Wire events via `data-action` dispatch and set
  styles with a class or `.style.x`. (`tests/test_v232.py` guards this.)
- **No emoji in the UI.** Use inline Lucide-style SVG icons
  (`stroke="currentColor"`, `viewBox="0 0 24 24"`) — match the sidebar. Plain
  Markdown / shields.io in the README. (CLI/agent terminal output may be plain
  ASCII.)
- **Cap variable-length panels.** Any box that renders a variable number of
  rows must cap height and scroll (`scrollable-table-wrap audit-scroll` for
  tables, `scroll-cap` for lists) — don't let it grow unbounded.
- **Wire sort on new tables.** Every new `<table>` wires
  `tableCtl.wireSortOnly(...)` + `sortRows(...)` and gives each sortable `<th>`
  a `data-col`.
- **Animate compositor-only properties.** For any always-on/`infinite`
  animation, animate `opacity`/`transform` only — never `box-shadow`,
  `background`, `width`, etc. (those repaint every frame).
- **Keep the agent copies in sync.** After editing `client/remotepower-agent.py`,
  run `cp client/remotepower-agent.py client/remotepower-agent`
  (a test enforces byte-identity).
- **Document user-facing changes** across the doc surfaces (in-app docs page,
  README, `docs/Manual.html`, the per-version `docs/vX.Y.Z.md`).
- **One typography scale, one set of colors** — reuse the existing CSS literals;
  don't introduce new body sizes or ad-hoc colors.

## Commits & pull requests

- Branch off `main`; PRs target `main`. Keep PRs focused.
- Write clear commit messages (a short imperative summary line, then a body
  explaining *why*). Conventional-style prefixes (`feat:`, `fix:`, `perf:`,
  `docs:`) are welcome but not required.
- Fill in the PR template checklist.
- CI must be green. Maintainers handle versioning and releases.

## Adding a webhook/alert event

A new event type must be registered in **every** registry or it half-works
silently (the canonical event tuple, the severity map, the channel-kind map, the
dashboard activity set, and the click-through routing). If you add one, grep for
an existing event (e.g. `smart_failure`) and mirror it everywhere; guardrail
tests cover most but not all of these.

Questions? Open a discussion or a draft PR — early feedback is welcome.
