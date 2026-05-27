# RemotePower — project notes for Claude Code

## Visual: no emoji in UI, use Lucide-style SVG

Never reach for an emoji as an icon. The left sidebar uses inline
SVG (Lucide-style strokes, `stroke="currentColor"`,
`viewBox="0 0 24 24"`) — match that style everywhere:

- Device drawer action buttons
- Settings tabs / section headers
- Table action buttons (Edit, Delete, Inspect, …)
- README badges / headers — plain Markdown or shields.io only

Bad (do not ship):

```html
<button>💻 Run command</button>
<button>🧹 Uninstall agent</button>
```

Good:

```html
<button>
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
       stroke-width="2" width="14" height="14"
       stroke-linecap="round" stroke-linejoin="round">
    <path d="M3 3h7v7H3z"/>
  </svg>
  Run command
</button>
```

CLI / agent log output (terminal-only) is allowed plain ASCII without
icons at all. The rule applies to anything that renders in the
browser or in the README.

Reference: https://lucide.dev/icons/

## Sortable tables — ALWAYS wire on new tables

Every new `<table>` added to the UI must wire up sort buttons. The
pattern is:

```js
// In the renderer that builds the tbody:
tableCtl.wireSortOnly('<thead-id>', '<prefs-name>', <rerender-fn>);
const sorted = tableCtl.sortRows('<prefs-name>', rows, r => ({
  col1: r.col1Value,
  col2: r.col2Value,
  // …
}));
```

Plus every sortable `<th>` MUST carry a `data-col="<key>"` attribute
matching the keys returned by the `sortRows` getColumns function.

**Eager wire-up:** call `tableCtl.wireSortOnly(...)` at the *top* of
the loader, before the data fetch / empty-state branches — otherwise
users see column headers with no ↕ indicator until data arrives.

**Why this lives here:** sort regressions shipped multiple times
(Custom Scripts results, Log Alert global rules, Processes) and had
to be patched in follow-up commits. Catch them in code review.

## Two-remote release workflow

- `origin` = `tyxak/claude-code` (test)
- `remotepower` = `tyxak/remotepower` (production)

Always push to both. Retag with `git push --force remotepower vX.Y.Z`
— do **not** delete-and-recreate, that destroys the GitHub release.

## Agent .py / extensionless sync

`client/remotepower-agent.py` and `client/remotepower-agent` must
stay byte-identical. After editing `.py`:

```
cp client/remotepower-agent.py client/remotepower-agent
```

A regression test (`test_agent_extensionless_matches_py`) enforces
this on every release.

## Version-bump checklist

When bumping to vX.Y.Z:

1. `SERVER_VERSION` in `server/cgi-bin/api.py`
2. `VERSION` in `client/remotepower-agent.py` + sync to extensionless
3. `CACHE_NAME` in `server/html/sw.js`
4. All `?v=` cache-bust occurrences in `server/html/index.html`
5. README version badge
6. Create `tests/test_vXYZ.py` with strict pins
7. Loosen previous `tests/test_vXYZ.py` strict pins to regex
8. Create `docs/vX.Y.Z.md`
9. New top entry in `CHANGELOG.md`

The `test_vXYZ.TestVersionBumps` class catches all of these.
