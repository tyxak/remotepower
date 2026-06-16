<!-- Thanks for the PR! Keep it focused; fill in the checklist. -->

## What & why

<!-- What does this change, and why? Link any related issue (Fixes #123). -->

## How it was tested

<!-- Commands run, manual verification, new/updated tests. -->

## Checklist

- [ ] `RP_DATA_DIR="$(mktemp -d)" python -m unittest discover -s tests` passes
- [ ] Added/updated tests for the change (regression test for a bugfix)
- [ ] **CSP-safe**: no inline `on*=` handlers or `style="…"` (HTML *or* `app.js` innerHTML); events via `data-action`, styles via class/`.style`
- [ ] **No emoji** in the UI; icons are inline Lucide-style SVG
- [ ] New tables wire `tableCtl.wireSortOnly` + `sortRows` + `data-col`; variable-length panels are scroll-capped
- [ ] Any always-on CSS animation uses `opacity`/`transform` only (no `box-shadow`/`background`/`width`)
- [ ] If the Linux agent changed: `cp client/remotepower-agent.py client/remotepower-agent`
- [ ] User-facing change is documented (in-app docs, README, `docs/vX.Y.Z.md`)
- [ ] No secrets, tokens, or real hostnames added to the repo

## Notes for reviewers

<!-- Anything risky, follow-ups, or areas you want extra eyes on. -->
