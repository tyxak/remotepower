# RemotePower — agent guidance

**The authoritative, always-current project guide for any AI coding agent is
[`CLAUDE.md`](CLAUDE.md).** OpenCode (and any other agent) should read it in full
before making changes — it is the single source of truth and is kept up to date
each release.

It covers, in detail:

- **House rules** — box-overflow caps (variable lists scroll, ~15-line cap),
  the typography scale (28/16/14/13/12/11/10px), no-emoji (Lucide SVG icons),
  the strict CSP (no inline `style=`/`on*=`; events via `data-action`), sortable
  tables (`tableCtl.wireSortOnly` + `data-col`), layout-as-cards.
- **The two-remote release workflow** — work on `main`; `origin/main` = TEST,
  `remotepower/main` = PRODUCTION; signed tags; `make test` / `make test-both` /
  `make check` as the local gate; release artifacts (`make release`), ghcr image,
  AUR packages, marketing site, GitHub wiki, CodeQL triage.
- **Recurring gotchas** — the lock-nesting bug class (never call
  `fire_webhook()`/`audit_log()` inside a `_LockedUpdate`/`_DeviceUpdate`); the
  "touch every registry" webhook-event checklist; the recover-event
  `_record_alert`-whitelist rule; the denylist-role security class; the
  agent `.py` ↔ extensionless sync; the version-bump checklist.
- **Subsystems** — the per-host Checks engine, monitors, alerts/correlation,
  integrations, the AI/RAG subsystem, storage backends (JSON/SQLite/Postgres),
  and per-release notes/codenames.

Do not duplicate that content here; update `CLAUDE.md` instead and keep this file
a thin pointer.
