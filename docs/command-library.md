# Command Library

**Fleet → Library** stores saved shell command snippets: the one-liners you
keep re-typing (service restarts, cache clears, quick greps). Each entry is a
name (up to 64 characters), a command (up to 512) and an optional description
(up to 256). The library holds up to 200 snippets.

## Where they surface

- The **exec modal** (Run command on a host) offers the library as a
  pick-list, so operators run vetted commands instead of ad-hoc typing.
- For AI clients, **MCP** exposes multi-line *saved scripts* (the
  [Scripts](scripts.md) feature) through the `run_saved_script` tool — the
  one-liner library itself is a UI pick-list only.

Everyone signed in can read the library and pick from it. Adding, editing and
deleting snippets is admin-only (`GET`, `POST`, `PUT` and `DELETE` on
`/api/cmd-library`).

Commands still run through the normal permission-gated, audited command
queue. The library is a convenience layer, not a bypass: running a snippet needs the
`command` permission, and a host's command allowlist still applies. For multi-line
bash with linting and batch execution, use [Scripts](scripts.md) instead.
