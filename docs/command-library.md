# Command Library

**Fleet → Library** stores saved shell command snippets — the one-liners you
keep re-typing (service restarts, cache clears, quick greps). Entries are
name + command + optional description.

## Where they surface

- The **exec modal** (Run command on a device) offers the library as a
  pick-list, so operators run vetted commands instead of ad-hoc typing.
- **MCP** exposes saved commands via `run_saved_script`-style tools, so AI
  clients can only trigger commands an admin saved deliberately.

Commands still run through the normal permission-gated, audited command
queue — the library is a convenience layer, not a bypass. For multi-line
bash with linting and batch execution, use [Scripts](scripts.md) instead.
