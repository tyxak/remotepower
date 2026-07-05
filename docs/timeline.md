# Timeline

**Monitoring → Timeline** merges fleet events and command runs into one
chronological stream — the "what happened around 03:40" view. Scope it to
the whole fleet or a single device.

- Every entry links to its source (alert, command output, drift diff, …).
- Filters by kind (events / commands) and time range.
- Useful for incident reconstruction: agent went offline, what commands ran
  before, which alerts fired after, when it recovered.

The same data feeds the dashboard activity feed (recent slice) and the
per-device history in the drawer; the Timeline is the full merged view.
