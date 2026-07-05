# Checks

**Monitoring → Checks** is the CheckMK-style rollup: every monitored signal
on every host as one row — **OK / WARN / CRIT / UNKNOWN** — with the check's
output text. It merges reachability, resource thresholds, security posture,
hardware health, custom checks and custom-script results into a single
sortable, filterable table.

## Using the page

- **Filter** by state, host, or check name; sort any column.
- **Toggle a check off** on a host to silence it there — the mute is stored
  server-side (`exposure`-style mutes) and honoured by alerting.
- *Hide muted* and *hide unmonitored* default ON.

## Where rows come from

- **Built-ins** — reachability, CPU/RAM/disk thresholds, posture (world-
  exposed ports honour exposure mutes), SMART, patch backlog, CVEs.
- **Custom checks** — server-side process/port checks and agent-side
  file/journal/log checks defined in the Check catalog.
- **Custom scripts** — a [custom script](custom-scripts.md) whose exit code
  maps to OK/WARN/CRIT.

The same engine feeds the per-device checks view in the device drawer and
the dashboard checks-rollup widget.
