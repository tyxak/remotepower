# Services

**Monitoring → Services** shows the systemd units watched on each device.
Agents report unit state with every heartbeat; a watched unit entering
`failed` (or going missing) raises a `service_down` alert, and recovery
auto-resolves it.

- **Click a row** for history, recent logs, and the unit's configuration.
- **Watch list** — which units are watched is configured per device (device
  drawer → Services) or inherited from group defaults.
- **Actions** — restart/stop/start run through the audited command queue,
  gated on the command permission.
- Failed-unit chips also appear on the device card and in the
  needs-attention rollup.
