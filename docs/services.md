# Services

**Monitoring → Services** shows the systemd units (Linux) and services (Windows)
you watch on each host. Agents report their state with every heartbeat. When a
watched unit that was running stops running, RemotePower raises a `service_down`
alert, and it clears when the unit is back.

## The page

Four cards at the top count **Services Up**, **Services Down**, **Hosts
Reporting** and **Units Watched**. A badge appears when a maintenance window is
active, because those suppress alerts. The table lists one row per host with its
group, how many units it watches, how many are up and down, and when it last
reported. Hosts with units down sort first.

- **Click a row** to see each unit's state, since when it has been in that
  state, its last 10 state changes and the last 20 log lines. Logs arrive about
  every 5 minutes and need `journalctl` access, so the agent has to run as root.
- **Configure** on a row edits that host's watch list.
- A unit that is not running also gets an **AI diagnose** button.

## Choosing what to watch

- **Per host.** Click **Configure** and enter one unit per line, for example
  `nginx.service`. You can watch up to 50 units per host. Saving needs the
  `services` permission or an admin.
- **Fleet baselines.** The **Service baselines** card on the same page sets a
  default list of units for every host its scope covers. A scope is the whole
  fleet, some groups, some tags or some sites. Baselines are merged with each
  host's own list, so you can watch `sshd.service` everywhere without editing
  every host. Only an admin can change baselines (with multi-tenancy on, only the
  platform operator), and you can keep up to 50.

The agent reports a unit the first time it sees it without alerting. After that, a
unit going from `active` to anything else (failed, stopped, or removed from the
host) raises `service_down`. When it returns to `active`, `service_up` resolves the
alert.

## Acting on a unit

In a host's row detail, **Restart**, **Stop** and **Start** queue the action
through the audited command queue (Linux and Windows hosts). It needs the
`command` permission, and quarantine, maintenance and audit mode apply as for any
other command. The action runs as a fixed `systemctl` call on Linux or as the
`Start-Service`, `Stop-Service` or `Restart-Service` cmdlet on Windows, never
through a shell.

## Related alerts

| Event | When |
|---|---|
| `service_down`, `service_up` | A watched unit stops being active, and the recovery. |
| `unit_flapping`, `unit_flapping_cleared` | A unit under `Restart=always` is restarting repeatedly. It looks healthy at every sample, so `service_down` never fires. Switched off by default. Set **Settings → Security → Service flap detection → Restarts per check** (0 = off) to the number of restarts between two heartbeats that counts as flapping. It clears when the restart counter stops climbing and the unit is running. |
| `failed_unit`, `failed_unit_cleared` | Any systemd unit on the host entered the failed state, whether you watch it or not. The host drawer lists failed units, and **Needs Attention** counts them. |

Per-event toggles are under **Settings → Notifications**.

## Troubleshooting

- **No logs captured yet.** The agent submits logs every few minutes, and needs
  `journalctl` access.
- **A unit shows `unknown`.** The host has no `systemctl`, or the check timed out.
- **No alert for a unit that was never running.** The first report only sets the
  baseline. Start it once, and a later stop is then an alert.

See also: [log-watch.md](log-watch.md) for log rules on the same units,
[maintenance.md](maintenance.md) for windows that mute alerts, and
[alerts.md](alerts.md).
