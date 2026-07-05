# Scheduled Commands

**Scheduling → Schedule** queues a **shutdown** or **reboot** on a device to run
at a specific future time, instead of dispatching it immediately.

## How it works

- Add a job: pick a device, the action (shutdown / reboot), and the date/time.
  Times are interpreted in the **server timezone** (shown next to the field).
- Pending jobs are listed with Device, Command, Scheduled-for and By (the actor
  who queued it). Delete a job any time before it fires.
- At the scheduled moment the command is placed on the device's normal
  [command queue](agent-commands.md) and delivered on the agent's next
  heartbeat — so it rides the same audit log, permission checks, quarantine and
  4-eyes controls as any other host command.

## Related scheduling surfaces

- For **recurring** shutdowns/reboots or arbitrary host jobs, manage the host's
  own [crontab and systemd timers](cron.md).
- For automatic **package upgrades** on a schedule, use [Auto-patch](auto-patch.md).
- For staged fleet-wide deploys, use [Rollouts](rollouts.md).
- To keep scheduled actions from alerting during expected downtime, pair them
  with [Maintenance Windows](maintenance.md).

## Permissions

Queuing and cancelling a scheduled command requires the **reboot** action
permission (or admin); every queue and cancel is audit-logged.
