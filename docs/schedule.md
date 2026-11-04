# Scheduled Commands

**Scheduling → Schedule** runs a command on a host at a time you choose, once or
on a repeating schedule, instead of dispatching it now.

## Adding a job

Press **Add job** and fill in:

- **Host.** The host the command runs on.
- **Command.** One of **Shut down**, **Reboot**, **Suspend (sleep)**, **Wake
  (Wake-on-LAN)**, **Upgrade packages** (apt, dnf or pacman, with cleanup),
  **Upgrade packages + cleanup + reboot**, or **Run script…** (pick a script from
  the library). The API also accepts `docker_prune` and
  `container_restart:<container name>` for a container the agent has listed.
- **When.** **One-shot** takes a date and time. The repeating choices are **Every
  hour (:00)**, **Every N hours**, **Daily**, **Weekly**, **Monthly** and **Custom
  cron**, a 5-field expression (minute, hour, day of month, month, day of week).
  Times are read in the **server timezone**, which is shown next to the field.
- **Suppress alerts for 1h (maintenance window).** Tick it to open a
  [maintenance window](maintenance.md) around the run, so the reboot or the
  upgrade doesn't page anyone.

The **Cron builder** below the list turns a plain-English description into a
cron expression, checks it and shows its next run times. It needs the AI
assistant to be set up.

## How it works

- Pending jobs are listed with Host, Command, Scheduled for and By (the admin who
  queued it). Delete a job any time before it fires. A repeating job keeps
  running until you delete it. You can keep up to 200 jobs.
- At the scheduled moment the command is placed on the host's normal
  [command queue](agent-commands.md) and delivered on the agent's next
  heartbeat, so it rides the same audit log, quarantine and approval controls as
  any other host command. With change approval on, a command of a gated kind (a
  reboot or shutdown, by default) is not queued when it comes due: it is parked for a
  second admin in your name, and you cannot approve your own job. A request that
  nobody approves within an hour expires, and a one-time job is then gone; a repeating
  job is parked again at its next time. If the server was down at the time, a
  repeating job catches up on what it missed in the last hour, and no more.
- An upgrade follows the host's [upgrade mode](patches.md#upgrade-mode), so a
  host set to Extended installs the new packages an update needs.
- Scheduling a **shutdown** or **suspend** on a host with no MAC address on record
  works, but the answer warns you that a scheduled Wake-on-LAN is not possible: the
  host stays down until someone wakes it.

## Related scheduling surfaces

- For jobs that run on the host itself, manage its own
  [crontab and systemd timers](cron.md).
- For automatic **package upgrades** with rings and holds, use
  [Auto-patch](auto-patch.md).
- For staged fleet-wide deploys, use [Rollouts](rollouts.md).
- To keep scheduled actions from alerting during expected downtime, tick the
  maintenance option above or define a [maintenance window](maintenance.md).

## Permissions

Adding, changing and deleting a scheduled command is **admin-only**, and every
change is audit-logged. Everyone who is signed in can see the list.
