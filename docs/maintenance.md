# Maintenance Windows

**Scheduling → Maintenance** defines windows during which **notifications are
held back** for specific hosts, groups, sites, tags, or the whole fleet. Expected
downtime (patching, reboots, migrations) then doesn't page anyone. A window can
also keep alerts out of the inbox altogether, and it can hold commands until the
window opens.

## How it works

A window has a scope, a schedule and, optionally, a list of events.

- **Scope.** A single **host**, a **group**, a **site**, a **tag**, a **smart
  group**, or the whole fleet (**Entire fleet**). Site and tag are the ones to
  reach for when you patch a customer rather than a group: sites span groups, so
  covering one would otherwise mean a window per host or silencing everything.
- **Schedule.** Either **One-shot**, with a start and an end in your local time,
  or **Recurring (cron)**, with a cron expression and a duration in minutes (1 to
  10,080, which is a week). The weekly builder fills the cron expression from the
  days and the time you tick. Or **Follow a time period**: the window is open
  whenever a [named time period](time-periods.md) is, in that period's time zone.
- **Events.** Leave the list empty and the window covers every event it can hold.
  Tick events to narrow it. The dialog offers `device_offline`, `device_online`,
  `monitor_down`, `monitor_up`, `service_down`, `service_up`, `patch_alert`,
  `cve_found` and `log_alert`. A narrowed window holds only what you tick, so tick
  the recovery event too (for example `device_online` with `device_offline`).
- A smart-group window follows the group's rules, so a host that starts matching
  is covered from its next check-in without anyone editing the window. If the
  smart group is deleted the window covers nothing, rather than everything.

While a matching window is active, events for the hosts in scope are **held back
from webhooks, e-mail and push**. By default the alert is still raised, so the
[Alerts](alerts.md) inbox keeps a record and nothing is lost. A window can also
be set to [raise no alerts at all](#raise-no-alerts-at-all).

### Writing the cron expression

The cron expression has five fields: minute, hour, day of month, month and day of
week. It is read in the **server timezone**, and the dialog shows which one that
is. Each field understands `*`, a number, a list (`1,15`), a range (`1-5`) and a
step (`*/15`). **Use numbers for days and months.** Sunday is `0` or `7`. Names
such as `SUN` or `JAN` are not understood: the window saves, but it never opens.
For example, `0 3 * * 0` is Sundays at 03:00 and `0 22 * * 1-5` is weeknights at
22:00.

## What it does and doesn't do

- It suppresses **notification**, not monitoring. Checks keep running and the
  data keeps flowing, so [Trends](trends.md) and [Timeline](timeline.md) stay
  complete.
- It holds a recovery notice with the alert it recovers, when the window covers
  every event. A window that holds `metric_warning` holds `metric_recovered` too,
  and `device_offline` and `device_online` go together, so nobody inside the window
  is told that something cleared that they were never told about. Every event that
  recovers a held event is held. A window with a list of events holds only the
  events on that list.
- A held notice is not sent when the window ends. With the default setting the
  alert in the [Alerts](alerts.md) inbox still opens and closes as usual, and the
  suppression log shows what was held. If an alert was delivered to a pager
  **before** the window began and clears **inside** it, the pager gets no resolve.
  End the window before the recovery, or resolve it there.
- The **Needs attention** digest still lists a held problem in the default mode.
  See [Needs Attention](attention.md).

## Raise no alerts at all

Some planned work raises alerts you never need to see. A nightly backup that stops
and starts seventeen containers opens seventeen *Container stopped* alerts, which
sit on the dashboard until each container returns and then stay in the alert
history. Set **While the window is active** to **Raise no alerts at all** for that
window:

- A covered event is not written to the Alerts inbox. What it reports is also left
  out of **Needs attention** and, for stopped containers, out of the count on the
  Home page, and so out of the health score those feed. Needs attention can hold
  back a host's offline state, containers, disks, services, failed units, patches,
  reboots, CVEs, configuration drift, stale backups and log alerts. An item that
  belongs to no single host stays. The window's row in the list says *no alerts*.
- Each held event is still listed in the suppression log (the **Suppression log**
  button, or `GET /api/maintenance/suppressions`), so you can see what the window
  kept out. The activity feed on Home also still records it: that feed is the log
  of what happened on the fleet, and the suppression log is where "held" is told
  apart from "did not happen".
- "Covered" is the same as for a notification: the hosts the window applies to and,
  if you ticked events, only those events. An event the window does not cover, such
  as a disk that fills up during the backup, still raises its alert.
- An alert that was already open when the window starts stays open. A recovery
  that arrives inside the window still closes it.
- A problem that begins inside the window and is still there when it ends does not
  become an alert later. It shows in Needs attention again once the window is over,
  but nothing opens an alert for it. If the work could leave something broken, keep
  the default and let the alert open, or look at Needs attention afterwards.

## Hold commands until the window opens

Tick **Gate command/upgrade execution to this window** to turn the window into a
change window. A command queued for a covered host, such as an upgrade, a reboot
or a script, **waits in the queue** until a gating window that covers the host is
open, and runs then. Changes to the host's poll interval are never held.

- A host that no gating window covers is never held.
- A window that never opens holds its commands for ever. Check the cron
  expression: a name such as `SUN` means the window never opens.
- Auto-patch, scheduled commands and rollouts queue commands the same way, so a
  gating window holds them too.

## Where else a window counts

- **Calendar.** Active and upcoming windows show on the [Calendar](calendar.md).
- **Uptime and SLA.** Time inside a **one-shot** window does not count as downtime
  in the [SLA](sla.md) figures. Recurring windows are not subtracted.
- **Integrity Guard.** A host that is inside a window is in report-only mode, so a
  planned deploy does not quarantine a file. See
  [Integrity Guard](integrity-guard.md).
- **Pentest.** An active (intrusive) scan of an enrolled host needs an active
  window for it, unless you choose to override. See
  [Security scans](security-scans.md).
- **Auto-patch.** Each enabled auto-patch policy keeps a window of its own
  (**Auto-patch: …**, one hour long, notifications only) so the patch run and
  its reboot do not page anyone. You can see it in the list, but the policy owns
  it. Change the policy, not the window.
- **Public status page.** A component whose hosts are inside an active window
  shows as under maintenance on the [status page](status-board.md). The
  announcement is off unless the window sets `public` and a `public_title`
  through the API. Only the title and the times are published, never the reason
  or the host names.

## Maintenance mode is something else

**Settings → Security → Maintenance mode** is a single switch for the whole
server. While it is on, new commands to hosts are refused with a message and a
banner is shown to everyone. Heartbeats and browsing keep working, so hosts do
not flip to offline. Use it while you upgrade the RemotePower server itself.
It is not a window: it has no schedule, and it does not hold alerts.

## Related

- To silence a *chronically noisy* alert permanently (not on a schedule), use
  [Alert tuning](alert-tuning.md).
- Managing the alerts themselves is the [Alerts](alerts.md) inbox.
- [Schedule](schedule.md) and [Auto-patch](auto-patch.md) queue the commands a
  gating window holds.

## Permissions

Everyone who is signed in can see the windows. Creating, editing and deleting
them is admin-only and audit-logged.

Under multi-tenancy a window belongs to the tenant that created it and only
covers that tenant's hosts.
