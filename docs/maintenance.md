# Maintenance Windows

**Scheduling → Maintenance** defines windows during which **webhook alerts are
suppressed** for specific hosts, groups, tags, or the whole fleet — so
expected downtime (patching, reboots, migrations) doesn't page anyone.

## How it works

- A window has a scope, a schedule (a cron expression, built with the weekly-day
  picker or entered directly) and a duration in minutes. The scope can be a
  single **host**, a host **group**, a **site**, a **tag**, a **smart
  group**, or the whole fleet (**global**).
- Site and tag are the ones to reach for when you patch a customer rather than a
  group: sites span groups, so covering one used to mean either a window per
  host or silencing everything.
- A smart-group window follows the group's rules, so a host that starts matching
  is covered from its next check-in without anyone editing the window. If the
  smart group is deleted the window covers nothing, rather than everything.
- While a matching window is active, events for in-scope hosts are **held back
  from webhooks, e-mail and push**. By default the alert is still raised, so the
  [Alerts](alerts.md) inbox keeps a record and nothing is lost. A window can also
  be set to [raise no alerts at all](#raise-no-alerts-at-all).
- Cron expressions are interpreted in the **server timezone** and validated
  before saving; the next runs are previewed.

## What it does and doesn't do

- It suppresses **notification**, not monitoring — checks keep running and the
  data keeps flowing, so [Trends](trends.md) and [Timeline](timeline.md) stay
  complete.
- It holds a recovery notice with the alert it recovers. A window that holds
  `metric_warning` holds `metric_recovered` too, and `device_offline` and
  `device_online` go together, so nobody inside the window is told that something
  cleared that they were never told about. Every event that recovers a held
  event is held; a test derives that list from the event registry (v7.4.2).
- A held notice is not sent when the window ends. With the default setting the
  alert in the [Alerts](alerts.md) inbox still opens and closes as usual, and the
  suppression log shows what was held. If an alert was delivered to a pager **before** the
  window began and clears **inside** it, the pager gets no resolve; end the
  window before the recovery, or resolve it there.
- [Auto-patch](auto-patch.md) upgrades and [scheduled commands](schedule.md)
  honour maintenance windows and host quarantine.

## Raise no alerts at all

Some planned work raises alerts you never need to see. A nightly backup that stops
and starts seventeen containers opens seventeen *Container stopped* alerts, which sit
on the dashboard until each container returns and then stay in the alert history.
Set **While the window is active** to **Raise no alerts at all** for that window:

- A covered event is not written to the Alerts inbox. What it reports is also left
  out of **Needs attention** and, for stopped containers, out of the count on the
  Home page, and so out of the health score those feed. Needs attention can hold
  back a host's offline state, containers, disks, services, failed units, patches,
  reboots, CVEs, configuration drift, stale backups and log alerts; an item that
  belongs to no single host stays. The window's row in the list says *no alerts*.
- Each held event is still listed in the suppression log (the **Suppression log**
  button, or `GET /api/maintenance/suppressions`), so you can see what the window
  kept out. The activity feed on Home also still records it: that feed is the log
  of what happened on the fleet, and the suppression log is where "held" is told
  apart from "did not happen".
- "Covered" is the same as for a notification: the hosts the window applies to and,
  if you ticked events, only those events. An event the window does not cover, a
  disk that fills up during the backup, still raises its alert.
- An alert that was already open when the window starts stays open. A recovery
  that arrives inside the window still closes it.
- A problem that begins inside the window and is still there when it ends does not
  become an alert later. It shows in Needs attention again once the window is over,
  but nothing opens an alert for it. If the work could leave something broken, keep
  the default and let the alert open, or look at Needs attention afterwards.

## Related

- To silence a *chronically noisy* alert permanently (not on a schedule), use
  [Alert tuning](alert-tuning.md).
- Managing the alerts themselves is the [Alerts](alerts.md) inbox.

## Permissions

Creating and editing maintenance windows is admin-only and audit-logged.
