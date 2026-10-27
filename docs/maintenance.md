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
- While a matching window is active, alerts for in-scope hosts are **held back
  from webhooks and the needs-attention card** — but history still records
  everything, so nothing is lost.
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
- A held notice is not sent when the window ends. The alert in the
  [Alerts](alerts.md) inbox still opens and closes as usual, and the suppression
  log shows what was held. If an alert was delivered to a pager **before** the
  window began and clears **inside** it, the pager gets no resolve; end the
  window before the recovery, or resolve it there.
- [Auto-patch](auto-patch.md) upgrades and [scheduled commands](schedule.md)
  honour maintenance windows and host quarantine.

## Related

- To silence a *chronically noisy* alert permanently (not on a schedule), use
  [Alert tuning](alert-tuning.md).
- Managing the alerts themselves is the [Alerts](alerts.md) inbox.

## Permissions

Creating and editing maintenance windows is admin-only and audit-logged.
