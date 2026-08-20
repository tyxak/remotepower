# Maintenance Windows

**Scheduling → Maintenance** defines windows during which **webhook alerts are
suppressed** for specific devices, groups, tags, or the whole fleet — so
expected downtime (patching, reboots, migrations) doesn't page anyone.

## How it works

- A window has a scope, a schedule (a cron expression, built with the weekly-day
  picker or entered directly) and a duration in minutes. The scope can be a
  single **device**, a device **group**, a **site**, a **tag**, a **smart
  group**, or the whole fleet (**global**).
- Site and tag are the ones to reach for when you patch a customer rather than a
  group: sites span groups, so covering one used to mean either a window per
  device or silencing everything.
- A smart-group window follows the group's rules, so a host that starts matching
  is covered from its next check-in without anyone editing the window. If the
  smart group is deleted the window covers nothing, rather than everything.
- While a matching window is active, alerts for in-scope devices are **held back
  from webhooks and the needs-attention card** — but history still records
  everything, so nothing is lost.
- Cron expressions are interpreted in the **server timezone** and validated
  before saving; the next runs are previewed.

## What it does and doesn't do

- It suppresses **notification**, not monitoring — checks keep running and the
  data keeps flowing, so [Trends](trends.md) and [Timeline](timeline.md) stay
  complete.
- [Auto-patch](auto-patch.md) upgrades and [scheduled commands](schedule.md)
  honour maintenance windows and device quarantine.

## Related

- To silence a *chronically noisy* alert permanently (not on a schedule), use
  [Alert tuning](alert-tuning.md).
- Managing the alerts themselves is the [Alerts](alerts.md) inbox.

## Permissions

Creating and editing maintenance windows is admin-only and audit-logged.
