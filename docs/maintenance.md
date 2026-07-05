# Maintenance Windows

**Scheduling → Maintenance** defines windows during which **webhook alerts are
suppressed** for specific devices, groups, tags, or the whole fleet — so
expected downtime (patching, reboots, migrations) doesn't page anyone.

## How it works

- A window has a scope — a single **device**, a device **group**, or the whole
  fleet (**global**) — a schedule (a cron expression, built with the weekly-day
  picker or entered directly) and a duration in minutes.
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
  deliberately honour maintenance windows and device quarantine.

## Related

- To silence a *chronically noisy* alert permanently (not on a schedule), use
  [Alert tuning](alert-tuning.md).
- Managing the alerts themselves is the [Alerts](alerts.md) inbox.

## Permissions

Creating and editing maintenance windows is admin-only and audit-logged.
