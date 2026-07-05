# Calendar

**Scheduling → Calendar** is a **shared events calendar** for the whole team —
backups, deploys, certificate renewals, maintenance, or anything else you want
everyone to remember.

## How it works

- Events are shared across all users of the instance — one team calendar, not a
  per-user view.
- Add an event with a title, date/time and optional notes; it shows on the month
  grid for everyone.
- Use it as a human-readable record alongside the automated systems: note *when*
  a planned change is happening so it lines up with the relevant
  [maintenance window](maintenance.md).

## Calendar vs. the automated schedulers

The Calendar is a **memory aid**, not an executor — it does not run anything.
For things that actually fire:

- [Scheduled Commands](schedule.md) — a one-off shutdown/reboot at a time.
- [Cron & timers](cron.md) — recurring jobs on a host.
- [Auto-patch](auto-patch.md) — recurring package upgrades.
- [Tasks](tasks.md) — a shared kanban board for work-in-progress.

## Permissions

Any signed-in operator can add and edit shared calendar events; changes are
visible to the whole team.
