# Calendar

**Scheduling → Calendar** is a **shared events calendar** for the whole team —
backups, deploys, certificate renewals, maintenance, or anything else you want
everyone to remember.

## How it works

- Events are shared across all users of the instance: one team calendar, not a
  per-user view. A calendar holds up to 1,000 events.
- Add an event with a title (up to 120 characters), a start and optional end, a
  description (up to 2,000 characters), an **all-day** flag, a colour (blue, green,
  amber, red, purple, teal or slate) and a repeat (none, daily, weekly, monthly or
  yearly). It shows on the month grid for everyone, and the next ones appear in the
  dashboard's **Upcoming** widget.
- **Export** the calendar as an iCalendar feed (`GET /api/calendar.ics`) to subscribe
  from a phone or desktop calendar. An admin can **import** events from an `.ics`
  file (`POST /api/calendar/import`).
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

Everyone signed in can read the calendar and export it. Adding, editing and deleting
events needs a role that can change things, so read-only roles (viewer, auditor,
finance) cannot. Importing is admin-only. Changes are visible to the whole team and
are audit-logged.
