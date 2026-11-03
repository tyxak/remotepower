# Time periods

A **time period** is a named set of hours: office hours, a night shift, a Sunday change window. You define it once under
**Settings → Alerting → Time periods** and then point the places that care about "when" at it. The settings that carry their own
times keep working as they did.

## What a period holds

- **Name.** Up to 64 characters. Two periods cannot have the same name.
- **Time zone.** A name from the time zone database, such as `Europe/Copenhagen`. The period then follows summer time. Leave it
  empty to use the clock of the server, which is what quiet hours and after-hours detection have always used. If your server has no
  time zone database, give a fixed **offset from UTC in minutes** instead.
- **Hours for each day of the week.** Up to six ranges a day. A range that ends before it starts crosses midnight, so `22:00` to
  `07:00` on Monday covers Monday night. A day with no ranges is closed.
- **Holidays.** Dates (`YYYY-MM-DD`) on which the whole period is closed. At most 200.

A server holds at most 50 periods.

## Where a period is used

| Place | What the period does |
| --- | --- |
| **Quiet hours** | Notifications below the always-deliver level are held while the period is on. |
| **After-hours activity detection** | The period is your business hours. A watched event outside it is recorded. |
| **Ticket SLA calendar** | The SLA clock runs only while the period is on, in the period's own time zone. |
| **Maintenance windows** | Choose **Follow a time period** as the window type. The window is open while the period is. |

Each of the first three has a **Time period** box above its own times. Pick a period there and the times below it are ignored. Leave
the box empty and they work as before. If the period you picked is deleted by hand-editing the settings, the box shows **Removed
time period**; quiet hours then hold nothing, after-hours detection records nothing and the ticket calendar falls back to its own
hours.

## Changing and deleting

A period that something still uses cannot be deleted. The error names what uses it, and one save can both stop using a period and
delete it. Editing a period changes every place that uses it at once.

## Reading the clock

All four places read a period the same way. A range includes its start minute and not its end minute. A holiday closes the calendar
day it names, in the period's time zone. The ticket SLA clock stops outside the ranges and on holidays.

## API

Periods are part of the settings document: `GET /api/config` returns `time_periods`, and `POST /api/config` with a `time_periods`
list replaces them (a period without an `id` is new, and the server makes one). Quiet hours, after-hours detection and the ticket
calendar take a `period` id in their own settings, and `POST /api/maintenance` takes a `period` instead of `start` and `end` or
`cron` and `duration`. Config as code carries `time_periods` too.

## Permissions

Creating, changing and deleting periods is part of saving the settings, so it needs the same rights as the settings. Under
multi-tenancy only the platform operator can save them.

## See also

- [Maintenance windows](maintenance.md)
- [Alerts](alerts.md)
- [Tickets and SLA](ticket-system.md)
