# Built-in ticket system (helpdesk)

RemotePower ships an **opt-in ticket system** — a lightweight helpdesk that lives
right next to your fleet, so the alert you just saw and the work you do about it
stay in one place. It is **off by default**; turn it on under **Settings →
Advanced → Tickets**.

Tickets are deliberately simple: no separate tool to run, no per-seat licence, no
data leaving your server. If you already use Jira / ServiceNow / Zendesk, those
integrations still exist (see [webhooks.md](webhooks.md)) — the built-in system is
for teams who'd rather not.

## Turning it on

**Settings → Advanced → Tickets** has the master switch. While it is off there is
no Tickets page, no nav item and every ticket API route returns 404 — nothing
runs. Switch it on and a **Tickets** item appears in the sidebar with a live
open-count badge.

## What a ticket is

| Field | Notes |
| --- | --- |
| **Number** | Every ticket has a stable `#RP000042` number. Tickets opened from an alert reuse that alert's id; standalone and email-created tickets draw from a separate reserved band so the two never collide. |
| **Type** | **Incident**, **Request** or **Change**. Alerts always become Incidents; you pick the type for anything you raise by hand. |
| **Priority** | **P1 Major**, **P2 Critical**, **P3 Warning**, **P4 Low**. Alert-derived tickets inherit the alert's severity (warning → P3, critical → P2…); P1 is chosen by hand. |
| **Status** | Ongoing · Pending customer · Pending internal · Resolved · Closed. |
| **Assignee & group** | Who owns it, and which team it belongs to. |
| **SLA** | A response-time target derived from the priority (see below). |
| **Devices** | One or more affected hosts, attached from your fleet. |
| **Parent / sub-tickets** | A ticket can be a child of a master ticket. |

## Creating tickets

- **From an alert** — the Alerts inbox has a **Ticket** button on each alert. It
  opens an Incident linked to that alert, inheriting its severity, device and
  title, and assigns it to you.
- **By hand** — the **New ticket** button on the Tickets page. Pick the type,
  priority and affected devices.
- **From email** — if you point the ticket mailbox at an inbox (below), a message
  that doesn't match an existing ticket opens a brand-new one automatically, so
  customers can raise tickets just by emailing you.

When you open a ticket from an alert and later resolve or close it, the **linked
alert is resolved for you** — the loop closes without a second click.

## Ownership, teams and groups

- **Take ownership** assigns the ticket to you and stamps it with your team.
- **Assign to group** hands a ticket to a team's queue: it clears the assignee and
  moves the ticket to *Pending internal*, ready for whoever picks it up next.
- Set your own team under **Profile → Team**. Everyone who types the same team name
  is on that team, which powers the **My team's open tickets** view.

The Tickets page is organised into four tables — **New** (untriaged), **My open
tickets**, **My team's open tickets**, and **Other** (everyone else's open work
plus everything closed) — each searchable and sortable. Search matches the number,
subject, device, group and assignee.

## SLA targets

Each priority has a **response-time target** in hours, configurable under
**Settings → Advanced → Tickets → Ticket SLA targets** (defaults: P1 = 1h,
P2 = 4h, P3 = 24h, P4 = 72h). Open tickets show the time remaining, and a red
**overdue** badge once they pass their target, so breaches are obvious at a glance.

## Business-hours SLA calendar

By default SLA targets count wall-clock hours (24/7). Turn on **Settings →
Tickets → Business hours** to count them in **business time only** — the SLA
clock pauses overnight, on weekends, and on configured holidays, so a P3 with a
"24 business hours" target opened Friday afternoon isn't breached over the
weekend. Configure a UTC offset, one open window per weekday (blank = closed),
and a holiday list. When enabled, the computed due date and breach flag come
from the server so the ticket list and detail agree; leaving it off preserves
the exact previous wall-clock behaviour.

## Master and sub-tickets

A big incident often spawns smaller pieces of work. Set a ticket's **Parent** to
another ticket's number and it becomes a sub-ticket: the list nests children under
their master, marks the master, and resolving or closing the master offers to
close its open children in one step.

## Email: replies and threading

The ticket system can send and receive email through your existing mail server.

- **Outbound** uses your configured SMTP (Settings → Notifications). The **Send
  email** button on a ticket emails the contact and logs the message on the ticket.
  Your personal **HTML signature** (Profile → Email signature) is appended as a
  rich part, with a plain-text fallback.
- **Inbound** uses a dedicated IMAP mailbox (Settings → Advanced → Tickets). The
  poller threads each reply onto its ticket by the `#RP` number in the subject, or
  opens a new ticket when there's no match. Auto-replies, bulk mail and the
  system's own outgoing messages are skipped, so nothing loops.

Recipients are resolved from your CMDB — a contact email on the device, then its
documentation, then its notes — so you usually don't have to type an address.

## The conversation

Each ticket keeps a chronological thread. Outbound messages (yours) and inbound
replies (the customer's) are shown as distinct chat bubbles, alongside internal
notes that are never emailed. The thread auto-scrolls to the newest message.

## Canned replies

Reusable reply snippets for answers you type over and over ("we're looking into
it", "resolved — please confirm"). Admins manage them under **Settings →
Tickets → Canned replies** (saving with an existing name updates it); everyone
gets an **Insert canned reply…** picker above the composer on every ticket.
Placeholders substitute at insert time:

| Placeholder | Becomes |
|---|---|
| `{ticket_id}` | The ticket's `#RP…` number |
| `{customer}` | The ticket's contact email address |
| `{assignee}` | The current assignee |

The inserted text is normal composer text — edit it freely before sending.
`GET/POST /api/tickets/templates`.

## Satisfaction survey (CSAT)

Turn on **Settings → Tickets → Satisfaction survey** to email the contact a
one-click rating link when a ticket is resolved. The email offers **Good /
Okay / Bad** — each a signed, single-use URL (`GET /api/tickets/csat`), so the
customer rates with one click and no login. The rating is stored on the ticket
and shown as a badge in the list; a second click just acknowledges the existing
rating. Requires SMTP and a contact email on the ticket; it's sent once, on the
first resolve, and is loop-safe (never to automated senders).

## Recurring tickets

For chores that must happen on a cadence — a quarterly restore drill, a monthly
certificate review — define a **recurring ticket** under **Settings → Tickets →
Recurring tickets**: a subject, optional body, priority and a 5-field cron
(`min hour day month weekday`, server-local time). When the cron matches, the
server opens a normal ticket (type *Request*, `created_by: schedule`), deduped
so a schedule fires at most once per matching minute even across worker
processes. Disable a schedule to pause it without deleting it.
`GET/POST /api/tickets/schedules`.

## A note on privacy

Everything here stays on your server. Ticket contents, email and contacts live in
your data directory with the rest of RemotePower's state — there is no external
helpdesk service involved.

See also: [Internal contact directory](contacts.md) · [Webhooks & ITSM](webhooks.md)
· [Alerts & notifications](features.md).
