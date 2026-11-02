# Tasks

**Scheduling → Tasks** is a **shared kanban board** for your team. Track work in
progress by dragging cards between columns, and optionally tie a card to a host.

## How it works

- There are four columns: **Upcoming**, **Ongoing**, **Pending** and **Closed**.
  Each shows how many cards it holds. **Drag a card** to another column to change
  its state.
- Click **New task** and give it a **title** (up to 200 characters), an optional
  **description** (up to 4,000) and a **state**. Click a card to edit it or delete
  it. The edit dialog shows who created the card and when it last changed.
- Cards are shared by everyone who can see the board. It is a team board, not a
  personal to-do list.
- **Link a task to a host** with the **Linked host** field to keep the context. The
  card carries the host name, and the filter at the top of the board narrows it to
  one host or to the cards that have no host.
- The board keeps up to 500 tasks. Close or delete old ones when you hit the limit.

## Tasks vs. tickets

- **Tasks** are a lightweight internal board for your team's own work.
- **[Tickets](ticket-system.md)** are a full helpdesk (incidents, requests,
  changes) with SLAs, email and customer-facing history.

Use Tasks for internal project work. Use the ticket system when there is a requester
and an SLA.

## Permissions

Everyone who is signed in can see the board. Creating, moving, editing and deleting
cards needs an admin or a role that has at least one action permission, so
read-only roles (viewer, auditor, finance) can look but not change anything. Changes
are written to the audit log. With multi-tenancy on, a card linked to a host shows
only to people who can see that host, and a card with no host is visible to every
tenant.

## API

| Method | Path | Notes |
|---|---|---|
| GET | `/api/tasks` | Optional `state` and `device` filters. Returns the cards and a count per state. |
| POST | `/api/tasks` | `{title, description?, state?, device_id?}`. |
| PUT | `/api/tasks/{id}` | Edit any of those fields. An empty `device_id` unlinks the host. |
| DELETE | `/api/tasks/{id}` | Delete a card. |

## Related

- [Calendar](calendar.md) holds shared dated events.
- A task linked to a host gives you a quick path to that host's [CMDB](cmdb.md) entry.
