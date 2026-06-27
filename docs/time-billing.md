# Time-tracking & billing (RackMatters)

*(v5.4.0)* A lightweight PSA layer on top of the helpdesk: log hours, keep a
weekly timesheet, and invoice customers for the time you spent plus recurring
fees. Built on one shared time-entry ledger so nothing is double-counted.

## Concepts

- **Time entry** — one logged block of work: hours (in **0.25-hour steps**),
  date, who, a **billable** flag, an optional **customer (site)** / device /
  ticket link, and a note (billable) or **category** (internal).
- **Customer = site.** Invoices are raised per **site**. A billable entry always
  resolves to exactly one site (the payer); `device` and `tag` are attribution
  detail, not separate billing targets.
- **Rate card** — a small set of named hourly rates (e.g. *Standard*,
  *After-hours*, *Project*). The effective rate resolves: named rate → the
  customer's default rate → the global default.
- **Recurring fees** — per-customer monthly **license / operation / service**
  fees that join the worksheet automatically.

## Logging hours

**On a ticket** — open a ticket, click **Log hours**, type the hours, choose
billable (debtable) or internal. The customer is taken from the ticket's device's
site; admins/finance can also pick a rate. The ticket shows a running total.

**On your timesheet** — open **Timesheet** (Planning → Timesheet, or *My Account
→ Open my timesheet*). Page through the week, and **Log time** for any day —
billable work against a customer, or internal time (meeting, education, admin,
travel, internal project). Hours logged on tickets show up here too.

Hours snap to the nearest **0.25** (so typing `1.3` stores `1.25`). A single
entry is capped at 24 hours.

## Billing (admins + the finance role)

Under **Admin → Billing**:

1. **Rates & Fees** — set the **currency**, global **default rate** and **VAT %**,
   an **invoice prefix**, and the **rate card**. Per customer (site), set an
   optional default rate / VAT override, a billing contact + address, and
   recurring fees.
2. **Worksheet** — pick a customer and month → billable hours grouped by rate +
   recurring fees → subtotal / VAT / total. **Export CSV**, or **Generate
   invoice**.
3. **Invoices** — issued invoices with **draft → sent → paid** (and **void**).
   View / **print to PDF**, **export CSV**.

### Locking

Issuing an invoice **snapshots its line items** and **locks** the hours it bills
(they can't be edited or deleted while locked) so an invoice can't drift from its
source. **Voiding** an invoice frees those hours to be re-billed.

## Roles

| Role | Can log own hours | See/export billing | Edit rates, issue/void invoices |
|------|:-:|:-:|:-:|
| any signed-in user | ✓ | — | — |
| **finance** (new) | ✓ | ✓ | — |
| **admin** | ✓ | ✓ | ✓ |

Assign **finance** on the **Users** page (Edit role).

## Export

- **CSV** — `?format=csv` on the ledger, worksheet and invoice (formula-injection
  safe; opens in Excel/Sheets).
- **API (JSON)** — `GET /api/time-entries`, `GET /api/timesheet?week=YYYY-Www`,
  `GET /api/billing/worksheet?site=&month=YYYY-MM`, `GET /api/invoices`,
  `GET /api/invoices/{id}`.
- **PDF** — print the invoice from the browser (Print / Save as PDF).

## API reference

| Method & path | Who | Purpose |
|---|---|---|
| `GET /api/time-entries` | self; admin/finance see all | List entries (filters: `user`, `site`, `from`, `to`, `ticket`, `billable`; `format=csv`) |
| `POST /api/time-entries` | any | Log time for yourself |
| `PATCH` / `DELETE /api/time-entries/{id}` | owner or admin | Edit / delete (refused once invoiced) |
| `GET` / `POST /api/tickets/{id}/hours` | any | Ticket hours (list / add) |
| `GET /api/timesheet?week=YYYY-Www` | self; admin/finance any `user=` | Week grouped by day |
| `GET` / `POST /api/billing/config` | finance (read) / admin (write) | Rate card, currency, per-site rates + fees |
| `GET /api/billing/worksheet?site=&month=` | admin/finance | Pre-invoice worksheet (`format=csv`) |
| `GET` / `POST /api/invoices` | admin/finance (list) / admin (issue) | List / issue invoices |
| `GET /api/invoices/{id}` | admin/finance | One invoice (`format=csv`) |
| `PATCH /api/invoices/{id}` | admin | Set status (draft/sent/paid/void) |
