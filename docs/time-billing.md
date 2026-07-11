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
   View / **print to PDF**, **export CSV**, or **email** to the customer.
   A payment webhook (below) can also move an invoice through
   **partially_paid → paid** automatically as payments come in.

### Payment webhook *(v6.1.1)*

A generic, **provider-agnostic** reconciliation sink under Rates & Fees —
**not** a Stripe/PayPal integration (no live processor credentials are
required or used). Point your payment processor's own webhook, or a thin
relay script, at the shown URL with header `X-RP-Billing-Secret: <secret>`
(set alongside the rate card) and a JSON body
`{invoice_id, amount, kind: "payment"|"refund", external_ref?, provider?}`.
Payments accumulate into the invoice's `amount_paid`; the status moves to
`partially_paid` once any payment lands and to `paid` once the total is
covered. A `refund` payment (or a full refund back to zero) reverts a
`paid`/`partially_paid` invoice to `sent`. Idempotent on `external_ref` — a
processor retrying the same webhook is a safe no-op, not a double-credit.
A voided invoice refuses further payments (409).

### Emailing invoices

Click the **mail** button on a draft or sent invoice to send it to that
customer's **billing contact** (set per site under Rates & Fees) over the same
SMTP you use for notifications. The email carries a plain-text invoice plus a
branded HTML alternative; sending a draft promotes it to **sent**.

Turn on **Email overdue-invoice reminders** (Rates & Fees) to have the server
send **one** reminder for any invoice still in *sent* status more than *N* days
after it was last emailed (default 14). Reminders ride the maintenance cadence,
are bounded per run, and never re-send for the same invoice — marking it
**paid** or **void** stops them.

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
| `POST /api/billing/payment-webhook` | shared secret (`X-RP-Billing-Secret`) | Record a payment/refund against an invoice — provider-agnostic, idempotent on `external_ref` |
