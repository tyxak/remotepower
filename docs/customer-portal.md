# Customer portal

The customer portal is a small, self-service page where your **customers** can
raise and follow their own support tickets — without an operator account and
without ever touching the RemotePower dashboard. It's opt-in, off by default, and
lives on its own closed `/api/portal/*` surface with no shared code or session
with the operator app.

## What a customer can do

- **Sign in with a magic link** — no password. They enter their email and receive
  a one-time sign-in link.
- **See their tickets** — only the tickets that belong to their own site
  (customer). They never see other customers' tickets, your internal notes, your
  devices, or anything else in the fleet.
- **Open a ticket** to read the conversation and status, **reply** to it, and
  **submit a new ticket**.

That's the whole surface. The portal is deliberately narrow: tickets in, replies
out, nothing else.

## How it fits together

The portal reuses two things you already have:

1. **The ticket system** (Advanced → `tickets_enabled`) — tickets are grouped by
   **site**, which is how the portal knows which tickets belong to which customer.
2. **The Contacts directory** — a contact is the person who gets portal access.

A customer is simply a **contact that has been given a site and portal access**.
Give a contact those two things and their email can use the portal; remove portal
access and they can't.

## Turning it on

1. **Enable the ticket system** if you haven't already (Advanced settings).
2. **Enable the portal** — set **Customer portal** on (`portal_enabled`) in
   Settings.
3. **Set the portal URL** (`portal_base_url`) — the public address your customers
   reach the portal at (for example `https://support.example.com`). This is the
   address baked into every magic-link email, so it must be the real one.
4. **Grant a contact access** — in Contacts, give the contact a **site** and turn
   on **portal access**. Their tickets are the tickets on that site.

Customers then visit the portal URL, enter their email, and follow the link.

## Sign-in flow

- The customer submits their email. If it maps to a portal-enabled contact, a
  one-time link is emailed to them (over your existing SMTP). The response is the
  same whether or not the email is registered, so the page can't be used to probe
  who your customers are.
- Clicking the link starts a session held in a **HttpOnly cookie** — there is no
  token in the page's JavaScript, and the link token is stripped from the URL
  immediately after use.
- Signing out clears the session.

## Security notes

The portal was built to be exposed to the public internet and was penetration-
tested as a dedicated surface:

- It talks **only** to the closed `/api/portal/*` namespace — never the operator
  API — and shares no session or code with the dashboard.
- Magic-link emails are built from the admin-set **`portal_base_url`**, never from
  the incoming request's `Host` header, so the link can't be redirected to an
  attacker's domain.
- A customer only ever sees tickets on their **own site**, and **internal notes
  are never returned** to the portal — only the customer-facing conversation.
- Magic-link requests are rate-limited and answered in constant time; the portal
  ships its own Content-Security-Policy and violation report endpoint.

## Endpoints (reference)

All under `/api/portal/`, cookie-authenticated:

| Method | Path | Purpose |
|---|---|---|
| POST | `/magic-link` | Request a sign-in link for an email |
| POST | `/session` | Exchange a link token for a session cookie |
| POST | `/logout` | Clear the session |
| GET / POST | `/tickets` | List the customer's tickets / open a new one |
| GET | `/tickets/{number}` | Read one ticket |
| POST | `/tickets/{number}/reply` | Reply to a ticket |

## Related

- [Ticket system](ticket-system.md) — the helpdesk the portal is a customer-facing
  window onto.
- [Contacts](contacts.md) — where portal access is granted.
