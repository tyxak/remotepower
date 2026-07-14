# DNS-blocker control (Pi-hole / AdGuard)

The write half of the read-only Pi-hole / AdGuard connectors. They could tell you
the blocker was up and how much it blocked; the one thing you then wanted to *do* —
*"something's broken, is it the ad-blocker?"* — was the one thing you had to leave
RemotePower for. Now you can read the blocking state and **pause blocking** from
the Integrations page.

## Every pause is timed — on purpose

A DNS blocker switched off and forgotten is a **silent, permanent security
regression** — the exact opposite of what this product exists to do. So "disable"
is modelled as a *timed* action:

- the driver **always** sends a timer (30 s – 4 h), clamped in the driver itself,
  not merely in the handler, so the bound does not depend on a caller remembering;
- the blocker **re-enables itself** when the timer lapses — the safe state is
  restored by the remote device, not by a sweep here that might never run;
- there is **no disable-forever action**. Not an oversight; a decision.

Pausing is **admin-only** and **audit-logged with the window**, so "who turned the
ad-blocker off, when, and for how long" is answerable after the fact.

## Use it

On the **Integrations** page, a controllable Pi-hole or AdGuard tile gains a
Pause / Resume control with a duration picker (5 min – 4 h). Resuming re-enables
blocking immediately.

## Shape

Drivers are pure functions over the same SSRF-guarded HTTP client every read-only
connector uses (the same design as `hypervisor.py`, the precedent for adding write
actions to the integrations layer). `api.py` owns the admin gate and the audit
log.

## API

- `GET /api/dns-control/blockers` — controllable blockers (no secrets/urls).
- `GET /api/dns-control/{id}/blocking` — is blocking on, and for how long.
- `POST /api/dns-control/{id}/blocking {enabled, seconds}` — admin, audited.

---

← [Back to docs index](README.md)
