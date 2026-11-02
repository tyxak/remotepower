# DNS-blocker control (Pi-hole / AdGuard)

The Pi-hole and AdGuard Home connectors tell you whether the blocker is up and how much
it blocked. When something breaks, the next question is "is it the ad-blocker?" This page
covers the control that lets you answer it without leaving RemotePower: read the blocking
state and **pause blocking** for a short, fixed time from the Integrations page.

You need a Pi-hole or AdGuard Home set up as an integration first (see
[integrations.md](integrations.md)). Pi-hole must be version 6 or later, because the control uses
its v6 API.

## Every pause is timed

A DNS blocker that is switched off and forgotten is a silent, permanent security regression.
So a pause is always a *timed* action:

- Every pause carries a timer between 30 seconds and 4 hours. The server clamps the value, so
  the limit does not depend on the caller remembering it. If a request leaves the timer out, it
  uses 5 minutes.
- The blocker **turns itself back on** when the timer ends. The Pi-hole or AdGuard host
  restores the safe state, not a job on the RemotePower server that might not run.
- There is **no pause-forever action**, and that is by design.

Pausing needs an **admin** account and is **written to the audit log** with its window, for example
`pihole <id> blocking=off for 300s`. So "who turned the ad-blocker off, when and for how long" can
be answered later.

## Use it

On **Integrations**, under the tiles, each controllable blocker has a card with:

- a status badge: **Blocking on**, **Blocking PAUSED — resumes in Nm**, or *Unreachable at the last
  poll* when the background check could not reach it (use **Check now** to ask the blocker directly);
- a drop-down with **5 minutes**, **15 minutes**, **1 hour** or **4 hours**;
- **Pause blocking**, which asks you to confirm, and **Resume blocking**, which turns blocking
  back on at once.

Only admins see the pause and resume buttons. Everyone else sees the state.

The card shows the state the blocker itself reports after each change. If the blocker ignored the
request, the badge does not pretend it obeyed.

## API

- `GET /api/dns-control/blockers` lists the controllable blockers (id, label and type only: no
  addresses and no secrets). It also returns `max_seconds` and `default_seconds`.
- `GET /api/dns-control/{id}/blocking` says whether blocking is on and how many seconds are left
  on a pause.
- `POST /api/dns-control/{id}/blocking` with `{"enabled": false, "seconds": 600}` pauses blocking.
  `{"enabled": true}` resumes it. Admin only, and audited.

## Troubleshooting

| Problem | What to check |
| --- | --- |
| No control card appears | The integration must be a Pi-hole or an AdGuard Home. Other types are read-only. |
| *Pi-hole authentication failed* | Enter the Pi-hole **App password** (in Pi-hole's own web interface, under its Web interface / API settings) on the integration's card. The control logs in with it. |
| *Unreachable at the last poll* | Check the address and credentials in **Settings → Integrations**. The integration tile shows the reason. |
| The buttons are missing | Pause and resume are for admins. |

---

← [Back to docs index](README.md)
