# Dashboard

The **Dashboard** (the landing page, titled "Fleet at a glance") is a composable overview of
everything that needs your attention. Each widget links to the page behind it.

## What you see first

These are on by default:

- Four tiles: **Hosts online**, **Pending updates**, **Drift events** and **Critical CVEs**
  (plus a mailbox tile once you show a mailbox monitor on the dashboard). A tile is tinted when
  something needs action, and a click opens the page behind it.
- **Upcoming**: the next events from the shared [calendar](calendar.md) and the
  [command scheduler](schedule.md).
- **Alerts**: open alerts, and the ones you recently acknowledged.
- **Fleet health**: the 0–100 score explained in [health-score.md](health-score.md). The coloured
  bar splits critical, warning and info counts.
- **Fleet heat map**: one cell per host, from green (healthy) to red (needs attention).
- **Needs attention** and **Recent activity**, side by side (see below).
- **Fleet roster**: up to 15 hosts with a 7-day status stripe, the worst first (offline hosts, then
  hosts with the most down days).
- **Quick links**: the cards from the [Links](links.md) page.
- **Ask AI**: a box under the grid. It sends your question to the [AI assistant](ai.md) with fleet
  context.

## Customising it

Click **Customize** (top right) to open the layout panel. There are over 70 widgets. Most of them
(offline hosts, pending updates, OS breakdown, disk-fill ETA, expiring certificates, backup jobs,
on-call, a post-it note and many more) start hidden.

- Use the **S / M / L** buttons to set a widget's width.
- Use the arrows to move a widget up or down, and the remove button to hide it.
- Choose a widget from **Add a widget** to show it.
- **Align** gives every widget the same width. **Reset** restores the default layout.
- **Share** copies a layout code and **Import** applies one from a teammate.

The layout belongs to your account, so it follows you to another browser. Every change can be
undone with the arrows in the top bar. Two widgets (the checks roll-up and the disk-fill ETA)
are heavy, so the server only computes them while they are on your dashboard.

## Reading it

- **Needs attention** shows offline monitored hosts, critical CVE findings, the patch backlog,
  drift and mailbox alerts, each once. The full list of what can appear is in
  [attention.md](attention.md). Click the **×** on an item to ignore it. You can bring ignored
  items back under **Settings → Ignored items**.
- **Recent activity** is the fleet-event stream (host offline, drift detected, CVE found and so
  on). Every entry links to the page that raised it. **Clear** hides everything up to now for
  your account; newer events still appear.
- **Fleet-wide note**: text you set under **Settings → General → Server identity** shows on the
  dashboard for everyone, for example a maintenance window.

Hosts you switched to unmonitored are left out of the tiles, the roster, alerting and the health
score. They still appear on the Hosts page.

If you choose the **Pilot** look (My Account → Appearance, see [my-account.md](my-account.md)), a
panel above the tiles shows the number of hosts online as a dot-matrix readout, next to one dot per
host, grouped by host group and coloured like the fleet health card. It draws from the same figures
as the tiles and changes nothing else.

## Common tasks

| You want to | Do this |
| --- | --- |
| Put a number you check every morning on the front page | **Customize → Add a widget** and pick it, then resize it. |
| Give a teammate your layout | **Customize → Share**, send the code, and they use **Import**. |
| Undo a layout change | Use the undo arrow in the top bar. |
| Mute an alert from the dashboard | Add the **Alerts (ack / resolve)** widget; it has **Mute** and **Resolve** on each row. |
| Show the dashboard on a wall screen | Use the [Status Board](status-board.md) instead. |

## See also

[health-score.md](health-score.md), [attention.md](attention.md), [alerts.md](alerts.md),
[ux.md](ux.md), [my-account.md](my-account.md).
