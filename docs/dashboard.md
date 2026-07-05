# Dashboard

The **Dashboard** (the landing page) is a composable overview of everything
that needs your attention: stat tiles (devices online, pending updates, drift
events, critical CVEs), the fleet-health score, open/acknowledged alerts, a
needs-attention card, upcoming calendar/scheduler events, and the recent
fleet-events feed.

## Customising it

Click **Customize** (top right) to choose which widgets render and in what
order — the layout is saved per browser. Widgets marked "heavy" (checks
rollup, disk-fill) are only computed server-side when you enable them.

## Reading it

- **Fleet health** — the 0–100 score explained in [health-score.md](health-score.md);
  the coloured bar splits critical / warning / info counts.
- **Needs attention** — offline monitored devices, critical CVE findings,
  patch backlog, drift and mailbox alerts, deduplicated. Items can be ignored
  permanently (review under Settings → Ignored items).
- **Recent activity** — the fleet-event stream (device offline, drift
  detected, CVE found, …); every entry deep-links to the page that raised it.
- **Upcoming** — the next events from the shared [calendar](calendar.md) and
  the [command scheduler](schedule.md).

Unmonitored hosts are shown in inventory-style widgets and flagged, but only
monitored hosts feed alerting and the health score.
