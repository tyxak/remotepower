# Trends

**Monitoring → Trends** charts the daily samples RemotePower already keeps —
fleet health score, compliance score, and per-device resource history
(CPU / RAM / disk) — as zero-dependency SVG time-series.

- Pick fleet-wide series or a single device.
- Underlying data comes from the daily samplers (health history, compliance
  history, per-device metrics rollups) — retention spans months, so slow
  drifts are visible that 24-hour dashboards hide.
- For *forward-looking* capacity projections — disk fill, and memory / swap /
  CPU-load headroom — use [Forecast](forecast.md); for
  long-range per-device metric zooming, the device drawer's metrics view
  reads the roll-up store across four resolutions: raw (last 24 h), **5-minute
  (last ~7 days)**, hourly (30 days) and daily (~2 years). The 5-minute tier is
  the one to reach for when investigating an incident a few days old — hourly
  averages smooth away the spike you're looking for, and the raw window only
  goes back a day.
- **Pinpointing a window.** The per-device chart takes a time window directly:
  drag across it to zoom, double-click (or **Reset**) to go back, or type the
  exact **From** / **To** and press Enter. Narrowing to a short recent window
  re-fetches the finest tier that still covers it rather than stretching the
  points already on screen, so zooming in genuinely gains resolution. The pinned
  window survives a data refresh. The same control is on the temperature
  timeline — see [Thermal](thermal.md).

## Metric explorer (v6.4.2)

The rest of this page answers questions about *one* host. The **Metric explorer**
card at the bottom answers the cross-host ones — "which of these eight boxes ran
hot last Tuesday?" — by overlaying any hosts and any metrics on a single axis.

- **Pick hosts and metrics, press Run.** CPU %, memory %, swap %, disk % and
  temperature are available; each host/metric pair becomes one series on the
  shared chart. Up to **8 hosts** are fetched per run — beyond that the note
  under the chart says how many were left out rather than dropping them
  silently.
- **Statistic** picks which of each roll-up bucket's aggregates to plot: `avg`,
  `min` or `max`. Reach for `max` when hunting a spike an average has smoothed
  away, which is the usual reason a coarse tier looks innocent.
- **The roll-up tier is chosen for you** from the window you asked for, across
  the same resolutions the per-device chart uses: 5-minute points (kept about 8
  days), hourly (30 days) and daily (about 2 years). Override it if you want a
  specific tier; the note under the chart always states which one produced the
  data you are looking at, and how far back that host's history actually goes.
- **Windows** are the usual presets (24 hours through 2 years) plus an exact
  **From** / **To**. The chart supports the same drag-to-zoom as the rest of the
  page.
- **Export CSV** downloads exactly the series on screen — same hosts, same
  metrics, same window, same tier.
- **Saved queries live in this browser only.** They are stored in
  `localStorage`, not on the server: they do not sync between browsers or
  operators, and clearing site data removes them. They are a convenience for
  repeat investigations, not a shared artifact — for something colleagues need,
  use a [report](reports.md) or a [saved fleet query](fleet-query.md).
