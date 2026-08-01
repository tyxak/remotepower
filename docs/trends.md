# Trends

**Monitoring → Trends** charts the daily samples RemotePower already keeps —
fleet health score, compliance score, and per-device resource history
(CPU / RAM / disk) — as zero-dependency SVG time-series.

- Pick fleet-wide series or a single device.
- Underlying data comes from the daily samplers (health history, compliance
  history, per-device metrics rollups) — retention spans months, so slow
  drifts are visible that 24-hour dashboards hide.
- For *forward-looking* disk projections, use [Forecast](forecast.md); for
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
