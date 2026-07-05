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
  reads the hourly/daily rollup store.
