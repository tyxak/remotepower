# Disk-fill forecast

The **Monitoring → Forecast** page projects when each mount will run out of
space, from a compact daily metrics snapshot kept per device (roughly six months
of history). For every mount it fits a least-squares trend of used-GB over time
and extrapolates to the mount's capacity, yielding a days-to-full estimate and a
projected fill date (e.g. *"/var fills in ~18 days"*).

## What you see per row

- **Device / Mount** — the host and mountpoint.
- **Used** — current used / total GB and percent.
- **Trend** — growth in GB/day from the fitted line.
- **Fills in** — the days-to-full estimate, or one of:
  - `fluctuating` — the trend is too noisy (low R²) to trust a date; the row is
    kept because current usage is still useful, but no date is invented.
  - `>2 yr` — the mount *does* fill, but more than ~2 years out. That's not an
    actionable risk, so the date is suppressed rather than shown as a misleading
    "fills 2031". (Mounts that are flat or shrinking show `no fill`.)
- **Fill date** — the projected calendar date, when one is shown.

## One row per filesystem, not per mountpoint

Many systems mount several paths that are really the **same filesystem** — btrfs
subvolumes (`/`, `/home`, `/var/log`, `/srv`, …) or bind mounts all share one
pool and report identical used/total figures. Forecasting each mountpoint
separately would print the same disk five times.

RemotePower collapses mounts that share a filesystem (detected by identical
used/total at each sample) into a **single row per filesystem**, choosing a
representative mountpoint (preferring `/`, otherwise the shortest path). The
collapsed mountpoints are listed on a hover ("+N") so nothing is hidden.

## Volatile mounts are skipped

Ephemeral / tmpfs-style mounts (`/tmp`, `/run`, `/dev/shm`, `/run/lock`,
`/run/user`, `/var/tmp`) are excluded — a linear fill date over a sawtoothing
tmpfs is meaningless.

## API

- `GET /api/devices/<id>/forecast` — per-mount projection for one device.
- `GET /api/forecast` — the fleet-wide forecast that backs the page. Each mount
  carries `current_gb`, `total_gb`, `current_percent`, `trend_gb_per_day`,
  `days_to_full` (null when flat / noisy / beyond the horizon), `fill_date_ts`,
  `noisy`, `beyond_horizon`, and `shared_mounts` (the mountpoints folded into
  the row).
