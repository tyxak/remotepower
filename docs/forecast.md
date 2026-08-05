# Capacity forecast

The **Monitoring → Forecast** page projects when a host runs out of headroom —
on disk, and (since v6.4.2) on memory, swap and CPU load — from a compact daily
metrics snapshot kept per device (roughly six months of history).

For every mount it fits a least-squares trend of used-GB over time and
extrapolates to the mount's capacity, yielding a days-to-full estimate and a
projected fill date (e.g. *"/var fills in ~18 days"*). The same fit, with the
same noise gate, runs over the non-disk series to give **resource headroom**.

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

## Resource headroom (memory, swap, CPU load)

Below the mounts table, the same daily samples are projected for three more
series. A row appears per metric per host, soonest-to-saturate first:

| Resource | Ceiling | Floor |
|---|---|---|
| Memory | 90% | 60% |
| Swap | 80% | 5% |
| CPU load | 100% | 50% |

The **ceiling** is what counts as saturated; the **floor** is the level below
which no date is projected at all — extrapolating a machine sitting at 12%
memory to 90% produces a confident-looking number built on nothing.

CPU load is normalised to **percent of cores** (`loadavg_1m ÷ cpu_count`), so
100% means "one runnable process per core". A load average without a core count
is dropped rather than projected — 4.0 is idle on a 64-core box and on fire on a
2-core one.

A row is kept even when no date is projected, because the current reading and
trend are useful on their own. The **Saturates in** column then says which gate
declined:

- `at ceiling` — already at or past it. A live problem, not a forecast.
- `below floor` — too low to project from.
- `growth stalled` — the long-run trend is up, but growth has flattened
  recently, so no saturation is projected.
- `fluctuating` — too noisy (low R²) for a trustworthy date.
- `>6 mo` — it does saturate at the current rate, but beyond the 180-day
  horizon (disk uses a longer, ~2-year horizon).

The noise gate is the same operator-tunable R² floor as the disk projection
(**Settings → Alert parameters → Disk-fill R² floor**).

## API

- `GET /api/devices/<id>/forecast` — projection for one device: `mounts`,
  `resources` and `sample_days`.
- `GET /api/forecast` — the fleet-wide forecast that backs the page. Each mount
  carries `current_gb`, `total_gb`, `current_percent`, `trend_gb_per_day`,
  `days_to_full` (null when flat / noisy / beyond the horizon), `fill_date_ts`,
  `noisy`, `beyond_horizon`, and `shared_mounts` (the mountpoints folded into
  the row).
  Each `resources` row carries `metric`, `label`, `current`, `ceiling`, `floor`,
  `headroom`, `trend_per_day`, `recent_per_day`, `days_to_saturation` (null when
  no date is projected), `saturation_date_ts`, `r2`, `points`, the flags
  `saturated` / `stalled` / `noisy` / `below_floor` / `beyond_horizon`, and the
  chartable `series` / `slope` / `intercept` / `t0_ts`.
  Both lists are scoped to the caller's tenant and role.
  `devices` counts hosts with a mount projection; `resource_devices` counts
  hosts with a resource projection — they are deliberately separate.
