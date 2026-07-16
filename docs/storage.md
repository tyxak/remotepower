# Storage & hardware

RemotePower surfaces the physical health of your fleet — disks, arrays, GPUs,
temperatures and power — across a set of focused pages, and alerts before things
fail. All of it comes from the agent's hardware inventory; unmonitored hosts still
appear (flagged) so nothing hides.

## Storage health (ZFS / mdadm / btrfs)

**Storage health** lists every pool/array — Device, Pool, Type, State, Capacity
%, Last scrub — with **degraded/faulted pools first**. A **`storage_degraded`**
event fires when a pool goes bad and **`storage_recovered`** when it heals;
**`scrub_overdue`** fires when a ZFS scrub is older than `scrub_overdue_days`
(default 35).

**Maintain…** runs one-click actions through the audited command queue
(`POST /api/devices/{id}/storage-action`):

| Type | Actions |
| --- | --- |
| **ZFS** | `status`, `scrub`, `clear`, `trim`, list `snapshots`, destroy a snapshot |
| **btrfs** | `usage`, `scrub`, `balance`, `devstats`, list/delete `snapshots` |

Destructive actions (scrub, balance, clear, snapshot delete) require confirmation.

## SMART & predictive disk health

The agent runs `smartctl` per physical disk (SMART health, temperature, key
attributes). A drive reporting failure/pre-fail raises **`smart_failure`**.

**Predictive health** goes further: it trends SMART data (reallocated/pending
sectors on HDDs, wear % on SSDs) to estimate an ETA, and lists at-risk disks
(Risk, Disk, Wear, ETA, Signals) plus frequently-restarting hosts. When a disk's
ETA drops to ≤180 days (or risk becomes critical/high) it raises
**`disk_predict_fail`** — one alert per disk. Data: `GET /api/fleet/disk-health`.

## GPUs

**GPUs** shows every NVIDIA/AMD GPU (hottest/busiest first) with utilisation,
VRAM, temperature, power draw, fan speed and ~4h trend sparklines. Collected via
`nvidia-smi` / `rocm-smi` (with an amdgpu sysfs fallback). GPU temperature feeds
the same thermal alerting as everything else.

## Thermal

**Thermal health** aggregates CPU/chipset sensors (lm-sensors), disk temps
(smartctl) and GPU temps into one hottest-first view (Device, Max temp, Hottest
sensor, Type, Threshold, Headroom, ~24h trend). ≥75 °C is flagged amber; ≥85 °C
raises **`temp_high`** (high) and cooling back down raises **`temp_normal`**.
Thresholds are per-device (metric-threshold UI); the global amber/red °C and the
`temp_high` threshold defaults are tunable in **Settings → Alert parameters**.
Data: `GET /api/fleet/thermal`.

## Power & UPS

**Power & energy** lists hosts on battery first (UPS status, battery %, load %,
runtime, watts). Where a smart PDU/plug is mapped on the device, you can
power **on / off / cycle** it (`POST /api/devices/{id}/power-control`,
SSRF-guarded, `command` permission, audited). A per-group/tag **energy cost**
card projects a monthly estimate from instantaneous watts and a $/kWh you set.
Data: `GET /api/fleet/power`.

## Permissions

- Viewing all of the above needs normal authentication (unmonitored hosts are
  shown, flagged, in the inventory views).
- Storage maintenance and power control require the **`command`** permission for
  the target device and are audit-logged; a viewer can look but not act.
