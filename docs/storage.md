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

Per physical disk the agent also runs `smartctl` (SMART health, temperature, key
attributes); a drive reporting failure/pre-fail raises **`smart_failure`**.

## Related hardware pages

The rest of the physical-health surface has its own focused page and guide — each
draws from the same agent hardware inventory (unmonitored hosts still appear,
flagged):

| Page | What it covers | Guide |
| --- | --- | --- |
| **Predictive health** | Trends SMART wear/sector data into a per-disk failure ETA and reliability score (`disk_predict_fail`). | [disk-health.md](disk-health.md) |
| **GPUs** | Every NVIDIA/AMD GPU — utilisation, VRAM, temperature, power, fan, trends. | [gpus.md](gpus.md) |
| **Thermal health** | CPU/chipset/disk/GPU temperatures in one hottest-first view (`temp_high`). | [thermal.md](thermal.md) |
| **Power & energy** | UPS status, PDU on/off/cycle control, and per-group energy-cost projection. | [power.md](power.md) |

## Permissions

- Viewing all of the above needs normal authentication (unmonitored hosts are
  shown, flagged, in the inventory views).
- Storage maintenance and power control require the **`command`** permission for
  the target device and are audit-logged; a viewer can look but not act.
