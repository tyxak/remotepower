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

## Guided provisioning — creating storage, not just maintaining it

The maintenance actions above only operate on pools and volumes that already
exist. Guided provisioning is the counterpart: grab N blank disks and build the
array. Five recipes — `mdadm_create` (RAID 0/1/5/6/10), `lvm_pvcreate`,
`lvm_vgcreate`, `lvm_lvcreate` and `mkfs` (ext4 / xfs / btrfs).

`POST /api/devices/{id}/storage-provision` with `{recipe, params, confirm}`.

It is deliberately narrower than a general partition-table editor, and the
limits are the point:

- **Whole-disk block devices only** — `/dev/sdX`, `/dev/vdX`, `/dev/nvmeXnY`.
  No partitions, no arbitrary paths, at most 24 members. Partition-level work
  still belongs to the ordinary shell/exec channel.
- **Type-to-confirm, checked on the server.** Every recipe requires you to type
  the exact identifier of the thing being created or overwritten, and the
  server compares it — this is not a UI-only guard that an API caller can skip.
- **`dry_run: true` returns the exact command with zero side effects** — not
  queued, not even audited — so you can always see precisely what would run
  before confirming.
- **Every recipe routes through the audited command queue with approval
  forced**, the same hook guided CIS remediation uses. If change-approval is
  enabled at all, provisioning is subject to four-eyes.

Requires the **`command`** permission for the target device.

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
