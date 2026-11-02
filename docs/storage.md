# Storage & hardware

RemotePower surfaces the physical health of your fleet (disks, arrays, GPUs,
temperatures and power) across a set of focused pages, and alerts before things
fail. All of it comes from the agent's hardware inventory. Unmonitored hosts still
appear, flagged, so nothing hides.

## Storage health (ZFS / mdadm / btrfs)

**Hardware → Storage** lists every pool or array with its Host, Pool, Type, State,
Capacity and Last scrub, with **degraded or faulted pools first**. The line above
the table counts pools and degraded ones. If the table is empty, no agent has
reported a ZFS, mdadm or btrfs pool yet.

- `storage_degraded` fires when a pool goes bad, and `storage_recovered` when it
  heals.
- `scrub_overdue` fires when a ZFS scrub is older than the limit (35 days by
  default). Change it under **Settings → Alert parameters → Storage & backup →
  Scrub overdue (days)**.
- Per physical disk, the agent also runs `smartctl` (SMART health, temperature, key
  attributes). A drive that reports failure or pre-fail raises `smart_failure`, and
  `smart_recovered` clears it.

### Maintain a pool

A ZFS or btrfs pool with a mounted target has a **Maintain…** button. The dialog
queues a fixed command on the host through the audited command queue. mdadm arrays
have no actions.

| Type | Actions |
| --- | --- |
| **ZFS** | Scrub, Trim SSDs, Clear errors, Status, List snapshots, and delete a snapshot by name |
| **btrfs** | Scrub, Balance (50%), Usage, `btrfs device stats`, List snapshots, and delete a snapshot by name |

Actions that change something (scrub, trim, clear, balance, snapshot delete) ask for
confirmation first. The read-only ones show their output in the dialog, usually
within the host's next check-in (up to about 90 seconds). Scrubs and balances run in
the background. The host needs the `zpool`, `zfs` or `btrfs` tools installed.

Every maintenance action, read-only ones included, needs the `command` permission
for the host and is written to the audit log. When **change approval** is on
(Settings → Security), each one waits for a second admin to approve it.

(`POST /api/devices/{id}/storage-action` with `{kind, action, target}`, and
`snapshot` for a delete.)

## Guided provisioning: creating storage

The maintenance actions only work on pools and volumes that already exist. **Provision
storage…** on the same page is the counterpart: pick a host, pick a recipe, fill in a
few fields and build the array. The five recipes are **Create RAID array (mdadm)**
(levels 0, 1, 5, 6 and 10), **LVM: create physical volumes**, **LVM: create volume
group**, **LVM: create logical volume** and **Create filesystem (mkfs)** (ext4, xfs or
btrfs).

It is narrower than a general partition editor, and the limits are the point:

- **Whole-disk devices only**: `/dev/sdX`, `/dev/vdX` and `/dev/nvmeXnY`. No partitions,
  no arbitrary paths, at most 24 members per request. Partition-level work belongs in
  the ordinary command channel.
- **Preview first.** **Preview command** returns the exact command with no side
  effects: nothing is queued and nothing is audited. You always see what would run.
- **Type the target to confirm.** After the preview you type the exact identifier of
  the thing being created or overwritten, and the server checks it itself. An API
  caller cannot skip it.
- **Approval is forced.** Every recipe goes through the audited command queue with
  approval required, so it is subject to four-eyes whenever change approval is
  enabled at all.

It needs the `command` permission for the host. (`POST
/api/devices/{id}/storage-provision` with `{recipe, params, confirm, dry_run?}`.)

## Related hardware pages

The rest of the physical-health surface has its own page and guide. Each one draws on
the same agent inventory:

| Page | What it covers | Guide |
| --- | --- | --- |
| **Predictive Health** | Trends SMART wear and sector data into a per-disk failure ETA and reliability score (`disk_predict_fail`). | [disk-health.md](disk-health.md) |
| **GPUs** | Every NVIDIA and AMD GPU: utilisation, memory, temperature, power, fan, trends. | [gpus.md](gpus.md) |
| **Thermal** | CPU, chipset, disk and GPU temperatures in one hottest-first view (`temp_high`). | [thermal.md](thermal.md) |
| **Power** | UPS status, PDU on, off and cycle control, and per-group energy-cost projection. | [power.md](power.md) |

## Permissions

- Viewing any of these pages needs only a signed-in account. Unmonitored hosts are
  shown, flagged, in the inventory views.
- Storage maintenance and provisioning need the `command` permission for the target
  host and are audit-logged. A viewer can look but not act.

See also: [disk-health.md](disk-health.md), [alert-parameters.md](alert-parameters.md),
[provisioning.md](provisioning.md) for server and cloud provisioning, which is a
different feature.
