# Patch Report

**Patching → Patches** is the fleet-wide view of **pending system updates** —
which hosts have updates waiting, and which packages are involved.

## The report

- Each online device with inventory data shows its count of pending updates,
  security-flagged updates, and whether a reboot is required.
- The headline **percentage up-to-date counts only online devices with data** —
  hosts that haven't reported inventory are excluded rather than skewing it.
- **Inventory search** finds a package (optionally an exact name/version) across
  the fleet, and the **patch catalog** inverts the table: pending updates
  aggregated *by package*, showing which update is waiting on how many hosts.

## Acting on updates

- Install, uninstall, or **hold / unhold** (pin) named packages on a target
  scope (device / group / tag / site) straight from this page — package names
  only, no shell.
- To apply updates **automatically** on a schedule, define an
  [Auto-patch](auto-patch.md) policy.
- To roll an upgrade out **in stages** with verification between rings, use
  [Rollouts](rollouts.md).

## Related

- Package **vulnerabilities** (CVEs) are tracked separately on the
  [CVE Findings](cve.md) page.
- Updates respect [maintenance windows](maintenance.md) and device quarantine.

## Permissions

Installing / removing / holding packages requires the **upgrade** action
permission (or admin); every dispatch is audit-logged.
