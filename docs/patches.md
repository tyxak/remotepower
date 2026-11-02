# Patch Report

**Patching → Patches** is the fleet-wide view of **pending system updates** —
which hosts have updates waiting, and which packages are involved.

## The report

- Each online host with inventory data shows its count of pending updates,
  security-flagged updates, and whether a reboot is required.
- The headline **percentage up-to-date counts only online hosts with data** —
  hosts that haven't reported inventory are excluded rather than skewing it.
- **Inventory search** finds a package (optionally an exact name/version) across
  the fleet, and the **patch catalog** inverts the table: pending updates
  aggregated *by package*, showing which update is waiting on how many hosts.

## Packages apt keeps back

On Debian and Ubuntu, `apt-get upgrade` keeps a package back when upgrading it needs a package that is
not installed yet: a new kernel image behind `linux-image-amd64`, or the split `linux-firmware`
packages. It installs nothing for that package, prints no error and exits 0.

Such a package counts as pending. Before, the host read **Fully Patched** while a security update was
waiting, because the report counted only what `apt-get upgrade` would install. If the update is a
security update it counts among the security-flagged ones too: the agent asks apt what an upgrade that
may install new packages would do (a simulation, nothing is installed) and takes the distro's own
security flag from that.

- **A held package does not count.** One held with `apt-mark hold` stays out, because somebody chose to
  keep it (auto-patch holds the packages you declined in the patch catalog the same way). If the agent
  cannot read the holds, it counts no kept-back package at all.
- **An update Ubuntu is still phasing in does not count.** Ubuntu releases many updates to a share of its
  hosts at a time and defers the rest. Until the update reaches your host it is not pending: apt would not
  install it, and neither would any upgrade mode. Ubuntu 24.04 lists such a package under a heading of its
  own. Ubuntu 22.04 lists it as kept back, so the agent asks apt the same question with phasing ignored, and a
  package that stops being kept back was only deferred. If that question fails, the package counts.
- **The patch run does not install them.** Auto-patch and the patch button run `apt-get upgrade`, which
  keeps the package back again, so it stays pending after a successful run. On the host,
  `apt-get install <package>` installs it with what it needs, and `apt-get full-upgrade` does everything
  that is waiting (it can remove packages too).
- **Update the agent.** The agent does the counting, so a host shows these packages once its agent has
  this. dnf, yum and pacman hosts are unchanged.

## Acting on updates

- Install, uninstall, or **hold / unhold** (pin) named packages on a target
  scope (host / group / tag / site) straight from this page — package names
  only, no shell.
- To apply updates **automatically** on a schedule, define an
  [Auto-patch](auto-patch.md) policy.
- To roll an upgrade out **in stages** with verification between rings, use
  [Rollouts](rollouts.md).

## Related

- Package **vulnerabilities** (CVEs) are tracked separately on the
  [CVE Findings](cve.md) page.
- Updates respect [maintenance windows](maintenance.md) and host quarantine.

## Permissions

Installing / removing / holding packages requires the **upgrade** action
permission (or admin); every dispatch is audit-logged.
