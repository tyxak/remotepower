# Patch Report

**Patching → Patches** is the fleet-wide view of **pending system updates** —
which hosts have updates waiting, and which packages are involved.

## The report

- Each online host with inventory data shows its count of pending updates,
  security-flagged updates, and whether a reboot is required. The columns are
  Host, Group, OS, Status, Pkg Manager, Pending, Patch Status and Recent Patch
  Cmds.
- Filter by text, group or host, and export the table as **CSV**, **XML** or
  **PDF**.
- The headline **percentage up-to-date counts only online hosts with data** —
  hosts that haven't reported inventory are excluded rather than skewing it.
- **Software inventory search** finds a package (optionally an exact name/version) across
  the fleet, and the **patch catalog** inverts the table: pending updates
  aggregated *by package*, showing which update is waiting on how many hosts.

## Packages apt keeps back

On Debian and Ubuntu, `apt-get upgrade` keeps a package back when upgrading it needs a package that is
not installed yet: a new kernel image behind `linux-image-amd64`, or the split `linux-firmware`
packages. It installs nothing for that package, prints no error and exits 0.

Such a package counts as pending, so the host does not read **Fully Patched** while a security update
is waiting. If the update is a security update it counts among the security-flagged ones too: the agent
asks apt what an upgrade that may install new packages would do (a simulation, nothing is installed)
and takes the distro's own security flag from that.

- **A held package does not count.** One held with `apt-mark hold` stays out, because somebody chose to
  keep it (auto-patch holds the packages you declined in the patch catalog the same way). If the agent
  cannot read the holds, it counts no kept-back package at all.
- **An update Ubuntu is still phasing in does not count.** Ubuntu releases many updates to a share of its
  hosts at a time and defers the rest. Until the update reaches your host it is not pending: apt would not
  install it, and neither would any upgrade mode. Ubuntu 24.04 lists such a package under a heading of its
  own. Ubuntu 22.04 lists it as kept back, so the agent asks apt the same question with phasing ignored, and a
  package that stops being kept back was only deferred. If that question fails, the package counts.
- **The patch run installs them only in Extended mode.** In the default Standard mode, auto-patch and the
  patch button run `apt-get upgrade`, which keeps the package back again, so it stays pending after a
  successful run. Switch the host to [Extended](#upgrade-mode), or on the host run
  `apt-get install <package>`, which installs it with what it needs.
- **Update the agent.** The agent does the counting, so a host shows these packages once its agent has
  this. dnf, yum and pacman hosts are unchanged.

## Upgrade mode

A host that uses apt runs its upgrades in one of two modes:

- **Standard** runs `apt-get upgrade`, as before. It keeps back an update that needs a package that is not
  installed yet, so that update stays pending.
- **Extended** runs `apt-get upgrade --with-new-pkgs`. It installs the new packages such an update needs, so
  a kept-back kernel or `linux-firmware` update is installed by the next upgrade. It removes nothing.

Standard is the default. To change a host, open it (click it on the Hosts page) and tick **Extended** under **Upgrade mode** in
**Host settings**, below the action buttons and next to the host's other checks. It saves as you tick it, and it names the packages
apt keeps back on that host. The host's **Patch Report** (its row on the Patches page) has the same setting. To change many hosts at
once, use **Bulk actions → Upgrade mode: Extended (apt hosts)**. Hosts in Extended mode carry an **Extended** badge on
the Patches page.

The mode applies to every upgrade RemotePower runs on the host: the patch button (one host or many),
[auto-patch](auto-patch.md) policies including their staged rings, scheduled upgrades, rollouts, the
compliance fix for pending updates, and the autonomy loop's patch action. A host that does not use apt
(Windows, macOS, dnf, pacman) ignores it, and the API refuses to set it there.

Only administrators set the mode, and a change is audited as `upgrade_mode_set`.
`GET` and `PUT /api/devices/{id}/upgrade-mode` read and set it; `PUT` takes `{"mode": "standard"}` or
`{"mode": "extended"}` and refuses anything else.

## Patch preview

The Patches page counts what is pending. The **patch preview** says what an upgrade would do. Open a Linux host's **Patch
Report** and choose **Preview the next upgrade**, or choose **Preview** beside a parked upgrade on the Approvals page.
RemotePower asks the host for a dry run, which changes nothing, and shows the answer when the host reports (a few seconds
to a minute):

- **Upgrades**: each package with the version it has and the version it would get, and a *security* mark where the
  distribution itself calls the update a security update.
- **New packages**: packages an update needs that are not installed yet, such as a new kernel image.
- **Removed**: anything the upgrade would take off.
- **Kept back**, **On hold** and **Deferred**: what apt leaves alone. A package held with `apt-mark hold` is on hold, on
  purpose. A package whose new version needs a new package is kept back, and the **Extended** [upgrade mode](#upgrade-mode)
  installs it. An update Ubuntu is still phasing in is deferred and arrives by itself.
- **Cleaned up afterwards**: packages that stop being needed once the upgrade is done, which the run removes.
- A **kernel update** or **reboot likely** note. This is an estimate from the package names (a kernel, microcode, the C
  library, systemd, D-Bus). The distribution's own reboot marker is written only after the install.

The preview follows the host's upgrade mode, so an Extended host is asked the Extended question. It works for hosts that
use apt, dnf, yum or pacman. pacman prints no removals in a dry run, so none are shown for it. The package lists are as
fresh as the host's last refresh, and the upgrade refreshes them first, so the real list can be longer. If the plan is
cut off, or its rows do not match the counts the package manager printed, the dialog says so.

A request that comes in while another one is waiting is the same request. A plan younger than ten minutes is shown as it is
when you open the dialog. When four-eyes approval is on, a parked upgrade asks its host for a preview at once, so the second
administrator finds the plan waiting. **Show the host's output** opens the start of the host's own answer, for when a plan
looks wrong.

A preview is a read-only command, so it is not parked for approval itself. It is refused like any command while the server
is in maintenance, for a quarantined host and for an agent in audit mode. It is not available for Windows and macOS hosts.
`POST /api/devices/{id}/patch-preview` asks for one (anyone who may patch the host), and `GET` reads the last plan and says
whether a request is still waiting (`?raw=1` adds the start of the host's answer).

## Package repositories

The **Package repositories** card on the Patches page lists the repositories the fleet's Linux hosts fetch their updates from.
An update only comes from a repository the host trusts, so the list is part of a host's attack surface. The agent sends the
repository definition files (apt's `sources.list`, `sources.list.d/*.list` and `*.sources`; dnf and yum's `*.repo` and main
configuration; pacman's `pacman.conf`) with the comments taken out, when they change and every six hours. RemotePower reads
them into one row per repository: its address, suite and components, how many hosts use it and what is wrong with it.

Click a repository to see the hosts that use it, the files it is defined in and its findings:

| Severity | Finding |
|---|---|
| High | signature checking is switched off (`trusted=yes` or `allow-insecure=yes` for apt, `gpgcheck=0` for dnf, `SigLevel = Never` or `TrustAll` for pacman) |
| High | certificate checking is switched off (`sslverify=0`) |
| Medium | fetched over plain http while signatures are not checked either |
| Low | fetched over plain http (the metadata is still signed, which is how most distribution mirrors work) |
| Low | not a distribution's repository: a vendor's, a personal package archive or an internal mirror. This is a fact, not a fault: a vendor repository a host needs is on the list because it is a third party |
| Low | the same repository defined twice on one host |

A repository that is disabled is listed and has no findings. The filter sets the lowest severity to list, and the line above it
counts the repositories by their worst finding and the hosts that report. A `deb` line and a `deb-src` line for one archive are two
entries, not a repeat. `GET /api/repositories` lists them (`?min=critical|high|medium|low`, `?q=` to filter on address, host
or host name, `?host=<id>` for one host); a host outside your tenant or role scope is not listed.

Update the agents for this. Nothing raises an alert: most hosts have a vendor repository, so an alert would never clear. A
Windows or macOS host reports no repositories.

## Patch SLA

The **Patch SLA** card flags hosts whose pending updates have gone unpatched for
too long. Add a rule with a scope (the whole fleet, a group or a tag), a
**Security max days** and an **All max days** (1 to 3650 each, and at least one
of them). The first rule that matches a host decides. The age of a pending update
counts from when the host first showed one and starts again when the host is
clean. A breach raises `patch_sla_violation` and `patch_sla_ok` when it clears.
The sweep runs hourly. It only reports: nothing is installed for you. You can
keep up to 100 rules.

## Acting on updates

- Install, uninstall, or **hold / unhold** (pin) named packages on a target
  scope (all hosts, a group, a tag or one host id) from the **Install software**
  card on this page — package names only, no shell.
- To apply updates **automatically** on a schedule, define an
  [Auto-patch](auto-patch.md) policy.
- To roll an upgrade out **in stages** with verification between rings, use
  [Rollouts](rollouts.md).

## Related

- Package **vulnerabilities** (CVEs) are tracked separately on the
  [CVE Findings](cve.md) page.
- Upgrades and package changes are commands, so server maintenance mode, host
  quarantine and change approval apply to them. A
  [maintenance window](maintenance.md) with **Gate command/upgrade execution** ticked
  holds them in the queue until the window opens.

## Permissions

Starting an upgrade needs the **patch** permission on the target hosts, and
installing, removing or holding packages needs the **packages** permission (admins
have both). Every dispatch is audit-logged.
