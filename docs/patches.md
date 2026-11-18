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
- The **Mean time to patch** card under the counts shows how long patching takes
  (see [Mean time to patch](#mean-time-to-patch)).
- **Software inventory search** finds a package (optionally an exact name/version) across
  the fleet, and the **patch catalog** inverts the table: pending updates
  aggregated *by package*, showing which update is waiting on how many hosts.
  See [Software inventory](#software-inventory) for what each system reports.
- A Windows host's count leaves out the Defender definition updates, which Windows offers several times a day, and its
  patch report says when the last Windows Update search ran and whether it worked. A search that failed keeps the count the
  host had and names the date of it. After 3 days of failed searches that count is too old to call the host patched, so the
  host is listed as **No data** (the report's `upgradable` is `null`, and `stale_count` holds the count and the time it was
  taken), and the check of an upgrade you queued waits for a count taken after it. See
  [Windows Update](windows-client.md#windows-update).

## Software inventory

Every agent reports the software installed on its host. The **Software** tab of this page, the **Software center** on the
[Software Policy](software-policy.md) page, the software metering in [Reports](reports.md), the SBOM and the `packages` entity of
the [Data Explorer](data-explorer.md) all read that one list. What a host reports depends on its system:

| System | What is listed | Where the agent reads it | What a row holds |
| --- | --- | --- | --- |
| Linux | The packages of the distribution | `dpkg`, `rpm`, `apk` or `pacman` | Name, version, architecture; the source package and the epoch where the package format has them |
| Windows | The programs of **Programs and Features** | The Uninstall keys of the registry, the 64-bit one and the 32-bit one (read only) | Name, version, publisher, install date, architecture |
| macOS | The applications in `/Applications`, `/System/Applications` and the `Applications` folder of each account, and the Homebrew formulae and casks | The `Info.plist` of each application bundle, and `brew list --versions` | Name, version, bundle identifier; a row for each version of a Homebrew package |

The agent sends its list when it starts, about every six hours, and when you ask for it: **Scan packages** in the
quick actions of a host, **Scan now** in its Packages section, or **Send list** on the CVE page. A list that has not
changed since the last one is not sent again. A host keeps at most 5,000 rows, and a name, version or publisher at most
200 characters.

### What a Windows or macOS host leaves out

- **Windows:** updates and hotfixes, components that Windows hides from the list, and keys that have no name. The agent counts
  them and sends the count. A program that was installed for one user alone is kept in that user's own registry. The agent reads
  the registry of the machine only, so such a program is not listed. A program that Windows does not record under those keys at
  all, such as an app from the Microsoft Store or a portable program that was only copied to a folder, is not listed either.
- **macOS:** a bundle that is a symlink (the agent never follows one out of an application folder), a bundle whose
  `Info.plist` is missing or cannot be read, and folders more than one level inside an application folder. An application kept
  outside those folders, on an external disk or in a Downloads folder, is not listed. If Homebrew is
  installed and the agent cannot read its list, the agent sends no list at all that time instead of a list without the
  Homebrew rows. If the agent cannot run Homebrew as the account that owns it, it sends the applications only.

### How the views read such a list

- **Names** match without regard to case: a rule or a search for `teamviewer` finds `TeamViewer`. In the Software center
  one title is one row, however hosts spell it.
- **Versions** are read by the number they start with, and the words after it come second. `14.38` is above `14.9`, and
  `2.43.0.windows.1` is above `2.9` and below `2.100`. `2023.1 (64-bit)` is above `2023.1`. A version with no number in front,
  such as `Beta 3`, is below every version that has one, and an empty version is the lowest. The same two versions always
  have the same order, so the highest of a name's rows does not depend on the order the agent listed them in.
- **Not checked for vulnerabilities.** No vulnerability database is matched against the applications of a Windows or macOS
  host, so they are never scanned. See [CVE scanning](cve.md#which-hosts-are-scanned).
- **Not for the Linux commands.** Package snapshots, **Install software**, uninstall and hold are written for the packages of a
  Linux distribution. They skip a Windows or macOS host, and the job lists it as *Skipped: not a Linux host*. A request whose
  targets are all such hosts is refused with the reason, and nothing is reported as queued.

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

## Refreshing the package lists

**Scan now** reads what the package manager already has. On an apt host that is the lists as they were last downloaded, so a host whose
lists are a week old reports a week-old answer. **Check for updates now** asks the repositories first. Open a Linux host, open
**Packages** under **Software** on its **Audit** tab, and choose **Check for updates now**. The host runs its own refresh command. When
that refreshed the lists, it reads what is pending against them. Either way it reports how it went at its next check-in (about a minute).

The command is fixed. Nothing in it comes from the server, and the agent gives it no input and a limit of 120 seconds:

| Package manager | The agent runs |
|---|---|
| apt | `apt-get update` |
| dnf | `dnf makecache --refresh` |
| yum | `yum makecache` |
| zypper | `zypper --non-interactive refresh` |
| apk | `apk update` |
| Arch (pacman) | `checkupdates` from pacman-contrib, when it is installed |

**On Arch** the refresh is `checkupdates`. It syncs a private copy of the databases and leaves the host's own alone, so it cannot cause
a partial upgrade. Without `checkupdates` the answer is "not refreshed: no safe way on this distribution": nothing is run and no scan
follows. Install `pacman-contrib` to get a refresh.

The scan is a different command and has not changed. On Arch it syncs the host's databases with `pacman -Sy` before it lists what is
pending, whenever it runs: **Scan now**, the scheduled scan, and the read that follows a refresh that worked. A host that has been
scanned has databases newer than its installed packages, and `pacman -S <package>` on it is the partial upgrade Arch warns about:
packages built against libraries the host does not have yet. Install with `pacman -Syu <package>` instead. The **What this agent can
see** panel gives that command for a missing tool.

If another package manager process holds the lock, the agent waits at most 30 seconds and then gives up with the class **the
package manager was busy**. A refresh that is still running after 120 seconds is ended.

**How it went** shows beside the **Lists refreshed** time on the Packages section. The agent sends one of four statuses and a
class from a fixed list, and never the package manager's own output:

| Status | Meaning |
|---|---|
| Succeeded | The lists are fresh. |
| Partly succeeded | Some repositories were refreshed and some were not. The class says why (amber). |
| Failed | Nothing was refreshed. The class says why (red). |
| Not refreshed | The host cannot do it: no safe way on Arch, no package manager the agent knows, or a container (grey). |

Only a refresh that worked (Succeeded or Partly succeeded) is followed by a read of what is pending. After Failed or Not refreshed the
host sends how it went and nothing else changes.

The classes are: the package manager was busy, the repositories could not be reached, a repository answered with an error, no space
left or a read-only file system, not allowed to write the lists, it did not finish in 120 seconds, no safe way on this distribution,
no package manager the agent can refresh, not available in a container, and the reason is not known.

**Who and when.** Anyone who may patch the host (the **patch** permission, scoped to the host) can ask. The request is a queued
command, so server maintenance mode, a quarantined host, an agent in [audit mode](agent-commands.md#read-only-audit-mode) and a maintenance window that holds
commands apply to it. It can go through change approval: put the **Scan** kind under **Settings → Security → Change approval** and
the refresh waits for a second admin. It is not available for Windows and macOS hosts, for hosts without an agent, or from the
containerized agent, which would refresh its own image's lists and not the host's. The agent has to be version 8.0.2 or later. An older
agent does not know the command and drops it without an answer, so the request is refused with a 409 and the sentence "the agent on this
host is too old to refresh package lists: update the agent first", and nothing is queued. `POST /api/devices/{id}/refresh-package-lists`
asks for one.

**Before each scheduled scan.** **Settings → Security → Package lists** has **Refresh the package lists before each scheduled scan**.
It is off by default, and with it off a scan does what it always did. With it on, each Linux host refreshes its lists just before its
scheduled scan. A host that is quarantined, in audit mode, in maintenance mode or outside a change window that holds commands
scans without the refresh, and so does a host with an agent older than 8.0.2, which does not know the setting. The scan is the same as
ever, on Arch too (see above).

The **Package index updated recently** check template also counts a refresh the agent ran itself, so the check works on dnf, zypper
and apk hosts. A check applied from the template before this was added keeps its two apt paths: edit its path to add
`/var/lib/remotepower/pkg-refresh-ok`, or apply the template again. A refresh that failed does not make the lists look fresh.

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
The sweep runs hourly, and it runs whether or not you have a rule: without one
nothing is in breach and nothing is raised. It only reports: nothing is
installed for you. You can keep up to 100 rules.

## Mean time to patch

The **Mean time to patch** card next to the patch counts shows how long patching
takes. A patch is timed from the first hourly check that saw an update waiting
on a host to the first check that saw none waiting. The card shows the mean, the
median and the 90th percentile, and how many completed patches they come from
(n). Pick **Last 30 days** or **Last 90 days** in the toolbar; the 30 days are
the default.

- Only completed patches count. A host that never reaches zero pending updates
  adds nothing, and so does a host that stops reporting its packages.
- Updates your distribution flags as security fixes are counted on their own line,
  next to the figure for all updates, for hosts whose package manager reports them.
- With fewer than five completed patches the card says so, shows n and shows no
  number. A host with no completed patch is not listed and is never shown as zero.
- A patch is timed from the check that first saw the update, so an update that
  was already waiting when you upgraded starts its clock then. The checks run
  hourly, so a time is accurate to about an hour.
- It needs no Patch SLA rule. The server keeps the last 200 completed patches of
  each host, and none older than 400 days.
- You see the hosts your role and your tenant let you see, and no others.

The same figures are in the `mttp` field of `GET /api/patch-report`: the mean,
median and 90th percentile in hours for the fleet, for each host that has a
completed patch in the window and, for the operator of an installation with
tenants, for each tenant. `?mttp_days=30` or `?mttp_days=90` picks the window;
any other value gives 30.

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
