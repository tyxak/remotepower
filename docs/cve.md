# Vulnerabilities (CVE scanning)

**Security → CVEs** compares the packages installed on your hosts with the
[OSV.dev](https://osv.dev/) vulnerability database. It ranks what to patch first
with real exploit signals, not just the CVSS score.

## What you need

- A Linux host whose agent reports a package list. The agent sends one when it starts and
  about every six hours after that. **Send list** on the page, or **Send package list now** in
  the host view, asks for it at once. A Windows or macOS host also sends the software installed on
  it, but that list is not scanned (see [Which hosts are scanned](#which-hosts-are-scanned)).
- A distribution OSV covers (see [Which hosts are scanned](#which-hosts-are-scanned)).
- A server that can reach `api.osv.dev` and the two feeds behind the priority signals
  (CISA KEV and FIRST EPSS).

## The CVE page

The page opens with a severity summary (Critical / High / Medium / Low and hosts scanned),
six tiles that count the findings by [fix status](#fix-status), and a KEV feed status line.
When Debian or Ubuntu hosts have findings that are [counted and not listed](#what-is-listed-and-what-is-counted),
a line under the tiles says how many. When some of the packages were [not checked](#which-packages-were-checked),
another line gives the fleet total, the reasons, and the five hosts with the most of them; a click on a host opens
its view. After an upgrade the same line says how many scanned hosts it does not count yet. Below them is one row per host.

| Column | Meaning |
| --- | --- |
| **Host** and **Group** | The host and its group. Click a row to open its findings. |
| **Ecosystem** | The OSV ecosystem found from `/etc/os-release` and the package manager (Ubuntu, Debian, Rocky Linux, AlmaLinux, Red Hat or Alpine). |
| **KEV** | How many of the findings that count are in CISA's **Known Exploited Vulnerabilities** catalog, meaning attackers use them in the wild. A finding you accepted does not count. |
| **Critical / High / Medium / Low** | Finding counts by severity. |
| **Counted** | How many more known vulnerabilities the host's scan counted per package and did not list. Debian and Ubuntu only. |
| **Last scan** | When the host was last scanned, or why it was not: **not scanned**, **no package list**, **unsupported** or **not checked**. |

Rows sort by KEV count first, then by critical and high counts, then by the highest EPSS
score, so the dangerous hosts rise to the top. A host you [accepted](#accepting-a-host) is marked **Host accepted**, and **New** with a number when it has findings that came after.

The toolbar has:

- **Refresh** reloads the page.
- **Exposure priority** ranks hosts by how reachable they are (see [Exposure priority](#exposure-priority)).
- **AI prioritise** asks your AI provider which CVEs to patch first and why. The same button sits
  on each host row that has findings.
- **Scan all hosts** starts a scan (see [Scanning](#scanning)). Each host row also has its own
  **Scan** and **Send list** buttons.
- **Re-alert backlog** raises `cve_found` again for the current findings.
- **Fleet SBOM (CycloneDX)** and **Fleet SBOM (SPDX)** download a ZIP of one SBOM per host.
- **Views** saves the current filter and gives you a link to share it.
- A filter box that matches host, group and ecosystem.

Under the table you also find [container image CVEs](#container-image-cves) and
[remediation campaigns](#remediation-campaigns).

### The host view

A click on a host row lists its findings, KEV first, then by severity, then by EPSS. Each
finding shows its severity, the CVE ID (click to copy), a **KEV** badge and the EPSS percentage
(the chance of exploitation in the next 30 days), the package with its installed version, the
fix, a summary, the aliases and links to the advisories. **Triage** asks the AI about one
finding and **Ignore** accepts the risk. The buttons above the list are **Send package list
now**, **SBOM (CycloneDX)**, **SBOM (SPDX)**, **Baseline**, **Changes since baseline** and **Accept host** (see [Accepting a host](#accepting-a-host)).

On a Debian or Ubuntu host the view also shows the count: how many known vulnerabilities are
counted and not listed, how many of those are critical or high, how many an update would
clear, how many an installed kernel already fixes (a reboot applies them), how many are fixed
with Ubuntu Pro, and the packages that hold the most with the version installed. Open it with
a click.

Under it, **Packages checked** says how many of the packages the host listed the last scan checked.
When some were not, a click shows the reasons with their counts and the first 200 of those packages by
name, with the reason of each. A host with no finding says **None found in the packages that could be
checked** and not "No vulnerabilities found" when that is so.

### Accepting a host

Some hosts are acceptable as they are: a lab machine, a box that is being retired, a system whose findings you have read and decided to live with. In a host's view, **Accept host**
asks for a reason and accepts every finding the host lists now. They stay recorded and stop counting in the numbers of the CVE page, the Security badge, **Needs attention**, the risk
score, **Checks**, the posture digest and the reports, as the findings you ignore one at a time do. What the host's scan counted per package leaves the line under the tiles as well,
and a line under it says how many hosts are accepted and how many of their findings that is.

- **A finding that comes after is new.** A scan that lists a finding the host did not have when you accepted it counts it, alerts for it as it would for any host, and marks it **New**
  in the host's view and on the host's row of the CVE page. On a Debian or Ubuntu host the scan counts most findings per package and does not list them (see
  [What is listed and what is counted](#what-is-listed-and-what-is-counted)), and those have no ID to accept. One of them that enters the list later, because others were patched, is new too.
- **Accept what is new** accepts the findings that came after, and keeps the time, the account and the reason of the first acceptance. **Stop accepting** takes the acceptance back, and the
  findings count again. A finding you ignored on its own stays ignored.
- The host's view says since when, by whom and why. As with an ignore, each organisation sees its own records, and the ones the platform operator wrote for one of its hosts.
- Two hosts that share a finding are both accepted. Accepting one never takes the other's acceptance away.
- **Settings → Ignored items → Accepted hosts** lists the accepted hosts in one place: the host, when it was accepted, by whom, the number of accepted findings and the reason, with
  **Stop accepting** on each (after a question, and the findings count again at once). Each organisation sees the hosts it may see; the list holds the newest 500 and says so when there
  are more. **Ignored CVEs** in the same place does not list the records of an accepted host (a host holds up to 300), and the limit of 5,000 ignores for an organisation does not count
  them. Deleting a host removes them.
- The platform operator and a tenant administrator can accept the hosts they can see, as they can ignore a finding. The API is `POST /api/devices/{id}/cve/accept`, with an optional
  `reason`, and `POST /api/devices/{id}/cve/unaccept`. `GET /api/cve/ignore` lists the accepted hosts under `accepted_hosts` (with `accepted_hosts_total`), beside the ignores.

## Which hosts are scanned

| Host | Ecosystem |
| --- | --- |
| Debian (`apt`), and derivatives such as Raspberry Pi OS, Devuan and LMDE | `Debian:<major version>` of the Debian release they are built on |
| Ubuntu, and derivatives such as Linux Mint, Zorin OS, elementary OS and Pop!_OS | `Ubuntu` |
| Rocky Linux (`dnf` or `yum`) | `Rocky Linux:<major version>` |
| AlmaLinux | `AlmaLinux:<major version>` |
| Red Hat Enterprise Linux | `Red Hat` |
| Alpine (`apk`) | `Alpine:v<major.minor>` |

An Ubuntu host's release is read from the version it reports (22.04). Pop!_OS and KDE neon
number their releases the same way. Other derivatives report a version of their own: Linux Mint
21.3, Zorin OS 17 and elementary OS 7 are all Ubuntu 22.04 underneath. An agent from 8.0.1
reports the release a derivative is built on, and its fixes are read for that release.
Without it the release is not known;
[How a package is matched](#how-a-package-is-matched) says what that changes.

A derivative of Debian is scanned under the Debian release it is built on: Devuan 5 and LMDE 6
as Debian 12. Before 8.0.1 their own number was taken for Debian's, so they were asked for as
Debian 5 and Debian 6 and read as clean. Kali has no Debian release and shows **unsupported**.

OSV has no Arch Linux feed, so `pacman` hosts report no ecosystem. A Linux host on any other
distribution shows **unsupported** in the Last scan column and is skipped.

### Windows and macOS hosts

The Windows and macOS agents send the software installed on the host: the programs in the Uninstall keys of the registry, or the
application bundles and the Homebrew packages of a Mac. [Software inventory](patches.md#software-inventory) says what each one
reports. That list is shown in the software views, but **CVE matching for Windows and macOS applications is not done**: the names
of applications (`Google Chrome`, `7-Zip 23.01 (x64)`) are not names any advisory database is filed under, and a scan under the
wrong name would find nothing and read as clean.

So such a host shows **not checked** in the Last scan column, is never scanned, and is never asked of OSV. Its host view says that
nothing on it is checked, and has no "No vulnerabilities found" line, because an empty list there would say the opposite of what is
true.

## Which packages were checked

A scan that finds nothing is only as good as what it asked about. A package that was not asked about under the
name the advisory data is filed under has no findings, whatever is wrong with it, and that reads the same as a
clean one. So each scan keeps, on the host's record, how many of the packages the host listed it **checked**, and
for every other package one reason it did not:

| Reason | What it means |
| --- | --- |
| **No source name** | The data is filed under the source package, and the list of the host names none: the agent is older than 8.0.1. On a host that is asked for package by package, a package whose answer named an advisory still counts as checked, because the answer shows the name was the right one. |
| **No matcher for the package manager** | Nothing on the host is matched against a database: the applications of a Windows or macOS host, the packages of Arch and openSUSE, a distribution OSV has no feed for. |
| **Release not known** | A Debian or Ubuntu derivative whose release the scan does not know, so the data, which is kept per release, cannot be asked for. |
| **Past the limit of packages a scan reads** | A scan reads the first 10,000 packages of a list. |
| **Not answered in full by the data source** | The advisory list of the package was longer than the pages a scan reads, or a limit of the scan was reached: a package name listed at more versions than a scan asks about, or more answers than one scan holds (see [Scanning](#scanning)). |

An RPM host also lists the GPG keys it has imported (`gpg-pubkey`). They are records of a key in its database, not
software, and no advisory is filed under them, so they are in neither number, and an RPM host whose other packages were
all checked reads clean.

The host's record keeps the count of each reason and the first 200 packages that were not checked, never the whole
list. The CVE page, the host view, the host drawer, the dashboard tile, the assistant's CVE tool, the text of a
ticket, the runbook, the MCP tool `get_cves` and the SBOM all say what the scan did not check, and a host with no
finding says that none were found in the packages that could be checked.

What the data source answers for a package it has no record of is the same as for one it holds a record of and that
no advisory touches: an empty list. So a package of a third-party repository, or one built locally, is counted as
checked on a host that is asked by source package. Telling those apart needs the agent to report the repository of
each package, which it does not.

A host is told its packages were checked from the scan after the upgrade. Until then its view says nothing of its
packages, and the fleet total does not hold it: the line under the tiles says **Hosts scanned before the upgrade, not
counted until they are scanned again** and how many they are, because an upgrade starts no scan. A host nothing is
matched against says so at once, because no scan is made of it. The assistant's
CVE tool, the runbook and the text of a ticket say it too for such a host. The dashboard tile says **None found in the
packages that could be checked**, and is not green, when no monitored host shows a finding and part of the fleet is not
matched against anything.

## How a package is matched

OSV files an advisory under the name the distribution's security team uses, and that is not
always the name of the installed package. What RemotePower asks for depends on the
distribution:

| Distribution | Asked for by | What that means |
| --- | --- | --- |
| Alpine | The origin: the package whose build produced the installed one | `libcrypto3` and `libssl3` are checked as `openssl`. |
| Rocky Linux | The installed package and its source package | Older advisories name only the source package, newer ones name every package built from it. |
| AlmaLinux, Red Hat | The installed package | These advisories name every built package. |
| Debian, Ubuntu | The source package and its version | `libc6` is checked as `glibc`, `libssl3` as `openssl`, `openssh-server` as `openssh` and the kernel image as `linux`. |

Matching by source package needs an agent from 8.0.1 on. It reports the source package of
each installed package and, on RPM hosts, the epoch of its version. A host with an older
agent is asked for package by package, and its host view says what that leaves out.

A Debian or Ubuntu host is asked for by source package only when its release is known. For an
Ubuntu derivative with a version of its own (Linux Mint, Zorin OS, elementary OS) that needs an
agent from 8.0.1 as well, because it reports the Ubuntu release the derivative is built on.
With an older agent such a host is asked for package by package, and its host view says so.

One advisory against one source package is one finding. It carries the source package's name
and lists the installed packages built from it after **installed as**. `openssl` and
`openssl-libs` on an AlmaLinux host are one finding where they were two.

Rocky Linux and AlmaLinux are asked for with their major release, so a host on release 9 is
not shown the advisories of release 10.

Debian and Ubuntu announce a fix in a notice (a DSA, a USN) and also keep one record per CVE.
A notice is not a second finding when the records of its CVEs already tell the host to install
a version at or past the notice's fix. A notice whose fix nothing else reaches stays a finding.

### What is listed and what is counted

Debian and Ubuntu publish every known CVE of a release, fixed or not. In November 2026 the
kernel of a Debian 12 host alone had about 700 on a host with the newest kernel, none of which
an update clears, and almost 6,000 on a host whose kernel is a year behind. Listed one by one,
the findings you need to read would sit among thousands of rows, so for these two
distributions a scan lists a finding one by one when:

- an update for the host's release clears it,
- it is critical or high, or
- it is on the known-exploited (KEV) list.

A host lists at most 300 findings, and at most 50 for one package. When there are more, the
known-exploited ones come first, then the critical, then what an update clears (by severity),
then the high ones without a fix. Within each, the newest CVE comes first.

Everything else is counted. The host's scan keeps how many there are, by severity and by fix
status, and the 20 packages that hold the most. You see the number in the **Counted** column
and in the line under the tiles, and the packages in the host view. Nothing is left out without
being counted.

What is counted is not in the severity tiles, the fix tiles, the Security badge, **Needs
attention**, the risk score, alerts, campaigns, reports or the SBOM. Those read the listed
findings. The dashboard tile and the host drawer say when a host has a count and nothing
listed, so such a host is not shown as clean.

The rule applies to every Debian host, and to every Ubuntu host whose release is known, from
its next scan, also when its agent is older than 8.0.1. A host scanned before 8.0.1 keeps its
old findings until it is scanned again.

## The kernel a host runs

A host keeps the kernels it has installed, and the newest is not always the one that runs. A scan used to ask about
every kernel package version a host had, so the findings of a kernel that had been replaced were counted beside the
kernel that ran, and a fix that sat in a kernel the host had not booted into was offered as an update to install.

An agent from 8.0.2 reports the kernel it runs (`uname -r`) with its package list and, for each installed kernel image,
the release that image owns: the package that owns `/boot/vmlinuz-<release>` on Debian, Ubuntu, Rocky Linux, AlmaLinux and
Red Hat, and the package that lists the directory `lib/modules/<release>` on Alpine (its kernel file is named by flavour).
An Arch host reports the package named in `/usr/lib/modules/<release>/pkgbase` too, but no scan is made of it, so nothing
reads that. The agent reads this from the package database and the host's files, never from a name. Up to 16 images are
reported. A host that boots into another kernel sends its list again, though the list did not
change.

When exactly one installed package owns the running release, the scan:

- asks about, and counts, the findings of that package's version only. The kernels that are installed and do not run are
  left out, with the rest of the packages built from them (the host view says how many packages that is). On an RPM host the
  kernel is several packages built together (`kernel`, `kernel-core`, `kernel-modules`, `kernel-modules-core`) and only
  `kernel-core` owns the file, so every package built from the same source package at that version goes with it, and a
  kernel finding reads the same whatever order the host lists its packages in;
- marks a finding of the running kernel as **Reboot to apply** when a kernel installed beside it is at or past the fix, by
  the rule that leaves out a finding the installed version is past. The finding keeps the version that has the fix and names
  the kernel (`linux-image-6.1.0-48-amd64 6.1.192-1`);
- keeps such a finding in the list beside the ones an update clears, so a finding that goes from **Fixed** to **Reboot to
  apply** when the update is installed is not announced as cleared. It clears, once, at the scan after the reboot.

The host view shows the running kernel, its package, and a newer kernel installed beside it ("Reboot to start it"). The
text of a ticket for a new-CVE alert and the answer of the assistant's CVE tool say the same in a sentence, and the MCP
`get_cves` tool returns the block.

When the scan cannot tell with certainty which package the running kernel is, it matches every installed kernel as it did
before, and the host view says so and why: the agent does not report its kernel (older than 8.0.2); it found no installed
kernel package; no installed package owns the files of the running kernel (a kernel you built, or one that was removed);
more than one package owns it and they are built from different versions; or the package that owns it is not in the list
the host sent. A signed kernel package and the unsigned one it holds are built from one version and count as one owner.
Nothing is guessed from a package name.

A kernel finding is only marked **Reboot to apply** for a package whose version order the server can read (Debian and
Ubuntu, RPM and Alpine versions), and only a finding of the running kernel is: a package that is not a kernel never reads
**Reboot to apply**, whatever kernel is installed beside the running one. The reboot signals the host already has (the
reboot-required flag, **kernel_outdated**) are unchanged. The Windows and macOS agents report no kernel.

## Fix status

A finding records a fixed version, but a fix only helps a host if it reached the release
that host runs. Debian, Ubuntu and Alpine publish a fix per release (Debian 12, Ubuntu 22.04,
Alpine 3.19), and RemotePower reads the entry for the host's own release. Each finding
is one of:

| Status | Meaning |
| --- | --- |
| **Fixed** | An update for this host's release clears it. The finding names the version to install. |
| **Reboot to apply** | A kernel that is installed and not running already holds the fix, so there is nothing to install: a reboot clears it. The finding names that kernel. See [The kernel a host runs](#the-kernel-a-host-runs). |
| **Fixed in a newer release** | The host's release has no fix, a newer release does. The finding names that release and version (for example `Debian:13 8.7.1-1`) and offers nothing to install. |
| **No fix yet** | No release has a fix. |
| **Fixed with Ubuntu Pro** | The fix for the host's release ships in Ubuntu Pro only, which is where every fix of a release past its standard support goes. The finding names the Pro version and offers nothing to install. On a host that has a package from Ubuntu Pro installed (its version ends in `+esm1` or `~esm1`), such a finding is **Fixed**. A kernel from Ubuntu Pro carries no such mark, so a host whose only Pro packages are kernels is not recognised. |
| **Not checked** | Red Hat, and an Ubuntu derivative whose release is not known (its agent is older than 8.0.1), are scanned without a release, so their entries cannot be told apart. Rocky Linux and AlmaLinux publish an advisory per release together with its fix. In all of these a finding keeps the fixed version OSV lists and counts as fixable when it has one. |

The six tiles under the severity counts count the listed findings that are not ignored
(**Fixable now**, **Reboot to apply**, **Newer release only**, **No fix yet**, **Needs Ubuntu Pro**, **Not checked**). On a
release past its standard support most of what needs Ubuntu Pro is counted and not listed; the
count in the host view says how many. Click a tile to
keep only the hosts that have such a finding, and the host view then lists only those
findings. Click the tile again, or **Show all** in the host view, to undo it.

A package that is already at or past the fix of a newer release (a backport, say) counts as
patched. A fix in an older release never does.

"At or past" follows the distribution's own version order: the dpkg order for Debian and
Ubuntu, the RPM order of epoch, version and release for Rocky Linux, AlmaLinux and Red Hat, and
the Alpine order with its `-r` revision. The server computes all three itself, so it needs no
`dpkg` or `rpm` installed. A version that cannot be read keeps its finding.

If you upgrade from a version before 7.4.6, run **Scan all hosts** once. Findings keep their
old fixed version until their host is scanned again.

After an upgrade to 8.0.1, run **Scan all hosts** once more. Before it, a Rocky Linux,
AlmaLinux or Red Hat host showed nothing for a package whose version has an epoch and starts
with a higher number than that epoch (`openssl`, epoch 1, version 3), however old the
package was, and an Alpine host showed nothing when a fix differed only in its `-r` revision
or its letter.

For Debian and Ubuntu the numbers move in both directions on that scan, once the host runs an
8.0.1 agent:

- Libraries, the SSH server and the kernel are checked for the first time, so a host gets
  findings it never had. Many of them have no fix for its release. If critical and high are in
  your alert severities, expect one `cve_found` for each such host. To hear only about what an
  update clears, turn on **Only CVEs an update or a reboot can fix, or that are known to be exploited**
  before you scan (see [Alerts & ignores](#alerts--ignores)).
- A notice that repeats the findings of its CVEs is no longer a finding of its own, and a medium
  or low finding without a fix moves into the count, so some numbers go down. This part does
  not wait for the agent.
- **Needs attention**, the risk score and Checks read the listed findings, so they rise with
  them. With [counting only what an update can fix](#counting-only-what-an-update-can-fix) on,
  they count what you can act on. Reports and the compliance controls count every listed
  finding either way.
- The **KEV** badge and the EPSS percentage appear on findings of Debian, Ubuntu, AlmaLinux and
  Rocky Linux. A distribution's record names its CVE in a field RemotePower did not read, so
  the two signals matched nothing there. The badge shows after the scan. The percentage follows
  at the next daily refresh of the feeds, or when you click **Refresh KEV/EPSS feeds**: scores
  are kept only for the CVEs your hosts have.

## Counting only what an update can fix

By default the numbers you read count every finding that is not accepted as a risk: the badge
on the Security menu, the severity tiles on the dashboard and the CVE page, **Needs
attention**, the risk score, **Checks**, the scheduled posture digest and the CVE count of the
Fleet query. On a host with hundreds of findings that no update for its release can clear,
that is a number nobody can act on.

Settings → Security → **CVE counts** has **Count only CVEs an update or a reboot can fix, or that
are known to be exploited** (`cve_count_fixable_only`, off by default). With it on, those places
leave out a finding that is fixed only in a newer release, needs Ubuntu Pro or has no fix yet.
A finding on the known-exploited (KEV) list always counts, and so does a **Not checked**
finding that lists a fixed version and one that only needs a **reboot**: it is something to do.
The alert option follows the same rule.

- Every listed finding stays on the CVE page and in the host view, and the six fix tiles keep
  counting all of them, so you can see what the option leaves out. The CVE page says when the
  option is on.
- What a Debian or Ubuntu host has [counted per package](#what-is-listed-and-what-is-counted)
  is in none of these numbers, with the option on or off.
- Alerts have their own switch (see [Alerts & ignores](#alerts--ignores)). Reports, the
  printable fleet report, compliance checks and the assistant's context keep counting every
  listed finding.
- A finding you accepted as a risk, one at a time or with the whole [host](#accepting-a-host), never counts in those numbers, with the option on or off.
- The badge, **Needs attention** and the digest count monitored hosts only: a host you do not
  monitor is silent by choice. The CVE page and the dashboard tile still list its findings.

## Scanning

A scan runs when you start it. RemotePower does not rescan on its own, so the CVE page shows
the state of the last scan, not of the host today. To keep it fresh, press **Scan all hosts**
after patching, or call `POST /api/cve/scan` from a scheduled job with an
[API key](api.md).

- **Scan all hosts** (or **Scan** on one host row) runs in a **detached
  process**, so a long scan never blocks the request or hangs the browser. Poll progress
  with `GET /api/cve/scan-status`. A second scan is refused while one is running. If a
  scan crashes, the marker clears five minutes after its last checkpoint.
- With multi-tenancy on, **Scan all hosts** of a tenant's administrator scans the hosts of that
  tenant, and the answer counts those. The platform operator's scan covers every host. A tenant
  reads the numbers of its own scan. For another organisation's scan it learns whether one is
  running and nothing else. One organisation can start a scan every 30 seconds.
- Starting a scan takes the one scan slot in a single step, so two requests that arrive together
  cannot both start one. A scan stores each host's result as it goes. A result made from an older
  package list never replaces one made from a newer list, so a host that installed its fix and was
  scanned again is not shown as vulnerable by a scan that finished later. A host you delete while a
  scan runs is not stored, and raises no alert.
- The scanner **deduplicates packages across the whole fleet** and queries OSV once per
  ecosystem in a batch, so a 100-host fleet is not 100 times the API traffic.
- The details of an advisory are read once and kept. They are read again when OSV reports
  that the advisory changed, so a scan after the first asks only for what is new or changed.
  **Settings → Security → CVE details cache** (1 to 90 days, default 7) is the age after which
  they are read again when OSV gives no change date.
- The details are read eight at a time. The first scan of a Debian or Ubuntu host reads a few
  thousand of them, which takes about two minutes, and several thousand more when its kernel is
  far behind (almost 9,000 for a Debian 12 kernel from early 2024, about five minutes more). If
  some cannot be read, the host view says how many; those findings wait in the count as **Not
  checked** until the next scan reads them.
- An **OSV circuit breaker** opens after three failed requests in a row and skips OSV work
  for ten minutes, so an OSV outage degrades gracefully instead of stalling scans.
- If a request fails while the fleet's packages are looked up together, each host is scanned
  with its own requests instead. A host whose scan fails keeps its last findings.
- A package with more advisories than one answer holds is read to the end, up to 10,000. Past
  that, the host view names the package whose list is cut.
- A host sends its own package list, so a scan has limits that a list cannot raise. A package name
  is asked about at no more than 24 versions (a host keeps the kernel it runs and a few older
  ones). A scan holds no more than 150,000 advisory answers for a host, and reads no more than
  20,000 advisory records that the cache does not have yet. The packages and advisories a scan
  leaves out for a limit show in the host view as **Not answered in full** and as records that
  were not read, and the next scan reads the rest. The shared cache of advisory details keeps at
  most 250,000 records and drops the oldest first, and is written once at the end of a scan. A
  host whose findings are all listed (Alpine, Rocky Linux, AlmaLinux, Red Hat) keeps its 5,000
  most pressing findings and counts the rest, as a Debian host does.

### How severity is chosen

1. The distribution's own rating wins when the OSV record has one (the Debian, Ubuntu and
   similar priority fields), because distributions rate a CVE by how it affects their own
   packages. That includes Debian's **unimportant**: its judgement that a package is not
   affected in a way that matters, given per release. Such a finding is low on a host of
   that release, whatever its CVSS score.
2. Otherwise the CVSS score decides. The cut-offs are 9.0 for critical, 7.0 for high and 4.0
   for medium. You can change them under Settings → Alert parameters → **Forecast & CVE
   tuning**; the next scan applies the new cut-offs to every finding.
3. For Debian hosts with neither, Debian's urgency is used, capped at medium. It is in the
   record itself; the Debian Security Tracker is asked only for a record that carries none.
4. If nothing is known the finding is **unknown**.

## Prioritisation signals

RemotePower adds these to every finding:

- **CISA KEV**: is this CVE actively exploited?
- **EPSS**: the probability, from 0 to 1, that the CVE is exploited in the next 30 days.
- **Severity**: Critical to Low, chosen as described above.

KEV and EPSS data is cached and refreshed once a day. **Refresh KEV/EPSS feeds** on the CVE page
(or `POST /api/cve/refresh-feeds`) refreshes it now. If a feed cannot be loaded, the status line
says so, and the page falls back to plain severity.

## Exposure priority

**Exposure priority** (button on the CVE page) ranks hosts by how exploitable they are in
practice. Each host's critical and high counts are weighted by whether it has **world-reachable
listening ports** (`scope: world` on the [Exposure](exposure.md) page). Findings that an update
can fix add a little, and the whole score is scaled by the host's business criticality from
the [CMDB](cmdb.md). A critical CVE on an internet-facing host outranks more criticals behind a
firewall, so the list is a "patch this first" order rather than a raw count. The API is
`GET /api/cve/exposure-ranked`, filtered to the hosts the caller may see.

## SBOM

Generate a Software Bill of Materials per host or for the whole fleet:

- `GET /api/devices/{id}/sbom?format=cyclonedx|spdx` downloads one host.
- `GET /api/sbom?format=cyclonedx|spdx` downloads a ZIP of all hosts you can see. Add
  `group=` or `device_id=` to narrow it.
- **CycloneDX 1.5** carries the CVE findings as a VEX-style vulnerabilities
  section. **SPDX 2.3** is the packages-and-relationships interchange format. Running
  container images are included as components. A finding filed under a source package points
  at the installed packages it names: the ones built from that source at the affected version.
  A new kernel beside the old one is not named for a finding about the old one.
- Each SBOM says how much of its host a CVE scan checked, because a document with no vulnerability in it reads as a
  host with none: the properties `remotepower:cve_packages_checked` and `remotepower:cve_packages_not_checked` of the
  host component in CycloneDX (and `remotepower:cve_not_checked:<reason>` for each reason), and a sentence in the
  comment of the creation info in SPDX. A host that has not been scanned since 8.0.2 has none.
- A Windows or macOS host's SBOM lists its applications as `pkg:generic/<name>@<version>` components (no `@<version>` when the
  program wrote none), typed `application`. The publisher is the property `remotepower:publisher` of a CycloneDX component and the
  supplier of an SPDX package; the architecture, the install date, the bundle identifier and the manager (`windows`, `macos` or
  `brew`) are properties of the component too. No vulnerability is attached, because none is looked for. When the agent left entries
  out (updates, system components), the document says how many: the property `remotepower:left_out` in CycloneDX, the comment of the
  creation info in SPDX.
- **Baseline** snapshots a host's package list (`POST /api/devices/{id}/sbom/baseline`) and
  **Changes since baseline** (`GET /api/devices/{id}/sbom/diff`) lists the packages added,
  removed or changed since then. On a Windows or macOS host a program that wrote no version is in the
  list too, shown with a dash. Where Homebrew keeps two versions of one package, the higher one is compared.

## Alerts & ignores

- **`cve_found`** is edge-triggered. It fires only when *new* CVEs appear on a
  host, so a static backlog does not page you again and again. **Re-alert backlog**
  (`POST /api/cve/realert`) re-raises it for the current findings. When no finding is left in
  your severity filter, `cve_cleared` resolves the alert.
- Under **Settings → Notifications → Per-event toggles**, the `cve_found` row has the
  severities to alert on (`cve_severity_filter`, critical and high by default) and the
  switch for the event itself. `cve_webhook_enabled` is the older key for the same switch; a
  per-event setting wins over it.
- **Only CVEs an update or a reboot can fix, or that are known to be exploited** (the same row,
  `cve_alert_fixable_only`, off by default) keeps `cve_found` for the findings someone can act
  on. A finding fixed only in a newer release, or with no fix yet, stays on the CVE page and
  raises no alert. A finding that an installed kernel already fixes (**Reboot to apply**)
  alerts, because a reboot is something to do. One on the known-exploited (KEV) list always
  alerts, whatever its fix status. A finding that waited for a fix alerts when the fix arrives. **Re-alert backlog**
  follows the same rule. The severity filter and the ignore list still apply, **Needs
  attention** and the risk score still count every finding unless you also turn on
  [counting only what an update can fix](#counting-only-what-an-update-can-fix), and a
  `cve_cleared` recovery is sent as before.
- On a Debian or Ubuntu host an alert is about the listed findings (see
  [What is listed and what is counted](#what-is-listed-and-what-is-counted)). A new advisory
  that is counted and not listed raises none. A finding that enters the list only because more
  pressing ones were patched was there all along and is not announced as new. `cve_cleared` is
  sent when nothing in your alert severities is left, listed or counted.
- `cve_cleared` is sent for what a scan checked. A scan that could not match the host's packages
  (the agent sent no source package names, the Ubuntu release is not known) finds nothing because
  it asks for nothing, so it does not clear the alert: the host's page says how many packages were
  not checked, and the alert stays open until a scan that checks them finds them fixed. A scan
  that checked as much as the one before, or removed packages, clears as before.
- **Ignore** a CVE on one host or fleet-wide, with a reason (`POST /api/cve/ignore`, scope
  `global` or a host ID). The ID is the ID of a vulnerability as the advisory databases write it,
  such as `CVE-2024-3094`, `DEBIAN-CVE-2024-3094` or `GHSA-xxxx-xxxx-xxxx`.
  Ignored CVEs do not count and are left out of alerts and the re-alert backlog. You can
  see every ignore and take it back under **Settings → Ignored items → Ignored CVEs**
  (`DELETE /api/cve/ignore/{vuln_id}`).
- Each organisation has ignores of its own. With multi-tenancy on, what a tenant ignores never
  changes what another tenant's hosts show, and two tenants can ignore the same CVE. A tenant
  sees its own ignores, and the ones the platform operator wrote for one of its hosts. The same
  holds for the accepted-risk rows of **Monitoring → Tuning**. Every page that counts findings
  (a host's own page, Needs attention, the risk score, the compliance check and the reports)
  leaves out what a tenant ignored for its own hosts. One organisation can hold up to 5,000
  ignores.

## Container image CVEs

The **Container image CVEs (trivy)** card lists vulnerabilities in the images of running
containers, grouped by image across the fleet. It is off by default.

1. Install [`trivy`](https://trivy.dev/) on the Linux hosts that run containers.
2. Tick **Scan container images for CVEs with trivy** under Settings → Security → **Container
   image scanning**.

The agent runs `trivy` about once a day and sends a capped summary (the top findings per
image). **Refresh** on the card queues a scan on every host that reports containers
(`POST /api/image-cves/scan`); it runs at the host's next heartbeat. Hosts without `trivy`
and Windows or macOS agents are skipped. The numbers feed the [risk score](risk.md).

Since 7.5.0 the scan is read in more places:

- **Alert** — *Critical CVEs found in the container images of a host* (high), once for a host when its number of critical
  findings goes up, the first scan included. It clears with *No critical CVEs left in the container images of a host* when the
  number reaches zero. A scan that finds fewer but not none leaves the alert as it is. You can mute it per host, and a
  maintenance window can hold it.
- **Security Advisory** — a finding per host: high when an image has a critical CVE, medium when the worst is high. The image
  names are in the evidence.
- **Compliance** — the vulnerability control (PCI DSS 6.3.1, HIPAA risk analysis, SOC 2 CC6.8) counts critical and high CVEs in
  images as well as the host findings, so a fleet that runs a vulnerable image no longer passes. A fleet that scanned only its
  images is assessed for those, and says no host has a CVE scan. With neither source it reads **Not assessed**.
- **Fleet report** — the CVE section carries the critical and high counts for container images and the number of hosts running
  them.

A host that was never scanned has no row and counts as neither clean nor vulnerable.

## Remediation campaigns

A campaign groups CVEs into one effort with an owner and a target date, and tracks how many
hosts are still affected.

1. Scroll to **Remediation campaigns** on the CVE page.
2. Give it a name, an owner and a target date.
3. Choose the scope: severities (critical, high), **KEV only**, or an explicit list of CVE IDs
   (the list overrides the severity filter). An ID matches a finding by its own ID or by any of
   its aliases, so `CVE-2024-6387` finds the Debian, Ubuntu or AlmaLinux record of that CVE.
4. Click **Create campaign**.

Each campaign shows its affected hosts, its finding count and a burn-down chart that gains one
point per day. When no host is affected any more it is marked completed and the
`campaign_completed` event fires. If findings come back, the campaign reopens. Ignored
findings do not count. One organisation can keep up to 200 campaigns: with multi-tenancy on,
each tenant has 200 of its own, and the operator's count includes the campaigns of the
installation. The operator's list shows the tenant that owns each row.

## Security news watch

The **Security news** tab reads security news feeds and tells you when one reports a critical flaw in software your hosts run. It can start a scan of all
hosts at the same moment. It is off until you switch it on.

To start it, open the tab, tick **Watch security news feeds**, check the feed address and save. It starts with the feed of The Hacker News. You can keep up
to five feeds, one address on each line.

### What counts as critical

An item counts as critical when its headline or summary does one of these:

- calls a flaw critical (the word "critical" in the headline or summary, together with a word for a flaw such as flaw, bug or vulnerability)
- gives a CVSS score of 9 or more
- reports a zero-day
- says attackers exploit a flaw, or that it is exploited in the wild
- describes code execution that needs no sign-in
- names a CVE that CISA lists as known to be exploited
- holds a word or phrase you chose (see below)

Round-ups, webinars and checklists never count, even when they list every flaw of the week, and that includes a headline that holds one of your words. Each item on the tab shows which of
these it met.

**Words that make an item critical.** A flaw often travels under a nickname before it has a CVE or a score, and some products you do not want to miss a word about. Under **Words that
make an item critical**, write one word or phrase on each line (`wp2shell`, `log4shell`, `remote code execution`), up to 50. A headline or summary that holds one of them as a whole word
or phrase, in any case, counts as critical whatever else it says, and its item shows **Matches a word you added**. `wp2shell` does not match inside `wp2shells`. Each is 3 to 40 letters,
digits, blanks, dots, hyphens or underscores; a single everyday word such as `patch` or `file` is refused, since it would make nearly every item critical. The words apply to items
found after you save: an item the watch has already recorded keeps the reasons it was recorded with. Which items then count for you, and what is done with them, is decided by the two choices
below, as for any other critical item.

### Which critical items count for you

**Critical items that count** has three choices:

- **Only items that name software running on my hosts.** The narrowest. An item counts only when it names software that an agent reports as running (see
  [The red !](#the-red-)). Software that is only installed does not count, so a story about Ruby does nothing when no host runs Ruby.
- **Only items that name software on my hosts** (the default). The watch compares the headline and the summary with what your hosts have and run. A story
  about PHP counts when a host has a PHP package. A story about a firewall you do not run does not.
- **Every critical item.**

An item that does not count is listed on the tab and does nothing else.

### The red !

Software can be on a host in two ways, and the tab tells them apart:

- **Running.** An agent reports a process, a program that listens, or a container with that name. The item gets a red **!** before its headline. The line under
  it, **Running on your hosts**, gives the number of hosts that run the software and says **reachable from the Internet** when a program of that name listens
  on a port that is open to it. A line above the list counts the items with a !. A host that has not reported for a week is not counted as running anything.
- **Installed.** A package has its name, and it is well-known server software: a web server, a database, a language, the kernel, a mail or DNS server, the
  container tools and the like. The line under the headline says **Names software on your hosts**, and the item has no !.

Both count for **Only items that name software on my hosts**, and the alert says which it was. The ! is worked out each time you open the tab, from the hosts
as they are then, so it follows what runs today and not what ran when the item was found.

**The mark on the sidebar and the tab.** When a new item names software that runs on a host, the **CVEs** entry in the sidebar and the **Security news** tab get a
red **!** as well, so you see it without opening the tab. Opening the tab clears it in that browser until a newer item comes. Only the platform operator sees it.
An item recorded when a feed was first read, an item too old to act on, and an item that names software that is only installed do not set it, and neither does
a watch that is switched off.

**Clearing the !.** An item with a ! has a **Clear !** button, and the line above the list has **Clear all !**. A cleared item stays in the list and still shows what runs
on your hosts, but it loses its ! and no longer counts for the mark on the sidebar and the tab. It says **! cleared**, and when. The clear is kept on the server, so it holds
in every browser and for every operator account, and it does not come back by itself. **Clear all !** clears the items that show a ! at that moment. An item whose software no host runs
has none, and it gets one when a host starts to run that software. A new item shows its own !. Only the platform operator can clear.

**Bringing the ! back.** A cleared item has a **Bring back !** button, and the line above the list has **Bring back all !** while any item is cleared. They undo a clear, for every
browser and every operator account: the item shows its ! again, in the state it had before. The mark on the sidebar and the tab goes by that state, so a browser that had not shown
the item yet is told again, and a browser that had shown it before it was cleared is not.

Most package names start with an everyday word: `console-setup`, `command-not-found`, `software-properties-common`, `xml-core`. They do not make an article about
a management console or a command line relevant. The first word of a package name counts only when it is software people write about, or when something runs
under that name, so software that is not on the list still counts as soon as it runs.

Software that is installed, does not run and is not on the list is not matched. To count it, add its name under **Other software to count**, one name on each
line: the word its packages start with, such as `unrealircd` (a version is dropped, so `unrealircd6` is read as `unrealircd`). Up to 50 names. A name that is an
everyday word, such as `console`, is refused, because the watch never counts those.

A few words are read with their context: `apache` counts for Apache HTTP
Server, `httpd` or Apache 2 and not for Apache Roller, Tomcat or Kafka; `node` counts for Node.js; the kernel of Windows or macOS is not the Linux kernel.

### What happens when one counts

**When one counts** has three choices:

- **Only list it here.**
- **Raise an alert.** The alert is the event `security_news_critical`. It shows in the Alerts inbox and the activity feed, and it goes to the channels you
  chose for **Security news** in Settings → Notifications. It is high when the item names software on your hosts and medium when it does not. It carries
  the headline, the feed, the link and why the item counts.
- **Raise an alert and scan all hosts** (the default). The watch also starts the scan that **Scan all hosts** starts. It starts at most one scan in six
  hours, and none while a scan is running. The alert always goes out, and the item on the tab says whether a scan started.

A scan reads the advisory database as it is when the scan runs. A flaw that was in the news an hour ago may not be in OSV.dev yet, so the scan can find
nothing new. Scan again when OSV.dev has the record.

**Scan again later.** The setting of that name does the second scan for you. With **Scan again 6, 12 or 24 hours later**, a scan the watch started is followed by one more that long after,
once: the same scan of every host, taken by the same slot, so it never runs beside another scan. A scan that is running when it is due is waited for, at the next read of the feeds, and one
that could not start for a day is dropped. A newer scan the watch starts takes the follow-up's place, since it reads the database as it is then. The choice needs **Raise an alert and scan all
hosts**: with another action the plan is forgotten. It is off by default, and the audit log says `follow_up=1` on the second scan.

### How the feeds are read

The feeds are read every 30 minutes. **Check now** reads them at once, and it is refused when they were read less than a minute ago.

The first read of a feed only records what it holds, so switching the watch on does not alert you about the last fifty headlines. After that an item
counts when it is new and no more than three days old. One read raises at most five alerts, and the tab says which items went over. For each feed the tab
shows when it was read, how many new items it held and, when a read failed, why.

**A feed that keeps failing.** A feed that cannot be read looks like a quiet week, and the stream of critical items the watch exists for has stopped. When one feed fails six reads in a
row (three hours), the watch raises the alert `security_news_feed_failing` once: it is in the Alerts inbox and the activity feed, goes to the channels you chose for **Health**, and says which
feed (by its title, or else its host) and the last answer. The address is not in it. The first read that works raises `security_news_feed_recovered`, which closes the alert. Taking the feed
out of the list, or switching the watch off, closes it too. Two feeds with the same name are two alerts.

### Who can use it, and what it reads

- Only the platform operator can read or change the watch. With multi-tenancy on, a tenant administrator sees nothing of it, because the software an item
  names comes from every host of the installation.
- The server reads the feeds. It refuses an address on the server itself and a link-local address (the cloud metadata address among them), and it checks
  the address each connection reaches, after a redirect too.
- An address with a user name or a password in it, or with a parameter that looks like a token, is refused. The addresses are shown to administrators, so
  use a public feed.
- A feed is untrusted text. A feed over 2 MB is refused, a feed that declares a DTD or an entity is refused, markup is taken out of headlines, and only
  `http` and `https` links are kept.

## Permissions

- Viewing findings, campaigns, ignores and SBOMs needs a signed-in user.
- Running scans, re-alerting, refreshing feeds, ignoring CVEs, saving an SBOM baseline and
  creating or changing campaigns are **admin-only**. Every scan and ignore is written to the
  audit log.
- The **Security news** tab is the platform operator's: reading it, changing the feeds and using **Check now**.
- With multi-tenancy on (Settings → Security → **Multi-tenancy**), a tenant admin sees and changes
  only the hosts and records of their own tenant. A campaign a tenant admin creates counts that
  tenant's hosts, in its numbers and in its burn-down. A campaign of the whole installation
  shows a tenant admin the numbers of their own hosts and no burn-down.

## Troubleshooting

| Problem | What to check |
| --- | --- |
| A host shows **unsupported** | It reported a package list, but its distribution has no OSV ecosystem (Arch, openSUSE, Fedora and others). Its host view says that nothing on it is checked. |
| A host shows **not checked** | It is a Windows or macOS host. Its software is listed, and nothing is matched against a vulnerability database. |
| A host shows **no package list** | The agent has not sent one yet. Click **Send list**, or wait for the next report. A Windows or macOS agent older than the one that sends its software list sends none. |
| The KEV column is 0 everywhere | The feed may not have loaded. Read the status line under the tiles and click **Refresh KEV/EPSS feeds**. |
| **A scan is already running** | One scan runs at a time for the whole installation. Wait for `GET /api/cve/scan-status` to finish; a crashed scan unlocks five minutes after its last checkpoint. |
| **Your last scan started a moment ago** | With multi-tenancy on, an organisation can start a scan every 30 seconds. Try again shortly. |
| Scans fail or skip hosts | The circuit breaker may be open after OSV errors. It closes by itself after ten minutes. |
| You cleared the alerts and want them back | **Re-alert backlog**. |
| The count on a card is lower than the table | Counting only what an update can fix is on, or the finding is ignored. |
| A library has no findings on Debian or Ubuntu | The host's agent is older than 8.0.1. The host view says so. See [How a package is matched](#how-a-package-is-matched). |
| A Devuan, LMDE or Kali host changed after the upgrade | Devuan and LMDE are scanned under the Debian release they are built on and get the findings they never had. Kali has no Debian release and shows **unsupported** where it showed a scan with nothing in it. |
| A host says its agent does not report source packages | Update the agent, then click **Send package list now** and scan the host. |
| A host's view says the kernel could not be matched | See [The kernel a host runs](#the-kernel-a-host-runs): the reason is under it. An agent from 8.0.2 reports the kernel; a kernel you built, or one that no package owns, cannot be matched. |
| A finding says **Reboot to apply** and the host was rebooted | Scan the host again. The agent sends its list when the kernel changes, but the scan runs when you start it. |
| A host has no findings and says **None found in the packages that could be checked** | Some of its packages were not checked. Open its view for the reasons and the first 200 packages. See [Which packages were checked](#which-packages-were-checked). |
| A host's view says nothing of which packages were checked | It was scanned before 8.0.2. Scan it again. |
| The High count rose after the upgrade to 8.0.1 | Debian and Ubuntu hosts are matched by source package now. Many of the new findings have no fix for the host's release. **Count only CVEs an update or a reboot can fix** leaves those out of the numbers, and the alert option of the same name out of the alerts. |
| A host has a number under **Counted** and few findings | See [What is listed and what is counted](#what-is-listed-and-what-is-counted). |
| A campaign over CVE IDs was marked completed at once | Before 8.0.1 a campaign over a list of IDs, or over known-exploited findings, matched nothing. It reopens with the next daily sample if hosts are affected. |

## See also

[Alerts](alerts.md) for what to do with a `security_news_critical` alert, [Patches](patches.md) for installing the fixes, [Risk](risk.md) for the per-host score,
[Exposure](exposure.md), [Software policy](software-policy.md), [Alerts](alerts.md) and
[Security scans](security-scans.md).
