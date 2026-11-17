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
five tiles that count the findings by [fix status](#fix-status), and a KEV feed status line.
When Debian or Ubuntu hosts have findings that are [counted and not listed](#what-is-listed-and-what-is-counted),
a line under the tiles says how many. Below them is one row per host.

| Column | Meaning |
| --- | --- |
| **Host** and **Group** | The host and its group. Click a row to open its findings. |
| **Ecosystem** | The OSV ecosystem found from `/etc/os-release` and the package manager (Ubuntu, Debian, Rocky Linux, AlmaLinux, Red Hat or Alpine). |
| **KEV** | How many findings are in CISA's **Known Exploited Vulnerabilities** catalog, meaning attackers use them in the wild. |
| **Critical / High / Medium / Low** | Finding counts by severity. |
| **Counted** | How many more known vulnerabilities the host's scan counted per package and did not list. Debian and Ubuntu only. |
| **Last scan** | When the host was last scanned, or why it was not: **not scanned**, **no package list**, **unsupported** or **not checked**. |

Rows sort by KEV count first, then by critical and high counts, then by the highest EPSS
score, so the dangerous hosts rise to the top.

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
now**, **SBOM (CycloneDX)**, **SBOM (SPDX)**, **Baseline** and **Changes since baseline**.

On a Debian or Ubuntu host the view also shows the count: how many known vulnerabilities are
counted and not listed, how many of those are critical or high, how many an update would
clear, how many are fixed with Ubuntu Pro, and the packages that hold the most with the version
installed. Open it with a click.

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

## Fix status

A finding records a fixed version, but a fix only helps a host if it reached the release
that host runs. Debian, Ubuntu and Alpine publish a fix per release (Debian 12, Ubuntu 22.04,
Alpine 3.19), and RemotePower reads the entry for the host's own release. Each finding
is one of:

| Status | Meaning |
| --- | --- |
| **Fixed** | An update for this host's release clears it. The finding names the version to install. |
| **Fixed in a newer release** | The host's release has no fix, a newer release does. The finding names that release and version (for example `Debian:13 8.7.1-1`) and offers nothing to install. |
| **No fix yet** | No release has a fix. |
| **Fixed with Ubuntu Pro** | The fix for the host's release ships in Ubuntu Pro only, which is where every fix of a release past its standard support goes. The finding names the Pro version and offers nothing to install. On a host that has a package from Ubuntu Pro installed (its version ends in `+esm1` or `~esm1`), such a finding is **Fixed**. A kernel from Ubuntu Pro carries no such mark, so a host whose only Pro packages are kernels is not recognised. |
| **Not checked** | Red Hat, and an Ubuntu derivative whose release is not known (its agent is older than 8.0.1), are scanned without a release, so their entries cannot be told apart. Rocky Linux and AlmaLinux publish an advisory per release together with its fix. In all of these a finding keeps the fixed version OSV lists and counts as fixable when it has one. |

The five tiles under the severity counts count the listed findings that are not ignored
(**Fixable now**, **Newer release only**, **No fix yet**, **Needs Ubuntu Pro**, **Not checked**). On a
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
  update clears, turn on **Only CVEs an update can fix, or that are known to be exploited**
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

Settings → Security → **CVE counts** has **Count only CVEs an update can fix, or that are known
to be exploited** (`cve_count_fixable_only`, off by default). With it on, those places
leave out a finding that is fixed only in a newer release, needs Ubuntu Pro or has no fix yet.
A finding on the known-exploited (KEV) list always counts, and so does a **Not checked**
finding that lists a fixed version.

- Every listed finding stays on the CVE page and in the host view, and the five fix tiles keep
  counting all of them, so you can see what the option leaves out. The CVE page says when the
  option is on.
- What a Debian or Ubuntu host has [counted per package](#what-is-listed-and-what-is-counted)
  is in none of these numbers, with the option on or off.
- Alerts have their own switch (see [Alerts & ignores](#alerts--ignores)). Reports, the
  printable fleet report, compliance checks and the assistant's context keep counting every
  listed finding.
- A finding you accepted as a risk never counts in those numbers, with the option on or off.
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
- **Only CVEs an update can fix, or that are known to be exploited** (the same row,
  `cve_alert_fixable_only`, off by default) keeps `cve_found` for the findings someone can act
  on. A finding fixed only in a newer release, or with no fix yet, stays on the CVE page and
  raises no alert. One on the known-exploited (KEV) list always alerts, whatever its fix
  status. A finding that waited for a fix alerts when the fix arrives. **Re-alert backlog**
  follows the same rule. The severity filter and the ignore list still apply, **Needs
  attention** and the risk score still count every finding unless you also turn on
  [counting only what an update can fix](#counting-only-what-an-update-can-fix), and a
  `cve_cleared` recovery is sent as before.
- On a Debian or Ubuntu host an alert is about the listed findings (see
  [What is listed and what is counted](#what-is-listed-and-what-is-counted)). A new advisory
  that is counted and not listed raises none. A finding that enters the list only because more
  pressing ones were patched was there all along and is not announced as new. `cve_cleared` is
  sent when nothing in your alert severities is left, listed or counted.
- **Ignore** a CVE on one host or fleet-wide, with a reason (`POST /api/cve/ignore`, scope
  `global` or a host ID).
  Ignored CVEs do not count and are left out of alerts and the re-alert backlog. You can
  see every ignore and take it back under **Settings → Ignored items → Ignored CVEs**
  (`DELETE /api/cve/ignore/{vuln_id}`).

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
findings do not count. You can keep up to 200 campaigns.

## Permissions

- Viewing findings, campaigns, ignores and SBOMs needs a signed-in user.
- Running scans, re-alerting, refreshing feeds, ignoring CVEs, saving an SBOM baseline and
  creating or changing campaigns are **admin-only**. Every scan and ignore is written to the
  audit log.
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
| **A scan is already running** | One scan runs at a time. Wait for `GET /api/cve/scan-status` to finish; a crashed scan unlocks five minutes after its last checkpoint. |
| Scans fail or skip hosts | The circuit breaker may be open after OSV errors. It closes by itself after ten minutes. |
| You cleared the alerts and want them back | **Re-alert backlog**. |
| The count on a card is lower than the table | Counting only what an update can fix is on, or the finding is ignored. |
| A library has no findings on Debian or Ubuntu | The host's agent is older than 8.0.1. The host view says so. See [How a package is matched](#how-a-package-is-matched). |
| A Devuan, LMDE or Kali host changed after the upgrade | Devuan and LMDE are scanned under the Debian release they are built on and get the findings they never had. Kali has no Debian release and shows **unsupported** where it showed a scan with nothing in it. |
| A host says its agent does not report source packages | Update the agent, then click **Send package list now** and scan the host. |
| The High count rose after the upgrade to 8.0.1 | Debian and Ubuntu hosts are matched by source package now. Many of the new findings have no fix for the host's release. **Count only CVEs an update can fix** leaves those out of the numbers, and the alert option of the same name out of the alerts. |
| A host has a number under **Counted** and few findings | See [What is listed and what is counted](#what-is-listed-and-what-is-counted). |
| A campaign over CVE IDs was marked completed at once | Before 8.0.1 a campaign over a list of IDs, or over known-exploited findings, matched nothing. It reopens with the next daily sample if hosts are affected. |

## See also

[Patches](patches.md) for installing the fixes, [Risk](risk.md) for the per-host score,
[Exposure](exposure.md), [Software policy](software-policy.md), [Alerts](alerts.md) and
[Security scans](security-scans.md).
