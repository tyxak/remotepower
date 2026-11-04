# Vulnerabilities (CVE scanning)

**Security → CVEs** compares the packages installed on your hosts with the
[OSV.dev](https://osv.dev/) vulnerability database. It ranks what to patch first
with real exploit signals, not just the CVSS score.

## What you need

- A Linux host whose agent reports a package list. The agent sends one when it starts and
  about every six hours after that. **Send list** on the page, or **Send package list now** in
  the host view, asks for it at once.
- A distribution OSV covers (see [Which hosts are scanned](#which-hosts-are-scanned)).
- A server that can reach `api.osv.dev` and the two feeds behind the priority signals
  (CISA KEV and FIRST EPSS).

## The CVE page

The page opens with a severity summary (Critical / High / Medium / Low and hosts scanned),
four tiles that count the findings by [fix status](#fix-status), and a KEV feed status line.
Below them is one row per host.

| Column | Meaning |
| --- | --- |
| **Host** and **Group** | The host and its group. Click a row to open its findings. |
| **Ecosystem** | The OSV ecosystem found from `/etc/os-release` and the package manager (Ubuntu, Debian, Rocky Linux, AlmaLinux, Red Hat or Alpine). |
| **KEV** | How many findings are in CISA's **Known Exploited Vulnerabilities** catalog, meaning attackers use them in the wild. |
| **Critical / High / Medium / Low** | Finding counts by severity. |
| **Last scan** | When the host was last scanned, or why it was not: **not scanned**, **no package list** or **unsupported**. |

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

## Which hosts are scanned

| Host | Ecosystem |
| --- | --- |
| Debian (`apt`) | `Debian:<major version>` |
| Ubuntu, and derivatives such as Linux Mint, Zorin OS and Pop!_OS | `Ubuntu` |
| Rocky Linux (`dnf` or `yum`) | `Rocky Linux` |
| AlmaLinux | `AlmaLinux` |
| Red Hat Enterprise Linux | `Red Hat` |
| Alpine (`apk`) | `Alpine:v<major.minor>` |

OSV has no Arch Linux feed, so `pacman` hosts report no ecosystem. A Linux host on any other
distribution shows **unsupported** in the Last scan column and is skipped. The Windows and
macOS agents send no package list for CVE scanning, so those hosts show **no package list**.

## Fix status

A finding records a fixed version, but a fix only helps a host if it reached the release
that host runs. Debian and Alpine publish a fix per release (Debian 12, Debian 13,
Alpine 3.19), and RemotePower reads the entry for the host's own release. Each finding
is one of:

| Status | Meaning |
| --- | --- |
| **Fixed** | An update for this host's release clears it. The finding names the version to install. |
| **Fixed in a newer release** | The host's release has no fix, a newer release does. The finding names that release and version (for example `Debian:13 8.7.1-1`) and offers nothing to install. |
| **No fix yet** | No release has a fix. |
| **Not checked** | The scan name of the distribution does not say which release the host runs: Ubuntu, Rocky Linux, AlmaLinux and Red Hat. Such a finding keeps the fixed version OSV lists and counts as fixable when it has one. |

The four tiles under the severity counts count the findings that are not ignored
(**Fixable now**, **Newer release only**, **No fix yet**, **Not checked**). Click a tile to
keep only the hosts that have such a finding, and the host view then lists only those
findings. Click the tile again, or **Show all** in the host view, to undo it.

A package that is already at or past the fix of a newer release (a backport, say) counts as
patched. A fix in an older release never does.

If you upgrade from a version before 7.4.6, run **Scan all hosts** once. Findings keep their
old fixed version until their host is scanned again.

## Counting only what an update can fix

By default the numbers you read count every finding that is not accepted as a risk: the badge
on the Security menu, the severity tiles on the dashboard and the CVE page, **Needs
attention**, the risk score, **Checks**, the scheduled posture digest and the CVE count of the
Fleet query. On a host with hundreds of findings that no update for its release can clear,
that is a number nobody can act on.

Settings → Security → **CVE counts** has **Count only CVEs an update can fix, or that are known
to be exploited** (`cve_count_fixable_only`, off by default). With it on, those places
leave out a finding that is fixed only in a newer release or has no fix yet. A finding on the
known-exploited (KEV) list always counts, and so does a **Not checked** finding that lists a
fixed version.

- Every finding stays on the CVE page and in the host view, and the four fix tiles keep
  counting all of them, so you can see what the option leaves out. The CVE page says when the
  option is on.
- Alerts have their own switch (see [Alerts & ignores](#alerts--ignores)). Reports, the
  printable fleet report, compliance checks and the assistant's context keep counting every
  finding.
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
- OSV answers are cached. **Settings → Security → CVE details cache** sets how long, from 1
  to 90 days (default 7). A lower value picks up changed descriptions sooner and costs more
  requests.
- An **OSV circuit breaker** opens after three failed requests in a row and skips OSV work
  for ten minutes, so an OSV outage degrades gracefully instead of stalling scans.

### How severity is chosen

1. The distribution's own rating wins when the OSV record has one (the Debian, Ubuntu and
   similar priority fields), because distributions rate a CVE by how it affects their own
   packages.
2. Otherwise the CVSS score decides. The cut-offs are 9.0 for critical, 7.0 for high and 4.0
   for medium. You can change them under Settings → Alert parameters → **Forecast & CVE
   tuning**.
3. For Debian hosts with neither, the Debian Security Tracker's urgency is used, capped at
   medium.
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
  container images are included as components.
- **Baseline** snapshots a host's package list (`POST /api/devices/{id}/sbom/baseline`) and
  **Changes since baseline** (`GET /api/devices/{id}/sbom/diff`) lists the packages added,
  removed or changed since then.

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
   (the list overrides the severity filter).
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
  only the hosts and records of their own tenant.

## Troubleshooting

| Problem | What to check |
| --- | --- |
| A host shows **unsupported** | It reported a package list, but its distribution has no OSV ecosystem (Arch, openSUSE, Fedora and others). |
| A host shows **no package list** | The agent has not sent one yet, or it is a Windows or macOS agent. Click **Send list**, or wait for the next report. |
| The KEV column is 0 everywhere | The feed may not have loaded. Read the status line under the tiles and click **Refresh KEV/EPSS feeds**. |
| **A scan is already running** | One scan runs at a time. Wait for `GET /api/cve/scan-status` to finish; a crashed scan unlocks five minutes after its last checkpoint. |
| Scans fail or skip hosts | The circuit breaker may be open after OSV errors. It closes by itself after ten minutes. |
| You cleared the alerts and want them back | **Re-alert backlog**. |
| The count on a card is lower than the table | Counting only what an update can fix is on, or the finding is ignored. |

## See also

[Patches](patches.md) for installing the fixes, [Risk](risk.md) for the per-host score,
[Exposure](exposure.md), [Software policy](software-policy.md), [Alerts](alerts.md) and
[Security scans](security-scans.md).
