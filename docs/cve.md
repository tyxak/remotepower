# Vulnerabilities (CVE scanning)

**Security → CVEs** scans your fleet's installed packages against the
[OSV.dev](https://osv.dev/) vulnerability database and prioritises what to patch
first using real exploit signals — not just CVSS.

## The CVE page

The page opens with a severity summary (Critical / High / Medium / Low +
devices-scanned) and a KEV-feed status bar, then a per-device findings table:

| Column | Meaning |
| --- | --- |
| **Device / Group** | The host and its group |
| **Ecosystem** | The OSV ecosystem detected from `/etc/os-release` + package manager (Ubuntu, Debian, Rocky, AlmaLinux, Red Hat, Alpine) |
| **KEV** | Count in CISA's **Known Exploited Vulnerabilities** catalog — actively exploited in the wild |
| **Critical / High / Medium / Low** | Finding counts by severity |
| **Last scan** | When this host was last scanned |

Rows sort **KEV first, then severity, then EPSS** so the genuinely dangerous
items rise to the top. Toolbar: **Refresh**, **AI prioritise**, **Scan all
devices**, **Re-alert backlog**, and **Fleet SBOM** (CycloneDX / SPDX).

## Scanning

- **Scan all devices** (or a single host from its drawer) runs in a **detached
  subprocess** (`cve_scan_runner.py`) so a long scan never blocks the request or
  hangs the browser; poll progress with `GET /api/cve/scan-status`.
- The scanner (`cve_scanner.py`) **deduplicates packages across the whole fleet**
  and batch-queries OSV once per ecosystem (`/v1/querybatch`), so a 100-host fleet
  isn't 100× the API traffic.
- An **OSV circuit breaker** opens after repeated OSV failures and skips OSV work
  for a cooldown, so an OSV outage degrades gracefully instead of stalling scans.
- Note: OSV has no Arch Linux feed, so `pacman` hosts report no ecosystem.

## Prioritisation signals

RemotePower enriches every finding with:

- **CISA KEV** — is this CVE actively exploited? (refreshed daily)
- **EPSS** — the Exploit Prediction Scoring System probability (0–1).
- **Severity** — Critical → Low from the OSV record.
- **Distro security flags** — packages the distro itself marks security-relevant.

Feeds are cached in `kev_epss.json` and refreshed daily, or on demand with
**`POST /api/cve/refresh-feeds`**.

## SBOM

Generate a Software Bill of Materials per host or for the whole fleet:

- `GET /api/devices/{id}/sbom?format=cyclonedx|spdx` — one host; the fleet button
  downloads a ZIP of all hosts.
- **CycloneDX 1.5** carries the CVE findings as a VEX-style vulnerabilities
  section; **SPDX 2.3** is the packages + relationships interchange format.
- Snapshot a package baseline (`…/sbom/baseline`) and diff against it
  (`…/sbom/diff`) to see exactly what changed.

## Alerts & ignores

- **`cve_found`** is edge-triggered — it fires only when *new* CVEs appear on a
  host, so a static backlog doesn't re-page you. **Re-alert backlog**
  (`POST /api/cve/realert`) deliberately re-raises it for the current findings.
- The `cve_severity_filter` config controls which severities page you; `cve_found`
  webhooks can be turned off with `cve_webhook_enabled`.
- **Ignore** a CVE globally or per host with a reason (`POST /api/cve/ignore`);
  ignored CVEs are excluded from alerts and the re-alert backlog.

## Permissions

- Viewing findings and SBOMs needs normal authentication.
- Running scans, re-alerting, refreshing feeds and ignoring CVEs are
  **admin-only**. Every scan/ignore is audit-logged.

## Exposure priority

**Exposure priority** (CVE-page button) ranks hosts by *real exploitability*: each
host's critical/high CVE counts are weighted by whether it has **world-reachable
listening ports** (`scope: world` on the Exposure page). A critical CVE on an
internet-exposed host outranks more criticals sitting behind a firewall, so the
list is a "patch this first" order rather than a raw count. Served by
`GET /api/cve/exposure-ranked` (tenant/scope-filtered).
