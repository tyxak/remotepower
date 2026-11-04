# Reports

**Business → Reports** produces a single **fleet posture report** — health
score, pending patches, open CVEs, host security posture, hardware health,
network exposure, threats and remote access, compliance, and what changed over
the last 30 days — as one export you can download on demand or have emailed on a
schedule. The page has two tabs: **Reports** and [**Capacity**](#the-capacity-tab).

## Posture report

- A live preview summarises the current fleet posture. Export it as **JSON** or
  **CSV**, or **Print / save as PDF** from the browser.
- The CVE figures also count the critical and high CVEs in the images of running
  containers, when the container-image scan is on *(7.5.0)*.
- The **evidence pack** bundles the posture report with the
  [compliance](compliance.md) baseline trend and an [audit-log](security.md)
  excerpt for the period into one JSON document — the artifact auditors ask for.
  The period is 90 days unless you ask for another one (1 to 366 days). The
  excerpt holds the newest 2,000 entries of the period, and the pack carries an
  HMAC-SHA256 signature so a change to it can be detected. An admin or the
  **auditor** role can generate it, and generating it is audit-logged.
- A report for one customer site is a separate download; see [sites.md](sites.md).

## Hardware health and network exposure *(7.5.0)*

Two sections answer the questions a customer asks about the machines themselves.

**Hardware health** counts, for the hosts you monitor, the ones with a
SMART-failed disk, a temperature over the limit, a UPS running on battery, or a
storage pool or array that is not healthy (ZFS, mdadm, Btrfs and the like).

**Network exposure** counts the hosts with a listening port reachable from the
world, and how many sockets that is. A socket you muted on the Exposure page is
accepted risk and is left out, the same as on the Checks page and in the risk
score. The ten most exposed hosts are listed with their ports.

Each line shows *affected / reporting*. A host that never sent the signal is not
in the second number, so silence is never counted as healthy, and a line no host
reports is left out. Names are listed up to ten per line. Hosts you do not
monitor are not counted. You see only the hosts your role and tenant allow.

The CSV and the emailed text carry these figures, and the **host security
posture** figures, as plain counts. The AI summary sees the counts and never the
host names.

## Threats and remote access

The **Threats & remote access** section answers two questions a security
reviewer asks of every report: *is anything attacking us*, and *who reached our
hosts remotely*.

- Hosts with a brute-force source over the alert threshold right now, and how
  many sources.
- Sources [IP intel](ip-intel.md) recorded in the last week, how many a
  reputation service lists as abusive, and how many of those are not blocked.
- Blocks currently in place and addresses reported in the period.
- [SSH gateway](sshgw.md) sessions in the period, by how many people, to how
  many hosts.
- The five most attacked hosts.
- What the edge sources saw, when you can see the whole fleet: addresses seen at
  the edge, how many were reported, how many are in the Cloudflare IP list now,
  and the edge bans in force. The edge belongs to the installation, so a report
  for one site, or for a reader limited to some hosts or one tenant, leaves these
  rows out.

A count of zero still prints: "nothing attacked us" is a finding worth reading.
Every other figure is limited to the hosts the person generating the report can see.

## What changed in the last 30 days

Every other section is a live counter, so two reports a week apart can look the
same. The **period** block shows movement:

- Alerts opened and alerts resolved, the median time to resolve and the mean time
  to acknowledge.
- The health score and the compliance percentage against their values 30 days ago.
  A change shows only once the daily samplers hold a sample that old.
- How many patch runs were recorded on your hosts in the period.

The report also carries the fleet's uptime over the same 30 days.

## Scheduled reports

- **Scheduled email delivery** emails the posture report on a cron schedule (five
  fields, for example `0 8 * * 1` for Mondays at 08:00). It needs outbound email
  set up under **Settings → Notifications**. Leave the recipients empty to use the
  configured notification recipients, or list up to 50. Only an administrator of
  the installation can change it.
- **Custom reports** save a named configuration: the sections you want, a format
  (JSON or CSV, attached to the email), a cron schedule, recipients, an optional
  **Site** and webhook destinations. A report for one site covers only that site's
  hosts, which is how you send a customer a report of their own hosts. With no
  sections ticked, a report holds every section except the AI summary. A report can
  go to the destinations you set up under **Settings → Notifications** instead of,
  or as well as, email. You can save up to 30.

## Delivered report archive

Every scheduled report RemotePower **sends**, by email or to a webhook
destination, is kept under Reports → *Delivered report archive*. Reports you
download or print on demand are not archived; only deliveries are.

This exists because a past-dated posture report cannot be reconstructed. Fleet
health and fleet compliance % are sampled daily, but **CVE counts, patch backlog
and per-framework control pass/fail keep no history at all** — so "the posture
report as it stood at the end of Q1" has exactly one possible source: the copy
of the report that was sent at the time.

- **As of** a date returns the nearest delivery **at or before** it — never
  after. A report generated a week later would look like an answer and is not
  one.
- Each archived report downloads as JSON or CSV from the stored copy, so the
  figures are the ones that were sent.
- The archive keeps the newest 60 reports, and no more than 4 MiB in all. The
  list says how many older reports have aged out, so you can see coverage rather
  than assume it.
- Deleting one is a hard confirm, not an undoable action: it is the only copy.
- Reading is available to admins and the **auditor** role, and only to full-access
  ones: a stored report is a whole-fleet snapshot with no scope to filter on, so a
  role limited to some hosts and a tenant's administrator get a 403. Deleting is
  admin-only.
- The **evidence pack** includes the archive index for its period. Note that
  the pack's `posture` block is the *current* fleet posture at generation time,
  not an end-of-period snapshot — the pack states this in a `posture_note`
  field, and its period coverage comes from `compliance_history`,
  `audit_excerpt` and `archived_reports`.

## AI summary

A report definition can include an optional **AI summary** section. It opens the
report with a short plain-prose paragraph — whether the fleet is in good shape
and how that compares to the previous period, the one or two things driving the
numbers, and what (if anything) needs a decision from the reader.

It exists for the person a report is usually *for*: the manager or the customer,
who never logs in and reads the top of the document rather than the figures.

Practical notes:

- **Off by default and opt-in per report.** It costs provider tokens on every
  delivery, so it is not part of the "no sections chosen = everything" default.
- **Needs AI enabled** under Settings → AI assistant. With AI off the section is
  simply skipped.
- **Only the report's own figures are sent** to the provider — health, host
  counts, attention counts, patch and CVE totals, SLA, compliance, the period
  deltas. Never the per-host rows, so a hostname or IP cannot leak through it.
  Your AI privacy redaction settings apply on top of that.
- **A provider outage costs the paragraph, not the report.** The email says
  *AI summary unavailable* with the reason, rather than silently arriving
  without one.
- It is rendered first in the emailed body and in the printable / Save-as-PDF
  view.

## The Capacity tab

The second tab of the Reports page holds five cards. They read the same data as the
rest of the product and do not change anything.

- **Capacity** — the average and the highest CPU, memory and swap use across the
  online hosts you monitor, the fleet's disk use in total, and the top five hosts for
  CPU, memory and disk (the fullest mount counts for disk).
- **Agent integrity** — each agent reports the hash of its own program, and the
  server compares it with the published build. The pills count *verified*,
  *mismatch* and *unknown*; the table lists only the hosts that are not verified. A
  mismatch on the current version means a changed, damaged or half-updated agent.
- **Resource anomalies** — hosts whose latest memory, swap or disk reading is far
  from their own recent baseline: a mean and spread per host, flagged at 2.5
  standard deviations. Tick **Seasonal baselines** to score each host against its
  matching day of the week and four-hour block; it falls back to the flat baseline
  until about two weeks of data exist. `GET /api/fleet/anomalies?z=` takes a
  threshold from 1.5 to 6.
- **Software metering** — install counts of named software against an allowance,
  from the package inventory. Enter one line per item as `name = limit`, optionally
  `| alias1, alias2` to fold name variants into one entry; a limit of 0 only counts.
  An entry over its limit is flagged, and *reclaimable* counts hosts where the
  software is installed but not seen in running processes or listening ports. You
  can track up to 100 items. Saving needs an administrator.
- **Uptime (SLA)** — per-host and fleet uptime over 7, 30 or 90 days; see
  [sla.md](sla.md).

## API

| Endpoint | Purpose |
| --- | --- |
| `GET /api/report/fleet` | The posture report. `format=csv` for CSV, `sections=a,b` to pick sections (add `summary` for the AI paragraph) |
| `GET /api/report/site/{id}` | The same report for one site |
| `GET /api/report/evidence` | The evidence pack. `days=` sets the period, `format=download` saves it as a file |
| `GET /api/report/archive` | The delivered report archive. `since=`, `until=` or `as_of=` (epoch seconds) narrow it |
| `GET`, `DELETE /api/report/archive/{id}` | One archived report (`format=csv` or `format=download`), or delete it |
| `GET`, `PUT /api/report/schedule` | The scheduled email delivery |
| `GET`, `POST /api/report/definitions` and `DELETE /api/report/definitions/{id}` | The custom reports |
| `GET /api/fleet/capacity`, `/api/fleet/agent-integrity`, `/api/fleet/anomalies`, `/api/inventory/metering` | The Capacity tab |

## Related

- The underlying scores come from [health](health-score.md),
  [patches](patches.md), [CVE findings](cve.md) and [compliance](compliance.md).
- Per-customer **billing** invoices are separate — see [time & billing](time-billing.md).

## Permissions

Any signed-in user can view and export the posture report, limited to the hosts
their role and tenant allow. The evidence pack and the delivered report archive
are for admins and the **auditor** role, and deleting an archived report is
admin-only. Changing the schedule or the custom reports is admin-only.

## With multi-tenancy

Report definitions and the schedule are the operator's: they mail fleet-wide reports. With tenant isolation on, only users of the default tenant can read them, and only the platform operator can change them. A tenant's administrator still gets the fleet report and the evidence pack for its own hosts.
