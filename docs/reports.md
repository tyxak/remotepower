# Reports

**Business → Reports** produces a single **fleet posture report** — health
score, pending patches, open CVEs and compliance — as one export you can
download on demand or have emailed on a schedule.

## Posture report

- A live preview summarises the current fleet posture. Export it as **JSON** or
  **CSV**, or **Print / Save as PDF** from the browser.
- The **evidence pack** bundles the posture report with the 90-day
  [compliance](compliance.md) baseline trend and an [audit-log](security.md)
  excerpt for the period into one JSON document — the artifact auditors ask for.
  Generating it is admin-only and itself audit-logged.

## Scheduled reports

- Set a cron schedule and recipient list to have the posture report emailed
  automatically (requires outbound email configured under Settings).
- **Custom report definitions** let you save named report configurations with
  their own recipients and cadence.

## Delivered report archive

Every report RemotePower **emails** is kept, exactly as it was sent, under
Reports → *Delivered report archive*. Reports you download or print on demand
are not archived; only deliveries are.

This exists because a past-dated posture report cannot be reconstructed. Fleet
health and fleet compliance % are sampled daily, but **CVE counts, patch backlog
and per-framework control pass/fail keep no history at all** — so "the posture
report as it stood at the end of Q1" has exactly one possible source: the copy
of the report that was sent at the time.

- **As of** a date returns the nearest delivery **at or before** it — never
  after. A report generated a week later would look like an answer and is not
  one.
- Each archived report downloads as JSON or CSV, byte-for-byte as delivered.
- The archive is capped (60 by default) and the list says how many older
  reports have aged out, so you can see coverage rather than assume it.
- Deleting one is a hard confirm, not an undoable action: it is the only copy.
- Reading is available to admins and the **auditor** role; deleting is
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
- **Only the report's own figures are sent** to the provider — health, device
  counts, attention counts, patch and CVE totals, SLA, compliance, the period
  deltas. Never the per-device rows, so a hostname or IP cannot leak through it.
  Your AI privacy redaction settings apply on top of that.
- **A provider outage costs the paragraph, not the report.** The email says
  *AI summary unavailable* with the reason, rather than silently arriving
  without one.
- It is rendered first in the emailed body and in the printable / Save-as-PDF
  view.

## Related

- The underlying scores come from [health](health-score.md),
  [patches](patches.md), [CVE findings](cve.md) and [compliance](compliance.md).
- Per-customer **billing** invoices are separate — see [time & billing](time-billing.md).

## Permissions

Viewing and exporting reports is available to admins and the **finance** /
**auditor** read-only roles; the evidence pack is admin-only.
