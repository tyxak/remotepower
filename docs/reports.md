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

## Related

- The underlying scores come from [health](health-score.md),
  [patches](patches.md), [CVE findings](cve.md) and [compliance](compliance.md).
- Per-customer **billing** invoices are separate — see [time & billing](time-billing.md).

## Permissions

Viewing and exporting reports is available to admins and the **finance** /
**auditor** read-only roles; the evidence pack is admin-only.
