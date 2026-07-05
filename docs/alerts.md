# Alerts inbox

**Alerts** is the operational inbox: every fired event that carries a
severity lands here, grouped by host, until it is acknowledged, resolved, or
auto-resolved by its matching recover event (`device_online`,
`service_recover`, `custom_script_recover`, …).

## Working the inbox

- **Acknowledge** — takes ownership; optionally prompts for a comment
  (Settings → Alerts inbox) that is stored on the alert and included in the
  acknowledgement webhook.
- **Resolve / Clear resolved / Clear all** — housekeeping; history is kept.
- **Group by host** — folds symptom alerts under their probable root cause
  (a `device_offline` folds the service/port alerts it likely caused).
- **Filters** — state dropdown + free-text filter by device, event or title.
- **Open a ticket** — with the [ticket system](ticket-system.md), an alert
  row can spawn a linked ticket; opening one auto-acknowledges the alert.

## Getting fewer of them

Recurring noise is silenced at the source on the [Tuning](alert-tuning.md)
page (per host + alert type), suppressed during
[maintenance windows](maintenance.md), or routed per event kind under
Settings → Notifications. The **Resolution timeline (MTTR)** card at the
bottom tracks how quickly alerts get resolved.
