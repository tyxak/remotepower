# Alerts inbox

**Alerts** is the operational inbox: every fired event that carries a
severity lands here, grouped by host, until it is acknowledged, resolved, or
auto-resolved by its matching recover event (`device_online`,
`service_recover`, `custom_script_recover`, …). An alert also resolves when the
condition behind it is removed rather than recovered: **deleting a device**
resolves all of its open alerts, **deleting a custom check or script** resolves
its alerts fleet-wide, and **accepting or disabling** a protect/baseline check
fires `custom_check_recovered` so its alert closes — so nothing lingers pointing
at something that no longer exists.

**The contract (v6.4.0): every alert that records an ongoing condition
auto-resolves when the condition clears** — including CVEs (patched →
`cve_cleared`), pending updates (`patch_ok`), expiring watched certificates
(`tls_renewed`), ECC error bursts (`ecc_stable` after 24 quiet hours) and
exposed secrets (`secret_cleared`). Point-in-time alerts (something
*happened* — a login, a config change) can't self-heal by definition; those
rows carry a **confirm** badge so you know to resolve them yourself after
looking.

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

## Ignored items — and keeping them from piling up *(v6.4.0)*

Hiding a Needs-Attention card (the × on the card) sends it to **Settings →
Ignored items**, alongside hidden stale containers, devices, ignored CVEs and
cleared log lines. On a large fleet that list used to grow without bound —
so it now maintains itself:

- **Self-pruning.** An ignore is garbage-collected once its underlying condition
  has been gone past a short grace window (the drift resolved, the disk
  recovered, the point-in-time event aged out). You only keep the ignores you
  still need.
- **Device cleanup.** Deleting or decommissioning a host drops every ignore
  scoped to it — no tombstones from fleet churn.
- **Last active.** Each ignore shows when its condition was last actually seen,
  so a stale one is obvious, and every category has a bulk **Restore all**.
- **Class-level suppression.** When the same benign signal fires on many hosts,
  add one **suppression rule** (Settings → Ignored items) that silences a whole
  *kind* across the fleet, a group, a tag or a device — one entry instead of
  one ignore per host.

You should also need to ignore *less*, because more alerts now clear themselves:
open `patch_alert` and `cve_found` alerts are periodically re-checked against
current state and **auto-resolve** when the condition clears (pending drops under
threshold; no CVE findings left), so they leave the inbox on their own.
