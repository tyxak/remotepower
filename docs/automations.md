# Automation rules

*(engine v3.4.2; actions extended in v5.6.0 "ProvisionMatters")*

The **Automation** page (Settings → Automation) runs **event-driven rules**:
*when an event fires on a matching device, run one or more actions.* Rules are
evaluated as part of the event-firing path, so they react as soon as an event
happens — with a per-rule **cooldown** to dampen flapping. Rules are admin-only
and every action is audited.

## Anatomy of a rule

- **Match** — one or more **events** (e.g. `service_down`, `disk_full`,
  `fail2ban_ban`; blank = any) and/or **severities** (critical/high/medium/low),
  optionally narrowed to a **device group** and/or **tags**.
- **Actions** — one or more of the below.
- **Cooldown** — minimum seconds between firings of the same rule (default 60).

## Actions

| Action | What it does |
| --- | --- |
| **Run script** | Queues a saved custom script on the event's device (honours quarantine / audit-mode at dispatch). |
| **Notify** | Re-dispatches the event to a named webhook destination. |
| **Open a ticket** *(v5.6.0)* | Opens a helpdesk ticket for the event's device (requires the ticket system enabled). Priority follows the event severity unless you pick one. Deduped per rule so a flapping event doesn't pile up tickets. |
| **Add a tag** *(v5.6.0)* | Adds a tag to the event's device — handy for auto-classifying ("seen-flapping", "needs-review"). |
| **Mute the alert** *(v5.6.0)* | Mutes *this event from this host* — the same `(device, event)` silence the Alerts **X** button creates. Useful to self-suppress a known-noisy source. |

The three v5.6.0 actions compose subsystems you already have (tickets, device
tags, alert mutes), so they add **no new webhook event** and run on the same
lock-safe path as the existing script/notify actions.

## Example

*When `disk_full` at **high** severity on tag `prod` → run the `cleanup-logs`
script, and if it keeps firing, open a **P2** ticket.* Two rules (or one rule
with two actions plus a cooldown) cover it.

## API

| Method & path | Purpose |
| --- | --- |
| `GET /api/automation/rules` | List rules |
| `POST /api/automation/rules` | Create a rule (admin) |
| `PUT /api/automation/rules/{id}` | Replace a rule (admin) |
| `DELETE /api/automation/rules/{id}` | Delete a rule (admin) |

Rules are stored in `rules.json`.
