# Automation rules

*(engine v3.4.2; actions extended in v5.6.0 "HeapMatters")*

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

## Guarded, verified remediation *(v6.4.0)*

The **Run script** action is the auto-*fix* channel, so it carries its own
safety rig (per rule, editable in the rule editor):

| Knob | Default | What it prevents |
| --- | --- | --- |
| **Per-host cooldown** | 3600 s | A flapping alert turning into a restart loop — the same rule won't re-run its script on the same host within the window. |
| **Max hosts / hour** | 3 | An event storm (bad deploy, network split) running the script fleet-wide. Distinct-host cap per rule per hour. |
| **Verify within** | 0 (off) | Fire-and-forget fixes. When set, the verify sweep checks that the *triggering alert is no longer open* once the window expires: cleared → **verified**; still open → **failed**, and a `remediation_failed` alert (severity high) fires with the rule, host and script named. |
| **Disable after failures** | 3 | A fix that keeps not working keeps running. N *consecutive* verify-failures turn the rule off (the `remediation_failed` payload says so); any verified run resets the counter. |

Every firing — queued, verified, failed, or **suppressed** by a guard — lands
in the **Recent auto-remediations** ledger on the Automations page
(`GET /api/automation/remediations`, visibility-filtered). A `run_script`
action never fires on `remediation_failed` itself (no fix-the-fix loops);
notify/ticket actions on it are the intended way to escalate.

## Example

*When `disk_full` at **high** severity on tag `prod` → run the `cleanup-logs`
script, and if it keeps firing, open a **P2** ticket.* Two rules (or one rule
with two actions plus a cooldown) cover it. With **Verify within** set to
`900`, a cleanup that didn't actually clear the disk alert raises
`remediation_failed` instead of silently "fixing" forever.

## API

| Method & path | Purpose |
| --- | --- |
| `GET /api/automation/rules` | List rules |
| `POST /api/automation/rules` | Create a rule (admin) |
| `PUT /api/automation/rules/{id}` | Replace a rule (admin) |
| `DELETE /api/automation/rules/{id}` | Delete a rule (admin) |
| `GET /api/automation/remediations` | The auto-remediation attempt ledger *(v6.4.0)* |

Rules are stored in `automation_rules.json`; remediation attempts in
`remediations.json` (last 500).
