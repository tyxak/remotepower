# On-call & escalation

*Rotation and escalation tiers introduced in v3.4.2; per-tier targets in
v5.5.0; the anchored calendar schedule and overrides in v6.0.0.*

An alert that nobody acknowledges should get louder, not sit silent. This
feature adds two things on top of the normal alert pipeline:

- an **on-call rotation** — a list of contacts who take turns being "the
  person", so escalation messages can name who should be looking;
- an **escalation policy** — tiers that re-notify your webhook destinations
  when an alert has sat **unacknowledged** for N minutes, optionally paging a
  different (louder) destination at each tier.

Escalations **re-fire the original alert's event through the existing webhook
fan-out** — there is no separate escalation event and no extra channel setup.

Both are configured on one card: **Settings → Alerting → On-call &
escalation**.

---

## The on-call rotation

Turn the rotation **On**, list the **contacts** (comma-separated, up to 50 —
they rotate in the order given) and set **Rotate every (days)** (1–365,
default 7). Contacts are just names/strings for the escalation message — they
don't have to be RemotePower users.

### Calendar schedule (anchored rotation)

Set a **Rotation start** date to anchor the schedule: contact #1 holds the
first slot starting at that date, and every handoff after that is
deterministic — "who is on call this week" is computable from the anchor, not
from whenever the server happened to do the modulo. With an anchor set, the
Settings card (and `GET /api/oncall`) shows the current holder plus the next
four **upcoming handoffs** as a mini schedule.

Leave the start date blank for the legacy stateless rotation (wall-clock
modulo over the contact list — still supported, just not predictable enough
to print a schedule from).

### Overrides (swaps and holidays)

An override is a dated window that wins over the rotation: `{contact, start,
end}` (unix timestamps, up to 100 kept, fully-past ones are pruned on save).
Active and upcoming overrides show as pills on the Settings card, and
`GET /api/oncall` lists them. There is no UI editor — set them via the API:

```bash
curl -sSf -X POST https://your-server/api/config \
  -H "X-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{"oncall": {"enabled": true, "contacts": ["alice","bob"],
       "rotation_days": 7, "anchor": 1767225600,
       "overrides": [{"contact": "carol", "start": 1768000000, "end": 1768604800}]}}'
```

Note that `POST /api/config` replaces the whole `oncall` object — include the
full rotation when scripting overrides, and be aware that saving the Settings
card (which doesn't send overrides) drops any API-set overrides.

Resolution order for "who is on call right now": **override window → anchored
schedule → legacy modulo**; empty string when the rotation is off.

The current on-call person also shows on the dashboard via the opt-in
**"On-call now"** widget.

---

## Escalation tiers

Turn **Escalation** on and give it:

- **Tiers** — comma-separated minutes-unacknowledged, e.g. `15, 60, 240`
  (up to 10 tiers, each 1–10080 minutes; stored sorted ascending).
- **Severities** — which alert severities escalate, default
  `critical, high` (any of `critical, high, medium, low, info`).
- **Per-tier target** *(optional)* — a webhook destination **name or id**,
  position-aligned with the tiers; blank = all destinations. Example: tiers
  `15, 60, 240` with targets `Slack, , PagerDuty` re-notifies Slack at 15
  minutes, everything at 60, and only PagerDuty at 4 hours — the "page a
  human at tier 3" pattern.

### How the tick works

A background tick runs about **once a minute**. For every open alert that is
neither acknowledged nor resolved and matches the severity filter, it checks
the alert's age against each tier; any tier the alert has aged past (and not
already fired) sends a re-notification:

```
ESCALATION tier 2 — unacknowledged 63m: Device Offline: web-1 · on-call: alice
```

The message rides the **original alert's event** through
`_send_webhook_to_url`, restricted to the tier's target destination if one is
set. Fired tiers are recorded on the alert (`escalated_tiers`), so each
(alert, tier) pair fires exactly once. **Acknowledging or resolving the alert
stops all further escalation** — that's the whole point: ack early, ack often.

Since escalation walks the Alerts inbox, it only applies to events that
actually record an alert (and does nothing if the Alerts module is switched
off).

---

## API

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| GET  | `/api/oncall` | any | `{current, upcoming, overrides, oncall, escalation}` — current holder, next 4 handoffs (anchored schedule only), active/upcoming overrides, and both config blocks. |
| POST | `/api/config` | admin | Set the `oncall` and/or `escalation` objects (shapes above). |

The home payload (`GET /api/home`) also carries `oncall.current` for the
dashboard widget.

Implementation: `server/cgi-bin/oncall_handlers.py` (rotation resolver,
escalation tick, `handle_oncall`); config validation in `api.py`'s
`handle_config_save`; UI in `app.js` (`saveOncall`, `_renderOncallSchedule`).

Related: [webhooks.md](webhooks.md) for destinations and the
PagerDuty/Opsgenie formats, [alerts.md](alerts.md) for acknowledge/resolve,
[calendar.md](calendar.md) for the (separate) shared events calendar.
