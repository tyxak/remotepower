# Alert tuning & per-host mute

Noisy, expected alerts drown the real signal. Two features address that.

## Mute (the X button)

On the **Alerts** page and the dashboard "Open alerts" widget, each alert row has an
**X "Mute"** button. Bulk **Ack selected**, ticket auto-acknowledge and escalation
work as before.

Muting silences **one exact alert from one host**: the specific `(host, event)` pair,
for example *rkhunter warnings on web-01*. While a mute is in effect:

- no inbox row, no webhook, and — for the Needs-Attention kinds that map to
  this event — no needs-attention card either;
- any currently-open matching alerts are resolved;
- **history keeps recording** (`fleet_events`), so the source stays visible on
  the Tuning page and you can always lift the mute.

A mute lasts until you lift it, or you can give it a duration (15 minutes to a year)
and it lapses on its own. A forgotten permanent mute is a way to stop monitoring
something without noticing. Muting is admin-only and audited, and a fleet can hold up to
5,000 mutes.

Two variations:

- **A container mute** silences every alert about one container on one host. Use the
  per-container **Mute** button in the Containers drawer.
- **An alert with no host** (for example a Threat Intel report or an edge feed that is
  down) is muted for the whole install. Only an unscoped admin can do that, because
  everyone sees those alerts.

## Tuning (Monitoring → Tuning)

The Tuning page reads the fleet-event **timeline** over the last 30 days and ranks:

- **Noisiest alerts** — the top `(host, event)` pairs by count, each with a
  **Silence** button (or a "silenced" badge);
- **Noisiest sources** — the top event types fleet-wide;
- **Active mutes** — every mute, with **Un-silence** to lift it;
- **Container exclude list** — containers kept out of alerts for the whole
  fleet, one entry per line (below);
- **Container CPU and memory lines** — the fleet's CPU and memory limits for
  containers, with a count of reports in a row before an alert. A line left empty
  or at 0 keeps that resource off. See [containers.md](containers.md);
- **Everything currently silenced** — every active suppression in one table,
  from all eight mechanisms: alert mutes, Needs Attention ignores and class
  rules, accepted-risk CVEs, exposure mutes, running maintenance windows, quiet
  hours and the container exclude list. Each row has the host, the reason and a
  link to the page that can lift it.

Silencing from here creates the same `(host, event)` mute as the X button.

To change the numbers that make an alert fire in the first place, use
[Alert parameters](alert-parameters.md) instead.

### Container exclude list

A container that matches an entry raises no stopped or restart alert, and it
stays out of Needs Attention and the dashboard's stopped-containers widget.
Use it for containers that exit by design. One entry per line, up to 200
entries of 128 characters:

- `pause` matches containers with `pause` in the name;
- `image:ghcr.io/getarcaneapp/tools` matches containers whose image contains
  that text, whatever the name and the tag. Use it for helper containers that
  get a random name on every run.

**Save exclude list** stores the list and the change shows in **Everything
currently silenced** at once. Only an administrator can change the list;
everyone else sees it. The change is in the audit log. See
[containers.md](containers.md) for the matching rules and the API form.

## API

| Method & path | Purpose |
| --- | --- |
| `GET /api/alert-mutes` | List active mutes |
| `POST /api/alert-mutes` | Mute `{device_id, event}`, `{alert_id}` or `{device_id, container}`; optional `{hours}` (0.25 to 8760) for a timed mute (admin) |
| `DELETE /api/alert-mutes/{id}` | Lift a mute (admin) |
| `GET /api/alert-tuning?days=N` | Noisiest pairs and sources over the window (1 to 365 days, 30 by default) |
| `GET /api/suppressions` | Everything currently silenced, with a count per mechanism |

See also: [alerts.md](alerts.md) for the inbox, [maintenance.md](maintenance.md) for
planned work, and [problems.md](problems.md) for one list of what is wrong.
