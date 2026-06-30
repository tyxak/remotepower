# Alert tuning & per-host mute

*(v5.6.0 "ProvisionMatters")*

Noisy, expected alerts drown the real signal. Two features address that:

## Mute (the X button)

On the **Alerts** page and the dashboard "Open alerts" widget, each alert row
has an **X "Mute"** button (it replaced the per-row *Ack*; bulk "Ack selected",
ticket auto-ack and escalation are unchanged).

Muting silences **one exact alert from one host** — the specific `(device,
event)` pair, e.g. *rkhunter warnings on tviapp01*. While a mute is in effect:

- no inbox row, no webhook, no needs-attention card for that pair;
- any currently-open matching alerts are resolved;
- **history keeps recording** (`fleet_events`), so the source stays visible on
  the Tuning page and you can always lift the mute.

Mutes are **permanent** until removed, and muting is admin-only and audited.

## Tuning (Monitoring → Tuning)

The Tuning page reads the fleet-event **timeline** and ranks:

- **Noisiest alerts** — the top `(host, event)` pairs by count, each with a
  **Silence** button (or a "silenced" badge);
- **Noisiest sources** — the top event types fleet-wide;
- **Active mutes** — every mute, with **Un-silence** to lift it.

Silencing from here creates the same `(host, event)` mute as the X button.

## API

| Method & path | Purpose |
| --- | --- |
| `GET /api/alert-mutes` | List active mutes |
| `POST /api/alert-mutes` | Mute `{device_id, event}` or `{alert_id}` (admin) |
| `DELETE /api/alert-mutes/{id}` | Lift a mute (admin) |
| `GET /api/alert-tuning?days=N` | Noisiest pairs + sources over the window |
