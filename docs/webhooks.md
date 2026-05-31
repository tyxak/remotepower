# Webhook destinations

Fire each event to as many endpoints as you like, with per-destination format adapters and event filters.

## Why multi-webhook

Single-URL is fine when "alerts" means one channel. Once you have a notification policy ("Discord for everything; Pushover for critical-only; Teams for the on-call channel"), one URL stops scaling. v3.0.2 adds a `webhook_urls` array under `config.json`, each entry self-contained with its own format and filter.

The legacy single `webhook_url` field is still honoured — operators with one Discord/ntfy receiver don't need to migrate. New setups should use the multi-webhook editor (Settings → Notifications → Webhook destinations).

## Supported formats

| Format | Detected by | Body shape |
|---|---|---|
| `discord` | `discord.com`, `discordapp.com` | Embed with severity colour, footer "RemotePower vX.Y.Z" |
| `slack` | `hooks.slack.com` | Plain markdown text with bold title |
| `pushover` | `api.pushover.net` | Form-encoded with `token`, `user`, `title`, `message`, `priority` |
| `teams` | `outlook.office.com`, `webhook.office.com` | MessageCard schema with theme colour |
| `ntfy` | `ntfy.sh` | Plain-text body + `Title`/`Priority`/`Tags` headers |
| `github` | `api.github.com` | Opens a GitHub issue (PAT in the destination's credential field) |
| `pagerduty` | `events.pagerduty.com` | Events API v2 — triggers an incident; recover events auto-resolve it (v3.4.1) |
| `opsgenie` | `opsgenie.com` | Alerts API v2 — P1–P4 by severity (v3.4.1) |
| `generic` | Anything else | JSON `{event, ts, title, message, priority, ...payload}` + `X-Title`/`X-Priority`/`X-Tags` headers |

Format auto-detect runs only on the legacy `webhook_url`. Entries in the new array carry an explicit `format` field — change it in the UI dropdown.

## On-call vs. ticketing

These are two different jobs — use the right tool for each:

- **On-call / paging** (wake someone, escalate if unacked): the `pagerduty` and
  `opsgenie` formats above.
- **Ticketing / help-desk** (a durable queue someone triages and closes): see
  below.

### osTicket (and any email-to-ticket help-desk) — zero code

The simplest, dependency-free path to a ticketing system like **osTicket**,
Zammad, Request Tracker, or FreeScout is the **email channel** — no webhook
adapter required:

1. In your help-desk, create an inbound mailbox/pipe that opens a ticket from
   email (osTicket: *Admin → Emails → Add Email*; it polls the mailbox or
   accepts a local pipe).
2. In RemotePower, **Settings → Notifications → Email notifications (SMTP)**, add
   that address to the recipient list and enable email for the events you want
   to become tickets.
3. Each fired event now arrives as an email → a new ticket, subject = the event
   title, body = the human-readable detail.

Because it rides the existing email channel, it inherits maintenance-window and
quiet-hours suppression and the per-event opt-in for free. This keeps RemotePower
self-hosted end to end — no SaaS dependency. (A native osTicket REST adapter
could follow, but the email path covers the common case with zero new code.)

## Pushover specifics

The Pushover API needs an **app token** (from your app at pushover.net/apps) and a **user/group key** (under "Your User Key"). Both are stored encrypted in `config.json`, redacted from the GET response (the UI sees `pushover_token_set: true/false`), and redacted from the backup export tarball.

Priority mapping (RemotePower internal → Pushover):

| Internal | Pushover | Behaviour |
|---|---|---|
| 0 (info) | 0 (normal) | Standard notification |
| 1 (warning) | 1 (high) | Bypasses user's quiet hours |
| 2 (critical) | 1 (high) | NOT Pushover 2 (emergency tier) |

We deliberately don't map internal critical to Pushover priority=2. Pushover's emergency tier requires `retry` and `expire` parameters and demands user acknowledgment; that's not behaviour you want to opt into accidentally because RemotePower decided a "critical" event happened. If you need it, set up your own Pushover integration outside RemotePower.

## Per-destination filters

Each destination can narrow what fires there.

**Minimum priority** — drop events below the threshold:
- `0` (info+): everything fires
- `1` (warning+): drops `device_online`, `command_executed`, etc.
- `2` (critical only): only `device_offline`, `cve_found`, `monitor_down`, etc.

**Event allowlist** — exact event names, one per line:
```
device_offline
cve_found
monitor_down
```

When set, only those events fire to this destination. Empty list = all events (subject to the global per-event toggles in Settings → Notifications).

The two filters compose with AND: an event must pass both the priority floor and the allowlist (if present) to fire.

## Backward compatibility

The legacy `webhook_url` field still works. On every fire, the dispatcher builds a destination list from both sources:

1. Legacy `webhook_url` (single, format auto-detected) — if set
2. Each entry in `webhook_urls` where `enabled !== false`
3. Dedup by URL — if you migrated but didn't clear the legacy field, the duplicate is skipped

Migrating a single legacy URL to the new array:
1. Add a new destination with the same URL and explicit format
2. Test it (per-destination Test button)
3. Clear the legacy URL field
4. Save

## Endpoints

| Method | Path | Notes |
|---|---|---|
| GET  | `/api/config` | Returns `webhook_urls` with Pushover creds redacted, `pushover_token_set` / `pushover_user_set` flags |
| POST | `/api/config` | Accepts `webhook_urls` array; empty pushover_token/pushover_user fields preserve existing values |
| POST | `/api/webhook-test` | Body `{}` → fan out to all enabled destinations. Body `{id: "wh_xxx"}` → fire only to that one (uses a synthetic config without touching persisted state) |

Max 20 destinations. URL must be http or https. Format must be one of those listed above (anything else returns 400).

## Audit + logging

Every successful POST is logged to `webhook_log.json` with the format suffix: `OK (200) [pushover]`, `HTTP 400 [discord]: Bad Request`, etc. Visible in Settings → Notifications → Recent deliveries, and aggregated for the success-rate stat on the Server status page.
