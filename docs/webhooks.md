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
| `jira` | explicit | Opens a Jira issue via `POST /rest/api/2/issue` — HTTP Basic auth (account email + API token), with a project key and issue type. Fires on alert ACK (v5.0.0) |
| `servicenow` | explicit | Opens a ServiceNow incident via `POST /api/now/table/incident` — HTTP Basic auth. Fires on alert ACK (v5.0.0) |
| `zendesk` | explicit | Opens a Zendesk ticket via `POST /api/v2/tickets.json` — email/token Basic auth. Fires on alert ACK (v5.0.0) |
| `generic` | Anything else | JSON `{event, ts, title, message, priority, ...payload}` + `X-Title`/`X-Priority`/`X-Tags` headers |

Format auto-detect runs only on the legacy `webhook_url`. Entries in the new array carry an explicit `format` field — change it in the UI dropdown.

## On-call vs. ticketing

These are two different jobs — use the right tool for each:

- **On-call / paging** (wake someone, escalate if unacked): the `pagerduty` and
  `opsgenie` formats above.
- **Ticketing / help-desk** (a durable queue someone triages and closes): the
  native `jira` / `servicenow` / `zendesk` formats, or the zero-code email path
  below.

### Native ITSM tickets on acknowledge (v5.0.0)

The `jira`, `servicenow` and `zendesk` formats open a ticket in your ITSM tool
over its REST API (HTTP Basic auth over HTTPS). Wire one up in **Settings →
Notifications → Webhook destinations**: pick the format, paste the API URL, and
fill the credentials (account email + API token; Jira also needs a project key
and issue type). Tick **"Also fire on alert ACK"** so a ticket is opened when an
operator acknowledges an alert. RemotePower parses the created ticket's id/url
from the response and shows the **ticket link right on the alert row**, so you
can jump straight to it. Credentials are stored encrypted and redacted from the
config GET (`itsm_secret_set: true/false`).

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

**Digest window** — set **Digest window (min)** on a destination to batch its
non-critical notifications into a single summary message every N minutes
(0 = send immediately, the default). Held events are flushed as one delivery
titled "N notifications" listing each event. Critical / urgent events
(priority ≥ 4) always bypass the digest and page immediately, so a digest never
delays a real emergency. Useful for a chatty Discord/Slack channel where you
want a periodic roll-up instead of a stream.

## Verifying deliveries (HMAC signature)

A **generic**-format destination can carry an optional **HMAC signing secret**
(Settings → Notifications → the destination's *HMAC signing secret* field —
write-only; leave blank on later edits to keep it). When set, every delivery is
signed over the exact bytes sent:

```
X-RemotePower-Signature: sha256=<hex HMAC-SHA256 of the raw body>
X-RemotePower-Timestamp: <unix seconds>
```

Verify on the receiver (constant-time compare, and bound the timestamp to
reject replays):

```python
import hashlib, hmac, time

def verify(raw_body: bytes, headers, secret: str, max_age=300) -> bool:
    sig = headers.get('X-RemotePower-Signature', '')
    ts = int(headers.get('X-RemotePower-Timestamp', 0))
    if abs(time.time() - ts) > max_age:
        return False
    want = 'sha256=' + hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, sig)
```

Hosted-service formats (Discord/Slack/Telegram/Matrix/…) are never signed —
you don't control those receivers, so the header would be meaningless. Each
destination has its own secret; rotating one is just pasting a new value (and
updating the receiver).

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
| POST | `/api/webhook/test` | Body `{}` → fan out to all enabled destinations. Body `{id: "wh_xxx"}` → fire only to that one (uses a synthetic config without touching persisted state) |
| GET    | `/api/webhook/dlq` | List the dead-letter queue (failed deliveries) — admin (v5.0.0) |
| POST   | `/api/webhook/dlq/retry` | Re-dispatch one entry (`{id}`) or all (`{all: true}`) — admin (v5.0.0) |
| DELETE | `/api/webhook/dlq` | Clear the dead-letter queue — admin (v5.0.0) |
| POST   | `/api/webhook/replay` | Replay past fleet events to a destination — admin (v5.0.0) |

Max 20 destinations. URL must be http or https. Format must be one of those listed above (anything else returns 400).

## Dead-letter queue & replay (v5.0.0)

A delivery that fails permanently (after retries) is parked in a **dead-letter
queue** (`webhook_dlq.json`, capped at the most recent entries) so it isn't lost
when the receiver is down. From **Settings → Notifications → Webhook log** you can
**Retry** a single entry, **Retry all**, or **Clear** the queue; each retry is
logged and its attempt counter bumped. You can also **replay** past fleet events
to a destination, which is handy after a receiver outage.

## Audit + logging

Every successful POST is logged to `webhook_log.json` with the format suffix: `OK (200) [pushover]`, `HTTP 400 [discord]: Bad Request`, etc. Visible in Settings → Notifications → Recent deliveries, and aggregated for the success-rate stat on the Server status page.

## One-click ack from alert emails

Turn on **Settings → Notifications → Add one-click Acknowledge / Resolve links
to alert emails** (`alert_email_ack_links`, default off) and every alert email
gains two links:

```
Acknowledge: https://<server>/api/alerts/act?a=<id>&op=ack&s=<hmac>
Resolve:     https://<server>/api/alerts/act?a=<id>&op=resolve&s=<hmac>
```

The `s` parameter is an HMAC (per-install key) binding the alert id and the
operation — it is the capability, so clicking acks or resolves the alert with
**no login**, from any device or network (the endpoint is exempt from the IP
allowlist). The action is idempotent (clicking a link for an
already-resolved alert just reports its state) and audit-logged as actor
`email-link`. The link uses the server hostname from the request that sent the
mail, so leave the toggle off if your server isn't reachable at that address.

## Agent lifecycle events

Two events fire around an agent's lifecycle (both routable to any destination and
in the Alerts inbox): **`agent_stopped`** when an agent shuts down cleanly (a
distinct signal from `device_offline`, which means "stopped reporting"), and
**`agent_started`** when it comes back. Payload: `device_id`, `name`, `hostname`.
