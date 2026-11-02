# Detection self-test

A green dashboard proves the monitoring found nothing, not that the monitoring
*would* find something. The detection self-test closes that gap. It checks the
alert **detection → routing → delivery** chain for every alert type and shows the
silent holes that no build-time test can catch, because they live in your own live
configuration.

Find it on **Admin → Server Status**, in the **Detection self-test** card (click **Run**), or
call `GET /api/detection-selftest`. Only admins can run it, because it reflects your full
notification setup. It is read-only: it reads the event list and your live settings and never
sends anything.

## What it checks

For every alert type (a group of related events, such as *CVE findings* or *Hardware temperature*), it
checks that a fired alert would actually reach a person, and it flags:

- **An alert type with every routing column off.** The event fires, gets recorded, and
  reaches nobody: no inbox row, no Needs Attention card, no webhook. This is the
  **critical** finding, and it appears as *SILENT — reaches nobody*. A type that ships
  quiet by design (for example *Agent stopped / started*, which is expected churn during
  upgrades) is not flagged. It reads *quiet by default*.
- **Sandbox mode left on.** **Settings → Security → Notification sandbox mode**
  (`notifications_test_mode`) logs webhook and email deliveries without sending them. It is
  the most dangerous silent gap and the easiest to forget after a test, so it is listed first
  as *critical*.
- **A webhook-only route with nowhere to go.** An alert type is routed to the webhook column
  only (not the inbox, not Needs Attention), but no outbound destination is set up (SMTP, web
  push, or a webhook URL). This is a *warning* and reads *no destination*.
- **A recover event that cannot clear its alert.** A recovery whose resolve target is not
  itself an alert would leave alerts open for ever. The check reads the event list at
  runtime, which catches an event that was never added to the alertable set. This is a
  *warning*.
- **No outbound destination at all.** An *info* note says alerts land only in the in-app inbox.

The *Recent activity* column alone does not count as delivery. A passive audit feed is
effectively silent for alerting, so only the **Inbox** (alerts), **Needs Attention** and
**Webhook** columns count as reaching someone.

## Reading the result

The top line gives the number of alert types, how many are silent, how many have no
destination and how many are fine, and says whether sandbox mode is on and whether external
delivery is configured. Under it is the issue list, then a table with one row per alert type:
whether it **reaches a human**, and ticks for **Inbox**, **Attention** and **Webhook**, plus the
number of events in that type.

Anything flagged is a place where a real problem could page nobody. To fix it:

- Turn a channel back on for that type under **Settings → Alerting → Channel routing**.
- Add an outbound destination under **Settings → Notifications** (email, web push or a
  webhook destination).
- Turn sandbox mode off under **Settings → Security**.

Run it after any change to routing, after you restore a backup, and after you copy settings to
a new server.

## What it does not do

It proves that routing is wired. It does not send a message. For active delivery to a channel you
already have, use the test buttons on **Settings → Notifications**, such as **Send test email**. The two complement each
other: the test button proves a channel works, and the self-test proves that alerts are sent to
a channel at all.

## See also

[alerts.md](alerts.md), [alert-tuning.md](alert-tuning.md), [webhooks.md](webhooks.md),
[self-monitoring.md](self-monitoring.md).
