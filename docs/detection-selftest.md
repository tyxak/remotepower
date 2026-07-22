# Detection self-test

A green dashboard proves the monitoring found nothing — not that the monitoring
*would* find something. The detection self-test closes that gap. It inspects the
alert **detection → routing → delivery** chain for every alertable event type
and surfaces the silent holes that no build-time test can catch, because they
live in your own live configuration.

Find it under **Monitoring → Checks** (the "Detection self-test" card) or call
`GET /api/detection-selftest`. It is read-only and side-effect free — it reads
the event registry and your live config and never fires anything.

## What it checks

For every alertable event kind, it verifies that a fired alert would actually
reach a human, and it flags:

- **A kind whose routing columns are all off.** The event fires, gets recorded,
  and reaches nobody — no inbox row, no webhook, no email.
- **Test mode left on.** `notifications_test_mode` sandboxes the whole fleet's
  external delivery. It is the single most dangerous silent gap and the easiest
  to forget after a test — so it is called out first.
- **Routed out to nowhere.** The `webhook` column is on for a kind but no
  outbound destination (SMTP, web push, or a webhook URL) is configured, so the
  route leads off-box to nothing.
- **A recover event that can't clear its alert.** A recovery whose resolve
  target isn't itself alertable would leave alerts open forever. This is
  verified at runtime against the registry, catching the class where a match key
  was never whitelisted.

The "recent activity" feed alone doesn't count as delivery — landing only in a
passive audit feed is effectively silent for alerting, so the check treats
`alerts`, `needs_attention` and `webhook` as the columns that actually reach
someone.

## Reading the result

The report lists each event kind with its routing state and an actionable issue
list. Anything flagged is a place where a real problem could occur and page
nobody — fix it by enabling a channel for that kind under **Settings →
Notifications → Channel routing**, adding an outbound destination, or turning
test mode off.

This complements the "send a test" button in Settings, which exercises *active*
delivery for a channel you already have. The self-test proves the **routing is
wired** before you ever rely on it — silence isn't clearance.
