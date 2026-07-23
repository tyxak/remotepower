# Logs (log watch)

**Monitoring → Logs** keeps a 6-hour rolling buffer of journal/syslog lines
across the fleet. Search it, tail it live, or attach alert rules to it.

## Using the page

- **Search** — free-text across the buffer, per device or fleet-wide.
- **Tail live** — follow new lines as heartbeats deliver them.
- **Alert rules** — pattern → severity: when a matching line arrives, a
  `log_alert` event fires (inbox + webhooks). Rules can be global or
  per-device, with cooldowns so a log storm doesn't page you 400 times.

## Clearing a noisy line *(v6.4.0)*

A rule matches a **class** of lines. `err|warn|critical|FATAL` on a PHP-FPM
unit will keep firing on the same routine message forever, and the two obvious
escapes are both wrong: snoozing brings it back on schedule, and deleting the
rule goes blind to the errors you actually wanted.

**Clear line** is the third option — *this exact message is understood, stop
paging me about it, but still page me about a new one.*

Every log alert now carries the **matched line** that caused it, on the alert
row and on the Needs-Attention card. From either, `Clear line` opens a dialog
showing:

- **The line** — the raw text that matched.
- **What will be matched** — the same line with timestamps, process ids,
  addresses, hashes, numbers **and hostnames/FQDNs** folded out. That folded
  form is the identity, so the same message tomorrow, from a different worker
  pid, still matches; a genuinely different error does not. Folding hostnames
  matters for host-varying noise — a postfix `dnsblog` line checks each sender
  against many blocklists (`…bl.spamcop.net`, `…zen.spamhaus.org`, …), and
  because the domain folds to `<host>`, clearing one clears the whole class.
  (Two-label names like `docker.service` or `app.js` are deliberately *not*
  folded, so unrelated unit or file messages stay distinct.)

Choose how wide it applies (this host + unit, this host + any unit, or — for
admins — the whole fleet) and optionally an expiry and a note explaining why
it's expected.

Cleared lines stop counting toward their rule's threshold, so a rule whose
matches are all cleared simply stops firing. The alert count stays honest: an
alert that matched five lines of which three were cleared reports "2 hits,
3 already cleared" rather than silently under-reporting. Acknowledging also
resolves the open alerts that captured that line, so clearing it clears the
board.

Everything cleared is listed under **Logs → Cleared lines** *and* under
**Settings → Ignored items** (a "Cleared log lines" section), with how many
matches each has caught since — un-clear one and it alerts again. Clearing is
audited (`log_ack_add` / `log_ack_delete`).

### When the alert carries no line

An alert recorded before RemotePower kept matched lines has nothing to clear by
signature. Those alerts offer **Silence rule** instead: it stops that whole
pattern firing on that unit and host.

This is deliberately coarser and labelled as such — it hides future messages you
have not seen yet, which clearing a line does not. Prefer clearing a line
whenever the alert carries one. Rule silences appear in the same **Cleared
lines** list and are un-done the same way.

A rule's `exclude_pattern` is still there for the cases where you genuinely
want a regex; clearing a line needs no regex authoring and is reversible per
line.

## Sources

Agents ship recent journald/syslog excerpts with their heartbeats; syslog
can also be ingested directly (`POST /api/syslog/in/{token}` accepts either
`{lines:[…]}` or a bare JSON array) for devices that forward rather than
run an agent.

The buffer is deliberately short-retention — it is an operational triage
window, not a log archive. Ship to a real log store for retention.
