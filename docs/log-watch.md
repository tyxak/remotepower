# Logs (log watch)

**Monitoring → Logs** keeps a rolling buffer of journal and syslog lines across
the fleet. Search it, tail it live, export it, or attach alert rules to it.

The buffer is a short triage window, not a log archive. Ship your logs to a real
log store if you need to keep them.

## How long it keeps lines

The window is **6 hours by default**. Change it under **Settings → Advanced →
Data retention & maintenance**:

| Setting | What it does |
|---|---|
| **Ingested log lines (hours)** (`log_buffer_retention_hours`) | How long a line stays, 0 to 168. `0` restores the default of 6. |
| **Log bytes per unit** (`log_buffer_max_bytes_per_unit`) | An optional cap for each unit, up to 64 MiB. It keeps the newest lines, so one chatty unit cannot crowd every other unit out of the buffer. `0` means no cap. |

## Using the page

- **Live tail.** With the search box empty, the page shows the newest lines and
  refreshes every 30 seconds. It starts from the last 10 minutes and holds up to
  1,000 lines. **auto-scroll to newest** keeps the view at the bottom.
- **Search.** Type a regular expression (case-insensitive, up to 128
  characters), for example `error|critical`, optionally pick a host, and press
  **Search**. The page shows up to 500 matching lines, newest first. **Clear**
  goes back to the live tail. The unit menu filters the live tail and the
  exports, not a search.
- **Export.** **Export CSV** and **Export NDJSON** download exactly the lines the
  current host, unit and search describe, not the whole buffer, up to 50,000
  lines. Log content comes from outside, so CSV cells are escaped against
  spreadsheet formula injection: a line that starts with `=`, `+`, `-` or `@`
  gets a `'` in front.

The same data is available at `GET /api/logs/search`, `GET /api/logs/tail`,
`GET /api/logs/export` and `GET /api/devices/{id}/logs`.

## Alert rules

A rule is a pattern with a severity. When enough matching lines arrive, a
`log_alert` event fires: it lands in the Alerts inbox and goes to your webhooks
and email, like any other alert. Press **+ Add rule**. The two tabs hold
**Per-host** rules and **Fleet-wide** rules.

| Field | Notes |
|---|---|
| **Source** | A systemd unit, an absolute file path (the agent tails the file), or on a Windows host an [event log unit](#windows-event-rules) such as `eventlog.Security.4625`. A fleet-wide rule can use `*` for any unit on any host, except an event log unit. A rule matches the unit name exactly. |
| **Pattern** | A regular expression, up to 128 characters. A pattern with nested unbounded quantifiers such as `(a+)+` is refused, because a crafted line could make it very slow. |
| **Threshold** | 1 to 100. The rule fires when at least this many matching lines arrive in one delivery from the agent. |
| **Severity** | `OK`, `WARN` or `CRIT`. An `OK` rule raises nothing. Use it to mark a pattern as expected. |
| **Exclude pattern** | Lines that match this one do not count. |
| **Message** | An optional template for the alert text. It can use `{device}`, `{unit}`, `{pattern}`, `{count}`, `{sample}`, `{sample0}`, `{sample1}` and `{sample2}`. |

Fleet-wide rules can be added, changed and deleted by admins. Repeat alerts from
the same host and unit join the open alert in the inbox instead of adding rows.

## Windows event rules

A Windows host has no journal, but its agent can read the Windows event log for a rule. The events it reads are sent as units named after the channel and the event
id, and a rule on such a unit is an ordinary log rule: the same pattern, threshold, severity and message, and the same `log_alert` alert.

| Unit | Holds |
|---|---|
| `eventlog.Security.<id>` | one event id of the Security log |
| `eventlog.System.<id>` | one event id of the System log |
| `eventlog.Application.<id>` | one event id of the Application log |

In **+ Add rule**, **Ready-made Windows rule** fills the form for you. The rules below are ready-made. A rule on any other event id of those three logs works the same
way: type its unit as the source.

| Rule | Unit | Fires when | Severity | Needs |
|---|---|---|---|---|
| Failed logons | `eventlog.Security.4625` | 10 or more in one report from the host | WARN | on by default |
| Account locked out | `eventlog.Security.4740` | at least 1 | WARN | on by default; a domain controller logs it for domain accounts |
| Service installed | `eventlog.System.7045` | at least 1 | WARN | always logged |
| Service installed | `eventlog.Security.4697` | at least 1 | WARN | the audit policy *Audit Security System Extension* |
| Scheduled task created | `eventlog.Security.4698` | at least 1 | WARN | the audit policy *Audit Other Object Access Events* |
| Local user created | `eventlog.Security.4720` | at least 1 | WARN | on by default |
| Member added to Administrators | `eventlog.Security.4732` | at least 1 | CRIT | on by default |
| Audit log cleared | `eventlog.Security.1102` | at least 1 | CRIT | always logged |

How it works:

- **Nothing is read until a rule asks.** The server tells each Windows agent which
  events to read from the rules that apply to that host, its own and the fleet-wide
  ones. Remove the last rule for an event and the agent stops reading it. A host
  with no such rule sends nothing, and a Linux or macOS host is never asked.
- **The threshold counts lines in one report.** The agent reports at every
  check-in, so "10 or more" means 10 events since the last report, about one poll.
- **Nothing repeats and nothing is skipped.** For each event the agent remembers
  the last record it sent and asks only for later ones, oldest first. It starts at
  the newest record of the log, so turning a rule on does not raise an alert for
  history. A report the server did not take is read again. At most 50 events for
  one event id and 300 lines in all go in one report, and the rest follows in the
  next one.
- **A cleared log is noticed.** When the log's newest record is older than the last
  one the agent sent, the log has been cleared and its records started again, and
  the agent reads what is there now, the clearing itself (event 1102) included.
- **Limits.** Up to 12 event ids for each log and host, counting the fleet-wide
  rules and the host's own together (two rules on one id are one id). Every place
  that saves rules refuses a save that would take a Windows host past 12 ids from one
  log, and says so, because the agent reads the first 12 and a rule on a thirteenth
  would look saved and never fire: the host form, the services and log rules dialog,
  a host profile (when it is saved and when it is applied), a fleet-wide rule
  (added or edited, also when it would put a host that has rules of its own over)
  and the declarative import, which also refuses a unit that no agent can feed and a
  registry check that the agent would refuse. A host that is not a Windows one reads
  no event log and is not counted. The agent runs as SYSTEM, which is what the
  Security log needs. A log the agent cannot read is skipped without an error.

A line is built from the fields of the event, not from its message, which is in the
language of the host. For example:

```
[4625] failed logon rid=1048576 source=203.0.113.50 type=3 status=0xc000006d substatus=0xc000006a user="bob" domain="CORP" workstation="ATTACKBOX"
```

A name in an event can have been typed by anyone (the user in a failed logon, a
workstation name, a service's file), so every text is cut at 64 characters, control
characters and the characters that reorder or hide text become spaces (the format characters
of Unicode such as the bidirectional marks, the zero-width characters and the tag characters that
spell ASCII without showing it, the line and paragraph separators, the invisible fillers and the
variation selectors), and the text is put in double quotes, with any double quote inside it turned into a single one. The program a new service or scheduled task runs is cut at 64 or 120 characters after the
password in it has been replaced (the value after a name such as `password`, `token` or `secret`,
and the password of a URL). The fixed words and the
values the system itself writes (an address, a security ID, a status) come first. The
ready-made patterns start with `^`, so something a person typed cannot match them. The
Logs page and the alerts show the line as text.

## Clearing a noisy line

A rule matches a **class** of lines. `err|warn|critical|FATAL` on a PHP-FPM
unit will keep firing on the same routine message forever, and the two obvious
escapes are both wrong: snoozing brings it back on schedule, and deleting the
rule goes blind to the errors you actually wanted.

**Clear line** is the third option: *this exact message is understood, stop
paging me about it, but still page me about a new one.*

Every log alert carries the **matched line** that caused it, on the alert row and
on the Needs Attention card. From either, **Clear line** opens a dialog showing:

- **The line**, which is the raw text that matched.
- **What will be matched**, which is the same line with timestamps, process ids,
  addresses, hashes, numbers **and hostnames** folded out. That folded form is
  the identity, so the same message tomorrow, from a different worker pid, still
  matches. A different error does not. Folding hostnames matters for
  host-varying noise: a postfix `dnsblog` line checks each sender against many
  blocklists (`…bl.spamcop.net`, `…zen.spamhaus.org`, …), and because the domain
  folds to `<host>`, clearing one clears the whole class. Two-label names such as
  `docker.service` or `app.js` are *not* folded, so unrelated unit or file
  messages stay distinct.

Choose how wide it applies: this host and unit, this host and any unit, or the
whole fleet (admins only). You can also set an expiry, up to 365 days, and add a
note that says why it is expected. Anyone who can manage log rules can clear a
line.

Cleared lines stop counting toward their rule's threshold, so a rule whose
matches are all cleared simply stops firing. The alert count stays honest: an
alert that matched five lines, three of them cleared, reports "2 hits, 3 already
cleared". Clearing a line also resolves the open alerts that captured it.

Everything cleared is listed under **Logs → Cleared lines** and under
**Settings → Ignored items** (the **Cleared log lines** section), with how many
matches each has caught since. Un-clear one and it alerts again. The page keeps
up to 2,000 clears. Clearing and un-clearing are audited (`log_ack_add` and
`log_ack_delete`).

### When the alert carries no line

An alert recorded before RemotePower kept matched lines has nothing to clear by
signature. Those alerts offer **Silence rule** instead: it stops that whole
pattern firing on that unit and host.

This is coarser and labelled as such. It hides future messages you have not
seen yet, which clearing a line does not. Prefer clearing a line whenever the
alert carries one. Rule silences appear in the same **Cleared lines** list and
are undone the same way.

An **Exclude pattern** is still there for the cases where you want a regex.
Clearing a line needs no regex authoring and is reversible per line.

## Sources

Agents ship recent journald and syslog excerpts, and the files named by file
rules, with their check-ins. A host that has no agent can send syslog straight to
RemotePower with an inbound token: `POST /api/syslog/in/{token}` accepts either
`{"lines": […]}` or a bare JSON array. See [Inbound tokens](inbound-tokens.md).

## Troubleshooting

| You see | Check |
|---|---|
| A host has no lines | The agent has not delivered any since the window started, or the unit writes nothing. Lines older than the window are dropped. |
| A rule never fires | The unit name must match exactly (or use `*` on a fleet-wide rule). The threshold counts lines in one delivery. The exclude pattern or a cleared line may be removing the matches. |
| The rule is refused when you save it | The pattern is not a valid regular expression, or it has nested unbounded quantifiers. Simplify it. |
| An alert fires with severity `OK` | It does not. An `OK` rule is a marker only. |
| A Windows event rule never fires | The event may not be logged: check the audit policy in the table above. Run `wevtutil qe Security /c:1 /rd:true /f:text` on the host as an administrator to see that the log is readable. The rule's unit must be exactly `eventlog.<Channel>.<id>`, and the threshold counts events in one report. |

## See also

- [Alerts](alerts.md): the inbox the `log_alert` events land in.
- [Inbound tokens](inbound-tokens.md): syslog and other push endpoints.
- [Needs Attention](attention.md): where a log alert also shows up.
