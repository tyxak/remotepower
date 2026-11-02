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
| **Source** | A systemd unit or an absolute file path (the agent tails the file). A fleet-wide rule can use `*` for any unit on any host. A rule matches the unit name exactly. |
| **Pattern** | A regular expression, up to 128 characters. A pattern with nested unbounded quantifiers such as `(a+)+` is refused, because a crafted line could make it very slow. |
| **Threshold** | 1 to 100. The rule fires when at least this many matching lines arrive in one delivery from the agent. |
| **Severity** | `OK`, `WARN` or `CRIT`. An `OK` rule raises nothing. Use it to mark a pattern as expected. |
| **Exclude pattern** | Lines that match this one do not count. |
| **Message** | An optional template for the alert text. It can use `{device}`, `{unit}`, `{pattern}`, `{count}`, `{sample}`, `{sample0}`, `{sample1}` and `{sample2}`. |

Fleet-wide rules can be added, changed and deleted by admins. Repeat alerts from
the same host and unit join the open alert in the inbox instead of adding rows.

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

## See also

- [Alerts](alerts.md): the inbox the `log_alert` events land in.
- [Inbound tokens](inbound-tokens.md): syslog and other push endpoints.
- [Needs Attention](attention.md): where a log alert also shows up.
