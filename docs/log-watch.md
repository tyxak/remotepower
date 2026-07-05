# Logs (log watch)

**Monitoring → Logs** keeps a 6-hour rolling buffer of journal/syslog lines
across the fleet. Search it, tail it live, or attach alert rules to it.

## Using the page

- **Search** — free-text across the buffer, per device or fleet-wide.
- **Tail live** — follow new lines as heartbeats deliver them.
- **Alert rules** — pattern → severity: when a matching line arrives, a
  `log_alert` event fires (inbox + webhooks). Rules can be global or
  per-device, with cooldowns so a log storm doesn't page you 400 times.

## Sources

Agents ship recent journald/syslog excerpts with their heartbeats; syslog
can also be ingested directly (`POST /api/syslog/in/{token}` accepts either
`{lines:[…]}` or a bare JSON array) for devices that forward rather than
run an agent.

The buffer is deliberately short-retention — it is an operational triage
window, not a log archive. Ship to a real log store for retention.
