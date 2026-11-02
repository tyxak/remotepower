# Cron & timers

**Scheduling → Cron** views and manages a host's **crontabs** and **systemd
timers** directly from RemotePower.

## How it works

- Pick a host to see the crontabs, `cron.d` entries and systemd timers its agent
  reports. Timers show their unit, what they activate, and their state. Without a
  host selected, the page lists every host with its job and timer counts.
- **Save crontab** replaces a user's crontab (root by default, up to 64 KB), and
  **Remove crontab** deletes it. You can also apply an action to a timer unit.
  Changes run through the **audited, permission-gated
  [command queue](agent-commands.md)**.
- **Quarantined / audit-mode hosts are skipped** — edits won't apply to a host
  you've locked down.

## Safety

- Crontab content travels base64-encoded and is installed from a **temp file**
  (`crontab -` from a written file). It is **never assembled through a shell**, so
  there is no shell-injection surface. User and unit names are checked against a
  strict pattern.
- systemd timer changes are applied through the same audited pipeline.

## Cron vs. the other schedulers

- **Cron & timers** — edit the *host's own* recurring jobs in place.
- **[Scheduled Commands](schedule.md)** — a one-off shutdown/reboot from
  RemotePower's queue.
- **[Auto-patch](auto-patch.md)** — recurring package upgrades managed centrally.

## Permissions

Anyone signed in can view the page (within their host scope). Editing crontabs and
timers requires the **command** action permission (or admin); every change is
audit-logged.
