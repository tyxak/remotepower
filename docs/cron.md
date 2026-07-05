# Cron & timers

**Scheduling → Cron** views and manages a host's **crontabs** and **systemd
timers** directly from RemotePower.

## How it works

- See the root crontab entries and systemd timers reported by the agent for a
  host, with their schedules and (for timers) next-run.
- Add, edit or remove entries; changes run through the **audited,
  permission-gated [command queue](agent-commands.md)**.
- **Quarantined / audit-mode hosts are skipped** — edits won't apply to a host
  you've locked down.

## Safety

- Crontab content is installed via a **temp file** (`crontab -` from a written
  file) — **never assembled through a shell**, so there's no shell-injection
  surface.
- systemd timer changes are applied through the same audited pipeline and
  validated before activation.

## Cron vs. the other schedulers

- **Cron & timers** — edit the *host's own* recurring jobs in place.
- **[Scheduled Commands](schedule.md)** — a one-off shutdown/reboot from
  RemotePower's queue.
- **[Auto-patch](auto-patch.md)** — recurring package upgrades managed centrally.

## Permissions

Editing crontabs and timers requires the **command** action permission (or
admin); every change is audit-logged.
