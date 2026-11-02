# Uptime & SLA

RemotePower tracks each host's up and down history and turns it into uptime
percentages, a 7-day status stripe on the Home roster, and per-host and fleet SLA
figures on the **Reports** page.

This page is about **host uptime**. Ticket response and resolution targets are in
[ticket-system.md](ticket-system.md), and patch deadlines are in
[patches.md](patches.md).

## Where the data comes from

Uptime is rebuilt from a log of **state changes**, not from polling samples. Each
time a host flips online or offline, RemotePower records an event with the time.
The percentage is the share of the window the host spent online. This is cheap to
store and exact between changes.

- **Agent hosts** record a change when missed heartbeats mark them offline, and
  again when they return.
- **Agentless and SNMP hosts** are probed by the reachability sweep. The first
  probe records the current state as a baseline, and later probes write only when
  the state changes.
- RemotePower keeps the last 500 changes per host. A host that flaps constantly
  can therefore have history for only part of a long window. The earlier part
  counts as unknown.

## "No data" is unknown, never downtime

If RemotePower has no record for part of the window, most often the time before a
host was enrolled, that part is **unknown** and left out of the calculation. It is
never counted as downtime.

Hosts you do not monitor, and decommissioned hosts, are skipped entirely.
Decommissioning a host turns monitoring off, so it drops out of the SLA instead of
dragging the number down.

This matters on a fresh install: a host enrolled 8 days ago, measured over 30
days, is scored over the 8 days actually covered. It is not reported as "22 days
down". The table shows `unknown` for a host with no usable history yet.

## Maintenance windows don't burn the SLA

One-shot [maintenance windows](maintenance.md) (a fixed start and end, scoped to
the host, its group, or the fleet) are removed from both the downtime and the
covered time. Planned work does not count against a host's SLA. Recurring windows
are not removed from past figures.

## Reading the Uptime (SLA) card

On **Business → Reports**, the **Uptime (SLA)** card lists every monitored host
with its group, **Uptime**, **Downtime**, **SLA target** (marked *met* or
*breached*) and **Error budget**. Pick **7**, **30** (default) or **90** days, search
by host or group, and use the download button for a CSV. The line above the table
gives the fleet figure for the window, its target and the remaining error budget.

The **error budget** is the downtime your target allows in the window. A 99.9%
target over 30 days allows about 43 minutes. The table shows how much is left (or
how far over you are) and what share is used. The cell turns amber at 80% used.

On the Home page, the roster shows each host's last 7 days as a stripe of up, down
and unknown days. It lists the 15 hosts with the worst recent history first.

## SLA targets

Set a target uptime percentage and RemotePower measures each host against it. The
most specific target wins:

1. a target for the **host** (by host name), else
2. a target for one of the host's **tags**, else
3. a target for the host's **group**, else
4. the fleet **default**.

Click **SLA targets** on the card. The editor has a default field and overrides per
group, tag or host. Each row takes a percentage above 0 and up to 100, for example
99.9. A row without a name or percentage is ignored. Only an admin can change
targets (with multi-tenancy on, only the platform operator). The change is written
to the audit log.

## API

- `GET /api/fleet/sla?days=N` returns per-host and per-group uptime over an N-day
  window (1 to 365, default 30). Each host row has `uptime_pct`,
  `downtime_seconds`, `covered` (false means unknown), `sla_target`, `sla_met` and
  `error_budget` (`budget_seconds`, `used_seconds`, `remaining_seconds`,
  `used_pct`). The top level also has `fleet_uptime_pct`, `fleet_sla_target`,
  `fleet_sla_met` and `fleet_error_budget`. It is limited to the hosts you may see.
- `GET /api/fleet/uptime7d` returns the 7-day daily stripe per host (`up`, `down`
  or `unknown`, oldest first, today last).
- `GET /api/devices/{id}/uptime` returns the raw up and down events for one host.
- `GET /api/fleet/sla-targets` and `PUT /api/fleet/sla-targets` read and set the
  targets (`default`, `groups`, `tags`, `devices`). Send `null` or leave a level
  out to clear it.

## With multi-tenancy

The SLO figures and the monitors behind them belong to the organisation that runs the installation. With tenant isolation on, only users of the default tenant can open or change them. Users of every other tenant are refused, and the dashboard leaves them out of its summaries.

See also: [reports.md](reports.md), [maintenance.md](maintenance.md),
[time-billing.md](time-billing.md) for per-customer reporting.
