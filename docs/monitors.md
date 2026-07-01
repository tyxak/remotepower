# Active monitors & probes

Beyond the metrics each agent reports about *itself*, RemotePower runs
**server-side synthetic checks** against targets you name, plus receivers for
telemetry hosts push to it. These live under **Monitoring → Remote Checks** (and
a few sibling pages), and every failure/recovery is a first-class event.

## Remote Checks

**Monitoring → Remote Checks** lists your synthetic checks — Label, Type, Target,
Status, Detail and last-checked time — with **Check now**, **Reset alerts** and
**Add target**. The server runs them on a cadence (`monitor_interval`, default
300s) and stores results in `monitor_history.json`.

| Type | Target | Checks |
| --- | --- | --- |
| `ping` / `icmp` | host or IP | ICMP reachability (icmp adds loss/latency stats) |
| `tcp` | `host:port` | TCP connect |
| `http` / `https` | full URL | HTTP request + expected status code |
| `dns` | name (+ optional expected record) | resolves to an answer |
| `db` | `host:port` | database liveness (TCP-style) |

Targets are validated server-side (`_sanitize_monitor_target`) so a check can't
be pointed at a private/rebound address. Each check raises **`monitor_down`** when
it fails and **`monitor_up`** when it recovers. The `/api/monitor` endpoint can
also be pinged by an external scheduler to force a run.

## Service monitoring

Watch specific systemd units per host (`watched_services`). The agent reports
each unit's state in its heartbeat; a stopped unit raises **`service_down`** and
a recovered one **`service_up`**. Service baselines let you snapshot the expected
running set and alert on deviation.

## Log-tail alerts

Two layers, both firing **`log_alert`**:

- **Per-device** log-watch rules (`log_watch`): `{unit, pattern, threshold,
  severity}` — the agent tails the unit's journal and reports matches.
- **Fleet-wide** rules (**`/api/logs/rules/global`**): a pattern + threshold +
  optional `exclude_pattern` and a `file:/path/to/log` synthetic unit for tailing
  a plain file. Managed on the Logs page.

## Inbound receivers (syslog & SNMP traps)

Devices and appliances can push to tokenised, admin-created endpoints (tokens
start with `rpwi_`, managed as inbound webhooks):

- **Syslog** — `POST /api/syslog/in/{token}` accepts `{lines:[…]}`, a bare JSON
  array, or plain newline-separated text. Lines are parsed for severity and run
  through the syslog rules (fires `log_alert`).
- **SNMP traps** — `POST /api/snmp/trap/{token}` accepts `{traps:[{oid,value,…}]}`
  or a single trap; a decoding trapd feeds it. New traps raise
  **`snmp_trap_received`** (coalesced to one open alert per host).
- **SNMP polling** is separate: per device, `POST …/snmp/poll` and a deep
  inspection at `GET …/snmp/deep`.

## Resolver health & watchdog

- **Resolver health** monitor (`resolver_health.py`): names you register are
  resolved at several vetted public resolvers on a cadence; latency, NXDOMAIN and
  failure counts are tracked, and a name that stops resolving raises
  **`resolver_unhealthy`** (and `resolver_recovered` when it comes back). See
  [dns.md](dns.md).
- **Healthchecks.io watchdog** — set `healthchecks_url` and RemotePower pings it
  every `healthchecks_interval_seconds`, so an external dead-man's-switch alerts
  *you* if the control plane itself goes dark.
- **Server disk watchdog** — `disk_watchdog_pct` (default 85, 0 = off) raises
  `server_disk_full` when the data volume fills.

## Permissions

- Viewing check status needs normal authentication.
- Adding/editing checks, log rules, inbound tokens and resolver-health targets is
  **admin-only**; inbound receiver endpoints authenticate by their `rpwi_` token,
  not a session.
- All targets/URLs are SSRF-guarded (loopback, link-local and cloud-metadata
  addresses are refused), and inbound endpoints are rate-limited.
