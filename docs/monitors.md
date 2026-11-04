# Active monitors & probes

Beyond the metrics each agent reports about *itself*, RemotePower runs
**server-side synthetic checks** against targets you name, plus receivers for
telemetry hosts push to it. The checks live on **Monitoring → Live Monitor**
(the page is titled *Monitoring*), and every failure and recovery is an event you
can notify on.

## Remote checks

The **Remote checks** card on **Monitoring → Live Monitor** lists your synthetic
checks (Label, Type, Target, Status, Detail and the time of the last check) with
**Check now**, **Reset alerts**, **Mail round-trip** and **Add target**. The
server runs them every `monitor_interval` seconds (default 300, between 60 and
3600; **Settings → General → Monitor check interval**) and stores results in
`monitor_history.json`. An install holds up to 50 targets. **Settings → Alert
parameters → Reliability tuning → Monitor checks kept** sets how many results
each check remembers (300 by default).

| Type | Target | Checks |
| --- | --- | --- |
| `ping` / `icmp` | host or IP | ICMP reachability (icmp adds loss/latency stats) |
| `tcp` | `host:port` | TCP connect |
| `http` | full `http://` or `https://` URL | HTTP request + expected status/latency, body contains/regex, JSON dot-path assertions |
| `http_flow` | first step's URL | multi-step HTTP transaction — up to 5 ordered steps sharing a cookie jar, per-step expect-status/contains and `extract` → `${var}` reuse |
| `dns` | name (+ optional expected record) | resolves to an answer |
| `db` | `host:port` | database liveness (PostgreSQL / MySQL / Redis protocol probe, credential-less) |
| `path` | host or IP | network path (traceroute) — fires `path_changed` when the route's hop set moves vs the baseline |

The server validates every target. Addresses on your LAN are allowed. A loopback
address is refused unless you tick **Settings → General → Allow monitoring of
internal / loopback targets**, and link-local and cloud metadata addresses are
always refused. The check runs again when the probe connects, so a name that later
resolves to a refused address is stopped. Each check raises **`monitor_down`** when
it fails and **`monitor_up`** when it recovers. Two more options in the dialog help
with noise: **Alert after consecutive failures** (1 to 10, where 1 alerts on the
first failure) waits for several failed checks in a row before it alerts, and
**Max latency ms** (HTTP and ICMP) and **Max packet loss %** (ICMP) turn a slow
answer into a failure.

A `ping`, `icmp` or `tcp` check can target **every host with a tag** or **every
host in a group** instead of one address. The server fans it out into one check
per host. A tag or group `tcp` check needs a port.

`GET /api/monitor` answers from the newest run when it is recent, and
`GET /api/monitor?run=1` probes now. That is what **Check now** does. You must be
signed in, and the call is limited to 30 a minute per user.

### HTTP checks

An `http` check is up when the answer is below 400. Fill in **Expected HTTP status**
and only that code is up, so an app behind a login that answers 401 at its root can
be watched for 401, and an API root that answers 404 for 404. The body, JSON and
latency checks you set are applied to that answer, whatever its status.

**Method.** The default, Auto, sends a HEAD request, which costs the target almost
nothing, and tries a GET once when HEAD is answered with 404, 405 or 501. Home
Assistant, Navidrome and a few other apps refuse HEAD and answer GET. Pick HEAD or GET
to send only that one. A body or JSON check always uses GET, so it cannot be combined
with HEAD.

**Verify TLS.** Untick it for a service on a self-signed certificate. The connection
is still encrypted and the address checks still apply; only the certificate is not
checked. Both options travel with the monitor through **Export** and **Import**, and an
Uptime Kuma import carries over *Ignore TLS/SSL errors* and the request method.

An alert belongs to the check's name. Change the target of a check that is down and
its alert closes the first time the new target passes. Delete or rename it and the
alert closes when you save, because nothing will probe the old name again.

Everyday controls on each row: **Pause** stops probing a target without
deleting it — config, history and uptime % survive, no alerts fire, and the
row stays visible (badged *PAUSED*) until you Resume. **Clone** prefills the
create form from an existing monitor. **Export** downloads the definitions as
JSON the **Import** box accepts (which also takes Nagios/Icinga configs,
Uptime Kuma backups and Zabbix XML exports). Import shows a preview first, skips a
check whose type and target you already have, and is for admins. Export leaves out
the satellite or host a check probes from, since those ids only exist on your
install. A monitor can be probed **from a
relay satellite** instead of the server (`via_satellite` — reaches
segmented/private space the server can't; the row shows a *via satellite*
badge). Every probe is timed, so the History modal shows **response-time
percentiles** (p50/p95/p99 over the window, successful checks only).

### Probe from a host

A check can run from the agent of one of your hosts instead of from the server. That reaches what only the host can reach: a
database on a private network, a port on the host's own loopback (`127.0.0.1:5432`), an internal web page.

Pick the host under **Probe from** in the check dialog. The row then carries a *via host* badge that names the host.

- The host has to run the **Linux agent**. The Windows and macOS agents and agentless hosts do not probe, and neither does a host in
  audit mode (read-only), since an audited host does not act on what the server tells it. The row says so. A host with
  `require-signed-commands` set does not probe either, because the checks are a setting and not a signed command. The server
  cannot see that marker, so those checks read WAITING.
- A host is sent at most 20 checks. A twenty-first is saved but never sent, and it stays at WAITING.
- The check is `tcp`, `http` or `ping`, and it names one address, not a tag or a group.
- An HTTP check can use **Expected HTTP status**, **Body must contain**, **Method** and **Verify TLS**. A regex, a *must not
  contain* text, a JSON field, a latency limit and a packet loss limit are only available from the server. Saving one with a
  host tells you which one to take out.
- A check runs from one place: the server, a satellite or a host.
- The host's loopback is allowed, since it is the host's own. Link-local and cloud metadata addresses stay refused, when you
  save the check and again when the agent connects.

The server sends the host its checks with a heartbeat answer. The agent runs them every **Monitor check interval** (60 seconds
at the least) and returns the results with a later heartbeat, so a result can be a heartbeat behind. History, uptime, SLO
figures and the `monitor_down` and `monitor_up` alerts work as they do for any other check, and **Alert after consecutive
failures** applies. A paused check is not sent.

A row that is not a reading says so. A check that has not reported yet reads **WAITING** with *awaiting first probe from the host*,
which is also what a host that has not updated its agent shows. If a host stops reporting, its checks stop with it. After the longest
a result should take to arrive, which is twice the sum of the monitor check interval and the host's own report interval, the row
reads **NO DATA** instead of up or down. The detail keeps the last result and the age column keeps the time it was taken. No alert is raised
for a row with no data: the host's own offline alert tells you why. The same holds for a check a satellite probes. When you move a
check to another host or to a satellite, the row shows nothing of the old prober's result and waits for the new one.

The agent follows no redirect, checks the certificate unless you untick **Verify TLS**, and reads at most 512 KB of a page for a
text check. It runs only `http` and `https` addresses it has checked itself, and the server accepts results from a host for
that host's own checks only.

## SLA / SLO objects

Named availability targets that remote probes attach to. Define an object —
name, target % (say 99.9, above 0 and below 100), rolling window in days (1 to 365,
30 by default) — in the **SLA / SLO objects**
card on **Monitoring → Live Monitor**, then tick it on each probe whose checks should count toward it
(checkboxes in the probe editor; any type, and a tag/group probe's fanned-out
per-host checks all count). The panel shows each object's check-weighted
**availability**, **error budget remaining** and **burn rate** over its own
window — filterable by name/probe and by compliance (breached / meeting / no
data), sortable on every column. An object with no measured checks reads *no
data*, never a fake breach; deleting one detaches its probes and keeps their
history.

Availability is a ratio of stored checks, and the window in days only counts the
checks still stored. Each check keeps its last 300 results by default, which at the
default five-minute interval is about a day, and at most 5,000, about 17 days. So an
object with a 30-day window needs **Monitor checks kept** raised before it sees 30
days. A window of N checks can only
resolve steps of 100/N percentage points. When that step is coarser than the
error budget itself — a 99.9% target leaves 0.1 pp, so it needs at least 1,000
checks in the window — the budget could only ever read 100% or 0%, and one
failed check would report a blown budget for a probe that was up 99.7%. The
budget column shows *too few checks* in that case instead. Raise **Monitor
checks kept** (`monitor_history_max`, under **Settings → Alert parameters →
Reliability tuning**) so the window holds more checks, or set a target the
window can actually measure.

`GET /api/slo` returns the objects alongside the per-monitor availability
list, and the same numbers export as Prometheus gauges
(`remotepower_slo_object_target_percent`, `…_availability_percent`,
`…_budget_remaining_percent`) for Grafana SLO dashboards. The budget and
burn-rate gauges are omitted while the window is too coarse to resolve the
target, so a Grafana panel never reads an unmeasurable budget as a real
breach; `availability` is always exported.

## Service monitoring

Watch specific systemd units per host (`watched_services`) on **Monitoring →
Services**. The agent reports each unit's state in its heartbeat; a stopped unit
raises **`service_down`** and a recovered one **`service_up`**. Service baselines
let you snapshot the expected running set and alert on deviation.

## Mail round-trip

The **Mail round-trip** button on the Remote checks card measures real mail
delivery from end to end. RemotePower sends a token-stamped e-mail through your
outbound SMTP server (**Settings → Notifications → Email notifications (SMTP)**
must be set up) to a probe address, then looks for it in that mailbox over IMAP.
It deletes the probe message once it finds it.

Fill in the probe address, the IMAP host, port, user, password and folder, and
tick **Enabled**. **Use SSL/TLS** and **Verify TLS certificate** are on by default;
untick the second for an internal IMAP server with a self-signed certificate.
**Max round-trip latency** is how long a probe may take, 30 seconds or more and 300
by default. RemotePower checks about every five minutes: one check sends a probe and
the next looks for it in the mailbox, so a probe goes out about every ten minutes
and the latency it records is the time up to the check that found the mail, never
less than five minutes. A probe that is still missing at the first check after the
limit raises **`mailflow_delayed`**. With the default of 300 seconds that is ten
minutes after it was sent. **`mailflow_ok`** follows when a probe gets through
again. The IMAP password is write-only and an empty field keeps the stored one.
Only admins can change these settings.

## Log-tail alerts

Two layers, both firing **`log_alert`**:

- **Per-host** log-watch rules (`log_watch`): `{unit, pattern, threshold,
  severity}` — the agent tails the unit's journal and reports matches.
- **Fleet-wide** rules (**`/api/logs/rules/global`**): a pattern + threshold +
  optional `exclude_pattern` and a `file:/path/to/log` synthetic unit for tailing
  a plain file. Managed on the Logs page. See [Logs](log-watch.md).

## Inbound receivers (syslog & SNMP traps)

Hosts and appliances can push to tokenised, admin-created endpoints (tokens
start with `rpwi_`, managed as inbound webhooks):

- **Syslog** — `POST /api/syslog/in/{token}` accepts `{lines:[…]}`, a bare JSON
  array, or plain newline-separated text. A syslog token is pinned to one host.
  Lines are parsed for severity and run through the log rules for the unit
  `syslog` (fires `log_alert`).
- **Alerts** — `POST /api/webhook/in/{token}` lands an external system's alert
  in the inbox. The sender's own payload shape is **adapted**: Prometheus
  Alertmanager, Grafana (legacy and unified), Authentik, or RemotePower's own
  `{severity, title, body, device}`. Detected automatically, or pinned on the
  token. A **resolved** notification closes the alert it opened, and a repeat
  firing updates that alert with a repeat count rather than adding a row — so
  a re-notifying source does not fill the inbox.
- **SNMP traps** — `POST /api/snmp/trap/{token}` accepts `{traps:[{oid,value,…}]}`
  or a single trap; a decoding trapd feeds it. New traps raise
  **`snmp_trap_received`**. Well-known OIDs are resolved to their MIB name on
  ingest, so the alert reads `upsOnBattery` rather than a bare dotted string.

### Trap rules

**Settings → Integrations → SNMP trap rules** decides what a trap *means*. A
rule matches an **OID prefix** — and optionally a regex against the value — and
sets the alert severity, or `ignore` to drop the trap without alerting at all.

- **Longest prefix wins.** A rule on `1.3.6.1.4.1.318.0.5` (upsOnBattery) beats
  a broad `1.3.6.1.4.1.318` rule added later, so you never have to reorder.
- **Traps matching different rules stay in different alerts.** The matched rule
  name is part of the alert's identity, so a UPS on battery and a chatty
  linkDown from the same switch do not fold into one row where acknowledging
  the noise buries the outage.
- A rule can be scoped to a single host, or left fleet-wide. The severity is
  `critical`, `high`, `medium`, `low`, `info` or `ignore`. You can keep up to 200
  rules.
- A trap that matches no rule raises one coalesced `medium` alert per host.
- **Test before you wait for 3am.** `POST /api/snmp/trap-rules/test` with
  `{oid, value}` (or the Test box on the settings pane) reports which rule would
  match and what it would do — a mistyped OID prefix otherwise looks exactly
  like a correct one until the host happens to emit.

`GET/POST /api/snmp/trap-rules`, `PATCH/DELETE /api/snmp/trap-rules/{id}`.

**SNMP polling** is separate: per host, `POST /api/devices/{id}/snmp/poll` polls
now and `GET /api/devices/{id}/snmp/deep` runs a deep inspection.

## Resolver health & watchdog

- **Resolver health** monitor: names you register are resolved at several vetted
  public resolvers on a cadence; latency, NXDOMAIN and failure counts are
  tracked, and a name that stops resolving raises **`resolver_unhealthy`** (and
  `resolver_recovered` when it comes back). See [DNS](dns.md).
- **Healthchecks.io watchdog.** Set the ping URL under **Settings →
  Notifications → Healthchecks.io watchdog** and RemotePower pings it every
  `healthchecks_interval_seconds` (60 by default, at least 30), so an external
  dead-man's-switch alerts *you* if the control plane itself goes dark.
- **Server disk watchdog.** **Settings → Alert parameters → Hardware & power →
  Server disk** (`disk_watchdog_pct`, default 85, 0 = off) raises
  `server_disk_low` when the data volume fills, and `server_disk_ok` when it
  recovers.

## Prometheus exposition

`GET /api/metrics` renders everything above — and most of what the rest of the
product measures — as Prometheus text exposition, for Grafana or an external
alertmanager. Authenticate with an operator session token, or with the dedicated
**status token** that you generate under **Settings → Integrations → Status
endpoint**, which is the usual choice for a scrape config:

```yaml
scrape_configs:
  - job_name: remotepower
    metrics_path: /api/metrics
    params:
      token: ['<status token>']
    scheme: https
    static_configs:
      - targets: ['remote.example.com']
```

A session caller sees only the hosts their role and tenant allow. A scrape with
the status token sees the whole instance.
[`prometheus-metrics-sample.txt`](prometheus-metrics-sample.txt) is real output
from a small seeded fleet; ready-made dashboards live in
[`contrib/grafana/`](../contrib/grafana/).

Every per-host family carries `device`, `name` and `group` labels, so a
dashboard can slice by host or by group without a join.

| Family | What it exposes |
| --- | --- |
| `remotepower_info`, `remotepower_devices_total`, `remotepower_devices_online`, `remotepower_device_online`, `remotepower_device_last_seen_timestamp_seconds` | Build version and fleet reachability |
| `remotepower_device_cpu_percent`, `…_mem_percent`, `…_disk_percent` | Per-host resource utilisation |
| `remotepower_device_swap_percent`, `…_fd_percent`, `…_conntrack_percent`, `…_cpu_iowait_percent`, `…_cpu_steal_percent`, `…_loadavg_1m` | More resource gauges: swap, open file descriptors and connection tracking as a share of their limit, CPU time spent waiting for I/O or taken by the hypervisor, and the one-minute load average |
| `remotepower_device_cpu_count`, `…_memory_total_bytes`, `…_disk_total_bytes` | Logical CPUs, physical memory and root filesystem size |
| `remotepower_device_failed_units`, `remotepower_device_mount_issues` | systemd units in a failed state and mount points reporting a problem |
| `remotepower_device_custom_metric` | The operator-defined metrics an agent reports |
| `remotepower_scrape_error` | 1 when the last scrape hit an internal error and returned a reduced exposition, otherwise 0 |
| `remotepower_device_upgradable_packages`, `remotepower_device_cve_findings`, `remotepower_cve_fixable_total` | Patch backlog and vulnerability findings (by `severity`) |
| `remotepower_monitor_up`, `remotepower_monitor_last_check_timestamp_seconds`, `remotepower_monitor_availability_percent` | The remote checks above |
| `remotepower_slo_target_percent`, `remotepower_monitor_slo_budget_remaining_percent`, `remotepower_monitor_slo_burn_rate`, `remotepower_slo_object_*` | SLO targets, error budgets and burn rate |
| `remotepower_service_active`, `remotepower_services_down_total` | Watched systemd units |
| `remotepower_fleet_health_score`, `remotepower_device_health_score`, `remotepower_attention_items` | Fleet health and the Needs-Attention digest behind it |
| `remotepower_script_state`, `remotepower_script_perf_value` | The state (0 ok, 1 warning, 2 critical, 3 unknown) of each custom monitoring script on a host, and the performance values of a script read as a Nagios plugin *(7.4.9)* |
| `remotepower_maintenance_windows_active`, `remotepower_commands_pending_total`, `remotepower_scheduled_jobs_total`, `remotepower_webhook_deliveries_total`, `remotepower_webhook_log_size`, `remotepower_control_plane_uptime_percent`, `remotepower_timeline_events_24h` | Control-plane state |

### Hardware, backup and posture families

These signals drive RemotePower's own alerts, drawers and scores, and they reach
the exporter too, so you can alert in Grafana on a failing drive, a UPS on
battery or a stale backup. Each block is emitted only when the underlying store
has data.

| Family | Extra labels | Notes |
| --- | --- | --- |
| `remotepower_device_temperature_celsius` | `sensor` | One series per reading. `sensor` is the board sensor label, `disk:<dev>` for a SMART drive, or `gpu:<name>` |
| `remotepower_device_temperature_max_celsius` | — | Hottest reading on the host, across all three sources |
| `remotepower_device_smart_disk_healthy` | `disk`, `model` | 1/0 from the **server-side** SMART verdict — the same one the alert, the digest and the badge use, not a second copy of the rule |
| `remotepower_device_smart_disks_failed` | — | Drives currently failing that verdict, per host |
| `remotepower_device_smart_reallocated_sectors`, `…_pending_sectors` | `disk` | The pre-fail counters behind the verdict |
| `remotepower_device_smart_power_on_seconds` | `disk` | Power-on time in **seconds** (the store keeps hours) |
| `remotepower_device_smart_wear_ratio`, `…_spare_ratio` | `disk` | SSD/NVMe endurance consumed and remap reserve left, as **0–1 ratios** (the store keeps percentages) |
| `remotepower_ups_on_battery` | `ups` | 1 when running on battery, using the same `OB`/`BATT` test as the `ups_on_battery` alert, so a dashboard and an alert cannot disagree |
| `remotepower_ups_battery_charge_ratio`, `remotepower_ups_load_ratio` | `ups` | 0–1 ratios |
| `remotepower_ups_runtime_seconds`, `remotepower_ups_input_volts`, `remotepower_ups_power_watts` | `ups` | Runtime left, line voltage, output draw |
| `remotepower_backup_ok`, `remotepower_backup_age_seconds` | `path` | Freshness of each watched backup path — see [backups.md](backups.md) |
| `remotepower_backup_max_age_seconds` | `path` | The configured threshold, emitted **only** where a monitor names that path, so a rule comparing age against it never compares to an invented default |
| `remotepower_device_disk_fill_eta_seconds` | — | Predicted time to a full filesystem, emitted only for hosts already trending full — see [forecast.md](forecast.md) |
| `remotepower_device_risk_score`, `remotepower_risk_devices` | `level` on the rollup | Security-posture risk, 0–100, higher is worse — see [risk.md](risk.md) |
| `remotepower_device_reliability_score`, `remotepower_reliability_devices` | `level` on the rollup | Predicted hardware failure — see [disk-health.md](disk-health.md) |
| `remotepower_compliance_pass_ratio`, `remotepower_compliance_devices_evaluated` | — | Fleet baseline compliance, severity-weighted, as a 0–1 ratio |
| `remotepower_device_compliance_pass_ratio` | — | Per-host, omitted when no check applied (a 0 would read as total failure) |
| `remotepower_compliance_check_devices` | `check`, `severity`, `result` | Host counts per outcome for one baseline control, so a panel can name the failing check — see [compliance.md](compliance.md) |
| `remotepower_compliance_framework_score`, `remotepower_compliance_framework_controls` | `framework`, plus `status` (pass, fail or na) on the controls | Score (0–100) and control counts for one compliance framework |
| `remotepower_device_bruteforce_sources` | — | Sources currently over the brute-force threshold on the host; quiet hosts are omitted |
| `remotepower_device_known_attackers_unblocked`, `remotepower_device_ip_blocks_active` | — | Known-abusive sources that attacked the host this week and are not blocked, and blocks in place — see [ip-intel.md](ip-intel.md) |
| `remotepower_sshgw_devices_opted_in`, `remotepower_sshgw_tunnels_connected`, `remotepower_sshgw_sessions_24h` | — | SSH gateway reach, live agent tunnels and recent sessions, emitted only when the module is on — see [sshgw.md](sshgw.md) |
| `remotepower_edge_feed_up`, `remotepower_edge_feed_age_seconds` | `feed` (`cloudflare`, `honeypot`) | Whether each edge feed's last read worked and how long ago it was, emitted only while edge sources are on — see [edge-sources.md](edge-sources.md) |
| `remotepower_edge_blocklist_entries`, `remotepower_edge_blocklist_up`, `remotepower_edge_blocklist_held`, `remotepower_edge_blocklist_sync_age_seconds`, `remotepower_edge_bans_active` | — | The Cloudflare IP list RemotePower keeps: entries, whether the last sync failed, whether one waits for an operator, its age, and live edge bans. Emitted only while the Edge blocklist is on |
| `remotepower_ip_intel_attackers_24h` | — | Addresses Threat Intel recorded in the last 24 hours, from hosts and from the edge |

The three edge rows are instance-level. A scrape with the status token and a platform operator's session get them; a role-scoped or tenant session does not.

Health, risk and reliability are three separate families, not one
number: health is the Needs-Attention rollup, risk is security posture, and
reliability is predicted hardware failure. Folding them together would lose the
distinction the product makes everywhere else.

## Permissions

- Viewing check status needs normal authentication.
- Adding/editing checks, log rules, inbound tokens and resolver-health targets is
  **admin-only**; inbound receiver endpoints authenticate by their `rpwi_` token,
  not a session.
- Pausing and resuming a check needs an admin or a role that can run actions.
- All targets/URLs are SSRF-guarded (link-local and cloud-metadata addresses are
  always refused, loopback unless you allow it).

## With multi-tenancy

The monitors, their history and the export belong to the organisation that runs the installation. With tenant isolation on, only users of the default tenant can open or change them. Users of every other tenant are refused, and the dashboard leaves them out of its summaries.

## See also

- [Logs](log-watch.md): log rules, clearing a noisy line.
- [Alerts](alerts.md): where `monitor_down`, `service_down` and the rest land.
- [Maintenance windows](maintenance.md): hold notifications while a target is down on purpose.
- [Integrations](integrations.md): health checks for the software your hosts run.
- [Inbound tokens](inbound-tokens.md): syslog, alert and SNMP trap endpoints.
