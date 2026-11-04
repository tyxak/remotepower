# Data Explorer

Ask arbitrary questions of your fleet. Pick what you want rows of, add conditions, run it, save it
as a template and share it with your team. You find it under **Automation → Data Explorer**.

It is **read-only**, and it is scoped to what you can already see: a query
cannot return a host your role or tenant would hide from you elsewhere.

Not to be confused with **[Fleet Query](fleet-query.md)** (**Fleet → Query**), which is the quick
host filter made of ready-made boxes. Data Explorer works on ten kinds of rows, not only hosts,
and its API accepts nested AND/OR/NOT conditions.

## Using the page

1. Choose the **Entity** (see below).
2. Click **Add condition**. Each condition is a field, an operator and a value. Use as many as you
   need. The page joins them with AND. The operator **in** takes a comma-separated list, and **is
   set** needs no value. A value that looks like a number is sent as a number.
3. Optionally choose **Sort by** and a direction.
4. Click **Run query**. The table shows the first rows and says how many matched.
5. To keep the query, type a template name, tick **Shared with team** if you want that, and click
   **Save as template**. Saved queries are listed on the page with **Run** and **Delete** buttons.

The page builds a flat AND list because that covers most questions. For OR and NOT, call the API
(see [API](#api)); the same engine runs both.

## The ten entities

The page lists them by these names.

| Entity | One row per | Use it for |
|---|---|---|
| `devices` | host | posture, telemetry, inventory |
| `cves` | (host, finding) | "which hosts still have a critical CVE in openssl" |
| `drift` | (host, watched file) | "which hosts have drifted from baseline on /etc/ssh/sshd_config" |
| `packages` | (host, installed package) | "which hosts still run openssl 3.0.x" |
| `ports` | (host, listening socket) | "who listens on 3306, and is it reachable from the world" |
| `services` | (host, watched unit) | "which units are failed, and which are quietly restarting" |
| `containers` | (host, container) | "what is stopped, and what keeps restarting" |
| `alerts` | alert | "every open critical on hosts in the prod group" |
| `attackers` | (source address, attacked host) | "which known-abusive addresses are hitting the web tier, and are they blocked" |
| `gateway_sessions` | finished SSH-gateway session | "who reached the database hosts through the gateway this week" |

## Conditions

A condition is a field, an operator and a value:

```json
{"field": "disk_pct", "op": "gt", "value": 90}
```

Combine them with `and`, `or` and `not`, nested up to six deep:

```json
{"and": [{"field": "tags", "op": "contains", "value": "prod"},
         {"field": "disk_encrypted", "op": "eq", "value": false}]}
```

Operators: `eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `contains`
(case-insensitive substring), `in` (value is a list), `exists`.

`exists` means *present and not empty*, which is worth knowing for the
tri-state fields below.

## Host fields

### Identity and inventory

| Field | Notes |
|---|---|
| `device_id`, `name`, `group`, `site`, `tags` | `tags` is comma-joined, so use `contains` |
| `hostname` | the host's own current hostname, not the name it enrolled under |
| `os`, `kernel`, `chassis` | `chassis` distinguishes a laptop from a server |
| `agent_version`, `agentless`, `monitored` | |
| `online`, `last_seen` | `last_seen` is a unix timestamp, so it sorts and compares |

### Load and capacity

`cpu_pct`, `mem_pct`, `disk_pct`, `swap_pct`, `loadavg_1m`, `cpu_count`,
`mem_total_mb`, `disk_total_gb`, `fd_pct`, `conntrack_pct`, `uptime_seconds`.

`uptime_seconds` is the numeric one — the human "up 3 weeks" string is not
sortable, which is why nothing could rank hosts by uptime before.

### Health

| Field | Notes |
|---|---|
| `reboot_required` | an update is installed and waiting on a reboot |
| `failed_units`, `mount_issues` | counts, so `gt 0` finds any |
| `quarantined_files` | files the integrity guard has quarantined |
| `listening_ports` | how many, not which — use the Exposure page for which |
| `metrics_limited` | the agent said its own metrics are limited. Distinguishes a host with no CPU figure from an idle one |

### Updates

| Field | Notes |
|---|---|
| `pending_updates` | packages the host's package manager would upgrade |
| `security_updates` | the part of that your distribution flags as security fixes (apt, dnf, and pacman with `arch-audit`) |

Both are empty when the host has not reported a package scan, so a host that was never checked is not read as
"nothing waiting". `{"field": "security_updates", "op": "gt", "value": 0}` finds the hosts that reported a fix
waiting.

### Security posture

| Field | Notes |
|---|---|
| `disk_encrypted` | LUKS / BitLocker / FileVault |
| `firewall_active` | any host firewall backend with an active ruleset |
| `secure_boot` | |
| `autoupdate_enabled`, `autoupdate_mechanism` | |
| `ssh_root_login`, `ssh_password_auth`, `ssh_empty_passwords`, `ssh_x11_forwarding` | the resolved sshd values, as strings (`"no"`, `"yes"`, `"prohibit-password"`) |
| `clock_synced`, `clock_offset_ms` | a skewed clock breaks log correlation and certificate validation |
| `battery_pct`, `battery_health_pct` | |
| `audit_mode` | the agent is in read-only mode and refuses every command |
| `usb_devices` | how many USB devices the host reports attached; empty when it never reported |
| `logged_in_users` | how many interactive sessions are open on the host right now |
| `sshgw_enabled` | the host is opted in to the [SSH gateway](sshgw.md) |

**The posture booleans are tri-state, and this matters when you write a
query.** `false` means the host reported, and the answer is no. **Absent** means
the host never told us — a Windows box does not report sshd, and a container
host may not be able to see device-mapper.

So `{"field": "disk_encrypted", "op": "eq", "value": false}` finds hosts that
told you their disks are not encrypted. It does **not** include hosts that said
nothing, which is what you want: a list of findings should not be padded with
hosts that were never asked. To find the silent ones, use `not` + `exists`.

## The other entities' fields

### `cves`

`device_id`, `device_name`, `cve_id`, `severity`, `package`, `fixed_version`, `fix_status`,
`ignored`.

`fix_status` is `fixed`, `newer_release`, `none` or `unknown`, as explained in
[cve.md](cve.md#fix-status). `ignored` is true for a finding you accepted as a risk. These rows
are the stored scan results, so they are as fresh as the last CVE scan.

### `drift`

`device_id`, `device_name`, `path`, `drifted`, `exists`, `dormant`, `ignored`.

`drifted` is true when the file's current hash differs from its baseline and the file is
neither dormant nor ignored. `exists` is false when the file is gone. See [drift.md](drift.md).

### `packages`

`device_id`, `device_name`, `package`, `version`, `ecosystem`.

Versions are strings, so compare them with `contains` (`"3.0."`) rather than
`gt` — a string comparison would put `3.10` before `3.9`.

The scan stops at 100,000 rows, because a large fleet reports more installed
packages than any single answer needs. When it stops, the response says so in
`meta.truncated`, so a partial answer is never presented as a complete one.

### `ports`

`device_id`, `device_name`, `proto`, `port`, `process`, `addr`, `scope`.

`scope` is the one to reach for: `world` means the socket is bound somewhere
reachable off the host, `lan` means the local network, `local` means loopback.
"Which of my hosts expose a database to the world" is `port` plus
`scope eq world`.

### `services`

`device_id`, `device_name`, `unit`, `canonical`, `active`, `sub`, `since`,
`restarts`, `flapping`, `running`.

`canonical` is what systemd actually matched, which differs from `unit` when
you watch an alias (`mysql.service` resolving to `mariadb.service`).

`flapping` is worth knowing about: a unit crash-looping under `Restart=always`
reads `active` every time it is sampled, because it comes back before the next
heartbeat. Only the restart count reveals it, so an `active`/`failed` query
will never find one.

### `containers`

`device_id`, `device_name`, `name`, `image`, `tag`, `status`, `runtime`,
`health`, `restart_count`, `running`.

`status` is the runtime's own wording, which differs between Docker, Podman and
Kubernetes (`Up 3 days`, `running`, `Ready`). `running` is the normalised
boolean, and it is the same test the Hosts page counts with, so the two
cannot disagree.

### `alerts`

`alertid`, `event`, `severity`, `title`, `device_id`, `device_name`, `status`,
`source`, `ts`, `first_seen`, `acknowledged_by`, `resolved_by`.

`status` is `open`, `ack` or `resolved`. `first_seen` is when the condition
first fired and `ts` is the most recent occurrence — they differ for a repeating
alert, and `first_seen` is the one to measure how long something has been
broken.

Alerts are the one entity where a row need not belong to a host: a fleet-level
condition such as a failed backup has no `device_id`, and those rows stay
visible to you.

### `attackers`

`ip`, `device_id`, `device_name`, `unit`, `count`, `score`, `reports`,
`country`, `isp`, `usage`, `blocked`, `reported`, `first_seen`, `last_seen`,
`source`, `classes`, `reported_to`, `in_edge_list`, `edge_banned`.

One row for each source address on each place that saw it, as
[IP intel](ip-intel.md) recorded it. `score` is the merged reputation (0–100)
and is empty until a lookup has run; `blocked` is whether the address is blocked
on that host right now; `reported` is whether it has been reported to a
reputation service.

`source` is `host` or `edge`. An edge row's `device_id` is `edge:cloudflare` or
`edge:trap` (the honeypot), and it exists for an address only Cloudflare or the
honeypot saw. `classes` lists what it did (`probe`, `sqli`, `bad_bot` and so on,
most telling first), and `reported_to` names the services that were told.
`in_edge_list` and `edge_banned` say whether the [Cloudflare IP
list](edge-sources.md#edge-blocklist) holds the address and whether a ban at the
edge is in force.

The edge belongs to the instance, not to a host. Edge rows, `in_edge_list` and
`edge_banned` are for the platform operator; everyone else gets host rows, and
those two columns are empty.

### `gateway_sessions`

`username`, `device_id`, `device_name`, `client_ip`, `fingerprint`, `started`,
`duration_s`, `bytes_in`, `bytes_out`, `reason`.

Finished [SSH gateway](sshgw.md) sessions. Visible to admins and auditors, the
same people who see the session list on the gateway page; for every other role
the entity returns no rows.

## Saved queries

Saved on the server, not in your browser. Private to your account by default,
tenant-scoped, shareable with your team when you choose. Data Explorer,
Fleet Query and the metric explorer on Trends share one store, and each page lists
only its own kind of query. You can delete your own saved queries, and an admin can delete any.

## API

`POST /api/query` runs one query:

```json
{"entity": "ports",
 "where": {"and": [{"field": "port", "op": "eq", "value": 3306},
                   {"field": "scope", "op": "eq", "value": "world"}]},
 "sort": "device_name", "sort_desc": false, "limit": 500, "offset": 0}
```

The answer has `rows` and a `meta` object with `total` (rows that matched), `limit`, `offset` and
`truncated`. `limit` defaults to 500 and is capped at 2,000. `truncated` is true when the scan of
the entity hit its row cap (100,000 rows), so `total` counts what was scanned.

- `GET /api/query/fields` returns the entities and their fields.
- `POST /api/query/batch` runs up to 10 queries in one call. A bad query returns an `error` entry at
  its position and does not stop the others.
- `GET /api/query/templates` and `POST /api/query/templates` list and create saved queries.

An unknown entity, field or operator returns HTTP 400 with the reason. See [api.md](api.md) for
authentication.

## Limits

A predicate is capped at 100 nodes and six levels of nesting. Both are cost
guards: a wide shallow tree with thousands of leaves is as expensive as a deep
one.

There is no raw SQL. Every entity's rows are fetched through the
same path every other page uses, so the tenant and role scoping that applies to
your data elsewhere applies here without a second implementation to keep in
step. See [scaling.md](scaling.md) for how that scoping works.

## See also

[fleet-query.md](fleet-query.md), [cve.md](cve.md), [drift.md](drift.md),
[exposure.md](exposure.md), [sshgw.md](sshgw.md), [ip-intel.md](ip-intel.md).
