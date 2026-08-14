# Data Explorer

Ask arbitrary questions of your fleet. Build a condition tree, run it, save it
as a template, share it with your organisation.

It is **read-only**, and it is scoped to what you can already see — a query
cannot return a device your role or tenant would hide from you elsewhere.

Not to be confused with **[Fleet Query](fleet-query.md)**, which is the quick
one-line device filter in the toolbar. Data Explorer is the one with nested
AND/OR conditions across three entities.

## The three entities

| Entity | One row per | Use it for |
|---|---|---|
| `devices` | host | posture, telemetry, inventory |
| `cves` | (host, finding) | "which hosts still have a critical CVE in openssl" |
| `drift` | (host, watched file) | "which hosts have drifted from baseline on /etc/ssh/sshd_config" |

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

## Device fields

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

**The posture booleans are tri-state, and this matters when you write a
query.** `false` means the host reported, and the answer is no. **Absent** means
the host never told us — a Windows box does not report sshd, and a container
host may not be able to see device-mapper.

So `{"field": "disk_encrypted", "op": "eq", "value": false}` finds hosts that
told you their disks are not encrypted. It does **not** include hosts that said
nothing, which is what you want: a list of findings should not be padded with
hosts that were never asked. To find the silent ones, use `not` + `exists`.

## Saved queries

Saved on the server, not in your browser. Private to your account by default,
tenant-scoped, shareable with your organisation when you choose. Data Explorer,
Fleet Query and Trends share the same store.

## Limits

A predicate is capped at 100 nodes and six levels of nesting. Both are cost
guards — a wide shallow tree with thousands of leaves is as expensive as a deep
one.

There is no raw SQL, deliberately. Every entity's rows are fetched through the
same path every other page uses, so the tenant and role scoping that applies to
your data elsewhere applies here without a second implementation to keep in
step. See [scaling.md](scaling.md) for how that scoping works.
