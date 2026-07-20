# Syslog ingestion

Devices that can't run an agent — switches, firewalls, printers, NAS boxes,
appliances — almost always speak **syslog**. RemotePower accepts their log
lines two ways and runs them through the same log-watch buffer and alert-rule
engine as agent-shipped journal lines, so a matching line pages you exactly
like any other host would.

Both paths land in the 6-hour rolling **Monitoring → Logs** buffer under a
synthetic `syslog` unit, and both evaluate your per-device and global
`log_alert` rules. See [log-watch.md](log-watch.md) for the buffer and rule
editor.

## Two ways in

### 1. HTTP push (rsyslog / fluent-bit / any HTTP client)

Point an HTTP log shipper at the per-device ingest endpoint:

```
POST /api/syslog/in/{token}
```

The token is an **inbound-webhook token of kind `syslog`**, created under
**Settings → Integrations → Inbound webhooks** and pinned to one device. The
token's scope decides which device the lines attach to — the URL carries no
device id. The body is either `{"lines": ["…", "…"]}` or a bare JSON array of
lines; up to 200 lines per POST. Each line's RFC 3164 / RFC 5424 `<PRI>`
prefix is parsed for severity (emerg…debug); a line with no valid `<PRI>` is
kept whole at severity *info*.

This path suits anything that can make an authenticated HTTPS request —
rsyslog `omhttp`, fluent-bit, Vector, or a one-off shipper.

### 2. Native UDP listener (`remotepower-syslogd`) *(v6.3.0)*

Most appliances only emit classic UDP syslog and can't add an auth header. The
optional **`remotepower-syslogd`** sidecar listens for UDP datagrams, maps each
datagram's **source IP** to the enrolled device that carries that IP, and
forwards the raw lines over loopback to the same `POST /api/syslog/in/{token}`
endpoint. Parsing, buffering, rule evaluation and token accounting all stay in
one place — the daemon is a thin network shim with no state of its own.

For a source to be accepted it needs **both**:

- an enrolled device whose **`ip`** equals the datagram's source address, and
- an enabled inbound-webhook token of **kind `syslog`** pinned to that device.

Unknown sources are dropped and logged at most once per 10 minutes each, so a
misconfigured sender can't flood the journal. Lines are batched per source and
flushed every couple of seconds (or at 200 lines), so a burst is one POST, not
one request per datagram.

#### Running the listener

The sidecar ships as a systemd unit (`remotepower-syslogd.service`). It runs
fully sandboxed under `DynamicUser` with read-only access to the data dir and
no secrets of its own.

```
systemctl enable --now remotepower-syslogd
```

Defaults (override with `systemctl edit`):

| Setting | Env var | Default |
|---|---|---|
| Listen address | `RP_SYSLOG_BIND` | `0.0.0.0:5514` |
| Loopback API base | `RP_SYSLOG_SERVER_URL` | `http://127.0.0.1:8090` |
| Data dir | `RP_DATA_DIR` | `/var/lib/remotepower` |

It listens on **udp/5514** (an unprivileged port) by default. To use the
classic **udp/514**, set `RP_SYSLOG_BIND=0.0.0.0:514` and give the unit
`AmbientCapabilities=CAP_NET_BIND_SERVICE` (both are commented placeholders in
the shipped unit).

Point your appliances' syslog target at the server on that port and make sure
each appliance's source IP matches its device record's `ip`.

## Retention

The log-watch buffer is a short-retention **operational triage window**, not an
archive. For long-term retention, keep shipping to a real log store alongside
RemotePower (the two aren't mutually exclusive — an appliance can fan out to
both).

## See also

- [log-watch.md](log-watch.md) — the buffer, live tail, and alert rules.
- [agentless-devices.md](agentless-devices.md) — records for devices with no agent.
- [integrations.md](integrations.md) — inbound-webhook tokens.
