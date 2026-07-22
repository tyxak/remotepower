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

#### Installing the listener

The daemon is **optional and opt-in** — `install-server.sh` does *not* install
it, so add it only on the server that will receive appliance syslog. It's a
single self-contained Python script (standard library only, no extra deps) plus
a systemd unit. From the release tarball or a source checkout:

```
# 1. Install the daemon and its unit
sudo install -m 755 server/syslog/remotepower-syslogd.py /usr/local/bin/remotepower-syslogd
sudo install -m 644 packaging/remotepower-syslogd.service /etc/systemd/system/

# 2. Enable and start it
sudo systemctl daemon-reload
sudo systemctl enable --now remotepower-syslogd
```

That's the whole install. The unit runs fully sandboxed under `DynamicUser`
with read-only access to the data dir and no secrets of its own. *(The AUR
`remotepower-server` package ships the same unit under `/usr/share/doc/` — copy
it into `/etc/systemd/system/` the same way.)*

#### Before logs will be accepted — the two prerequisites

A source is only accepted if **both** are true (this is the auth model — there is
no header to forge), so set these up first:

1. **A device record carrying the appliance's IP.** Add the appliance under
   *Devices → Add* as an [agentless device](agentless-devices.md) whose `ip`
   field is the exact source address its datagrams come from.
2. **A syslog token pinned to that device.** Under *Settings → Integrations →
   Inbound webhooks*, create a token of **kind `syslog`** scoped to the device.
   The daemon resolves source IP → device → token itself; the token never touches
   the appliance.

Then point the appliance's syslog target at the server on the listen port.

#### Configuration

Defaults — override in a drop-in with `sudo systemctl edit remotepower-syslogd`:

| Setting | Env var | Default |
|---|---|---|
| Listen address | `RP_SYSLOG_BIND` | `0.0.0.0:5514` |
| Loopback API base | `RP_SYSLOG_SERVER_URL` | `http://127.0.0.1:8090` |
| Data dir | `RP_DATA_DIR` | `/var/lib/remotepower` |

It listens on **udp/5514** (unprivileged) by default. For the classic
**udp/514**, uncomment the two placeholder lines in the shipped unit (or add
them in a `systemctl edit` drop-in):

```
[Service]
Environment=RP_SYSLOG_BIND=0.0.0.0:514
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

#### Verifying it works

```
systemctl status remotepower-syslogd     # active (running)
journalctl -u remotepower-syslogd -f     # 'listening on udp/…' at startup
```

Send a test datagram from an accepted source (or the appliance itself):

```
logger -n <server-ip> -P 5514 -d "hello from $(hostname)"
```

Within a couple of seconds the line appears in that device's **Logs** tab (the
log-watch buffer) and drives its log-alert rules. If nothing shows up, the
journal names the reason — see *Checking it arrived* below, which lists each
drop message and what to do about it.

## Pointing a client at it

Below, `<server-ip>` is the host running `remotepower-syslogd` and `5514` is the
listen port (use `514` if you moved it). Two rules apply to every client:

- **Send from the IP the device record carries.** The source address *is* the
  authentication, so a box with several interfaces must send from the one in the
  device's `ip` field — most daemons let you pin it, and the examples do.
- **Prefer UDP.** The listener is UDP-only; a client configured for TCP or TLS
  syslog will connect to nothing. Use the HTTP push path instead when you need a
  reliable or encrypted transport.

### rsyslog (most Linux distributions)

`/etc/rsyslog.d/90-remotepower.conf`:

```
# Forward everything; @ = UDP (@@ would be TCP, which the listener does not speak)
*.*  @<server-ip>:5514
```

To pin the source interface on a multi-homed host, and to keep a bounded queue
so a RemotePower outage can never block local logging:

```
$ActionQueueType LinkedList
$ActionQueueSize 10000
$ActionResumeRetryCount -1
$ActionSendUDPRebindInterval 100
*.*  @<server-ip>:5514
```

Then `sudo rsyslogd -N1 && sudo systemctl restart rsyslog`.

### syslog-ng

```
destination d_remotepower { udp("<server-ip>" port(5514)); };
log { source(s_src); destination(d_remotepower); };
```

### systemd-journald only (no syslog daemon)

journald does not forward over the network. Either install rsyslog as above, or
— better on a host you control — install the RemotePower **agent**, which ships
journal excerpts with its heartbeat and needs no syslog at all. The UDP listener
exists for appliances you *can't* put an agent on.

### MikroTik RouterOS

```
/system logging action add name=remotepower target=remote remote=<server-ip> remote-port=5514
/system logging add topics=info,error,warning,critical action=remotepower
```

Check `src-address` on the action if the router has several WAN/LAN addresses.

### OPNsense / pfSense

*System → Settings → Logging / Remote Logging* → add a destination
`<server-ip>:5514`, transport **UDP**, and select the log categories to send.
Set *Source address* to the interface whose IP the device record carries.

### VMware ESXi

```
esxcli system syslog config set --loghost=udp://<server-ip>:5514
esxcli system syslog reload
esxcli network firewall ruleset set --ruleset-id=syslog --enabled=true
```

### Switches, printers, UPSes, NAS appliances

Almost all expose a single "syslog server" field in their web UI: enter
`<server-ip>`, set the port to `5514`, pick UDP, and save. If the appliance only
allows port 514, move the listener to 514 (see *Configuration* above) rather
than fighting the device.

### Windows

Windows has no built-in syslog sender. Use the RemotePower **Windows agent**
(it reads the Event Log directly and needs none of this), or a forwarder such as
nxlog/winlogbeat pointed at `<server-ip>:5514` over UDP.

### Checking it arrived

```
# on the RemotePower server
journalctl -u remotepower-syslogd -f
```

- Lines flowing, nothing in the UI → the batch is in flight; wait a couple of
  seconds and refresh the device's **Logs** tab.
- `dropping syslog from unknown source <ip>: no enrolled device has this IP` →
  fix the device record's `ip`, or the sender's source address.
- `dropping syslog from <ip>: the device IS enrolled but has no enabled syslog
  ingest token` → create one under *Settings → Integrations → Inbound webhooks*
  (kind `syslog`), scoped to that device.
- Nothing at all in the journal → the datagrams aren't arriving. Check the
  server's firewall (`sudo ss -lun | grep 5514` should show the listener) and
  that the client is really using UDP.

## Retention

The log-watch buffer is a short-retention **operational triage window**, not an
archive. For long-term retention, keep shipping to a real log store alongside
RemotePower (the two aren't mutually exclusive — an appliance can fan out to
both).

## See also

- [log-watch.md](log-watch.md) — the buffer, live tail, and alert rules.
- [agentless-devices.md](agentless-devices.md) — records for devices with no agent.
- [integrations.md](integrations.md) — inbound-webhook tokens.
