# Syslog ingestion

Hosts that can't run an agent — switches, firewalls, printers, NAS boxes,
appliances — almost always speak **syslog**. RemotePower accepts their log
lines two ways and runs them through the same log-watch buffer and alert-rule
engine as agent-shipped journal lines, so a matching line pages you exactly
like any other host would.

Both paths land in the rolling **Monitoring → Logs** buffer (6 hours by default,
tunable — see [log-watch.md](log-watch.md)) under a
synthetic `syslog` unit, and both evaluate your per-host and global
`log_alert` rules. See [log-watch.md](log-watch.md) for the buffer and rule
editor.

> **Where does the token go?** If a firewall, switch or printer sends the
> syslog, nowhere. It sends plain UDP, and the receiver on the RemotePower
> server finds the token from the sender's IP address. Only a tool that posts
> over HTTP uses the token as a URL. [Inbound tokens](inbound-tokens.md) has the
> whole picture, and [OPNsense](opnsense.md#send-the-firewalls-logs) has the
> steps for a firewall.

## Two ways in

### 1. HTTP push (rsyslog / fluent-bit / any HTTP client)

Point an HTTP log shipper at the per-host ingest endpoint:

```
POST /api/syslog/in/{token}
```

The token is an **inbound-webhook token of kind `syslog`**, created under
**Settings → Integrations → Inbound webhooks & syslog → Tokens** and pinned to
one host. The token's scope decides which host the lines attach to, so the URL
carries no host id. The body can be:

- JSON: `{"lines": ["…", "…"]}`, or a bare JSON array of lines,
- plain text (any other content type): one line per row, up to 256 KiB,
- the JSON that CrowdSec's HTTP notification posts (each alert becomes one line,
  see [firewall-sources.md](firewall-sources.md)).

You can send up to 200 lines per POST. Each line's RFC 3164 / RFC 5424 `<PRI>`
prefix is parsed for severity (emerg to debug), and a line with no valid `<PRI>`
is kept whole at severity *info*. A wrong or disabled token gets 401, and a
token that is not pinned to a host gets 400.

This path suits anything that can make an authenticated HTTPS request: rsyslog
`omhttp`, fluent-bit, Vector, or a one-off shipper.

### 2. Native UDP listener (`remotepower-syslogd`)

Most appliances only emit classic UDP syslog and can't add an auth header. The
optional **`remotepower-syslogd`** sidecar listens for UDP datagrams, maps each
datagram's **source IP** to the enrolled host that carries that IP, and
forwards the raw lines over loopback to the same `POST /api/syslog/in/{token}`
endpoint. Parsing, buffering, rule evaluation and token accounting all stay in
one place — the daemon is a thin network shim with no state of its own.

For a source to be accepted it needs **both**:

- an enrolled host whose **`ip`** equals the datagram's source address, and
- an enabled inbound-webhook token of **kind `syslog`** pinned to that host.

Unknown sources are dropped and logged at most once per 10 minutes each, so a
misconfigured sender can't flood the journal. Lines are batched per source and
flushed every couple of seconds (or at 200 lines), so a burst is one POST, not
one request per datagram.

#### Installing the listener

The receiver is **optional and off by default**, so a fresh install opens no
extra port. Add it only on the server that will receive appliance syslog. It is a
single self-contained Python script (standard library only) plus a systemd unit.

The simplest way is to run the installer with the flag. It is safe to run again on
an existing install, and it sets the unit's user to match your distribution:

```
sudo ./install-server.sh --with-syslogd
```

Or install the two files by hand, from the release tarball or a source checkout:

```
# 1. Install the daemon and its unit
sudo install -m 755 server/syslog/remotepower-syslogd.py /usr/local/bin/remotepower-syslogd
sudo install -m 644 packaging/remotepower-syslogd.service /etc/systemd/system/

# 2. Enable and start it
sudo systemctl daemon-reload
sudo systemctl enable --now remotepower-syslogd
```

The unit runs as the same user as the web app (`www-data` in the shipped file), with
`ProtectSystem=strict` and read-only access to the data directory, because it reads
the host and token lists through the same storage layer as the server. If your web
user has another name (`nginx` on Fedora, `http` on Arch), change `User=` and
`Group=` in the unit to match it before you start the service, or the daemon cannot
read the data directory and drops every packet. The installer does this for you.
*(The AUR `remotepower-server` package ships the same unit under `/usr/share/doc/`.
Copy it into `/etc/systemd/system/` the same way.)*

#### Before logs will be accepted — the two prerequisites

A source is only accepted if **both** are true (this is the auth model — there is
no header to forge), so set these up first:

1. **A host record carrying the appliance's IP.** Add the appliance on
   the Hosts page (**+ Agentless host**) as an
   [agentless host](agentless-devices.md) whose `ip` field is the exact source
   address its datagrams come from.
2. **A syslog token pinned to that host.** Under *Settings → Integrations →
   Inbound webhooks & syslog*, create a token of **kind `syslog`** scoped to the
   host.
   The daemon resolves source IP → host → token itself; the token never touches
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

On FreeBSD (OPNsense, pfSense) `logger` takes different flags:

```
logger -h <server-ip> -P 5514 -t remotepower-test "hello"
```

Within a couple of seconds the line appears on **Monitoring → Logs** (filter by that
host and the `syslog` unit) and drives its log-alert rules. If nothing shows up, the
journal names the reason. See *Checking it arrived* below, which lists each drop
message and what to do about it.

## Pointing a client at it

Below, `<server-ip>` is the host running `remotepower-syslogd` and `5514` is the
listen port (use `514` if you moved it). These rules apply to every client:

- **Send from the IP the host record carries.** The source address *is* the
  authentication, so a box with several interfaces must send from the one in the
  host's `ip` field — most daemons let you pin it, and the examples do.
- **Prefer UDP, over IPv4.** The listener is UDP-only and IPv4-only; a client
  configured for TCP, TLS or IPv6 will connect to nothing. Use the HTTP push path
  instead when you need a reliable or encrypted transport.
- **Send to the server's own address.** UDP does not pass through an HTTP proxy
  such as Cloudflare, so a hostname that points at the proxy never reaches the
  receiver.
- **The Docker image does not run the receiver.** It belongs to the standard
  systemd install (`install-server.sh --with-syslogd`).

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
/system logging add topics=info action=remotepower
/system logging add topics=error action=remotepower
/system logging add topics=warning action=remotepower
/system logging add topics=critical action=remotepower
```

One rule per topic, so it works however RouterOS combines the topics of a single rule.
Check `src-address` on the action if the router has several WAN/LAN addresses.

To have Threat Intel read the router's firewall log, a decoy port and failed
sign-ins, see [Firewall sources](firewall-sources.md#mikrotik-routeros). It
uses different logging rules from the ones above.

### OPNsense

OPNsense has no setting for the source address of a log target: it sends from the
address of the interface that leads to the server, and that is the address the
host record needs. The full steps, with the fields to fill in, are in
[opnsense.md](opnsense.md#send-the-firewalls-logs). In short, **System ‣ Settings
‣ Logging**, add a target with transport **UDP (IPv4)**, the server's address and
port `5514`. You do not enter the token on OPNsense. To have Threat Intel read
the firewall log and Suricata alerts, see
[Firewall sources](firewall-sources.md#opnsense).

### pfSense

**Status ‣ System Logs ‣ Settings**, tick *Enable Remote Logging*, set *Source
Address* to the interface address the host record carries, set *IP Protocol* to
IPv4, and add `<server-ip>:5514` under *Remote log servers*. Choose what to send
under *Remote Syslog Contents*.

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
than fighting the host.

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
  seconds and refresh the host's **Logs** tab.
- `dropping syslog from unknown source <ip>: no enrolled host has this IP` →
  fix the host record's `ip`, or the sender's source address.
- `dropping syslog from <ip>: the host IS enrolled but has no enabled syslog
  ingest token` → create one under *Settings → Integrations → Inbound webhooks &
  syslog* (kind `syslog`), scoped to that host.
- Nothing at all in the journal → the datagrams aren't arriving. Check the
  server's firewall (`sudo ss -lun | grep 5514` should show the listener) and
  that the client is really using UDP.

## Retention

The log-watch buffer is a short-retention **operational triage window**, not an
archive. For long-term retention, keep shipping to a real log store alongside
RemotePower (the two aren't mutually exclusive — an appliance can fan out to
both).

## A source that can never receive

The receiver maps an incoming line to a token by the datagram's **source IP**,
matched against the enrolled host's `ip` field — the sender is never
addressed by the token itself. So a token whose host has an empty `ip`, whose
host has been deleted, or that is simply disabled, is dropped from the source
map: nothing it is pointed at can ever arrive, however correctly the appliance
is configured.

**Admin → Server Status** names such a token and says why, for example "1 of 2
sources wired to nothing · fw01 (no IP on the host, so the receiver cannot map its
packets)". The receiver does not report itself healthy while one of its sources is
wired to nothing. The fix is on the **host**: set its IP to the address the syslog
packets come from. RemotePower also raises `ingest_source_unmappable` for the token
(cleared by `ingest_source_mapped`). A token you disabled yourself is not
reported. The flow receiver behaves the same way, see
[flow.md](flow.md#never-exported-is-usually-not-the-router).
See [self-monitoring.md](self-monitoring.md) for the rest of that page.

## See also

- [log-watch.md](log-watch.md) — the buffer, live tail, and alert rules.
- [agentless-devices.md](agentless-devices.md) — records for hosts with no agent.
- [inbound-tokens.md](inbound-tokens.md) — what each kind of inbound token is
  for, and why a UDP sender never holds one.
- [opnsense.md](opnsense.md) — sending an OPNsense firewall's logs and traffic.
