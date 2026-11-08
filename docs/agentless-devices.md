# Agentless hosts

Most of RemotePower assumes an agent on the host that sends heartbeats. That works for
Linux, macOS and Windows machines. It does not work for the rest of the estate: the
managed switch, the printer, the IPMI card, the IP camera, the smart plug, the UPS.

An agentless host is a record for one of those. It gets the same CMDB metadata, the
same vault credentials, the same SSH links and the same place on the network map as any
other host. It just has no heartbeat, so RemotePower learns about it by pinging it,
polling it over SNMP, or running a command over SSH.

---

## Adding one

On the **Hosts** page, click **+ Agentless host**. The form asks for:

- **Name** (required, up to 64 characters).
- **Type**: switch, router, firewall, access point, printer, camera, IPMI / BMC, UPS,
  PDU, NAS, IoT, smart plug, phone or other.
- **Connected to (upstream)**: optional. Pick an existing host so the network map can
  draw the link.
- **Hostname, IP and MAC**: all optional, but you want an IP if you plan to use the SSH
  link, ping it or poll it over SNMP.
- **Group**: optional.
- **Notes**: optional, up to 1 KB.
- **Mark as currently up**: ticked by default. It is the status RemotePower shows when
  you set the reachability mode to manual.

The host appears in the list straight away.

Other ways to get agentless records:

- **Network discovery.** Run a LAN scan from an enrolled host's **Health & hardware**
  card. The **Network** page then lists the unmanaged addresses it found, and **Add as
  host** turns one into an agentless host.
- **Cloud import.** **Settings → Integrations → Cloud import** pulls running instances
  from AWS EC2, Hetzner Cloud or DigitalOcean in as agentless hosts. It is read-only,
  and running it again updates the records in place. Tick **Auto re-sync on a schedule**
  to repeat the import on its own (the interval is in seconds, 3,600 to 604,800).
  Instances that vanish from the cloud account are marked decommissioned, never
  deleted. Azure and GCP work the same way, but the page does not offer them. Add them
  as `cloud_accounts` entries in `POST /api/config`. Azure needs `tenant_id`,
  `client_id`, `subscription_id` and `secret_key` (the client secret). GCP needs
  `project_id`, `client_email` and `secret_key` (the service account's private key).
  The secret is write-only: a later save that leaves it out keeps the stored one.

---

## What works on agentless hosts

- **CMDB metadata**: asset ID, server function, hypervisor URL, SSH port and Markdown
  documentation. The CMDB dialog works the same as for any host.
- **Credential vault**: encrypt and store passwords against the host. Revealing one is
  admin-only and audit-logged.
- **SSH link**: for any credential, the SSH and Copy buttons work the same way. They use
  the host's hostname or IP and its SSH port. This suits IPMI consoles and switch CLIs.
- **Network map**: agentless hosts are first-class nodes. The map gets useful once you
  model the switches and access points.
- **Audit log**: creation, deletion and credential operations are all logged.
- **Syslog**: a host that only speaks classic syslog over UDP (a switch, firewall,
  printer or NAS) can feed the log-alert pipeline through the syslog receiver. Install
  the receiver with `install-server.sh --with-syslogd`, or by hand:

  ```
  install -m 755 server/syslog/remotepower-syslogd.py /usr/local/bin/remotepower-syslogd
  install -m 644 packaging/remotepower-syslogd.service /etc/systemd/system/
  systemctl daemon-reload && systemctl enable --now remotepower-syslogd
  ```

  Point the appliance's syslog output at the server (UDP port 5514 by default; to use
  514, uncomment the `CAP_NET_BIND_SERVICE` lines in the unit). RemotePower accepts a
  source when an enrolled host has that **IP** and carries an enabled **syslog inbound
  token** pinned to it (**Settings → Integrations → Inbound webhooks & syslog**, kind `syslog`).
  The receiver batches lines to the same `POST /api/syslog/in/<token>` endpoint that
  rsyslog and fluent-bit users use, so `log_watch` rules for the unit `syslog` fire
  `log_alert` in the same way. Unknown sources are dropped. See [syslog.md](syslog.md).

## Reachability and health

An agentless host cannot run a check on itself, but RemotePower can still tell whether
it is up and read some basic facts, without installing anything on it. Pick the mode in
the host drawer under **Actions & settings → Reachability**.

- **ICMP ping (default).** Every agentless host with an IP or hostname is pinged about
  once a minute. After two consecutive misses it flips to offline and fires
  **`device_offline`**. When it answers again it fires **`device_online`**. One dropped
  packet does not page you.
- **Manual.** For hosts that block ping. The status is whatever you set with the **Host
  is up** box (`manual_status`, up by default) and RemotePower does not probe.
- **SSH.** See "Agentless SSH" below.
- **SNMP polling (opt-in).** Point a host at an SNMP endpoint and RemotePower polls it
  every five minutes for reachability plus basic facts. Losing contact fires
  **`snmp_unreachable`** and recovering fires **`snmp_recover`**. It supports
  **SNMPv2c** (a community string) and **SNMPv3 / USM** (per-user authentication and
  AES privacy). A poll reads the system group and the host-resource OIDs, so you get
  sysName, sysDescr, sysUpTime, sysContact, CPU load across processors, memory usage,
  filesystem-like storage entries, and some vendor extras (for example MikroTik board
  and CPU temperatures) on the host card. See the
  [SNMP walkthrough](cookbook.md#watch-an-agentless-host-with-snmp) for setup. Turn on
  **per-port history** for a switch if you want bandwidth, utilisation, error counters
  and link state per port; it is off by default because a full interface walk is heavy
  on a big switch. With it on, a port that is enabled on the switch but goes down fires
  **`snmp_if_down`** (a port shut on purpose is not an incident), and a port at 90% of its
  speed or more in two samples in a row fires **`snmp_if_saturated`**. If polling keeps
  failing for six hours, **`snmp_dead`** follows **`snmp_unreachable`**.
- **Memory without the cache.** net-snmp counts the page cache and the buffers as used
  in the "Physical memory" row and lists them again as the rows "Cached memory" and
  "Memory buffers", so a firewall or a NAS can read 90% when most of it is cache.
  RemotePower takes those two rows off the figure. The result is what the memory alert,
  the history graph, the Hosts page and the SNMP section show. The SNMP section also
  shows the figure the host reports, with the cache and buffers next to it. A host that
  lists no such rows is read as it reports. The figure can still be higher than the
  host's own `top`. On FreeBSD (OPNsense, pfSense) the pages waiting to be written back
  to disk, which `top` lists as Laundry, count as in use, as they do in the host's own
  "Real memory" row, so the figure sits above Active plus Wired. The poll reads one
  table, and a host may keep reusable memory that it does not put in it; RemotePower
  cannot tell which from here. To see what your host offers, open the **SNMP** section,
  go to **Browse OID tree** and walk the presets **Storage table** and **Memory
  (UCD-SNMP)**; the second names `memShared`, `memBuffer` and `memCached`. To alert at a
  different level, set the memory warning and critical thresholds for the host under
  **Metric thresholds**.
- **OID browser.** The poll reads a fixed set of OIDs, the ones RemotePower knows how to
  interpret. When a host exposes something outside that set (a vendor counter, a PDU's
  per-outlet draw, a UPS's runtime estimate), open the host drawer, go to the **Audit**
  tab and expand **System → SNMP**. **Browse OID tree** at the bottom walks any subtree
  with the stored credentials. Presets cover the common MIBs, well-known OIDs are
  resolved to names, and anything vendor-private stays numeric so you can look it up in
  the vendor's own MIB. Walks are admin-only, written to the audit log, and return a
  capped page, so narrow the OID instead of raising the cap. The browser only reads and
  never sets a value. It stays available when the poll itself fails, because a host you
  cannot poll cleanly is exactly the one worth exploring by hand.

Unmonitored agentless hosts are still probed and polled, so you keep status and uptime
history, but they stay silent and send no webhooks.

### Agentless SSH

For Linux, BSD and macOS machines where you cannot or will not install an agent, RemotePower
can run commands and read a basic snapshot over SSH.

1. Turn it on under **Settings → Security → Agentless SSH** and paste an SSH private key.
   The feature is off by default, and the key is write-only: RemotePower never returns
   it.
2. In the host drawer, under **Actions & settings**, set **Reachability** to **SSH** and
   fill in the SSH user and port.
3. Use **Poll over SSH** to read the OS, hostname, uptime, memory, disk and load, which
   then show as the host's metrics.
4. Use **Run command** to run one command and read what it prints. The dialog shows the
   output and the exit code, and nothing is queued: the server connects and runs it while
   you wait. The button is on the host drawer of a host whose reachability is **SSH**, and
   an agent host keeps its own Run command, which goes through the agent.

Connections never prompt (`BatchMode`, key only) and trust the host key on first use. A
changed host key stops the connection. Running a command needs an admin, the host's
command allowlist applies, and every poll and command is audited.

A quarantined host refuses commands over SSH, and so does every host while the server is in
maintenance mode. These are the same two refusals the agent's command queue gives, in the
same words. A poll only reads, so it keeps working in both. The Ansible runner and the web
terminal follow the same rules: the runner stops for maintenance mode and leaves quarantined
hosts out of its targets, and the web terminal refuses a quarantined host (it does not stop
for maintenance mode, like the SSH gateway).

## What still doesn't work

- **Full system information, services, packages, CVE scanning, update logs, patches,
  resource graphs, container listing and agent self-update.** These need an agent that
  sends rich data. SNMP and SSH polling only cover the basic facts above. Custom
  commands work only through agentless SSH.
- **Wake-on-LAN** is not wired up for agentless hosts. Use the host's own Wake-on-LAN
  feature if it has one.
- **Bulk add from a CSV file**, and **auto-discovering neighbours from an SNMP walk**
  (LLDP or CDP), are not supported. Network discovery and cloud import cover most of
  the same ground.

You can also point a standard ping or HTTP monitor from the Monitors page at an
agentless host, on top of the built-in reachability check.

---

## API

`POST /api/devices/agentless` (admin only):

```json
{
  "name": "core-switch-1",
  "device_type": "switch",
  "hostname": "switch-1.lan",
  "ip": "10.0.0.1",
  "mac": "aa:bb:cc:dd:ee:ff",
  "os": "RouterOS",
  "group": "core-network",
  "tags": ["rack-1"],
  "notes": "MikroTik CRS328 in the rack",
  "connected_to": "",
  "manual_status": true
}
```

Only `name` is required. `tags` takes up to 20 entries. The reply is
`{"ok": true, "id": "al_<hex>"}`. The `al_` prefix tells agentless hosts apart from
agent hosts, from credentials (`cred_<hex>`) and from TLS targets (`tls_<hex>`).

You change the record through the standard CMDB and host endpoints:
`PUT /api/cmdb/{al_xyz}` for documentation, `PUT /api/devices/{al_xyz}/connected-to`
for the network-map link, and `DELETE /api/devices/{al_xyz}` to remove it. SSH has
`POST /api/devices/{id}/ssh-poll` and `POST /api/devices/{id}/ssh-exec`
(body: `{"command": "…"}`), and SNMP has `GET` and `PATCH /api/devices/{id}/snmp`,
`POST /api/devices/{id}/snmp/poll` and `GET /api/devices/{id}/snmp/interfaces`.

---

## Host types

The fifteen accepted types:

| Type | Use for |
|------|---------|
| `switch` | Managed or unmanaged Ethernet switch |
| `router` | Edge router, firewall and router combination, MikroTik |
| `firewall` | Dedicated firewall (a pfSense box, a Fortigate, and so on) |
| `access_point` / `ap` | Wi-Fi access points (`ap` is an alias) |
| `printer` | Network printer |
| `camera` | IP camera, baby monitor, doorbell camera |
| `ipmi` | Dell iDRAC, HP iLO, Supermicro IPMI |
| `ups` | APC, CyberPower, Eaton |
| `pdu` | Switched or metered PDU |
| `nas` | Synology, QNAP, or a TrueNAS box you do not run the agent on |
| `iot` | Generic catch-all for IoT gear and ESP-based boards |
| `smart_plug` | Tasmota, Shelly, Kasa |
| `phone` | VoIP phones |
| `other` | Anything else |

The server enforces the list because it drives the icons on the network map.

---

See also: [cookbook.md](cookbook.md) for the SNMP walkthrough, [cmdb.md](cmdb.md) for
the asset records and vault, [network-map.md](network-map.md) for the map,
[syslog.md](syslog.md) for the syslog receiver, and [monitors.md](monitors.md) for ping
and HTTP monitors.
