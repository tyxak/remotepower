# Agentless devices

*Introduced in v1.11.0.*

Most of RemotePower's features assume a Python agent on the device
posting heartbeats. That works for Linux hosts. It doesn't work
for the rest of the homelab — the managed switch, the printer, the
IPMI card, the IP camera, the smart plug, the UPS. v1.11.0 adds
agentless device records: same CMDB metadata, same vault
credentials, same SSH link feature, same place in the network
map. Just no heartbeat.

---

## Adding one

On the Devices page toolbar, click **+ Agentless device**. The
form asks for:

- **Name** — required, free text up to 64 chars
- **Type** — switch / router / firewall / AP / printer / camera /
  IPMI / UPS / PDU / NAS / IoT / smart plug / phone / other
- **Connected to (upstream)** — optional, picks from existing
  devices for the network map
- **Hostname / IP / MAC** — all optional, but you'll want at least
  IP if you ever plan to use SSH-link or HTTP-link features
- **Group** — optional, free text
- **Notes** — optional, free text up to 1 KB
- **Mark as currently up** — checkbox, defaults to true

Save and the device appears in the list immediately with an amber
outline (vs. accent-blue for agented devices) so you can see at a
glance which are which.

---

## What works on agentless devices

- **CMDB metadata** — asset_id, server_function, hypervisor_url,
  ssh_port, Markdown documentation. All of it. The CMDB modal works
  identically.
- **Credential vault** — encrypt and store passwords against the
  device. Reveal is admin-only and audit-logged just like
  everything else.
- **SSH link** — for any credential, the SSH and Copy buttons work
  the same way. Useful for IPMI consoles, switch CLIs, any device
  that takes SSH login. The link uses the device's hostname / IP
  and ssh_port the same way as for agented devices.
- **Network map** — agentless devices are first-class nodes. The
  map only really starts being useful once you can model your
  switches and APs.
- **Audit log** — creation, deletion, credential operations are
  all logged.
- **Native syslog** *(v6.3.0)* — devices that only speak classic
  syslog/UDP (switches, firewalls, printers, NAS appliances) can feed the
  log-alert pipeline via the `remotepower-syslogd` sidecar. Install:

  ```
  install -m 755 server/syslog/remotepower-syslogd.py /usr/local/bin/remotepower-syslogd
  install -m 644 packaging/remotepower-syslogd.service /etc/systemd/system/
  systemctl daemon-reload && systemctl enable --now remotepower-syslogd
  ```

  Point the appliance's syslog output at the server (udp/5514 by default;
  uncomment the unit's `CAP_NET_BIND_SERVICE` lines for classic 514). A
  source is accepted when an enrolled device has that **IP** and carries an
  enabled **syslog inbound-webhook token** (Settings → Integrations →
  Inbound webhooks, kind `syslog`, pinned to the device) — the daemon is a
  thin shim that batches lines to the same `POST /api/syslog/in/<token>`
  endpoint rsyslog/fluent-bit users already use, so `log_watch` rules with
  unit `syslog` fire `log_alert` identically. Unknown sources are dropped.
  The deploy/self-update flows refresh and restart the daemon like the
  other sidecars.

## Reachability and health

Agentless devices don't run an agent, but RemotePower can still tell
whether they're up and read a handful of basic facts about them —
without anything installed on the device.

- **ICMP reachability (default).** Every agentless device with an IP or
  hostname is pinged on a cadence (roughly once a minute). When a device
  stops responding it flips to offline and fires **`device_offline`**;
  when it comes back it fires **`device_online`**. The transition is
  debounced (a couple of consecutive misses) so a single dropped packet
  doesn't page you. Set a device's reachability mode to **manual** for
  hosts that block ping — then status is whatever you set in the Up/Down
  control (`manual_status`, defaults to up) and RemotePower won't probe.
- **SNMP polling (opt-in).** Point a device at an SNMP endpoint and
  RemotePower polls it on a schedule for reachability plus a set of basic
  facts. Losing contact fires **`snmp_unreachable`**; recovering fires
  **`snmp_recover`**. Both **SNMPv2c** (community string) and, as of
  v5.8.0, **SNMPv3 / USM** (per-user auth + AES privacy) are supported.
  A poll reads the standard system group and host-resource OIDs, so you
  get **sysName / sysDescr / sysUpTime / sysContact**, CPU load across
  processors, memory usage, filesystem-like storage entries, and some
  vendor extras (e.g. MikroTik board/CPU temperatures) surfaced on the
  device card. See the [SNMP walkthrough](cookbook.md#watch-an-agentless-device-with-snmp)
  for setup.

Unmonitored agentless devices are still probed and polled (so you keep
rolling status and uptime history), but they stay silent — no webhooks.

## What still doesn't work

- **Full sysinfo, services, packages, CVE scanning, update logs,
  patches, resource graphs, custom exec, container listing, agent
  self-update.** These need an agent posting rich telemetry, and there
  isn't one — SNMP polling only covers the basic facts listed above.
- **Wake-on-LAN.** Could in theory work for devices on the same L2
  segment as a host that's running an agent, but isn't wired up here.
  Use the host's WoL feature if you have it.

---

## API

`POST /api/devices/agentless`:

```json
{
  "name": "core-switch-1",
  "device_type": "switch",
  "hostname": "switch-1.lan",
  "ip": "10.0.0.1",
  "mac": "aa:bb:cc:dd:ee:ff",
  "group": "core-network",
  "notes": "MikroTik CRS328 in the rack",
  "connected_to": "",
  "manual_status": true
}
```

Returns `{"ok": true, "id": "al_<hex>"}`. The `al_` prefix
distinguishes agentless devices from agented ones (which use
their enrollment-time device ID format) and from credentials
(`cred_<hex>`) and TLS targets (`tls_<hex>`).

The same record can be updated through the standard CMDB and
device endpoints — `PUT /api/cmdb/{al_xyz}` to set
documentation, `PUT /api/devices/{al_xyz}/connected-to` to
change the network-map link, `DELETE /api/devices/{al_xyz}` to
remove it (with the same exclusion-rule path the regular delete
uses).

---

## Device types

The fifteen accepted types are roughly:

| Type | Use for |
|------|---------|
| `switch` | Managed/unmanaged Ethernet switch |
| `router` | Edge router, firewall+router combo, MikroTik |
| `firewall` | Dedicated firewall (pfSense box, Fortigate, etc.) |
| `access_point` / `ap` | Wi-Fi APs, Unifi/Aruba/etc. |
| `printer` | Network printer |
| `camera` | IP camera, baby monitor, doorbell cam |
| `ipmi` | Dell iDRAC, HP iLO, Supermicro IPMI |
| `ups` | APC, CyberPower, Eaton |
| `pdu` | Switched/metered PDU |
| `nas` | Synology, QNAP, TrueNAS-without-agent (although TrueNAS Linux can run the agent if you want) |
| `iot` | Generic catch-all for IoT, ESP-based stuff |
| `smart_plug` | Tasmota, Shelly, Kasa |
| `phone` | VoIP phones |
| `other` | The escape hatch |

The type list is enforced server-side because it powers the
icon mapping on the network map. If you need a new type, add it
to `AGENTLESS_DEVICE_TYPES` in `server/cgi-bin/api.py`.

---

## Already shipped since v1.11.0

Several things this page once listed as "future ideas" are now live:

- **ICMP reachability + SNMP polling** — agentless devices are pinged on
  a cadence and can be polled over SNMP (v2c or SNMPv3/USM) for status
  and basic facts, instead of relying solely on the manual Up/Down flag.
  See **Reachability and health** above.
- **Watch with ping/HTTP monitors** — any agentless device can also be
  targeted by a standard ping or HTTP monitor from the Monitors page, on
  top of the built-in reachability sweep.

## Still on the wish list

- **Auto-import from your switch** via SNMP walk / LLDP / CDP topology
  discovery. Manual SNMP polling of a known device is supported;
  auto-discovering neighbours from it is not.
- **Bulk-add** from a CSV. Useful if you have 50 IoT devices to enrol at
  once.
- **HTTP launch** button alongside SSH link, for things like UniFi
  controllers and printer admin pages. The data is there
  (`hypervisor_url` works for any HTTP admin URL); it just doesn't have a
  dedicated one-click affordance yet.
