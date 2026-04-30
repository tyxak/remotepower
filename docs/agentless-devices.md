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

## What doesn't work

- **Sysinfo, services, packages, CVE scanning, update logs,
  patches, monitoring graphs, custom exec, container listing,
  agent self-update.** All of these require an agent posting
  data, and there isn't one.
- **Online/offline detection.** There's no probing in v1.11.0 —
  status is whatever you set in the `manual_status` field
  (defaults to True). If a device's status is wrong, edit it.
- **Wake-on-LAN.** Could in theory work for devices on the same
  L2 segment as a host that's running an agent, but isn't wired
  up in v1.11.0. Use the host's WoL feature if you have it.

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

## Future ideas (not in v1.11.0)

These keep coming up and aren't shipped:

- **HTTP/ICMP probing** for agentless devices to set
  `manual_status` automatically. Decided against for v1.11.0
  because probing means cron jobs and outbound network
  permissions, and the user said no probing. May come back as
  opt-in.
- **Auto-import from your switch** via SNMP / LLDP / CDP.
  Real-network-monitoring territory; out of scope.
- **Bulk-add** from a CSV. Useful if you have 50 IoT devices to
  enrol at once. Possible v1.12.0 candidate.
- **HTTP launch** button alongside SSH link, for things like
  Unifi controllers and printer admin pages. Reasonable to add
  later — the data is there (`hypervisor_url` works for any
  HTTP admin URL), just no UI affordance for it yet.
