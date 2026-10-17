# Inbound tokens

An inbound token lets one sender, or one device, send data to RemotePower
without logging in. You create them under **Settings → Integrations →
Inbound webhooks**, and they all start with `rpwi_`.

There are five kinds. Three work the way you would expect: the sender gets a
URL and posts to it. **Syslog** and **NetFlow/IPFIX** from a firewall, switch or
router do not. They arrive as plain UDP, and the token never leaves the
server. If you were looking for the place to paste it into OPNsense, that is
why you could not find one.

## Which kind do you need?

| You want | Kind | What the sender is given | Port | Pinned to a device |
|---|---|---|---|---|
| Logs from a firewall, switch, NAS or printer | Syslog | nothing: it sends plain UDP syslog | UDP 5514 | required |
| Logs from a tool that can POST (rsyslog `omhttp`, fluent-bit, Vector) | Syslog | the URL `/api/syslog/in/<token>` | your dashboard's HTTPS port | required |
| Traffic records from a router or firewall | NetFlow/IPFIX | nothing: it exports plain UDP flows | UDP 2055 | required |
| Alerts from Grafana, Alertmanager, Authentik, n8n, Home Assistant | Alert webhook | the URL `/api/webhook/in/<token>` | your dashboard's HTTPS port | optional |
| SNMP traps | SNMP trap receiver | the URL `/api/snmp/trap/<token>`, called by a handler script you write | your dashboard's HTTPS port | required |
| Closing an alert when a ticket closes in Jira, ServiceNow or Zendesk | ITSM callback | the URL `/api/itsm/in/<token>` | your dashboard's HTTPS port | no |

Alert and SNMP trap tokens are covered in [monitors.md](monitors.md), and ITSM
callbacks in [webhooks.md](webhooks.md). The rest of this page is about the two
that use UDP.

## Syslog and NetFlow: where the token goes

Syslog and NetFlow have no way to carry a password. A firewall sends a UDP
packet and that is all it does. So RemotePower recognises the sender by its
**IP address**, and the token is looked up from there by a small receiver that
runs on the RemotePower server:

```
OPNsense ──UDP──▶ remotepower-syslogd ──▶ RemotePower
 192.0.2.1  :5514   1. reads the packet's source address, 192.0.2.1
                    2. finds the device whose IP is 192.0.2.1
                    3. finds that device's syslog token
                    4. posts the lines to /api/syslog/in/<token>
```

`remotepower-flowd` does the same for NetFlow on UDP 2055. The token is the
link between the device and the receiver. You never type it anywhere else.

That gives you four things that all have to be right:

1. **The receiver is running.** `systemctl status remotepower-syslogd` for logs,
   `remotepower-flowd` for NetFlow. They are not installed by default: add
   `--with-syslogd` or `--with-flowd` to `install-server.sh`, or follow the
   steps in [syslog.md](syslog.md) and [flow.md](flow.md). The Docker image does
   not run them. NetFlow does not carry logs, so a running `remotepower-flowd`
   does nothing for syslog.
2. **The device has the right IP.** Add the firewall under **Devices → +
   Agentless device** with type *Firewall*, and put in the IP address its
   packets come from. See [Which address?](#which-address-does-the-firewall-send-from)
   below.
3. **The device has a token of the right kind.** A *Syslog* token for logs, a
   *NetFlow/IPFIX* token for traffic, **pinned to that device**. One device can
   have both. A token of another kind does nothing here.
4. **The sender points at the receiver.** The server's address, the receiver's
   UDP port, and UDP rather than TCP.

The table on the Inbound webhooks page shows the device's name and IP next to
each token, and says so in amber when a syslog or flow token's device has no IP. The
**Server status** page has a *Syslog receiver* and a *Flow receiver* row that
say whether the receiver is running and how many of its sources can receive.

## Which address does the firewall send from?

The IP on the device record has to be the **source address of the packets**, and
a firewall often has several addresses. OPNsense does not let you choose one for
a log target: it uses the address of the interface that leads to the server. If
the server is on your LAN, that is the firewall's LAN address; if it is across a
VPN, it is the tunnel address.

You can read the right one off the server instead of working it out. Send a
test line, then look at the receiver's journal:

```
journalctl -u remotepower-syslogd -n 20
```

`dropping syslog from unknown source 192.0.2.1` names the address. Put that on
the device.

## Reading the symptoms

| What you see | What it means | What to do |
|---|---|---|
| Hits stay at 0 and `systemctl status remotepower-syslogd` says *could not be found* or *inactive* | The receiver is not installed or not running | Install it (point 1 above) |
| Nothing from `sudo tcpdump -ni any udp port 5514` on the server | The packets never arrive | Check the sender's target (UDP, the right port, saved and applied), the server's firewall, and that the sender uses the server's own address, not a hostname behind a proxy such as Cloudflare. UDP does not pass through an HTTP proxy |
| `dropping syslog from unknown source <ip>` in the journal | No device has that IP | Set the device's IP to `<ip>` |
| `the device IS enrolled but has no enabled syslog ingest token` | The device has no enabled token of the right kind | Create a *Syslog* token pinned to it, or enable the one you have |
| `flow from unmapped exporter <ip> dropped` | The same, for NetFlow | Set the IP, and create a *NetFlow/IPFIX* token pinned to the device |
| Amber text on the token: *No IP set: nothing can arrive* | The receiver cannot match any packet to it | Fill in the device's IP |
| The token's Type reads *alert* but you made a NetFlow token | Versions before 7.4.0 showed NetFlow and ITSM tokens as *alert* | Nothing is wrong with the token; update |
| Lines arrive but no alert fires | Receiving works; no `log_alert` rule matches | See [log-watch.md](log-watch.md) |

The journal only complains about a source once every ten minutes, and it says
nothing about packets that were accepted. The proof that it works is the token's
**Hits** and **Last seen** moving, and the lines on the device's **Logs** tab
(or the **Network flows** card for NetFlow). Hits counts batches the receiver
forwarded, not single lines.

## Security

The sender's IP address is the only check, and a UDP source address can be
forged by anything on the same network. Syslog over UDP is also readable by
anyone on the path. So use these on a network you control or across a VPN, and
let only the firewall's address reach the receiver's port:

```
sudo ufw allow from 192.0.2.1 to any port 5514 proto udp
```

The receivers drop packets from any address that is not on a device record, and
they cap how much they remember about unknown senders, so a flood of forged
addresses costs bandwidth and not memory.

## Managing tokens

- A token is shown once, when you create it. To rotate it, revoke it and create
  a new one. The UDP receivers pick the new token up within half a minute.
- **Disable** turns a token off without deleting it. A disabled token is
  dropped by the receivers.
- Deleting the device leaves the token behind with nothing to receive for; the
  table flags it. Revoke it.

## See also

- [OPNsense](opnsense.md): the steps for sending an OPNsense firewall's logs and
  traffic.
- [syslog.md](syslog.md) and [flow.md](flow.md): the receivers, their settings
  and the other senders (rsyslog, MikroTik, ESXi, Cisco).
- [agentless-devices.md](agentless-devices.md): records for devices with no
  agent.
