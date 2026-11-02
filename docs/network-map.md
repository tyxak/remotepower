# Network map

The **Network** page (**Fleet → Network**) draws your fleet as a graph of nodes
and links. You record the links by hand: each host has a `connected_to` field
that says what it plugs into, and the graph follows it. RemotePower can also
suggest links it has seen (LLDP neighbours and observed connections), and you
accept or dismiss each one.

Below the map, the page has a few cards for things that sit around the network:
the internet connection, jobs that check in, things advertising themselves on the
LAN, and suggestions to review. They are described under
[Other cards on the page](#other-cards-on-the-page).

---

## What it shows

Every enrolled host and every agentless host appears as a node. A node is a
circle with a three-letter tag for its type, its name and its IP address.

- **Fill.** Green for online, red for offline.
- **Outline.** Agent hosts are outlined in the accent colour. Agentless hosts
  (switches, access points and so on) are outlined in amber, so you can see at a
  glance which ones are heartbeating and which are records you maintain.
- **Unmanaged hosts.** A host that a LAN scan found, but that is not enrolled,
  shows as a muted node with a dashed outline and a dotted line to the host that
  saw it. It has no online or offline state, because it is only a sighting.

The links come in three kinds:

| Line | Meaning |
|---|---|
| Solid grey | `connected_to`: what a host plugs into. If host A has `connected_to: B`, a line runs from A to B. |
| Dashed amber | A **tunnel**: a peer link between two hosts, such as a VPN or a site-to-site link. |
| Dashed violet | `depends_on`: a host needs another host to work. The line turns red when the upstream host is offline, which points at the root cause. |

A link to a host that no longer exists is dropped silently. That is convenient
when you delete an upstream switch without clearing the downstream pointers, but
it can leave nodes looking unconnected when they are not.

The line under the map reads `N nodes, N links, N tunnels`, with `— scoped` when
a filter is on.

---

## Setting it up

Once your hosts and agentless hosts are in the system:

1. Click **Edit links**.
2. For each host, pick what it plugs into from the dropdown of all other hosts.
   Leave it on `— none —` for the internet gateway, the root switch or the edge
   router. The same dialog has a **depends on** selector for the hosts a host
   needs.
3. Click **Save changes**. Each modified link saves as its own change, and you
   can press Save more than once with no ill effect.

Only admins can change links, tunnels and positions. A host cannot connect to
itself, and the API refuses a host that does not exist. RemotePower does **not**
detect cycles (`A → B → A`), because some real setups want them, such as LACP
rings and back-up links. The graph draws them as crossing lines.

Other controls on the toolbar:

- **Drag** any node to place it. Positions are stored on the server, so they
  persist across refreshes and browsers. A click without a drag opens the host.
  **Reset positions** clears them and goes back to the automatic layout.
- **Tunnels** opens a dialog where you pair two hosts. Delete one from the same
  list.
- **Scope** has three dropdowns: **Site**, **Group** and **Tag**. Pick one, or
  combine them, and the map shows just that slice, so you can look at one site's
  or one customer's topology. Leave them on "All" for the whole fleet.
- **AI review** asks the assistant for a *network dependency review*: single
  points of failure and what each one would take down. It needs the AI assistant
  to be set up.
- **Refresh** reloads the map.

> Looking for throughput rather than topology? The **Network Metrics** page
> (**Monitoring → Network Metrics**) shows per-host RX/TX, scoped the same way.
> See [network-metrics.md](network-metrics.md).

---

## Layout

The layout is simple: one row per host type, with the rows in alphabetical order
by type, and nodes spread evenly along each row. A node you have dragged keeps
its saved position. It is deterministic, so the same data always lays out the same
way, and it needs no layout library. It suits the 20 to 30 nodes of a homelab or a
small office. Past a hundred nodes it gets cluttered, and the scope filter is the
way to keep it readable.

---

## API

`GET /api/network-map` returns the whole graph, filtered by role and tenant.
Optional filters: `?site=<site>&group=<group>&tag=<tag>`.

```json
{
  "nodes": [
    {
      "id": "dev-abc123",
      "name": "web-1",
      "hostname": "web-1.lan",
      "ip": "10.0.0.10",
      "os": "Ubuntu 22.04",
      "type": "host",
      "group": "production",
      "agentless": false,
      "online": true,
      "pos_x": null,
      "pos_y": null,
      "depends_on": []
    }
  ],
  "edges": [
    {"from": "dev-abc123", "to": "al_5e3f4a"}
  ],
  "tunnels": [
    {"id": "tun_1a2b3c", "endpoints": ["dev-abc123", "al_5e3f4a"]}
  ],
  "dep_edges": [
    {"from": "dev-abc123", "to": "al_5e3f4a"}
  ],
  "scopes": {"sites": [], "groups": [], "tags": []}
}
```

| Request | Purpose |
|---|---|
| `PUT /api/devices/{id}/connected-to` with `{"connected_to": "<device_id>" \| ""}` | Set or clear a link. Empty string clears it. A self-link or an unknown host gets a 400. |
| `PUT /api/devices/{id}/depends-on` with `{"depends_on": ["<device_id>", …]}` | Set the hosts this one depends on. |
| `PUT /api/network-map/positions` with `{"positions": [{"id", "x", "y"}, …]}` | Save node positions (up to 1,000 in one request). |
| `GET /api/network-map/tunnels` | List tunnels. |
| `POST /api/network-map/tunnels` with `{"endpoints": ["<id>", "<id>"]}` | Add a tunnel. |
| `DELETE /api/network-map/tunnels/{id}` | Remove a tunnel. |

---

## Why the links are manual

Working out what is plugged into what is hard to automate:

- ARP tables tell you who is reachable on a subnet, not who is plugged into
  which port.
- LLDP gives neighbour information, but only for managed switches that have it
  enabled, and not all consumer and small-office gear does.
- mDNS and SSDP find services, not topology.

Most homelab and small-office networks have fewer than thirty nodes and do not
move around much, so entering links by hand is fine. RemotePower helps where it
can: it reads LLDP neighbours from hosts that run `lldpd`, and it notices which
hosts talk to which. Both turn up as suggestions you accept, never as changes
made behind your back. A link you set by hand always wins over a suggested one.

## Why agentless hosts matter here

A switch, an access point or a router cannot run an agent, yet they are the things
that connect everything else. An [agentless host](agentless-devices.md) is a record
for one of them, so it can be a node, and other hosts can plug into it. If you only
want a map of the hosts that run agents, point their `connected_to` at each other.
The graph is not wrong, just less informative.

---

## Other cards on the page

### Internet (WAN)

Shows your public IP address, whether the internet is up, the last outages and the
30-day uptime. It is off until you switch it on under **Settings → Security →
Internet (WAN) watch**, because it makes an outbound request to find your public
address. A change of address raises `wan_ip_changed`, and an outage raises
`wan_down` and `wan_up`. With a Cloudflare zone configured, a changed address can
also update an A record for you.

### Job check-ins (dead-man's switch)

For cron jobs on things that are not in the fleet, such as a router's backup
script, a VPS or a NAS task. They fail silently, and you find out months later.
Give the job a name, a period and a grace time (the form starts at a daily
period and 60 minutes of grace) and press **Add job** to get a URL. Have the job
`curl` that URL when it finishes. If a check-in does not arrive within
the period plus the grace time, RemotePower raises `ping_missed`, and
`ping_recovered` when the job checks in again.

- The period is 1 to 43,200 minutes and the grace time 1 to 10,080 minutes. You
  can have up to 100 jobs.
- The clock starts at the first check-in, so a new job does not alert before you
  have added the `curl` line.
- `GET` or `POST /api/ping/<token>` records a check-in. The token in the URL is
  the credential, so it needs no sign-in, and it can only mark a job as healthy.
  It cannot read anything.
- This is the inverse of the Healthchecks.io pinger, which watches RemotePower
  itself. See [Monitors](monitors.md).

### LAN services (mDNS)

Names the things on your LAN that advertise themselves: printers, Chromecasts,
AirPlay speakers, HomeKit bridges and NAS boxes. These are the hosts nobody puts an
agent on, so without this they are anonymous IP addresses. It is off by default.
Switch it on under **Settings → Security → LAN service discovery (mDNS)**. It needs
`avahi-browse` on at least one agent per network segment.

### Suggested dependencies

Edges worked out from the outbound connections your hosts make to each other
(private addresses only). **Accept** adds a real `depends_on` link, which holds
alerts on a downstream host while its upstream is down. **Dismiss** hides the
suggestion.

### Dependency link health

Checks every declared `depends_on` link against traffic that agents and the
NetFlow/IPFIX receiver have seen. A link that carried traffic, then went silent
while both hosts stayed online, shows as **Broken**: a firewall, route or service
failure that the host-offline alert never catches. The card is always available.
To be alerted, switch on **Service-dependency link alerts** under **Settings →
Alerting**. It raises `dependency_missing` and `dependency_restored`. See
[Flow](flow.md).

### Suggested physical links (LLDP)

Neighbours that hosts running `lldpd` have reported, matched to hosts you know.
**Accept** sets the `connected_to` link, and **Dismiss** hides it.

### Unmanaged hosts on the LAN

Hosts that agents saw during a LAN scan and that are not enrolled. Run a scan from
a host's **Health & hardware** card (**Scan LAN**). A recurring scan is set up under
**Security → Pentest → Scheduled LAN discovery**.

---

## Troubleshooting

**An edge is missing although you set `connected_to`.** Check `GET /api/devices`:
it includes `connected_to` for each host. If it is set there but not on the map,
the upstream host was probably deleted, and the link is dropped. **Edit links**
shows `— none —` for those.

**The layout is cluttered.** That is the layout, not the data. Use the scope
filter, or drag the nodes where you want them.

**A cycle shows up.** Cycles are allowed and drawn as crossing lines. If you have a
back-up link or an LACP ring, that is correct. If it is a mistake, fix one of the
`connected_to` values with **Edit links**.

**A suggestion never appears.** Dependency suggestions need agents to report their
outbound connections. LLDP suggestions need `lldpd` on the hosts and a neighbour
that matches a known host by management address or name.

## See also

- [Agentless hosts](agentless-devices.md): switches, access points and the like.
- [Network Metrics](network-metrics.md): throughput per host.
- [Flow](flow.md): the NetFlow/IPFIX receiver behind dependency link health.
- [Monitors](monitors.md): checks, watchdogs and inbound endpoints.
