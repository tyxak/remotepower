# WG Access — WireGuard road-warrior VPN

**Admin → WG Access** is a built-in, light [WireGuard](https://www.wireguard.com/)
VPN. It lets people reach the RemotePower dashboard — and, optionally, the fleet
or the wider internet — over an encrypted tunnel instead of exposing services on
the public internet. WireGuard is silent to anyone without a valid key, so this
*reduces* your attack surface rather than adding to it.

The hub is the **RemotePower server host itself** (running `wireguard-go`, a
userspace implementation — no kernel module, container-friendly). There is
nothing to install on the people who connect: they use the stock WireGuard client
on their laptop or phone.

## The model: tunnels → clients

WG Access has two levels.

### Tunnels

A **tunnel** is one WireGuard interface on the server, with its own UDP port,
address pool, public endpoint and optional pushed DNS. The tunnel carries the
*policy* every client on it inherits:

| Setting | What it does |
| --- | --- |
| **Listen port** *(optional)* | The UDP port the hub interface listens on. Leave blank to auto-assign the next free port; set it to pin the tunnel to a specific port (e.g. one you've already opened on the firewall). Must be unique across tunnels, and — like the interface and address pool — is fixed once the tunnel exists. |
| **Allow internet (full tunnel)** | On = the client routes all its **IPv4** traffic out through the hub (road-warrior egress). **IPv6 is not routed** — the hub is IPv4-only, so on a dual-stack client IPv6 keeps using the local connection and does not pass through the tunnel *(stated explicitly since v6.4.3; the setting previously implied `::/0` was included and it never was)*. Off = split tunnel: the client only reaches what the reach scope allows, plus the dashboard. |
| **Reach scope** | Which fleet devices the tunnel's clients can reach — `none` (dashboard only), `all` (the whole fleet), or a `site` / `group` / `tag`. This reuses RemotePower's normal RBAC scope vocabulary and is enforced by per-tunnel firewall rules on the hub. |
| **DNS** *(optional)* | A resolver IP pushed to the client. |
| **Expiry (TTL)** *(optional)* | Minutes / hours / days / weeks / years after which the tunnel is automatically torn down and deleted (with all its clients). |

You can run several tunnels at once — e.g. an "HQ" full-fleet tunnel, a
"Contractors" tunnel scoped to one tag, and an "Internet-only" full-tunnel — each
with its own policy.

The **dashboard is always reachable** on every tunnel: it's the hub, so even a
`reach scope = none` tunnel still gets you to the RemotePower UI.

### Clients

A **client** is a single WireGuard peer attached to a tunnel; it inherits the
tunnel's policy. When you create one you get, **once**:

- a **QR code** — scan it straight into the WireGuard mobile app, and
- a downloadable **`.conf`** for the desktop client.

The client's **private key is generated in your browser** and never reaches the
server (RemotePower only ever sees the public key). Because the config and QR are
shown only at creation time, treat them like a credential — re-issue a client if
they're lost. A client can carry its own TTL for temporary / contractor access,
independent of the tunnel's.

## Reach scopes at a glance

| Tunnel policy | Client can reach |
| --- | --- |
| `none`, internet off | The dashboard only (a "get me to the console" tunnel) |
| `site` / `group` / `tag`, internet off | The dashboard + the in-scope fleet devices (split tunnel) |
| `all`, internet off | The dashboard + every fleet device |
| internet **on** | The dashboard + the internet (full tunnel); reach scope still gates fleet devices |

Reach is enforced on the hub with **nftables** rules derived from the scope —
the client-side `AllowedIPs` in a `.conf` is only advisory, so widening it on the
client doesn't grant more access. Dashboard-only (non-forwarding) tunnels install
an explicit drop rule, so a client on one can never route through the hub
regardless of any other tunnel's settings.

## Live stats & events

Stats are surfaced at both levels:

- **Per tunnel** — interface status, connected / total clients, address-pool
  utilisation, and aggregate transfer.
- **Per client** — connection status, last-handshake age, the source endpoint it
  last connected from, and bytes transferred.

Client **connect / disconnect / stale-handshake** transitions raise first-class
events that flow through the alert inbox, the dashboard activity feed and your
webhooks:

| Event | Fires when |
| --- | --- |
| `vpn_client_connected` | A client completes a handshake (also auto-resolves its open disconnect/stale alert) |
| `vpn_client_disconnected` | A previously-connected client drops |
| `vpn_handshake_stale` | A client's handshake ages out |

Tunnel expiry is recorded in the audit log (no separate event).

## Ask the AI

WG Access posture is one of the assistant's fleet-knowledge (RAG) sources, so you
can ask things like *"who has road-warrior VPN access?"*, *"is anyone connected
right now?"* or *"what can VPN clients reach?"*. There's also a **Remote-access
review** AI advisor (on the AI Insights grid) that flags over-broad reach scopes,
full-tunnel where split would do, stale or never-connected clients to revoke, and
access expiring soon.

## Setup & requirements

The feature needs two things on the server host:

1. **`wireguard-go`** — the userspace WireGuard implementation.
2. The **`remotepower-wg-apply`** helper plus its scoped `sudoers` drop-in.

The RemotePower server packages and the installer put both in place. Until they're
present, the WG Access page shows a clear **"unavailable"** notice and the rest of
RemotePower is unaffected — nothing else depends on it.

You also need the hub's **UDP port(s)** reachable from where your clients connect
(forward the tunnel's UDP port to the server), and a public **endpoint** hostname
or IP for the client configs.

## Nobody can connect

A tunnel whose UDP port is not reaching the host looks **exactly** like one
nobody has got round to connecting to: the config is right, the server is up,
the client imported cleanly, and no handshake ever happens. It is the most
common WG-Access support question, and for a long time the page said only
"0 connected now".

When every client on an enabled tunnel has existed for more than 30 minutes and
not one has **ever** completed a handshake, the tunnel panel now says so, names
the UDP port, and points at the port forward. Check, in order:

1. The router forwards **UDP** on that port to this host — TCP is not enough and
   is the usual mistake.
2. No firewall between the client and the host drops it (a cloud security group,
   a CGNAT, an ISP-supplied router in bridge-refusing mode).
3. The client config's `Endpoint` is the address reachable from *outside*, not
   the host's LAN IP.

**A port scan cannot answer this**, which is why the product infers instead of
probing. WireGuard never replies to unauthenticated packets — that silence is
deliberate — so an open, working port and a firewalled one look identical to a
scanner. One successful handshake settles it, and once any client has handshaked
the notice does not return: the message is about whether inbound UDP has *ever*
worked, not whether someone is connected right now.

The evidence survives a restart. `wg show dump` reports a last-handshake time of
0 for every peer after the interface comes back, so a check reading that field
would accuse a perfectly healthy tunnel every time the host reboots — a warning
wrong that often is one you learn to ignore. The flag behind this notice only
ever goes from "never" to "has".

## Permissions & safety

- **Viewing** WG Access needs admin (or auditor) authentication; **all** changes —
  creating, editing or deleting tunnels and clients — are **admin-only** and
  written to the audit log.
- Client private keys are generated **in the browser** (X25519) and never
  transmitted. The per-tunnel hub key is generated and held root-only by the
  helper; no API ever returns a private key.
- The privileged helper accepts only a **structured JSON spec** and rebuilds the
  `wg` / `nftables` config itself (argv-only, no shell) — no untrusted string is
  ever interpolated into a command. The app-server process itself stays unprivileged; the
  one root action is the scoped, audited helper invocation.
- Reach is enforced on the hub (nftables), not on the client, so a tunnel's scope
  is authoritative.

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
