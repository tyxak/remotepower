# Network flow visibility (NetFlow / IPFIX) — v6.4.0

RemotePower observes hosts through the agent and appliances through syslog/SNMP;
`remotepower-flowd` adds the **traffic** view for gear that can't run an agent
but can export flow records — routers, firewalls, L3 switches. It answers "what
is talking to what, and how much" per exporter: top talkers, top conversations,
and a protocol breakdown, updated every few seconds. Agentless.

It is the flow sibling of the [syslog receiver](syslog.md): a small UDP sidecar
that maps each exporter's source IP to an enrolled device, aggregates the flow
records, and forwards a compact rollup to the per-device ingest API. Parsing,
storage and the UI all live in the app server — the daemon is a thin shim.

## What it parses

- **NetFlow v5** — fixed-format, no templates. Common on older/edge gear.
- **NetFlow v9** — template-based; templates are cached per exporter and applied
  to data records (a data record whose template hasn't arrived yet is skipped —
  normal at startup, the exporter resends templates periodically).
- **IPFIX (v10)** — the same template model as v9.
- **sFlow v5** — a different, packet-sampling protocol: RemotePower dissects the
  sampled packet headers (Ethernet → IPv4/IPv6 → TCP/UDP) and scales
  bytes/packets by the sampling rate to estimate the flow's contribution.
  Point the switch's sFlow collector at the same udp/2055.

## Setup

1. **Enrol the exporter** as an agentless device in RemotePower with its **`ip`
   set to the address the flow packets will come from** (the router's source
   IP). The daemon maps datagrams to devices by that IP.
2. **Create a flow token**: Settings → Integrations → Inbound webhooks → add a
   token with **kind = `flow`**, scoped to that device.
3. **Install + run the receiver** (bundled with the server install; the
   `deploy-server.sh` refresh copies it):
   ```bash
   sudo install -m755 server/flow/remotepower-flowd.py /usr/local/bin/remotepower-flowd
   sudo install -m644 server/flow/flow_parse.py          /usr/local/bin/flow_parse.py
   sudo install -m644 packaging/remotepower-flowd.service /etc/systemd/system/
   sudo systemctl enable --now remotepower-flowd
   ```
   It listens on **udp/2055** by default (the de-facto NetFlow port,
   unprivileged). Override with `RP_FLOW_BIND` in the unit.
4. **Point the exporter at it.** On the router/firewall, configure NetFlow/IPFIX
   export to `<remotepower-host>:2055`. (Cisco: `ip flow-export destination …
   2055` / `flow exporter`; MikroTik: `/ip traffic-flow target`; pfSense/OPNsense:
   the softflowd/pflow plugin.)

The token is the device scope — no RBAC on the ingest path, exactly like syslog.
Unmapped exporters are dropped and logged (at most once per 10 min each).

## Where it shows up

Device drawer → **Network flows**: the latest window's top talkers (by bytes),
top conversations (`src → dst :port/proto`), the protocol split, and totals.
`GET /api/devices/{id}/flows` returns `{latest, history}` (a short rolling
history of total-bytes/flows for a trend). The receiver appears on the
Server-status **Distributed subsystems** card once sources are enrolled.

## Limits & retention

The daemon re-aggregates to the top ~20 talkers/conversations per flush, and the
server re-caps every size on ingest (never trusts the sender). Only the **latest
rollup** plus a short (~4 h) history of totals is kept per device — this is a
live traffic view, not a long-term flow archive. For long-term flow retention,
export to a dedicated collector (nfdump/nfcapd, Elastiflow) in parallel.

## Verifying declared dependencies (the "missing edge" alert)

The flow receiver does more than show traffic — it **verifies service
dependencies**. RemotePower already *suggests* `depends_on` edges from observed
traffic (Network → *Suggested dependencies* → **Accept** promotes one to a real
dependency link). Once an edge is declared, this feature watches it:

- an edge is **healthy** while traffic between the two hosts is observed (by an
  agent's peer-connection report **or** any exporter's NetFlow/IPFIX flows);
- it is **broken** (`dependency_missing` alert) when it was carrying traffic and
  then went silent for the configured window **while both hosts stayed online** —
  a firewall change, a route drop or a crashed listener the device-offline alert
  never catches;
- it **recovers** (`dependency_restored`, auto-resolving the alert) when traffic
  returns;
- an edge with no flow/peer coverage reads **Unverified** and can never fire; an
  edge that went silent because an endpoint is **offline** reads **Silent** (it's
  collateral of the offline alert, not a separate break).

Alerting is **off by default** — enable it under **Settings → Alerts →
Service-dependency link alerts**, where you also set the silence window (default
30 minutes). The read-only status view is always available:
`GET /api/dependency-health` and the **Dependency link health** card on the
Network page. Because only edges that were *seen live* can ever fire, turning it
on cannot flood a fleet that has no flow visibility.
