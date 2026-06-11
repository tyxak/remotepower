# Deployment guide — install everything

A map of every RemotePower component, the script that installs it, and when you
need it. Start at the top; most installs only need the first two rows.

| Component | Script | When you need it |
|-----------|--------|------------------|
| **Server** | `install-server.sh` | always (the dashboard + API) |
| **Linux agent** | `install-client.sh` | each Linux host to manage |
| **Windows agent** | `client/install-windows.ps1` | each Windows host |
| **macOS agent** | `client/install-macos.sh` | each Mac |
| **Relay satellite** | `packaging/satellite-setup.sh` | agents in a segmented network — see [satellites.md](satellites.md) |
| **PostgreSQL backend** | `packaging/postgres-setup.sh` | larger fleets / multi-node — see [scaling.md](scaling.md) |
| **Postgres HA (primary)** | `packaging/postgres-ha-primary.sh` | DB failover |
| **Postgres HA (standby)** | `packaging/postgres-ha-standby.sh` | DB failover |
| **PgBouncer pooler** | `packaging/pgbouncer-setup.sh` | very high request rates |
| **Load balancer** | `packaging/loadbalancer-haproxy.cfg.example` | multi-node |
| **Web SSH terminal** | `packaging/install-webterm.sh` | optional browser SSH |
| **Read-only demo** | `packaging/install-demo.sh` | a public sandbox vhost |

---

## 1. Server

```bash
git clone https://github.com/tyxak/remotepower && cd remotepower
sudo bash install-server.sh        # nginx + fcgiwrap + deps + admin password
sudo certbot --nginx -d remote.example.com   # TLS (or your own cert)
```

Open the printed URL, log in, change the admin password. **Put it behind HTTPS**
before enrolling agents — agent tokens ride that hop.

## 2. Agents

```bash
# Linux (root):
sudo bash install-client.sh                                  # interactive enroll
# Windows (admin PowerShell):
powershell -ExecutionPolicy Bypass -File client\install-windows.ps1
# macOS (root):
sudo bash client/install-macos.sh https://remote.example.com 123456
```

Each enrolls with a 6-digit **PIN** (or an enrollment token) from
**Devices → + Add device**, then runs as a service (systemd / launchd / Windows
service) and appears in the dashboard within ~60 s. Agents verify the server's
TLS cert; for an **internal CA**, set `RP_CA_BUNDLE=/path/to/ca.crt` in the
agent's environment (no verification weakening).

## 3. Relay satellites (segmented networks)

When a network segment can't reach the server directly, run a satellite there:

```bash
sudo RP_UPSTREAM=https://remote.example.com RP_SATELLITE_TOKEN='<minted>' \
     bash packaging/satellite-setup.sh --self-signed satellite.internal
```

Point that segment's agents at the satellite. Full walkthrough + the TLS posture
in **[satellites.md](satellites.md)**.

## 4. Scaling out (large fleets, HA)

For 1000+ agents or redundancy, in order:

```bash
# a) PostgreSQL backend (the first wall JSON file-locks hit)
sudo bash packaging/postgres-setup.sh --install --write-marker /var/lib/remotepower
#    then migrate: Settings → Advanced → Storage backend → Migrate

# b) DB high availability (streaming replication)
sudo STANDBY_CIDR=192.0.2.11/32 bash packaging/postgres-ha-primary.sh    # on primary
sudo PRIMARY_HOST=192.0.2.10 REPL_PASS='…' CONFIRM=yes \
     bash packaging/postgres-ha-standby.sh                             # on standby
#    DSN → postgresql://rp:pw@pg-primary,pg-standby:5432/remotepower  (auto-failover)

# c) more app nodes behind a load balancer (see "App nodes" below)
# d) PgBouncer if per-request connection setup becomes the ceiling
sudo RP_DB_PASS='…' bash packaging/pgbouncer-setup.sh --install
```

The full reasoning + capacity tables + transport-encryption matrix are in
**[scaling.md](scaling.md)**.

### App nodes (horizontal scale)

An app node is just **another `install-server.sh` install pointed at the shared
Postgres** — the app is stateless, so any node serves any request:

1. Install the server code on the node (`install-server.sh`).
2. Point it at the shared DB: set `RP_PG_DSN` (env, in the fcgiwrap unit) or the
   storage marker `DATA_DIR/storage_backend.json` → the HA DSN.
3. **Mount `DATA_DIR` on shared storage (NFS/EFS)** so file artifacts (avatars,
   SCAP reports, host-config snapshots, mitigation logs) are visible from every
   node, and deploy the `agent/` binary to each node. (DB stores are in Postgres
   already — only those file artifacts need sharing. See scaling.md.)
4. Enable **`trust_proxy`** so the real client IP comes from `X-Forwarded-For`,
   not the balancer.
5. Add the node to the load balancer (`packaging/loadbalancer-haproxy.cfg.example`
   — HAProxy, or the nginx `upstream` in its comments). Health check
   `GET /api/health`. No session stickiness needed.

---

## Encrypt every hop

The edge (agent/browser → server/LB) is TLS by default; **internal hops are not
unless you configure them.** Don't ship the DB password or replication stream in
clear over an untrusted link. The full hop-by-hop matrix is in
[scaling.md → Transport encryption](scaling.md). For the agent→satellite hop,
see [satellites.md](satellites.md).

See also: [install.md](install.md) (quick start), [https.md](https.md),
[admin-guide.md](admin-guide.md), [windows-client.md](windows-client.md).
