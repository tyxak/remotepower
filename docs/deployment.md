# Deployment guide — install everything

## Recommended: the unified `install.sh` wizard

For almost every deployment, you don't need the individual scripts below — the
turnkey path covers server, agents, and teardown:

```bash
# Server — bare-metal wizard (nginx + app + TLS + admin, HTTPS by default):
git clone https://github.com/tyxak/remotepower && cd remotepower
sudo bash install.sh

# Server — one-command Docker (self-signed HTTPS on first boot, no insecure
# default password — the admin password is printed to the container log):
docker compose up -d

# Agent — one line on the target host (self-hosted installer endpoint):
wget -qO- "https://your-server/install?t=<token>" | sudo sh

# Agent — bootstrap many hosts over SSH from the server checkout:
sudo bash install.sh agent push --server https://your-server --token <token> user@host1 [user@host2 ...]

# Clean uninstall (server, agent, or demo; keeps data unless --purge):
sudo bash install.sh uninstall
```

The agent one-liner downloads the **signed** agent with the server URL, token and
integrity baked in, verifies its checksum, enrols, and the host appears by its
hostname within ~60 s. See [install.md](install.md) for the full quick-start.

The component map below remains the **advanced** reference — the individual
scripts still exist and are what you reach for on bigger / segmented / HA
deployments (the explicit heavy-fleet track), or when the wizard isn't a fit.

---

A map of every RemotePower component, the script that installs it, and when you
need it. Start at the top; most installs only need the first two rows.

| Component | Script | When you need it |
|-----------|--------|------------------|
| **Server** | `install-server.sh` | always (the dashboard + API) — Postgres + WSGI + scheduler + a co-located scanner satellite are all default-on single-node; `--no-postgres`/`--no-scheduler`/`--no-scanner` opt back down |
| **Linux agent** | `install-client.sh` | each Linux host to manage |
| **Windows agent** | `client/install-windows.ps1` | each Windows host |
| **macOS agent** | `client/install-macos.sh` | each Mac |
| **Relay satellite** | `packaging/satellite-setup.sh` | agents in a segmented network — see [satellites.md](satellites.md) |
| **Scanner satellite** | `packaging/scanner-setup.sh` | Security → Pentest scans — default-on, co-located, via `install-server.sh`; run standalone for the doc-recommended separate machine — see [security-scans.md](security-scans.md) |
| **PostgreSQL backend** | `packaging/postgres-setup.sh` | default-on via `install-server.sh` — see [scaling.md](scaling.md) |
| **Postgres HA (primary)** | `packaging/postgres-ha-primary.sh` | DB failover |
| **Postgres HA (standby)** | `packaging/postgres-ha-standby.sh` | DB failover |
| **PgBouncer pooler** | `packaging/pgbouncer-setup.sh` | very high request rates |
| **Persistent WSGI tier** | `server/conf/remotepower-wsgi.service` | default-on via `install-server.sh` — a pre-warmed gunicorn app server (the only server since v6.1.0) — see [wsgi.md](wsgi.md) |
| **Out-of-band scheduler** | `server/conf/remotepower-scheduler.service` | default-on via `install-server.sh` — runs the maintenance cadence off the request path / leader-elected for multi-node — see [scaling.md](scaling.md) |
| **Load balancer** | `packaging/loadbalancer-haproxy.cfg.example` | multi-node |
| **Web SSH terminal** | `packaging/install-webterm.sh` | optional browser SSH |
| **Read-only demo** | `packaging/install-demo.sh` | a public sandbox vhost |

---

## 1. Server

```bash
git clone https://github.com/tyxak/remotepower && cd remotepower
sudo bash install-server.sh        # nginx + gunicorn/Flask + Postgres + deps + admin password
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
**Devices → + Add device**, then runs supervised (systemd / launchd / a **Windows
service** — scheduled-task fallback; see [windows-client.md](windows-client.md))
and appears in the dashboard within ~60 s. Agents verify the server's
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
2. Point it at the shared DB: set `RP_PG_DSN` (env, in `/etc/remotepower/api.env`,
   the `remotepower-wsgi` unit's `EnvironmentFile=`) or the storage marker
   `DATA_DIR/storage_backend.json` → the HA DSN.
3. **Mount `DATA_DIR` on shared storage (NFS/EFS)** so file artifacts (avatars,
   SCAP reports, host-config snapshots, mitigation logs) are visible from every
   node, and deploy the `agent/` binary to each node. (DB stores are in Postgres
   already — only those file artifacts need sharing. See scaling.md.)
4. Enable **`trust_proxy`** so the real client IP comes from `X-Forwarded-For`,
   not the balancer.
5. Add the node to the load balancer (`packaging/loadbalancer-haproxy.cfg.example`
   — HAProxy, or the nginx `upstream` in its comments). Health check
   `GET /api/health`. No session stickiness needed.

### Hard multi-tenancy & DB row-level security (opt-in, v5.5.0)

Both are **config switches, applied live — there is no migration script to run.**

- **App-layer tenancy** — *Settings → Security → Multi-tenancy* (`tenancy_enforced`,
  default off). Assign users and devices to a tenant; tenant admins are confined to
  their own devices, while an admin in the **default** tenant is the cross-tenant
  superadmin. Toggling it on takes effect immediately; existing data stays in the
  `default` tenant until reassigned.
- **Postgres row-level security** — the deeper, DB-enforced layer beneath it
  (`tenancy_rls`, default off; **Postgres backend only**). When enabled the app adds
  a `tenant_id` column to the `devices` table, a trigger to keep it in sync with each
  device's tenant, and a `FORCE ROW LEVEL SECURITY` policy keyed on a per-request
  `app.rp_tenant` GUC — all **idempotently and at runtime** on the first request after
  you flip the switch (no downtime, no `ALTER` by hand). It fails *closed* (an unset
  GUC matches no rows). This is defense-in-depth: even a bug in the app-layer scope
  would not leak another tenant's device rows.

Disable either by un-ticking it; the RLS objects are harmless if left in place, and
the policy is bypassed (`app.rp_tenant = '*'`) for agent/system/tool paths.

---

## Upgrades, rollback & recovery (v4.3.0)

**Every `deploy-server.sh` run snapshots the deployed code first** (last 3
kept in `/var/backups/remotepower-deploys/`). To undo a bad deploy:

```bash
sudo bash deploy-server.sh --rollback
```

Rollback restores **code only** — your data dir (`/var/lib/remotepower/`) is
never touched by the deploy script. Two recovery situations to know:

- **Rolled back under a newer database.** If the newer version migrated the
  SQLite schema, the old code now logs `database schema vN is NEWER than this
  server` on every request (nginx error log). The data the newer version
  wrote is preserved but invisible — either re-deploy the newer version or
  restore the matching data backup.
- **Corrupt SQLite store.** The `/api/diagnostics` bundle (Server status →
  Diagnostics) includes a `database.quick_check` field — anything but `ok`
  means corruption. Recovery, in order of preference: (1) restore the data
  dir from backup (`tar` of `/var/lib/remotepower/`), (2) salvage with
  `sqlite3 remotepower.db ".recover" | sqlite3 new.db` and swap the file in,
  (3) migrate back from a JSON-backend backup via
  `tools/migrate_storage.py`. Take a copy of the broken file before any of
  these.

Plain-files backup of everything (config, users, devices, history):

```bash
tar -czf remotepower-backup-$(date +%F).tar.gz /var/lib/remotepower/
```

---

## Encrypt every hop

The edge (agent/browser → server/LB) is TLS by default; **internal hops are not
unless you configure them.** Don't ship the DB password or replication stream in
clear over an untrusted link. The full hop-by-hop matrix is in
[scaling.md → Transport encryption](scaling.md). For the agent→satellite hop,
see [satellites.md](satellites.md).

See also: [install.md](install.md) (quick start), [https.md](https.md),
[admin-guide.md](admin-guide.md), [windows-client.md](windows-client.md).
