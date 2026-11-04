# Deployment guide — install everything

## Recommended: the unified `install.sh` wizard

For almost every deployment, you do not need the individual scripts below. The
turnkey path covers the server, the agents and teardown:

```bash
# Server — bare-metal wizard (nginx + app + TLS + admin, HTTPS by default):
git clone https://github.com/tyxak/remotepower && cd remotepower
sudo bash install.sh

# Server — one-command Docker (self-signed HTTPS on first boot; the generated
# admin password is printed once in the container log):
docker compose up -d

# Agent — one line on the target host (the server serves its own installer):
wget -qO- "https://your-server/install?t=<token>" | sudo sh

# Agent — enrol a host over SSH from the server checkout. One token enrols one
# host, so mint a token per host in the dashboard:
sudo bash install.sh agent push --server https://your-server --token <token> user@host1

# Clean uninstall (server, agent, or demo; keeps data unless --purge):
sudo bash install.sh uninstall
```

`install.sh` also has `update` (see [upgrading.md](upgrading.md)) and `doctor` (preflight
checks only). Its `tls` and `passwd` commands are placeholders and do nothing yet. Use
`certbot` or `make tls-selfsigned` for certificates (see [install.md](install.md)) and
`remotepower-passwd` for admin accounts.

The agent one-liner downloads the **signed** agent with the server URL, token and
integrity baked in, verifies its checksum, enrols, and the host appears by its
hostname within about 60 seconds. See [install.md](install.md) for the full
quick-start.

The component map below is the **advanced** reference. The individual scripts
still exist, and they are what you reach for on bigger, segmented or HA
deployments, or when the wizard is not a fit.

---

A map of every RemotePower component, the script that installs it, and when you
need it. Start at the top; most installs only need the first two rows.

| Component | Script | When you need it |
|-----------|--------|------------------|
| **Server** | `install-server.sh` | Always (the dashboard and API). Postgres, the WSGI app server, the scheduler, a co-located scanner satellite and the push daemon are all on by default for a single node. `--no-postgres`, `--no-scheduler`, `--no-scanner` and `--no-push` opt back down. |
| **Linux agent** | `install-client.sh` | Each Linux host to manage |
| **Windows agent** | `client/install-windows.ps1` | Each Windows host |
| **macOS agent** | `client/install-macos.sh` | Each Mac |
| **Relay satellite** | `packaging/satellite-setup.sh` | Agents in a segmented network — see [satellites.md](satellites.md) |
| **Scanner satellite** | `packaging/scanner-setup.sh` | Security → Pentest scans. Installed with the server by default; run it on its own for a separate scanning machine — see [security-scans.md](security-scans.md) |
| **PostgreSQL backend** | `packaging/postgres-setup.sh` | Installed with the server by default — see [scaling.md](scaling.md) |
| **Postgres HA (primary)** | `packaging/postgres-ha-primary.sh` | Database failover |
| **Postgres HA (standby)** | `packaging/postgres-ha-standby.sh` | Database failover |
| **PgBouncer pooler** | `packaging/pgbouncer-setup.sh` | Very high request rates |
| **App server (WSGI)** | `server/conf/remotepower-wsgi.service` | Installed with the server — a pre-warmed gunicorn app server, the only app server RemotePower has — see [wsgi.md](wsgi.md) |
| **Out-of-band scheduler** | `server/conf/remotepower-scheduler.service` | Installed with the server — runs the maintenance sweeps off the request path, with leader election for multi-node — see [scaling.md](scaling.md) |
| **Agent push daemon** | `server/conf/remotepower-push.service` | Installed with the server (`--no-push` opts out). Idle until you enable the channel in Settings — see [push.md](push.md) |
| **SSH gateway** | `install-server.sh --with-sshgw`, `packaging/install-sshgw.sh`, or `RP_WITH_SSHGW=1` in Docker | Reach hosts with plain `ssh` through one port, with no inbound port on any host. Off by default — see [sshgw.md](sshgw.md) |
| **Syslog receiver** | `install-server.sh --with-syslogd` | Agentless syslog from switches, firewalls and appliances — see [syslog.md](syslog.md) |
| **Flow receiver** | `install-server.sh --with-flowd` | Agentless NetFlow, IPFIX and sFlow — see [flow.md](flow.md) |
| **KMIP key server** | `install-server.sh --with-kmip` | Hold Synology, TrueNAS and vSphere encryption keys off the appliance — see [kmip.md](kmip.md) |
| **Load balancer** | `packaging/loadbalancer-haproxy.cfg.example` | Multi-node |
| **Web SSH terminal** | `packaging/install-webterm.sh` (Docker: `RP_WITH_WEBTERM=1`) | Optional browser SSH |
| **Read-only demo** | `packaging/install-demo.sh` | A public sandbox vhost |

### What listens where

| Port | What | Reachable from |
|------|------|----------------|
| 443 and 80 | nginx: dashboard, API, agent installer and downloads | Your network |
| 8090 | The gunicorn app server | This machine only (nginx proxies to it) |
| TCP 2222 | SSH gateway, if installed | Wherever your users' SSH clients are |
| UDP 5514 | Syslog receiver, if installed | The switches, firewalls and appliances that send syslog |
| UDP 2055 | NetFlow, IPFIX and sFlow receiver, if installed | Your routers and switches |
| TCP 5696 | KMIP key server, if installed | Your NAS and hypervisors |

The optional receivers are off by default, so a fresh install opens no port you did not ask
for. In Docker, nginx listens on 8443 (HTTPS) and 8080 inside the container, which Compose
publishes as 443 and 80.

---

## 1. Server

```bash
git clone https://github.com/tyxak/remotepower && cd remotepower
sudo bash install-server.sh        # nginx + gunicorn/Flask + Postgres + deps + admin password
sudo certbot --nginx -d remote.example.com   # TLS (or your own cert)
```

Open the printed URL, sign in, and change the admin password. **Put it behind HTTPS**
before you enrol agents, because agent tokens travel over that connection. After
install, `sudo rp doctor` checks the whole stack (see [cli.md](cli.md)).

### Docker

`docker compose up -d` starts three containers from `docker-compose.yml`: the app (with nginx
inside it), PostgreSQL 16 and a scanner satellite. The database sits on an internal network
that only the app can reach. Data lives in two named volumes (`remotepower_data` for the
app and `remotepower_pg` for Postgres), so back them up and keep them when you recreate the
containers.

- Set **`RP_PG_PASSWORD`** before the first start. The compose file falls back to a
  placeholder password when it is not set.
- Set `RP_TLS_HOST` to the address people and agents use, or the certificate will not match.
- `RP_HTTPS_PORT` and `RP_HTTP_PORT` change the published ports.
- The first start prints a generated admin password in the container log. Set `RP_ADMIN_USER`
  and `RP_ADMIN_PASS` to choose your own.

The rest of the Docker options (the published image, signature check, browser terminal) are in
[install.md](install.md#docker-one-liner-alternative).

## 2. Agents

```bash
# Linux (root):
sudo bash install-client.sh                                  # interactive enroll
# Windows (admin PowerShell):
powershell -ExecutionPolicy Bypass -File client\install-windows.ps1
# macOS (root):
sudo bash client/install-macos.sh https://remote.example.com 123456
```

Each enrols with a 6-digit **PIN**, or with an enrollment token, from
**Hosts → Enroll host**. It then runs supervised (systemd, launchd, or a **Windows
service** with a scheduled-task fallback; see [windows-client.md](windows-client.md))
and appears in the dashboard within about 60 seconds. Agents verify the server's
TLS certificate. For an **internal CA**, set `RP_CA_BUNDLE=/path/to/ca.crt` in the
agent's environment. That adds your CA and does not weaken verification.

## 3. Relay satellites (segmented networks)

When a network segment cannot reach the server directly, run a satellite there:

```bash
sudo RP_UPSTREAM=https://remote.example.com RP_SATELLITE_TOKEN='<minted>' \
     bash packaging/satellite-setup.sh --self-signed satellite.internal
```

Point that segment's agents at the satellite. The full walkthrough and the TLS posture are in
**[satellites.md](satellites.md)**.

## 4. Scaling out (large fleets, HA)

For 1000+ agents or redundancy, work through these in order:

```bash
# a) PostgreSQL backend (the first wall that JSON file locks hit)
sudo bash packaging/postgres-setup.sh --install --write-marker /var/lib/remotepower
#    then migrate: Settings → Advanced → Storage backend → Migrate & switch

# b) Database high availability (streaming replication)
sudo STANDBY_CIDR=192.0.2.11/32 bash packaging/postgres-ha-primary.sh    # on primary
sudo PRIMARY_HOST=192.0.2.10 REPL_PASS='…' CONFIRM=yes \
     bash packaging/postgres-ha-standby.sh                             # on standby
#    DSN → postgresql://rp:pw@pg-primary,pg-standby:5432/remotepower  (auto-failover)

# c) more app nodes behind a load balancer (see "App nodes" below)
# d) PgBouncer if per-request connection setup becomes the ceiling
sudo RP_DB_PASS='…' bash packaging/pgbouncer-setup.sh --install
```

The standby script replaces that node's PostgreSQL data directory with a copy of the primary,
so run it only on a machine that is meant to be a replica.

The full reasoning, capacity tables and the transport-encryption matrix are in
**[scaling.md](scaling.md)**.

### App nodes (horizontal scale)

An app node is **another `install-server.sh` install pointed at the shared
Postgres**. The app is stateless, so any node serves any request:

1. Install the server code on the node (`install-server.sh`).
2. Point it at the shared database: set `RP_PG_DSN` (in `/etc/remotepower/api.env`, which
   the `remotepower-wsgi` unit reads) or write the storage marker
   `DATA_DIR/storage_backend.json` with the HA DSN.
3. **Mount `DATA_DIR` on shared storage (NFS or EFS)**, so file artifacts (avatars,
   SCAP reports, host-config snapshots, mitigation logs) are visible from every node, and
   deploy the `agent/` binary to each node. The database stores are in Postgres already;
   only those file artifacts need sharing. See [scaling.md](scaling.md).
4. Turn on **`trust_proxy`**, so the real client IP comes from `X-Forwarded-For` and not
   from the balancer. There is no checkbox for it. Set it through the config API:
   `POST /api/config` with `{"trust_proxy": true}`.
5. Add the node to the load balancer (`packaging/loadbalancer-haproxy.cfg.example` for
   HAProxy, or the nginx `upstream` in its comments). Use `GET /api/health` as the health
   check. You need no session stickiness.

### Multi-tenancy and database row-level security (opt-in)

Both are **config switches that apply live. There is no migration script to run.**

- **App-layer tenancy**: Settings → Security → **Multi-tenancy** (`tenancy_enforced`,
  off by default). Assign users and hosts to a tenant. Tenant admins are confined to
  their own hosts, and an admin in the **default** tenant is the cross-tenant
  superadmin. Turning it on takes effect at once. Existing data stays in the
  `default` tenant until you reassign it.
- **Postgres row-level security**: the deeper layer beneath it, enforced by the database
  (`tenancy_rls`, off by default; **Postgres backend only**, and it needs "Enforce tenant
  isolation"). When it is on, the app adds a `tenant_id` column to **four** tables —
  `devices` and the three that derive from it (`entity`, `listrow`, `metric_samples`) —
  with a trigger that keeps each in step with its host's tenant, and a
  `FORCE ROW LEVEL SECURITY` policy keyed on a per-request `app.rp_tenant` setting. It does
  this itself, safely to repeat, on the first request after you flip the switch, with no
  downtime and no manual `ALTER`. It fails *closed*: an unset tenant matches no rows. A row with
  no owning host (a fleet-level alert, an instance-wide setting) is tagged `__shared__` and
  stays visible to every tenant, and moving a host to another tenant moves its derived rows
  with it. This is defence in depth: even a bug in the app-layer scope would not leak another
  tenant's rows.

  Row-level security does **not** cover the singleton stores (tickets, CMDB, billing), which
  are one document for the whole deployment rather than per-host rows.
  `GET /api/tenancy/readiness` (platform operator only) reports which stores are isolated at
  which layer, so you can check before you rely on it. **Settings → Security → Multi-tenancy
  → Isolation coverage** shows the same list.

Switch either off by un-ticking it. The row-level security objects are harmless if you leave
them in place, and the policy is bypassed (`app.rp_tenant = '*'`) for agent, system and tool
paths.

---

## Upgrades, rollback and recovery

**Every `deploy-server.sh` run first snapshots the deployed code**, and the last three are
kept in `/var/backups/remotepower-deploys/`. To undo a bad deploy:

```bash
sudo bash deploy-server.sh --rollback
```

Rollback restores **code only**. Your data directory (`/var/lib/remotepower/`) is never
touched by the deploy script. Two recovery situations to know:

- **Rolled back under a newer database.** If the newer version migrated the
  SQLite schema, the old code now logs `database schema vN is NEWER than this
  server` on every request (in the app server's log: `journalctl -u remotepower-wsgi`,
  or the container log in Docker). The data the newer version
  wrote is preserved but invisible. Either deploy the newer version again or
  restore the matching data backup.
- **Corrupt SQLite store.** The diagnostics bundle (**Server Status → Diagnostics bundle**, or
  `GET /api/diagnostics`) has a `database.quick_check` field on the SQLite backend. Anything but
  `ok` means corruption. In order of preference: (1) restore the data directory from backup
  (`tar` of `/var/lib/remotepower/`), (2) salvage with
  `sqlite3 remotepower.db ".recover" | sqlite3 new.db` and swap the file in,
  (3) migrate back from a JSON-backend backup with `tools/migrate_storage.py` (it converts
  between JSON and SQLite only). Take a copy of the broken file before any of these.

A plain-files backup of the data directory (config, users, hosts, history) holds everything on
the JSON and SQLite backends:

```bash
tar -czf remotepower-backup-$(date +%F).tar.gz /var/lib/remotepower/
```

On the Postgres backend the data lives in the database. Use the built-in backup under
**Settings → Backups**, which runs by default and writes one archive shape for every backend
(see [backups.md](backups.md)), or back up the database with `pg_dump`.

---

## Encrypt every hop

The edge (agent or browser to server or load balancer) is TLS by default. **Internal hops are
not, unless you configure them.** Do not send the database password or the replication stream
in clear over an untrusted link. The hop-by-hop matrix is in
[scaling.md → Transport encryption](scaling.md). For the agent-to-satellite hop, see
[satellites.md](satellites.md).

---

## Troubleshooting

| Problem | What to check |
| --- | --- |
| Something does not start | `sudo rp doctor` checks the app server, scheduler, scanner, push, nginx and the storage backend. `rp status` lists every component. |
| The dashboard returns 502 | The app server is down. `sudo rp restart wsgi`, then look at `journalctl -u remotepower-wsgi`. |
| Agents cannot reach the server | Check the URL and port from the host, and that the certificate matches the name the agent uses (`RP_TLS_HOST` in Docker). |
| The client IP in the audit log is the load balancer | Turn on `trust_proxy` (see App nodes). |
| A node shows old data | Every node must use the same database and the same `DATA_DIR` for file artifacts. |

## See also

[install.md](install.md) (quick start), [upgrading.md](upgrading.md), [https.md](https.md),
[admin-guide.md](admin-guide.md), [cli.md](cli.md), [scaling.md](scaling.md),
[windows-client.md](windows-client.md).
