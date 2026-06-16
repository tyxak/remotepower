# Advanced: scaling RemotePower to a heavy fleet (1000+ agents)

> **ADVANCED — you do NOT need any of this for a normal install.** A single box
> with the default SQLite backend comfortably runs a typical homelab / SMB fleet
> (up to a few hundred hosts). Postgres, HA, satellites, app nodes and load
> balancers below are a separate **heavy-fleet** track — ignore them unless you
> are genuinely at large scale. The [installer](install.md) never asks about any
> of it.

This guide is for **large fleets — roughly 1,000 agents and up**, where the
defaults start to strain. It explains *what actually limits scale*, then the
levers, in the order you should pull them.

> TL;DR for 1000+: **(1) move the storage backend to PostgreSQL, (2) raise the
> agent poll interval, (3) widen the fcgiwrap worker pool, and only then (4) go
> horizontal behind a load balancer.** Most fleets never need step 4.

---

## How RemotePower is deployed (why scale behaves the way it does)

```
agents ──HTTPS──> nginx ──FastCGI──> fcgiwrap ──fork──> api.py (one process / request)
                    │                                        │
                    └─ serves static assets directly         └─ reads/writes the storage backend
```

Two facts drive everything below:

1. **The app is request-scoped CGI.** `fcgiwrap` forks a fresh `api.py` process
   per request. There is no long-lived application server holding state — which
   is *great* for horizontal scaling (any node can serve any request) but means
   **throughput is bounded by how many CGI processes can run at once.**
2. **All shared state lives in the storage backend.** With the default JSON
   backend that's flat files guarded by per-file locks — fine at small scale,
   a contention point under concurrent writes. The backend is pluggable
   (`json` → `sqlite` → `postgres`); **Postgres is what makes concurrent writes
   and multiple app nodes possible.**

### The arithmetic

Heartbeat load is simply:

```
requests/sec ≈ number_of_agents ÷ poll_interval_seconds
```

- 1,000 agents @ 60 s default ≈ **17 req/s** of heartbeats (plus UI + sweeps).
- 1,000 agents @ 300 s ≈ **3.3 req/s**.
- 5,000 agents @ 300 s ≈ **17 req/s**.

Each heartbeat is a short read-modify-write. The work is small; the limit is
*concurrency* (CGI process count) and *write contention* (storage backend).

---

## Step 1 — Move the storage backend to PostgreSQL  ⭐ do this first

JSON file locks serialize writes; at 1000 agents the heartbeat writes start
queueing (you'll see `HTTP 202 busy` retries). SQLite (WAL) is better for a
single node, but **PostgreSQL is the backend built for this** — concurrent
writers via `pg_advisory_xact_lock`, real transactions, and it's the *only*
backend that can be shared across multiple app nodes (Step 4).

1. Stand up Postgres 14+ and a database/user for RemotePower —
   **`packaging/postgres-setup.sh`** does this (creates the role + DB, can
   `--install` Postgres, `--write-marker` the storage config, and prints the DSN).
2. Point RemotePower at it with **one** of:
   - the marker file `DATA_DIR/storage_backend.json`:
     ```json
     { "backend": "postgres", "dsn": "postgresql://rp:***@db-host:5432/remotepower" }
     ```
   - or the env vars `RP_STORAGE_BACKEND=postgres` and `RP_PG_DSN=postgresql://…`
     (env wins over the marker; useful for the migration CLI / per-node config).
3. **Migrate existing data** with `tools/migrate_storage.py` (or the in-app
   *Settings → Advanced → Storage backend → Migrate*), which copies every store
   into Postgres and verifies before flipping the marker. The migration is
   online-safe and reversible (keep the JSON/SQLite files until you're happy).

> Sizing: the hot tables are `devices`, `entity`, `kv`, `listrow`, `file_meta`,
> and the metric time-series `metric_samples`. For 1000 agents this is small
> (single-digit GB with sane retention — see Step 6). A modest managed Postgres
> instance is plenty; co-locating it on the app node is fine until you go
> multi-node.

SQLite (`backend: sqlite`) is a reasonable middle step for a single node that's
outgrown JSON but isn't ready for Postgres — it gets WAL + diff-saves + a
single-row heartbeat path. It **cannot** be shared across nodes, so it's a
dead end for Step 4.

---

## Step 2 — Raise the agent poll interval

The single cheapest lever. The server pushes `poll_interval` to agents in the
heartbeat response, so you change it centrally and the fleet adopts it:

- Set a fleet default under **Settings** (`default_poll_interval`), or per
  device / per group.
- For 1000+ agents, **120–300 s** is usually the sweet spot — it cuts heartbeat
  req/s by 2–5× with no loss of useful signal (offline detection still works;
  `online_ttl` is derived from the interval).
- Bump `online_ttl` (`DEFAULT_ONLINE_TTL`) to match if you raise the interval a
  lot, so a host isn't flagged offline between polls.

Sysinfo, package lists, drift, and logs are already sent on *slower* multiples
of the poll (every N polls), so raising the base interval thins everything
proportionally.

---

## Step 3 — Widen the FastCGI worker pool

CGI throughput = how many `api.py` processes can run concurrently. The stock
`fcgiwrap` spawns a small number of children; that's the ceiling you hit first.

- Run fcgiwrap with more children — e.g. `fcgiwrap -c <N>` (or
  `FCGI_CHILDREN=<N>` via the spawn unit). A good starting point is
  **2–4× CPU cores**; the work is I/O-bound on the DB, so you can oversubscribe.
- Make sure nginx's `fastcgi_pass` socket and the worker pool aren't the
  bottleneck: raise `worker_connections`, and the OS file-descriptor limit
  (`LimitNOFILE`) for both nginx and the fcgiwrap unit.
- Keep `fastcgi_read_timeout 600s` (already set) for the slow AI / scan
  endpoints, but those are rare; heartbeats return in milliseconds.

Rule of thumb: enough children that steady-state heartbeat req/s (Step 1
arithmetic) uses well under half the pool, leaving headroom for UI + bursts.

### Or skip the CGI tax entirely: the persistent API worker (v4.3.0)

Widening fcgiwrap raises *concurrency*, but every request still pays the
classic-CGI startup cost — fork + Python interpreter start + parsing the whole
`api.py` source — before a single handler line runs. The persistent worker
removes that cost instead: `server/cgi-bin/api_worker.py` (SCGI prefork)
imports `api.py` **once** at service start and forks per request, which keeps
CGI's process-isolation semantics (each request runs in a pristine
copy-on-write copy, crashes are isolated) while the startup tax is paid once.

```bash
cp server/conf/remotepower-api.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now remotepower-api
# then switch the nginx /api/ location to the commented scgi_pass block in
# server/conf/remotepower.conf (or your deployed copy) and reload nginx
```

Concurrency is capped by `RP_WORKER_MAX` (default 32). Rollback is the nginx
block swap in reverse — the worker and fcgiwrap can coexist; nginx decides
which serves. On a busy fleet this is the single biggest latency win in this
guide: it applies to **every** request, heartbeats and dashboard alike.

---

## Step 4 — Go horizontal (load balancer + shared Postgres)

Only needed past the point a single beefy node can serve (many thousands of
agents, or for redundancy). Because the app is stateless CGI, this is
straightforward **once you're on Postgres**:

```
agents / UI ──> Load Balancer (TLS) ──> app node 1 ─┐
                                       ──> app node 2 ─┼──> one PostgreSQL
                                       ──> app node N ─┘
```

- Each app node is an identical nginx + fcgiwrap + RemotePower install,
  **all pointed at the same Postgres DSN** (`RP_PG_DSN` per node, or the storage
  marker). No node holds *database* state.
- **No session stickiness required** — sessions are token-based, validated
  against the shared DB. Round-robin is fine.
- Health check the LB against **`GET /api/health`** (cheap, no auth).
- Terminate TLS at the LB or pass through; agents only need a stable hostname.
- **Enable `trust_proxy`** (Settings, or config) so the real client IP is taken
  from `X-Forwarded-For` (the hop your LB appended) instead of the balancer's
  address — otherwise the **audit log, IP allowlist, and brute-force detection**
  all see the LB. Only turn it on when a trusted proxy fronts *every* request
  (the HAProxy/nginx examples set `X-Forwarded-For`); off by default so a
  single-node install can't be spoofed.
- The per-request background sweeps (SNMP poll, image scan, KEV/EPSS refresh,
  scheduled backup) are **cheap-when-not-due and idempotent** — they self-gate
  on a timestamp in the shared config, so running them across N nodes doesn't
  double-fire.
- **Load-balancer config:** a ready HAProxy example (TLS, round-robin,
  `/api/health` check) is in **`packaging/loadbalancer-haproxy.cfg.example`**;
  an nginx `upstream` equivalent is in the comments there.

> ### One important caveat: shared file storage
>
> The Postgres backend holds the *logical* stores (devices, config, sessions,
> metrics, alerts, …) — those are node-agnostic. But `DATA_DIR` **also** holds a
> few **file artifacts that are NOT in the database** and would otherwise differ
> per node:
>
> - `avatars/` — user profile pictures
> - `scap_reports/` — full OpenSCAP HTML reports per device
> - `host_config_current/` — host-config snapshots
> - `mitigate_logs/` (and similar per-scope command/script output logs)
>
> …plus the **served agent binary** at `/var/www/remotepower/agent/`
> (`remotepower-agent`, its `.asc` signature, and any beta binary).
>
> For a multi-node deployment:
> 1. **Put `DATA_DIR` on shared storage** (NFS / EFS / a clustered FS) mounted
>    identically on every app node — simplest and covers all of the above. (The
>    DB stores are in Postgres regardless; the shared mount is only carrying
>    these file artifacts + the storage marker.)
> 2. **Deploy the agent binary to every node** (it ships with the code, so your
>    normal "deploy code to all nodes" step already handles it — just don't
>    forget the `agent/` dir).
>
> Skip the shared mount and the *core* product still works perfectly across
> nodes — but those specific features (seeing an avatar, downloading a SCAP
> report, reading a mitigation log) only succeed when the LB happens to route
> you to the node that wrote the file. Shared storage removes that surprise.

### Database HA — automatic failover + read replicas

RemotePower has built-in support for a highly-available Postgres:

- **Automatic failover (multi-host DSN).** Point the DSN at every Postgres node:
  ```
  postgresql://rp:pw@pg-primary,pg-standby:5432/remotepower
  ```
  RemotePower adds `target_session_attrs=read-write` automatically, so libpq
  always connects to the **writable primary** and skips standbys. When the
  primary fails and a standby is promoted, the next request reconnects to the
  new primary — connects are retried across a short promotion window so the blip
  doesn't surface as an error. Works with managed failover, Patroni, repmgr,
  pgpool, etc. (RemotePower just needs a host list that includes whoever is
  primary). For a plain streaming-replication pair, the helper scripts set it
  up: **`packaging/postgres-ha-primary.sh`** (on the primary) then
  **`packaging/postgres-ha-standby.sh`** (on each standby).
- **Read replicas (optional, off by default).** Set a separate read DSN —
  `RP_PG_READ_DSN` (env, per node) or `dsn_read` in the storage marker — and
  **pure reads (`load()`) are served from the replica**, while every write and
  every locked read-modify-write stays on the primary. This offloads the
  read-heavy UI / reporting traffic from the primary. Reads from a replica can
  be slightly stale (replication lag); RemotePower keeps all read-modify-write
  on the primary so lag can never cause a lost update. Leave it unset and reads
  use the primary, unchanged.

Current HA status (primary host(s), whether a replica is configured — never
credentials) is shown on *Settings → Advanced → Storage backend* and in
`GET /api/storage-backend/status` (`pg_ha`).

---

## Step 5 — Relay satellites (segmented / remote networks)

If agents live in networks that can't all reach the central server directly,
**relay satellites** (Settings → satellites) let agents report to a nearby
satellite that forwards (authenticated) to the server. This fans-in
connections and avoids opening the central server to every segment. Useful
for multi-site fleets regardless of raw scale.

---

## Step 5b — Connection pooling (PgBouncer), optional

The CGI model opens a fresh Postgres connection per request. At high request
rates that connection setup (and Postgres's per-connection memory) becomes the
ceiling before anything else. **PgBouncer** in front of Postgres pools and
reuses server connections, so the app's many short-lived connects map onto a
small, stable set of real Postgres sessions.

- **`packaging/pgbouncer-setup.sh`** installs + configures it (per app node on
  `127.0.0.1:6432`, or a central pooler). Then point RemotePower's DSN at
  PgBouncer instead of Postgres directly.
- **Transaction pooling is safe here.** RemotePower's Postgres driver disables
  server-side prepared statements (`prepare_threshold=None`) and uses only
  transaction-scoped advisory locks (`pg_advisory_xact_lock`), both of which
  are compatible with PgBouncer's transaction-pooling mode.
- For HA, set PgBouncer's upstream `host=pg-primary,pg-standby` so the pooler
  follows a failover (or keep RemotePower's own multi-host DSN and point it at a
  per-node PgBouncer — either layering works).

This is the cheaper alternative to a persistent application server: you keep the
stateless CGI app and just stop paying per-request connection setup.

## Transport encryption (who's encrypted, who isn't)

By default the **agent/UI → edge** hop is HTTPS (nginx/LB TLS). The *internal*
hops are only encrypted if you configure them — plan for this on a multi-node
or multi-host deployment:

| Hop | Encrypted by default? | How to secure |
|-----|-----------------------|---------------|
| agent / browser → LB (or single nginx) | **Yes** (TLS) | your cert; HSTS is set |
| LB → app node | **No** (the examples forward to nginx `:80`) | run the app nodes' nginx with TLS and point the LB at `:443`, **or** keep this hop on a trusted private network/VPC |
| app node → PostgreSQL | **No** unless you ask | add `?sslmode=require` (or `verify-full` with a CA) to the DSN; set Postgres `ssl=on` |
| app node → PgBouncer | local socket / loopback by default | keep PgBouncer on `127.0.0.1` (no network exposure), or require TLS if central |
| PgBouncer → PostgreSQL | **No** unless you ask | set `sslmode` in the pgbouncer `[databases]` line (the setup script takes `PG_SSLMODE`) |
| primary ↔ standby replication | **No** unless you ask | `sslmode=require` in the standby's `primary_conninfo` + Postgres `ssl=on` |

Rule of thumb: terminate client TLS at the edge, and either **put every internal
hop on TLS** or **confine them to a trusted private network** — don't send the
Postgres password or replication stream in clear over an untrusted link. None of
these internal hops carry agent credentials in the clear regardless (those are
bearer tokens over the already-TLS edge), but the DB password and your fleet
data do traverse the app→DB hop, so encrypt it off-LAN.

## Step 6 — Data retention & DB maintenance

At 1000+ agents the time-series and logs are what grow. Keep them bounded:

- **Metric retention** — `metric_samples_retention_days` (Settings → Data
  retention) controls how far back trend history is kept; the pruner trims
  older samples. 30–90 days is typical.
- **Other retention** — fleet events, alerts, audit log, webhook log all have
  retention/caps in the same framework.
- **`POST /api/db-maintenance`** (Settings → Advanced) runs backend maintenance
  — on Postgres that's `ANALYZE`/vacuum hints; on SQLite, `VACUUM`/`wal_checkpoint`.
  Schedule it (cron / `/schedule`) weekly.
- Agent log rotation is on by the agent side; server-side rolling buffers are
  capped.

---

## nginx / OS tuning checklist

- `worker_processes auto;` and a high `worker_connections`.
- Raise `LimitNOFILE` for nginx **and** the fcgiwrap unit (sockets + DB conns).
- Static assets are already served directly by nginx with an immutable cache +
  precompressed (brotli/gzip) — don't route them through FastCGI.
- `application/json` is intentionally **not** gzipped (defence-in-depth); leave
  it.
- Put Postgres on a low-latency link to the app nodes (same VPC/subnet); the
  heartbeat RMW does a couple of round trips.

---

## Capacity rules of thumb

| Fleet size | Backend | Poll interval | Shape |
|-----------:|---------|--------------:|-------|
| ≤ 200 | JSON (default) | 60 s | single small box |
| 200–1,000 | SQLite or Postgres | 60–120 s | single box, widen fcgiwrap |
| 1,000–5,000 | **PostgreSQL** | 120–300 s | single strong box, or 2 nodes + LB |
| 5,000+ | PostgreSQL (+ HA) | 300 s | N app nodes behind an LB |

Start at Step 1+2 (Postgres + interval) — that alone carries most fleets to
several thousand agents on a single node. Add Steps 3–4 only when the metrics
(fcgiwrap saturation, DB wait) say you need them.

See also: [architecture.md](architecture.md), [install.md](install.md),
[admin-guide.md](admin-guide.md).
