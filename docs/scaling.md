# Advanced: scaling RemotePower to a heavy fleet (1000+ agents)

> **ADVANCED — you do NOT need most of this for a normal install.** Since
> v6.1.0, a single box already runs the full single-node stack by default —
> PostgreSQL, gunicorn/Flask, the out-of-band scheduler and a co-located
> scanner satellite, all provisioned automatically by
> [`install-server.sh`](install.md) / `docker compose up` with no flags — and
> comfortably runs a typical homelab / SMB fleet (up to a few hundred hosts).
> HA (read replicas/failover), relay satellites, multiple **app nodes** and
> load balancers below are the separate **heavy-fleet** track — ignore them
> unless you are genuinely at large scale.
>
> To see and control that single-node stack (app server, scheduler, scanner,
> push) on a box, use [`rp status` / `rp tui` / `rp doctor`](cli.md).

This guide is for **large fleets — roughly 1,000 agents and up**, where the
defaults start to strain. It explains *what actually limits scale*, then the
levers, in the order you should pull them.

> TL;DR for 1000+: **(1) move the storage backend to PostgreSQL, (2) raise the
> agent poll interval, (3) tune the gunicorn worker/thread pool, and only then
> (4) go horizontal behind a load balancer.** Most fleets never need step 4.

---

## How RemotePower is deployed (why scale behaves the way it does)

```
agents ──HTTPS──> nginx ──proxy_pass──> gunicorn (threaded workers) ──> wsgi.py (Flask) ──> api.py
                    │                                                                          │
                    └─ serves static assets directly                    reads/writes the storage backend
```

Two facts drive everything below:

1. **The app is a persistent gunicorn/Flask server** (the only server since
   v6.1.0 — CGI/fcgiwrap is retired). Request state (context, output buffer, DB
   connections) is thread-local, so a worker serves requests concurrently on
   threads with no per-request fork/startup cost — which is *great* for
   horizontal scaling (any node can serve any request) and means **throughput
   is bounded by `--workers` × `--threads`, not process spawn cost.**
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
*concurrency* (gunicorn `--workers` × `--threads`) and *write contention*
(storage backend).

---

## How do I know what's actually serving? (verify, don't guess)

Open **Server status** in the app (the sidebar item that watches RemotePower
itself) → the **“Serving & runtime”** panel at the top. It shows, live from the
process handling your request:

| Row | What it tells you |
|-----|-------------------|
| **Storage backend** | `PostgreSQL` / `SQLite` / `JSON files` — the active `RP_STORAGE_BACKEND`. |
| **Request tier** | `WSGI · gunicorn` (the only server) — how requests are executed. |
| **Out-of-band scheduler** | `Running` (with a live heartbeat age), `Configured — no heartbeat` (flag set but the process is dead — fix it), or `Off`. |
| **Per-request maintenance** | Whether the ~33 sweeps run *inside each request* or are *offloaded to the scheduler*. |

A green check means the lever below is engaged. This is the fastest way to
confirm a change actually took effect after you edit `api.env` and restart.

> **Gotcha when verifying from the shell:** `systemctl show -p Environment <unit>`
> only prints *inline* `Environment=` lines — it does **not** show variables loaded
> from `EnvironmentFile=/etc/remotepower/api.env`. To see what a running worker
> actually has, read its process environment:
> `sudo cat /proc/$(pgrep -f 'gunicorn.*wsgi:application'|tail -1)/environ | tr '\0' '\n' | grep RP_`.
> The Serving panel reads the same live process state, so it's the reliable check.

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
   online-safe and reversible (keep the JSON/SQLite files until you're happy) —
   the old backend stays active and writable for the whole copy, and up to 3
   automatic catch-up passes re-copy any file a live heartbeat wrote during
   the migration before the marker flips *(v6.1.1)*.

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

## Step 3 — Tune the gunicorn worker pool

Throughput is `--workers` (processes) × `--threads` (per process) — both set
in `server/conf/remotepower-wsgi.service`'s `ExecStart` (`install-server.sh`
installs it by default; a fresh install ships `--workers 4 --threads 8`).
Request state (context, output buffer, DB connections) is thread-local, so a
worker serves requests concurrently on threads with no fork and no
per-request startup cost — validated correct under load on both the SQLite
and Postgres backends (no load-cache, correlation-id, or response-body bleed
across threads).

- **Workers** ≈ CPU cores (each is a real process — more than that just adds
  memory/context-switch overhead without more throughput on a CPU-bound host).
- **Threads** — the work is I/O-bound on the DB, so oversubscribe here: 8–16
  threads per worker is a good starting point.
- Edit the unit, then `systemctl daemon-reload && systemctl restart remotepower-wsgi`.
- Keep `proxy_read_timeout 130s` (already set in the shipped nginx snippet)
  for the slow AI / scan endpoints and the `/api/exec/wait` long-poll; those
  are rare — heartbeats return in milliseconds.

Rule of thumb: enough `workers × threads` that steady-state heartbeat req/s
(Step 1 arithmetic) uses well under half the pool, leaving headroom for UI +
bursts. See [wsgi.md](wsgi.md) for the full worker-model writeup.

### The out-of-band maintenance scheduler (v5.5.0, default on)

RemotePower runs ~33 `run_*_if_due` maintenance sweeps. Left in-process they'd
**piggy-back on request traffic** — convenient on a single node, but it means
(a) no traffic ⇒ no maintenance, (b) every request makes ~33 "is it due?" DB
round-trips, and (c) N horizontal nodes all race the same sweep. The default
`remotepower-scheduler.service` runs the cadence from one dedicated process:

```bash
cp server/conf/remotepower-scheduler.service /etc/systemd/system/
printf 'RP_EXTERNAL_SCHEDULER=1\n' >> /etc/remotepower/api.env   # on the app server
systemctl daemon-reload && systemctl enable --now remotepower-scheduler
systemctl restart remotepower-wsgi
```

A host file-lock plus (on Postgres) a `pg_advisory_lock` make it **leader-elected**:
run one scheduler per node and exactly one — the elected leader — executes the
sweeps, so it is HA-safe across the load-balanced topology in Step 4. Measured
**~25× lower request latency** on a networked Postgres backend (the request path
no longer makes the per-request due-checks). Roll back by disabling the unit,
removing `RP_EXTERNAL_SCHEDULER` from `api.env`, and restarting the worker — the
request path resumes the cadence.

**Verify it took:** the flag must be set on the **app-server tier** (worker), not
just the scheduler — that's what makes the request path *skip* the cadence. After
restarting, open **Server status → Serving & runtime**: the scheduler row should
read *Running* with a recent heartbeat, and *Per-request maintenance* should read
*Offloaded to scheduler*. If the scheduler row says *Configured — no heartbeat*,
the `remotepower-scheduler` process isn't running; if *Per-request maintenance*
still says *Runs in each request*, the flag didn't reach the worker (check
`api.env` and that you restarted `remotepower-wsgi`).

---

## Step 4 — Go horizontal (load balancer + shared Postgres)

Only needed past the point a single beefy node can serve (many thousands of
agents, or for redundancy). Because the app server holds no cross-request
state (per-request context is thread-local, never shared), this is
straightforward **once you're on Postgres**:

```
agents / UI ──> Load Balancer (TLS) ──> app node 1 ─┐
                                       ──> app node 2 ─┼──> one PostgreSQL
                                       ──> app node N ─┘
```

- Each app node is an identical nginx + gunicorn + RemotePower install,
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

Each gunicorn thread caches and reuses ONE Postgres connection across requests
(thread-local, reconnects only if broken) — so live connections per node are
bounded by `--workers × --threads`, not one per request. At many app nodes (or
a large worker/thread count), that fixed pool can still add up to more
connections than Postgres's `max_connections` comfortably serves. **PgBouncer**
in front of Postgres pools and reuses server connections, so many app-side
connections map onto a small, stable set of real Postgres sessions.

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

Reach for this once you're running enough app nodes (Step 4) that their
combined connection counts approach Postgres's limit — a single node rarely
needs it given the per-thread connection reuse above.

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
- Raise `LimitNOFILE` for nginx **and** the `remotepower-wsgi` unit (sockets + DB conns).
- Static assets are already served directly by nginx with an immutable cache +
  precompressed (brotli/gzip) — don't route them through the app server.
- `application/json` is intentionally **not** gzipped (defence-in-depth); leave
  it.
- Put Postgres on a low-latency link to the app nodes (same VPC/subnet); the
  heartbeat RMW does a couple of round trips.

---

## Capacity rules of thumb

| Fleet size | Backend | Poll interval | Shape |
|-----------:|---------|--------------:|-------|
| ≤ 200 | PostgreSQL (default) or SQLite/JSON | 60 s | single small box |
| 200–1,000 | PostgreSQL | 60–120 s | single box, tune gunicorn workers/threads |
| 1,000–5,000 | **PostgreSQL** | 120–300 s | single strong box, or 2 nodes + LB |
| 5,000+ | PostgreSQL (+ HA) | 300 s | N app nodes behind an LB |

Start at Step 1+2 (Postgres + interval) — that alone carries most fleets to
several thousand agents on a single node. Add Steps 3–4 only when the metrics
(gunicorn saturation, DB wait) say you need them.

See also: [architecture.md](architecture.md), [install.md](install.md),
[admin-guide.md](admin-guide.md).
