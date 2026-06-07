# Scaling RemotePower to large fleets (1000+ agents)

RemotePower runs fine on a single small box for a typical homelab or a few
hundred hosts. This guide is for **large fleets — roughly 1,000 agents and up**,
where the defaults start to strain. It explains *what actually limits scale*,
then the levers, in the order you should pull them.

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

1. Stand up Postgres 14+ and a database/user for RemotePower.
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
  **all pointed at the same Postgres DSN.** No node holds state.
- **No session stickiness required** — sessions are token-based, validated
  against the shared DB. Round-robin is fine.
- Health check the LB against **`GET /api/health`** (cheap, no auth).
- Terminate TLS at the LB or pass through; agents only need a stable hostname.
- The per-request background sweeps (SNMP poll, image scan, KEV/EPSS refresh,
  scheduled backup) are **cheap-when-not-due and idempotent** — they self-gate
  on a timestamp in the shared config, so running them across N nodes doesn't
  double-fire.

> Not yet built-in: automatic DB failover / read replicas. Use your Postgres
> platform's HA (managed failover, Patroni, etc.) — RemotePower just needs the
> DSN to point at the writable primary.

---

## Step 5 — Relay satellites (segmented / remote networks)

If agents live in networks that can't all reach the central server directly,
**relay satellites** (Settings → satellites) let agents report to a nearby
satellite that forwards (authenticated) to the server. This fans-in
connections and avoids opening the central server to every segment. Useful
for multi-site fleets regardless of raw scale.

---

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
