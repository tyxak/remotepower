# High availability — the reference topology

RemotePower manages the fleet, which makes it **tier-0 infrastructure**: when
it is down you are blind *and* you can't fix anything through it. This guide
is the supported active/passive reference topology — no new components beyond
what a standard install already uses (nginx, gunicorn, PostgreSQL, systemd),
plus a floating IP.

**TL;DR:** two identical server hosts, PostgreSQL streaming replication,
a floating IP (keepalived) in front of nginx, the scheduler running on the
active node only, and a rehearsed promote runbook. Target: **RTO ≤ 15 min,
RPO ≈ 0** (synchronous replication) or **RPO ≤ seconds** (asynchronous).

## What state lives where (and what that means for HA)

| State | Where | HA answer |
| --- | --- | --- |
| Every logical store (devices, alerts, config, tickets, …) | PostgreSQL | Streaming replication — this is the whole ballgame |
| App workers (gunicorn) | Stateless | Run on both nodes; only the active one receives traffic |
| Maintenance sweeps | The out-of-band scheduler | **Singleton** — must run on the active node ONLY (two schedulers double-fire webhooks and races) |
| Sidecars (webterm, scanner, push, syslogd) | Per-node daemons | Installed on both; enabled with the active role |
| Agent enrolment tokens / TLS | In Postgres + nginx certs | Certs deployed to both nodes; agents follow the floating IP/DNS name |
| Signing keys (`signing-gpg/`), backups passphrase, `api.env` | Files under `DATA_DIR` / `/etc/remotepower` | **Not in Postgres** — sync once at setup and after key changes (they change rarely; a root-only rsync or config management) |

**Hard requirement: the PostgreSQL backend.** The flat-JSON/SQLite backends
keep state on one node's disk and have no replication story — fine for
homelab/dev, not for HA. `docs/scaling.md` Step 1 covers the migration.

## The topology

```
                    agents (poll https://rp.example.com)
                                   │
                        floating IP (keepalived VRRP)
                          ┌────────┴────────┐
                   ┌──────▼─────┐    ┌──────▼─────┐
                   │  node A    │    │  node B    │
                   │  (active)  │    │ (standby)  │
                   │ nginx      │    │ nginx      │
                   │ gunicorn   │    │ gunicorn   │
                   │ scheduler ✓│    │ scheduler ✗│
                   │ sidecars ✓ │    │ sidecars ✗ │
                   │ PG primary─┼────┼→PG standby │  (streaming replication)
                   └────────────┘    └────────────┘
```

- **Floating IP**: keepalived (VRRP) with a health-check script — track nginx
  *and* a `GET /api/public/status` probe, not just the interface. In cloud
  environments, replace with the provider's floating/elastic IP or a DNS
  failover with a short TTL (agents re-resolve on every poll cycle).
- **PostgreSQL**: standard streaming replication (`primary_conninfo` on the
  standby). `synchronous_commit = on` with a synchronous standby gives RPO 0
  at a small write-latency cost; async is fine when losing the last seconds
  of telemetry on failover is acceptable (heartbeats re-report within a
  minute anyway — the stores that matter for RPO are config, tickets and the
  audit log).
- **Scheduler singleton**: `remotepower-scheduler.service` enabled on the
  active node only. The simplest robust arrangement is to let keepalived's
  transition scripts start/stop it (`notify_master` / `notify_backup`); the
  alternative (running it everywhere behind a Postgres advisory lock) is not
  currently supported — don't run two.
- **App servers on both nodes, always up**: gunicorn is stateless (all state
  goes through the storage backend), so the standby's app tier can stay
  running — failover is then purely "move the VIP + promote Postgres +
  start the scheduler/sidecars".

## Failover runbook (promote the standby)

Rehearse this until it's boring — it is the whole point of the setup:

1. **Fence the old primary** (stop nginx + scheduler on node A, or confirm
   it's dead). Split-brain with two schedulers + two primaries is the one
   scenario this topology cannot tolerate.
2. **Promote Postgres** on node B: `pg_ctl promote` (or `SELECT pg_promote()`).
3. **Move the VIP** (keepalived does this automatically on node-A death;
   manual failover = adjust priority or stop keepalived on A).
4. **Start the singleton services** on B: `systemctl start
   remotepower-scheduler remotepower-webterm remotepower-scanner
   remotepower-push remotepower-syslogd` (whichever are in use).
5. **Verify**: Server-status page → storage backend reachable, scheduler
   heartbeat fresh, Distributed-subsystems rows green; a test device shows a
   fresh heartbeat; `GET /api/self/status` clean.
6. **Re-establish replication** the other way once node A is repaired
   (`pg_rewind` or re-basebackup), and fail back in a maintenance window —
   or simply leave B active; the nodes are identical by design.

Agents need nothing: they retry failed heartbeats, spool metrics while the
server is unreachable (v6.2.x), and follow the same URL.

## Backups are not HA (do both)

Replication replicates mistakes and ransomware faithfully. Keep the built-in
encrypted backups (Settings → Backup) + **weekly restore drills** (v6.3.0)
pointed at storage that lives on neither node. HA answers "a node died";
backups answer "the data is wrong".

## Capacity target and how to verify it

The reference topology is sized and tested against an explicit target —
verify on your hardware rather than trusting ours:

- **Target: 1,000 devices at a 60 s poll** ≈ 17 heartbeats/s sustained (plus
  UI traffic). On the recommended Postgres backend this is dominated by the
  heartbeat handler's store writes.
- **Load-test recipe**: enroll one throwaway device, capture its heartbeat
  body, then replay it at rate with unique device ids from a test enrolment
  batch (`ab`/`wrk`/a 20-line Python loop against `POST /api/heartbeat`)
  against a **staging copy** — never the live control plane. Watch: p95
  heartbeat latency (< 250 ms is healthy), gunicorn worker saturation
  (`docs/scaling.md` Step 3), Postgres write throughput, and the Server-status
  self-observability page for sweeps starting to lag.
- Beyond ~1–2k devices: raise the poll interval (Step 2), add relay
  satellites for remote segments (Step 5), and consult `scaling.md` Step 4
  for the multi-node app tier behind a load balancer (the same floating-IP
  pattern, load-balanced instead of active/passive).

## What this deliberately is not

- **Not active/active application HA** — one scheduler, one Postgres primary.
  Active/active app workers behind a load balancer work (scaling.md Step 4),
  but the singleton constraints stay.
- **Not automatic Postgres failover** — promotion is a human (or your
  Patroni/repmgr setup, if you run one; RemotePower only needs a reachable
  primary via its configured DSN). Automating promotion badly is how
  split-brain happens; this guide keeps the human in the loop, matching the
  product's own approval-gated philosophy.
