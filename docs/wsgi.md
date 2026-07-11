# The app server — gunicorn + Flask

The RemotePower server runs entirely under **gunicorn**, serving the real
`api.py` request path through a thin Flask app (`server/cgi-bin/wsgi.py`).
This is the **only** server since v6.1.0 — the earlier CGI entry point
(`api_cgi.py` behind nginx + fcgiwrap) and the SCGI prefork worker
(`api_worker.py` / `remotepower-api.service`) have both been retired.
`install-server.sh` installs and enables `remotepower-wsgi.service` by
default; nginx's shipped `remotepower-locations.conf` already `proxy_pass`es
`/api/` to it on `127.0.0.1:8090` — nothing to switch on.

## What it is

`wsgi.py` exposes `application`, a real `flask.Flask` instance (so gunicorn's
`wsgi:application` target, error handling, and Flask's own test client all
work). Business logic is unchanged: every request still runs the exact same
`api.main()` request path (dispatch table, auth, CSRF/read-only/IP-allowlist
enforcement, the ~33 maintenance sweeps) that has always served RemotePower —
only the transport shell (CGI vs a persistent Flask/gunicorn process) changed.

## Concurrency: threads and/or processes

Request state — the request context (environ + body), the response buffer,
the `load()` cache, the correlation/trace ids, and the database connections —
is all **thread-local**, so a worker serves requests **concurrently on
threads** (no global lock). Scale on either axis in
`server/conf/remotepower-wsgi.service`'s `ExecStart`:

- **`--threads N`** for in-process concurrency (lower memory; ideal for the
  I/O-bound, DB-backed requests that dominate). A thread-dispatching
  `sys.stdout` proxy routes each request's output to its own buffer.
- **`--workers N`** for process parallelism (more memory, sidesteps the GIL
  for CPU-bound work). Workers are independent processes.
- A typical mix is `--workers <cpus> --threads 8` (the shipped default is
  `--workers 4 --threads 8`). Tune threads to your DB connection budget (each
  active thread may hold one connection).
- Use **sync workers with threads** (the default — do not switch to
  gevent/eventlet). Long-poll endpoints (`/api/exec/wait`) and the
  `_LOAD_CACHE` per-request-invalidation contract were validated against this
  worker model.

Validated under load on real Postgres: 800 concurrent requests (24 threads),
zero errors, a unique correlation id per request (no cross-request state
leak), correct per-path responses. After editing the unit:

```bash
systemctl daemon-reload && systemctl restart remotepower-wsgi
```

## Database

- **SQLite** is single-node. Multiple worker *processes* on one host against
  one SQLite file work (WAL + per-thread connections), but you cannot run
  multiple *hosts* on SQLite.
- For multiple app **nodes** behind a load balancer, use the **Postgres**
  backend (`RP_STORAGE_BACKEND` / the storage marker). Sessions, rate-limit
  and long-poll state already live in the shared store, so the app tier is
  stateless and horizontally scalable on Postgres. Each gunicorn thread
  caches one Postgres connection and reuses it across requests (see
  [scaling.md](scaling.md) for connection-count math at many nodes).

---

## Out-of-band maintenance scheduler (default on)

RemotePower runs ~33 background maintenance sweeps (monitors, IMAP ingest,
KEV/EPSS refresh, scheduled reports, backups, escalation, …). Left
in-process they'd **piggy-back on request traffic** — when a request arrives,
`main()` runs whatever is due. Two limits at scale: with **no traffic
nothing runs**, and **N app nodes each** run the sweeps.

`server/cgi-bin/scheduler.py` runs the same sweeps from a dedicated process
with a leader lock so only one runs them. `install-server.sh` sets this up by
default (`--no-scheduler` to opt out); manually:

```bash
cp server/conf/remotepower-scheduler.service /etc/systemd/system/
printf 'RP_EXTERNAL_SCHEDULER=1\n' >> /etc/remotepower/api.env   # tell the app server to stop running it
systemctl daemon-reload && systemctl enable --now remotepower-scheduler
systemctl restart remotepower-wsgi
```

- **`RP_EXTERNAL_SCHEDULER=1` and the scheduler unit are a pair.** The flag
  tells the request path to stop running the cadence; the unit runs it
  instead. **Setting the flag without running the scheduler means nothing
  runs the cadence.**
- **Leader election:** a host file-lock (single node) plus, on Postgres, a
  `pg_advisory_lock` (cross-node) — run one scheduler per node; only the
  leader executes.
- **Interval:** `RP_SCHEDULER_INTERVAL` seconds (default 60). Sweeps are
  each `_if_due`-gated, so the interval just controls how often "what's due"
  is checked.
- **Measured win:** on a networked Postgres backend the per-request cadence
  costs ~33 "is it due?" DB round-trips. In a staging test that was **~0.68
  s/request on the request path vs ~0.027 s with the scheduler off-path — a
  ~25× latency drop.** On a networked DB, keeping it on is strongly
  recommended (it's the default).

---

## Verify what's serving

Open **Server status** in the app → the **"Serving & runtime"** panel, or
from the shell run **`sudo rp doctor`** ([cli.md](cli.md)) for a one-shot check of
the app server, scheduler and the rest of the stack. The raw equivalents:

```bash
journalctl -u remotepower-wsgi -f                        # requests arriving, no tracebacks
journalctl -u remotepower-scheduler -n 20 --no-pager      # acquires leadership, runs cadence
tail -n 5 /var/log/nginx/<vhost>_error.log                # no upstream errors
```
(`rp logs wsgi` / `rp restart wsgi` wrap the first and a restart.)

> **Gotcha:** `systemctl show -p Environment <unit>` only prints *inline*
> `Environment=` lines — it does **not** show variables loaded from
> `EnvironmentFile=/etc/remotepower/api.env`. To see what a running worker
> actually has:
> `sudo cat /proc/$(pgrep -f 'gunicorn.*wsgi:application'|tail -1)/environ | tr '\0' '\n' | grep RP_`.

---

## Troubleshooting

**`gunicorn :8090 → 000`** — gunicorn isn't answering. It's stopped
(`systemctl status remotepower-wsgi`), or crash-looping because a dependency
is missing (`journalctl -u remotepower-wsgi -n 40` — check for a missing
`flask`/`gunicorn`/`psycopg` import).

**502 from nginx** — the app server unit isn't running, or nginx's
`remotepower-locations.conf` doesn't match the shipped snippet (a hand-edited
vhost that still points at fcgiwrap is stale — reinstall
`server/conf/remotepower-locations.conf` or re-run `install-server.sh`).

**The cadence stopped running** — `RP_EXTERNAL_SCHEDULER=1` is set but the
scheduler unit isn't active. Start it: `systemctl enable --now
remotepower-scheduler`.

**Reinstalling the units after an upgrade:**

```bash
install -m644 server/conf/remotepower-{wsgi,scheduler}.service /etc/systemd/system/
systemctl daemon-reload && systemctl restart remotepower-wsgi
```
