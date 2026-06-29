# Running RemotePower under a persistent WSGI server (experimental)

> **Status: experimental (Phase-5 "keystone" Stage B).** The default and fully
> supported way to run RemotePower is the CGI entry point (`api_cgi.py` behind
> nginx + fcgiwrap, or the bundled installer). The WSGI path below is opt-in and
> meant for large fleets that want a persistent, pre-warmed app tier. It runs the
> **same `api.py`** — nothing about your data, config or agents changes.

## Why

The CGI model forks and re-interprets the app on every request. That's simple and
rock-solid for small/medium installs, but at thousands of agents the fork-per-request
overhead becomes the ceiling. A persistent WSGI worker imports `api.py` **once** and
reuses the process across requests, removing that overhead.

`server/cgi-bin/wsgi.py` exposes a standard `application(environ, start_response)`.
It's a thin bridge: it adapts the WSGI request to the CGI contract `api.py` already
speaks, runs the existing request path, and translates the response back. No handler,
auth, storage or response code changes — so it behaves identically to the CGI path.

## Run it

Install a WSGI server (gunicorn shown; any WSGI server works) and point it at the
module from the `cgi-bin` directory:

```bash
pip install gunicorn
cd /var/www/remotepower/server/cgi-bin     # where api.py + wsgi.py live
RP_DATA_DIR=/var/lib/remotepower \
  gunicorn --workers 4 --threads 1 --bind 127.0.0.1:8090 wsgi:application
```

Then proxy nginx to it instead of fcgiwrap:

```nginx
location /api/ {
    proxy_pass         http://127.0.0.1:8090;
    proxy_set_header   Host              $host;
    proxy_set_header   X-Real-IP         $remote_addr;
    proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header   X-Forwarded-Proto $scheme;
    proxy_read_timeout 120s;                 # long-poll heartbeats
}
```

Static files (`/`, `/static/…`) keep being served directly by nginx exactly as today.

## IMPORTANT: use synchronous, single-thread workers — scale with *processes*

This Stage-B shim serialises requests **within** a worker process (it briefly redirects
the process-global `os.environ` / `sys.stdin` / `sys.stdout` to service one request).
So:

- Use **sync** workers with **one thread each** (`--threads 1`). Do **not** use
  `gthread`/`gevent` worker classes yet — concurrent requests in one process would
  contend on the shared stdio.
- Get concurrency by running **more worker processes** (`--workers N`). Each process
  is independent. This is the standard, safe way to scale the shim today.
- The lock-free, fully-threaded path (a streaming response abstraction that removes the
  global stdio redirect) is a later stage of the keystone work.

## Database

- **SQLite** is single-node by design. Multiple worker *processes* on one host against
  one SQLite file work (WAL), but you cannot run multiple *hosts* against SQLite.
- For multiple app **nodes** behind a load balancer, use the **Postgres** backend
  (`RP_STORAGE_BACKEND`). Sessions, rate-limit and long-poll state already live in the
  shared store, so the app tier is stateless and horizontally scalable on Postgres.

## Out-of-band maintenance scheduler (optional)

By default RemotePower runs its ~33 background maintenance sweeps (monitors, IMAP
ingest, KEV/EPSS refresh, scheduled reports, backups, escalation, …) **piggy-backed
on request traffic** — whenever a request arrives, `main()` runs whatever is due.
That's simple and fine for most installs, but it has two limits at scale: with **no**
traffic nothing runs, and **N app nodes each** run the sweeps (duplicate work).

`server/cgi-bin/scheduler.py` is an opt-in standalone scheduler that runs the same
sweeps from a dedicated process, with a leader lock so only one runs them:

```bash
# 1) tell the request path to STOP running the cadence (so it isn't double-run)
export RP_EXTERNAL_SCHEDULER=1            # or config: external_scheduler: true
# 2) run the scheduler as a service / sidecar (one per deployment; or one per node for HA)
RP_DATA_DIR=/var/lib/remotepower python3 server/cgi-bin/scheduler.py
```

- **Leave it off and nothing changes** — without `RP_EXTERNAL_SCHEDULER` the request
  path runs the cadence exactly as it always has (the default).
- **Leader election:** a host file-lock (single node) plus, on the Postgres backend, a
  `pg_advisory_lock` (cross-node) — so you can run one scheduler per node and only the
  elected leader executes the sweeps.
- **Interval:** `RP_SCHEDULER_INTERVAL` seconds (default 60). The sweeps are each
  `_if_due`-gated, so the interval just controls how often "what's due" is checked.

**Why it matters (measured):** against a networked Postgres backend, the per-request
cadence costs ~33 "is it due?" DB round-trips per request. In a staging test that was
**~0.68 s/request with the cadence on the request path vs ~0.027 s with it off — a 25×
latency drop.** On a networked DB, turning the external scheduler on is strongly
recommended.

A ready-made systemd unit ships at `server/conf/remotepower-scheduler.service`
(mirrors the API worker's user/env/capabilities since it runs the same sweeps):

```bash
cp server/conf/remotepower-scheduler.service /etc/systemd/system/
printf 'RP_EXTERNAL_SCHEDULER=1\n' >> /etc/remotepower/api.env   # tell the WORKER to stop running it
systemctl daemon-reload && systemctl enable --now remotepower-scheduler
systemctl restart remotepower-api
```

## Falling back

Both the WSGI path and the external scheduler are opt-in and reversible: stop gunicorn
and repoint nginx at fcgiwrap / `api_cgi.py`, and unset `RP_EXTERNAL_SCHEDULER` (+ stop
the scheduler service), and you're back on the pure CGI path with zero data changes.
Keep CGI as your fallback until you've validated the persistent tier under your load.
