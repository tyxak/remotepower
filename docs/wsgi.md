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

## Falling back

The WSGI path is opt-in and reversible: stop gunicorn, repoint nginx at fcgiwrap /
`api_cgi.py`, and you're back on the CGI path with zero data changes. Keep CGI as your
fallback until you've validated WSGI under your own load.
