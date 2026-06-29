# Persistent app tier — gunicorn WSGI + out-of-band scheduler

> **Status: opt-in, experimental (the v5.5.0 "keystone").** The default and fully
> supported way to run RemotePower is the CGI entry point (`api_cgi.py` behind
> nginx + fcgiwrap) or the persistent **SCGI** worker (`remotepower-api.service`).
> The WSGI tier below is for large fleets that want a pre-warmed, threaded app
> tier. It runs the **same `api.py`** — nothing about your data, config or agents
> changes — and it is reversible at any time.

## TL;DR — switch back and forth with one command

From your server checkout (the repo, e.g. `/home/you/remotepower`):

```bash
sudo make app-server-wsgi      # → gunicorn WSGI tier + out-of-band scheduler
sudo make app-server-cgi       # → back to CGI/SCGI (and stop the scheduler)
make app-server-status         # which tier is active + unit/scheduler state
```

These wrap `packaging/remotepower-app-server.sh`. Custom vhost? See
[Custom vhosts](#custom-vhosts). **Always read [Before you switch](#before-you-switch)
first** — the one way to cause an outage is to point nginx at a gunicorn that isn't
actually serving, and the tool guards against that only if the served code is current.

---

## When to use which tier

| Tier | What it is | Good for |
|---|---|---|
| **CGI / fcgiwrap** (default) | forks + re-interprets `api.py` per request | small/medium installs; zero extra services |
| **SCGI worker** (`remotepower-api`) | imports `api.py` once, **forks** per request | a cheap persistent win; keeps CGI's process isolation |
| **WSGI / gunicorn** (this doc) | imports `api.py` once, serves **concurrently on threads** | large fleets; pre-warmed, lowest per-request overhead; pairs with the out-of-band scheduler |

`server/cgi-bin/wsgi.py` exposes a standard `application(environ, start_response)`.
It adapts the WSGI request to the CGI contract `api.py` already speaks, runs the
existing request path, and translates the response back — so behaviour is identical
to CGI/SCGI.

---

## Before you switch

The toggle starts gunicorn, **waits for `http://127.0.0.1:8090/api/health` to answer,
and only then repoints nginx** — so a dead worker aborts the switch instead of 502-ing
your site. That gate only helps if the served code can actually start, so confirm:

```bash
# 1. The SERVED code (what gunicorn imports) must be v5.5.0+ — wsgi.py has to exist.
ls -l /var/www/remotepower/cgi-bin/wsgi.py
grep -m1 SERVER_VERSION /var/www/remotepower/cgi-bin/api.py      # expect 5.5.0+

# 2. gunicorn must be installable (the tool installs it; or `pip install gunicorn`).
```

If `wsgi.py` is missing, deploy the current code first (`sudo bash deploy-server.sh`)
— that is a real code deploy, do it deliberately. **Multiple hosts require the
Postgres backend** (see [Database](#database)); SQLite is single-node.

---

## What the toggle does (and why it's safe)

`packaging/remotepower-app-server.sh wsgi`:

1. installs gunicorn if missing and enables `remotepower-wsgi.service` (gunicorn on
   `127.0.0.1:8090`);
2. **health-gates** the change: polls `:8090/api/health` (≤15 s) — if it never
   answers, it **stops before touching nginx** and you stay on CGI/SCGI;
3. **surgically** rewrites the active RemotePower `/api` location blocks in your nginx
   config — it swaps only the backend directives (`fastcgi_pass`/`scgi_pass` and their
   `*_param` / `include *_params` / `*_read_timeout` lines) for `proxy_pass` + the proxy
   headers, and **preserves every other line** in the block (`include …/fw_private_rp`,
   `modsecurity off`, `limit_except`, `auth_request`, `add_header`, …). Locations that
   don't drive the RP backend (e.g. a webterm websocket proxy) are left untouched, and a
   `PATH_INFO` override such as `/install` → `/api/agent/install` is carried onto
   `proxy_pass`;
4. saves the pristine pre-switch file to `<file>.cgi.bak` (so the way back is **byte
   lossless**), runs `nginx -t`, and **auto-reverts** if validation fails;
5. enables the out-of-band scheduler (`--no-scheduler` to skip) — see
   [the scheduler](#out-of-band-maintenance-scheduler).

`packaging/remotepower-app-server.sh cgi` restores `<file>.cgi.bak`, stops
`remotepower-wsgi`, and disables the scheduler (`--keep-scheduler` to leave it). Your
data is never touched. Both directions are idempotent — re-running detects the current
state and only changes what differs.

### Custom vhosts

The tool finds your nginx config in this order:

1. `RP_NGINX_CONF=/path/to/your/vhost` (or `RP_NGINX_SNIPPET`) if you set it;
2. the shared snippet `/etc/nginx/snippets/remotepower-locations.conf`;
3. otherwise it **auto-detects** the file under `/etc/nginx` that defines the
   RemotePower `/api` backend (fcgiwrap socket, the RP scgi socket, or `:8090`),
   resolving symlinks.

If you keep several RemotePower vhosts (prod, demo, old), auto-detect finds more than
one and **refuses to guess** — pass the right one explicitly:

```bash
sudo RP_NGINX_CONF=/etc/nginx/sites-enabled/remotepower bash packaging/remotepower-app-server.sh wsgi
```

(With `make`, run the script directly as above so the env var reaches it.) The
surgical rewrite is exactly why a hand-tuned private vhost — IP allowlist, Authelia
forward-auth, `modsecurity off` on a route — survives the switch intact.

---

## Run it manually (under the hood)

If you'd rather not use the toggle, the same thing by hand:

```bash
pip install gunicorn
cp server/conf/remotepower-wsgi.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now remotepower-wsgi
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8090/api/health   # want 200 BEFORE nginx
```

Then point nginx `/api/` at it (keep your own `limit_except`, allowlist `include`s,
auth, etc.):

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

You do **not** need to forward `X-Token` / `X-RP-Vault-Key` as params — they are
hyphenated request headers and pass through `proxy_pass` to the WSGI environ as
`HTTP_X_TOKEN` / `HTTP_X_RP_VAULT_KEY` automatically. `RP_DATA_DIR` comes from the
unit's `Environment=`, not from nginx. Static files (`/`, `/static/…`) keep being
served by nginx exactly as today.

---

## Concurrency: threads and/or processes

Request state — the request context (environ + body), the response buffer, the
`load()` cache, the correlation/trace ids, and the database connections — is all
**thread-local**, so the worker serves requests **concurrently on threads** (no global
lock). Scale on either axis:

- **`--threads N`** for in-process concurrency (lower memory; ideal for the I/O-bound,
  DB-backed requests that dominate). A thread-dispatching `sys.stdout` proxy routes each
  request's output to its own buffer.
- **`--workers N`** for process parallelism (more memory, sidesteps the GIL for
  CPU-bound work). Workers are independent processes.
- A typical mix is `--workers <cpus> --threads 8`. Tune threads to your DB connection
  budget (each active thread may hold one connection).

Validated under load on real Postgres: 800 concurrent requests (24 threads), zero
errors, a unique correlation id per request (no cross-request state leak), correct
per-path responses.

## Database

- **SQLite** is single-node. Multiple worker *processes* on one host against one SQLite
  file work (WAL + per-thread connections), but you cannot run multiple *hosts* on
  SQLite.
- For multiple app **nodes** behind a load balancer, use the **Postgres** backend
  (`RP_STORAGE_BACKEND` / the storage marker). Sessions, rate-limit and long-poll state
  already live in the shared store, so the app tier is stateless and horizontally
  scalable on Postgres.

---

## Out-of-band maintenance scheduler

By default RemotePower runs its ~33 background maintenance sweeps (monitors, IMAP
ingest, KEV/EPSS refresh, scheduled reports, backups, escalation, …) **piggy-backed on
request traffic** — when a request arrives, `main()` runs whatever is due. Two limits at
scale: with **no traffic nothing runs**, and **N app nodes each** run the sweeps.

`server/cgi-bin/scheduler.py` runs the same sweeps from a dedicated process with a
leader lock so only one runs them. The toggle sets this up for you; manually:

```bash
cp server/conf/remotepower-scheduler.service /etc/systemd/system/
printf 'RP_EXTERNAL_SCHEDULER=1\n' >> /etc/remotepower/api.env   # tell the WORKER to stop running it
systemctl daemon-reload && systemctl enable --now remotepower-scheduler
systemctl restart remotepower-wsgi          # (or remotepower-api on the SCGI tier)
```

- **`RP_EXTERNAL_SCHEDULER=1` and the scheduler unit are a pair.** The flag tells the
  request path to stop running the cadence; the unit runs it instead. **Setting the flag
  without running the scheduler means nothing runs the cadence** — the toggle keeps the
  two in sync (`app-server-cgi` clears the flag and stops the unit together).
- **Leader election:** a host file-lock (single node) plus, on Postgres, a
  `pg_advisory_lock` (cross-node) — run one scheduler per node; only the leader executes.
- **Interval:** `RP_SCHEDULER_INTERVAL` seconds (default 60). Sweeps are each
  `_if_due`-gated, so the interval just controls how often "what's due" is checked.
- **Measured win:** on a networked Postgres backend the per-request cadence costs ~33
  "is it due?" DB round-trips. In a staging test that was **~0.68 s/request on the
  request path vs ~0.027 s with the scheduler off-path — a ~25× latency drop.** On a
  networked DB, turning it on is strongly recommended.

The SCGI worker reads `api.env` too, so you can run the scheduler with the SCGI tier as
well — you don't have to be on WSGI to benefit from it.

---

## Verify after switching

```bash
make app-server-status                                   # tier should read "wsgi"
journalctl -u remotepower-wsgi -f                        # requests arriving, no tracebacks
journalctl -u remotepower-scheduler -n 20 --no-pager     # acquires leadership, runs cadence
tail -n 5 /var/log/nginx/<vhost>_error.log               # no NEW upstream errors
# then load the dashboard from an allowed client
```

> **Reading `error.log`:** `tail -f` prints the existing (old) lines first, then waits.
> Check the **timestamps** — lines from before your switch are historical, not new
> failures. A genuine problem shows entries dated *after* the cutover.

---

## Rollback (lossless, anytime)

```bash
sudo make app-server-cgi
# custom vhost:
sudo RP_NGINX_CONF=/etc/nginx/sites-enabled/<vhost> bash packaging/remotepower-app-server.sh cgi
```

This restores `<file>.cgi.bak` (your exact pre-switch nginx config), stops
`remotepower-wsgi`, and hands the cadence back to the request path. **Keep the SCGI
worker (`remotepower-api`) or fcgiwrap enabled while you trial WSGI** — rollback is then
instant. Retire the old tier only once you're confident:
`systemctl disable --now remotepower-api`.

---

## Troubleshooting

**`502` + `connect() to unix:/run/remotepower/api.sock failed (No such file or
directory)` after switching.** nginx is still routing to the SCGI/fcgiwrap socket but
the worker's socket is gone. Causes and fixes:

- *You edited the wrong file.* The live vhost is whatever nginx actually loads
  (usually `/etc/nginx/sites-enabled/*`), not a `sites-available/*` copy that isn't
  symlinked in. Confirm with `make app-server-status` (it prints the resolved file) and
  pass the right one via `RP_NGINX_CONF`.
- *The socket was deleted by a `RuntimeDirectory` collision.* **Fixed in v5.5.0:** the
  `remotepower-wsgi`/`remotepower-scheduler` units must **not** declare
  `RuntimeDirectory=remotepower` (the SCGI worker uses `/run/remotepower` for its
  socket, and systemd deletes a `RuntimeDirectory` when its unit stops). If you carried
  older unit files, reinstall the current ones (`install -m644
  server/conf/remotepower-{wsgi,scheduler}.service /etc/systemd/system/ && systemctl
  daemon-reload`) and `systemctl restart remotepower-api` to recreate the socket.

**`gunicorn :8090 → 000`** — gunicorn isn't answering. It's stopped (`systemctl status
remotepower-wsgi`), or crash-looping because the served code isn't v5.5.0 (no `wsgi.py`)
or a dependency is missing (`journalctl -u remotepower-wsgi -n 40`). The health gate
will refuse to flip nginx in this state — fix the worker first.

**"multiple nginx files define the RemotePower /api backend"** — you have more than one
RemotePower vhost. Pick the live one and pass `RP_NGINX_CONF=<file>`.

**The cadence stopped running** — `RP_EXTERNAL_SCHEDULER=1` is set but the scheduler unit
isn't active. Either start it (`systemctl enable --now remotepower-scheduler`) or, if you
rolled back to the request-path cadence, clear the flag (`make app-server-cgi` does both).

---

## Falling back completely

Both the WSGI tier and the external scheduler are opt-in and reversible: `make
app-server-cgi` (or stop gunicorn + repoint nginx at fcgiwrap/SCGI, unset
`RP_EXTERNAL_SCHEDULER`, stop the scheduler). You're back on the CGI/SCGI path with zero
data changes. Keep that path as your fallback until you've validated the persistent tier
under your own load.
