# `rp` — node control CLI

`rp` is RemotePower's omd/checkmk-style command for running the stack on a single
node: one verb to see everything, start/stop/restart the whole thing, tail its
logs, and — most usefully — a `doctor` that diagnoses the common misconfigurations
in one shot.

It's installed to `/usr/local/bin/rp` by `install-server.sh` (fresh installs) and
`deploy-server.sh` (updates), and ships in the Docker image — so it's standard on
every path. `status`, `doctor`, `version`, and `logs` run as any user;
`start`/`stop`/`restart`/`reload` need root (they drive `systemctl`).

```text
rp status              show every stack component + host service
rp tui                 live interactive dashboard (arrow keys + action keys)
rp start   [component] start the RemotePower stack (or one component)
rp stop    [component] stop it
rp restart [component] restart it
rp reload              reload nginx + restart the app server (config reload)
rp doctor              run health checks; exit non-zero on any failure
rp logs    [component] follow the journal for the stack (or one component)
rp install [args…]     (re)run install-server.sh from the source checkout
rp deploy  [args…]     run deploy-server.sh (update code + units + restart)
rp repair              make everything current again (re-deploy, or restart+reload)
rp version             print the installed server version
rp help                this help
```

> **Run `status`/`doctor` as root for the full picture.** The data directory is
> `0700` (owned by the web user) and the nginx config/certs are root-only, so a
> non-root `rp doctor` can't read them — it will say so and skip those checks
> (`sudo rp doctor` gives the complete result). `install`/`deploy`/`repair`
> auto-escalate with `sudo` themselves.

A **component** is a stack unit named without the `remotepower-` prefix —
`wsgi` (the gunicorn app server), `scheduler`, `scanner`, `push`, `webterm`. With
no component, the lifecycle verbs act on the whole stack (started in dependency
order, stopped in reverse). `nginx` and `postgresql` are shown as host services
but are **not** touched by `rp stop`/`start` — they're shared with the rest of the
box.

## Examples

```bash
rp status                 # the dashboard: what's running, on which port, enabled at boot
sudo rp restart           # bounce the whole stack (workers cycle with zero dropped requests)
sudo rp restart push      # just the push daemon
sudo rp stop scanner      # take one component down
rp logs wsgi              # follow the app server's journal
rp doctor                 # full health check (see below)
```

## `rp status`

Prints one row per component — `running` / `stopped` / `FAILED`, whether it's
enabled at boot, and whether its port is actually listening (`:8090` app,
`:8766` push, `:8765` web terminal). It also shows nginx and, on a Postgres
install, whether Postgres is `ready`. It leads with the server version, the
storage backend, and the data directory.

## `rp tui` — live dashboard

`rp tui` (aliases `top`, `dashboard`) opens a full-screen, auto-refreshing
control board — think `htop`/`k9s` for the RemotePower stack. No dependencies;
it's drawn with box characters and ANSI colour, so it works over plain SSH.

<img src="screenshots/TUI.png" alt="rp tui — live stack dashboard" width="640">


```text
╭─ RemotePower  ·  tviweb01 ───────────────────────────────────────────────╮
│  version 6.4.0    backend postgres    uptime 3d 4h    load 0.42           │
├───────────────────────────────────────────────────────────────────────────┤
│  COMPONENT             STATUS        BOOT       PORT                       │
│ ▸ ● wsgi               running       enabled    :8090 ✓                    │
│   ● scheduler          running       enabled    —                         │
│   ● scanner            running       enabled    —                         │
│   ● push               running       enabled    :8766 ✓                    │
│   ○ webterm            stopped       disabled   :8765 ✗                    │
├───────────────────────────────────────────────────────────────────────────┤
│  ● 4 running   ○ 1 stopped   ✖ 0 failed                                    │
╰───────────────────────────────────────────────────────────────────────────╯
  ↑/↓ select   [r]estart [s]tart [x]stop   [d]octor [l]ogs   [q]uit
```

Keys: **↑/↓** (or `j`/`k`) move the selection; **r/s/x** restart / start / stop
the selected component (via `sudo` if you're not root); **d** runs `rp doctor` in
a pager; **l** shows that component's recent logs; **P** repairs the stack;
**?** (or `h`) opens an in-app help + troubleshooting panel; **q** quits. The
board refreshes every 2 seconds. It needs an interactive terminal — piped or in a
non-TTY it just prints `rp status` instead.

The **?** panel inside the TUI lists the keys **and** a compact version of the
troubleshooting table below, so you don't have to leave the dashboard to figure
out what a red check means.

## `rp doctor`

The one to reach for when something's off. It checks, and reports `OK` / `WARN` /
`FAIL`, exiting non-zero if anything failed (so you can wire it into monitoring):

- **Code + data dir** present, data dir mode `700`.
- **Every unit**: the app server must be running (FAIL if not); optional
  components (scheduler/scanner/push/webterm) WARN if installed-but-stopped, and
  each is checked against its port.
- **Storage backend connectivity** — on Postgres it actually loads the device
  store through the app's driver (using the DSN from the storage marker), so a
  broken DSN is caught here, not at 3am.
- **nginx** — `nginx -t` valid, the `/api/push/connect` route present, and the
  `$connection_upgrade` map present (WebSocket upgrades fail silently without it).
- **Push daemon specifics** — the exact failure class that bites on Postgres:
  it flags a daemon that fell back to flat-file reads or reports `backend=json`
  under a Postgres install (either means it will reject every agent).
- **Agent self-update source** — the `/var/www/remotepower/agent/` distribution
  copy exists (so a self-update doesn't serve nothing).

Example:

```text
$ rp doctor
rp doctor — RemotePower 6.4.0, backend=postgres

  OK   code present (/var/www/remotepower)
  OK   data dir /var/lib/remotepower (mode 700)
  OK   remotepower-wsgi running
  OK   remotepower-scheduler running
  OK   remotepower-push running
  OK   Postgres reachable (marker DSN, dsn set)
  OK   nginx config valid (nginx -t)
  OK   nginx routes /api/push/connect → push daemon
  OK   push daemon on the Postgres backend
  OK   agent distribution copy present (self-update source)

  All checks passed.
```

## Fixing things — `rp install`, `rp deploy`, `rp repair`

`rp` can drive the setup scripts directly, so you don't have to `cd` into the
source checkout. The installers record the checkout path in
`/etc/remotepower/rp.env` (`RP_SRC=…`); `rp` reads it (or the `RP_SRC` env var, or
a couple of common locations). All three escalate with `sudo` automatically.

| Command | What it runs | Use it when |
|---|---|---|
| `rp install [args…]` | `install-server.sh` | first-time setup, or to add a component later (`rp install --with-scanner`) |
| `rp deploy [args…]` | `deploy-server.sh` | ship new code — updates cgi-bin, static, the agent copy, `rp`, the push daemon, and restarts the app + scheduler + push |
| `rp repair` | `deploy-server.sh` if the source is present, else restart-stack + reload-nginx | something's wedged and you want it made current again in one shot |

If `rp` can't find the checkout it tells you to set `RP_SRC=/path/to/checkout`.

## Troubleshooting — reading `rp doctor` and fixing each failure

`rp doctor` prints `OK` / `WARN` / `FAIL` and exits non-zero if anything failed.
Here's what each result means and the exact fix. (The same table, condensed,
is in the TUI's **?** panel.)

| Check | What a red/amber result means | Fix |
|---|---|---|
| **not running as root** (banner) | You ran it unprivileged, so the backend + nginx checks were skipped and the header may show `backend=unknown`. | `sudo rp doctor` |
| **code present** FAIL | `api.py` isn't under the code dir (bad/partial deploy). | `rp deploy`, or check `RP_CODE_DIR` |
| **data dir … mode** WARN | The data dir isn't `0700` (too open, or missing). | `chown -R <webuser> /var/lib/remotepower && chmod 700 /var/lib/remotepower` |
| **`remotepower-wsgi` installed but NOT running** FAIL | The app server is down — the whole UI/API is offline. | `rp logs wsgi` to see why, then `sudo rp restart wsgi`; if it's a missing dep, `rp install` |
| optional unit **stopped** WARN | scheduler / scanner / push / webterm is installed but not running. | `sudo rp restart <name>` (or leave it if you don't use it) |
| **active but nothing on :PORT** WARN | The unit is up but not listening (crashed after start, or wrong bind). | `rp logs <name>` |
| **storage backend unknown** | Root: the marker is unreadable/corrupt. Non-root: just needs `sudo`. | `sudo rp doctor`; if still unknown, inspect `/var/lib/remotepower/storage_backend.json` |
| **Postgres … DSN check failed** FAIL | The backend is Postgres but the DSN in the marker is missing/invalid — the app *and* the push daemon can't read devices. | check `storage_backend.json` has a valid `dsn`; verify Postgres is up (`pg_isready`); see [scaling.md](scaling.md) |
| **nginx -t reports errors** FAIL | The live nginx config is invalid. | run `nginx -t` (as root) to see the exact line, fix it, `systemctl reload nginx` |
| **no `/api/push/connect` route** WARN | nginx isn't routing the push WebSocket to the daemon (push won't connect). | `rp repair`, or add the block from [push.md](push.md) to your vhost |
| **no `$connection_upgrade` map** WARN | The http-level WebSocket map is missing — push *and* the web terminal will fail their upgrade. | add `server/conf/remotepower-ws-map.conf` to `/etc/nginx/conf.d/`, reload |
| **push daemon … backend=json under Postgres** / **storage backend detection failed** | The push daemon fell back to flat files and can't read the DB, so it rejects every agent. | `sudo rp restart push`; if it persists, the daemon can't reach the marker/DSN — confirm it runs as the web user and see [push.md](push.md) |
| **no agent distribution copy** WARN | `/var/www/remotepower/agent/remotepower-agent` is missing, so agent self-update serves nothing. | `rp deploy` (it publishes the agent binary) |

**Still stuck?** `rp repair` re-runs the deployer (restores units, binaries and
routes, and restarts), which fixes the large majority of "it was working
yesterday" situations. For a component that won't start, `rp logs <component>`
is almost always the fastest answer.

## In Docker

The container has no systemd, so `rp status` and `rp doctor` fall back to
port/process probes (still useful — `docker exec <name> rp doctor`). Lifecycle is
the container's job: `docker restart <name>`, or `RP_WITH_PUSH=0` etc. to change
what the entrypoint starts.

## Related

- [self-monitoring.md](self-monitoring.md) — the in-app Server-status page (the
  GUI counterpart to `rp status`).
- [scaling.md](scaling.md) — what each component does and when to split them off.
- [push.md](push.md) — the push daemon `rp doctor` inspects.
