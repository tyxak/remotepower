# `rp` — node control CLI

`rp` is RemotePower's omd/checkmk-style command for running the stack on a single
node: one verb to see everything, start/stop/restart the whole thing, tail its
logs, and — most usefully — a `doctor` that diagnoses the common misconfigurations
in one shot.

It's installed to `/usr/local/bin/rp` by `install-server.sh` and ships in the
Docker image. `status`, `doctor`, `version`, and `logs` run as any user;
`start`/`stop`/`restart`/`reload` need root (they drive `systemctl`).

```text
rp status              show every stack component + host service
rp start   [component] start the RemotePower stack (or one component)
rp stop    [component] stop it
rp restart [component] restart it
rp reload              reload nginx + restart the app server (config reload)
rp doctor              run health checks; exit non-zero on any failure
rp logs    [component] follow the journal for the stack (or one component)
rp version             print the installed server version
rp help                this help
```

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
rp doctor — RemotePower 6.1.1, backend=postgres

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
