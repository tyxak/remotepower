# Upgrading

## The one command

```bash
cd /path/to/remotepower
git pull origin main
sudo bash install.sh doctor    # optional — see what it detects before touching anything
sudo bash install.sh update
```

That's it, regardless of where you're upgrading *from*. On a box that already has
the [`rp`](cli.md) CLI you can also just run **`rp deploy`** (updates code + units
+ restarts), and **`sudo rp doctor`** afterwards to confirm the stack is healthy.

`install.sh update` self-detects the two cases that used to need different tools:

- **Already on gunicorn/Flask (v6.1.0+)** — deploys the new code and restarts
  the app server. Equivalent to `deploy-server.sh`, which it calls directly.
- **Still on the retired CGI (fcgiwrap) or SCGI transport (pre-6.1.0)** —
  installs gunicorn + Flask, deploys the code, converts the shared nginx
  snippet to `proxy_pass`, starts `remotepower-wsgi`, health-checks it, and
  only *then* stops and removes the old `fcgiwrap`/`remotepower-api.service`
  stack. If that health check fails, nothing old is touched — you're left
  exactly where you started, not half-converted.

Either way it also detects a **demo vhost** (`packaging/install-demo.sh`) and
upgrades it to its own dedicated process if it's still on the old per-request
override model, matching its storage backend (Postgres or flat-JSON) to
whatever the main install ends up using.

This is a **transport update, not a topology change** — your storage backend,
scheduler mode and scanner setup are left exactly as they were. It never
silently opts you into Postgres, the out-of-band scheduler, or a co-located
scanner; those stay whatever you already had configured.

`sudo bash install.sh doctor` is worth running first — it reports the current
transport state (CGI/SCGI vs. gunicorn/Flask vs. no install found), free disk
space, and — importantly — names whatever's already bound to ports 80/443 if
they're not free, so a stray conflicting service doesn't surprise you mid-run.
`install.sh update --dry-run` prints every step it would take without changing
anything, if you want to see the plan first.

## Other install methods

- **Docker:** `docker compose pull && docker compose up -d --build` — a
  container can't update itself from the inside; recreate it from the new
  image/checkout instead. `install.sh update` refuses to run inside a
  container and tells you this.

  **This only picks up new code.** It does NOT rewrite your
  `docker-compose.yml` — an existing pre-6.1.0 compose file (no `postgres`/
  `scanner` services, no `RP_STORAGE_BACKEND`) stays on that same topology
  forever; nothing breaks, but you also don't get Postgres/the scheduler/the
  scanner satellite just by pulling. To actually move onto the new default
  topology, adopt the repo's current `docker-compose.yml` by hand (diff it
  against your own first) — and **back up your data volume before you do**,
  since that switches your `remotepower` service onto `RP_STORAGE_BACKEND:
  postgres`, which triggers a one-time automatic migration of every file in
  `/var/lib/remotepower` into the new `postgres` service on first boot. If
  that migration fails partway (a container log line will say so), the app
  still starts — but now serving an empty/partial Postgres DB while your
  real data sits untouched on the volume. Recovery in that case is: stop the
  stack, fix whatever the log says was wrong with Postgres (usually just "it
  wasn't ready yet" — Docker's own health-check startup ordering handles the
  common case, but a slow first boot on constrained hardware can still race
  it), and `docker compose up -d` again — the migration retries from
  scratch on every boot until `PG_HAS_USERS` sees real data. It will NOT
  retry from the UI (Settings → Advanced → Storage backend refuses with 409
  as long as `RP_STORAGE_BACKEND` is set in the compose file, which it is by
  default) — only a container restart re-runs it.
- **Arch (AUR):** `yay -S remotepower-server` upgrades the package files and
  Python deps. The package deliberately isn't fully turnkey (you already
  wired your own nginx vhost and admin account) — its `post_upgrade` hook
  detects whether `remotepower-wsgi.service` is already active and, if not
  (the case for anyone still on a pre-6.1.0 CGI/fcgiwrap AUR install — that
  transport is fully gone, there's nothing left to "restart" instead), it
  prints the same one-time finish-setup block a fresh install gets: enable
  `remotepower-wsgi` (the unit ships staged at
  `/usr/share/doc/remotepower-server/remotepower-wsgi.service`, copy +
  `systemctl enable --now` it per the printed command), reload nginx (the
  already-installed `remotepower-locations.conf` snippet is proxy_pass-
  shaped from the package alone, nothing to convert there), done. If WSGI
  was already active, it just prints the restart reminder for the new code.

Before any upgrade you can flip **Settings → Advanced → Maintenance mode** to
pause new command dispatch (heartbeats and browsing keep working, so devices
don't flap offline), then turn it off when you're done.

## Guided self-update from the dashboard

**Settings → Install** compares the running version against the latest
published release and shows the upgrade command for your install method. For
hands-off upgrades, point it at a server-side **update script** (an absolute
path, set under the same panel). The **Run update** button then executes that
script (`POST /api/server/self-update`, admin-only, audited, run directly
rather than through a shell). The button's output is shown on success or
failure. Self-update stays disabled until you set the script path.

A ready-made, install-aware script ships at
`packaging/remotepower-server-update.sh`. It auto-detects the install type
(git checkout, pacman/AUR, or apt), pulls the new version, and restarts the
app server — it assumes gunicorn/Flask is already the transport (v6.1.0+); if
`remotepower-wsgi.service` doesn't exist yet, it warns rather than guessing,
since installing packages and rewriting nginx config unattended from a
web-triggered button is exactly the kind of thing that should require a human
running `install.sh update` once, deliberately. Because the API runs
unprivileged, the script re-execs itself under scoped passwordless `sudo` —
its header has the setup commands (drop it in `/usr/local/sbin/` and add a
one-line sudoers entry for the API user). Then set the path to
`/usr/local/sbin/remotepower-server-update`.

On bare metal, the storage layout migrates itself transparently on first
start after an upgrade — nothing to run by hand for that part. On Docker,
first-boot Postgres migration is a real one-shot step with a real failure
mode; see the Docker section above for what a failed migration looks like
and how to recover.

## Agents

Clients self-update automatically within ~1 hour, or push from the dashboard
with the ↺ button. (Read-only audit-mode agents refuse the self-update; the
containerized agent upgrades by pulling a new image tag.)

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
