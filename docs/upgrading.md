# Upgrading

## The one command

```bash
cd /path/to/remotepower
git pull origin main
sudo bash install.sh doctor    # optional — see what it detects before touching anything
sudo bash install.sh update
```

That's it, regardless of where you're upgrading *from*. `install.sh update`
self-detects the two cases that used to need different tools:

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
- **Arch (AUR):** `yay -S remotepower-server` — the package's `.install`
  hooks already handle the gunicorn/Flask transport; nothing extra to run.

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

The storage layout migrates itself transparently on first start after an
upgrade, so there's nothing to run by hand for that part.

## Agents

Clients self-update automatically within ~1 hour, or push from the dashboard
with the ↺ button. (Read-only audit-mode agents refuse the self-update; the
containerized agent upgrades by pulling a new image tag.)

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
