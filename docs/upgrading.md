# Upgrading

## Manual (git + deploy)

```bash
cd /path/to/remotepower
git pull origin main
sudo bash deploy-server.sh
```

Docker: `docker compose pull && docker compose up -d`. Arch (AUR):
`yay -S remotepower-server`.

Before a server upgrade you can flip **Settings → Advanced → Maintenance mode** to
pause new command dispatch (heartbeats and browsing keep working, so devices don't
flap offline), then turn it off when you're done.

## Check for updates, and guided self-update (v5.0.0)

**Settings → Install** compares the running version against the latest published
release and shows the upgrade commands for your install method. For hands-off
upgrades, point it at a server-side **update script** (an absolute path, set under
the same panel). The **Run update** button then executes that script
(`POST /api/server/self-update`, admin-only, audited, run directly rather than
through a shell). Your script is responsible for pulling the new version and
restarting the service the way your install expects, so it works for git, package
and container setups alike. The button's output is shown on success or failure.
Self-update stays disabled until you set the script path.

A ready-made, install-aware script ships in the repo at
`packaging/remotepower-server-update.sh`. It auto-detects the install type (git
checkout, pacman/AUR, or apt), pulls the new version, and restarts the SCGI
worker. Because the API runs unprivileged, the script re-execs itself under
scoped passwordless `sudo` — its header has the two install commands (drop it in
`/usr/local/sbin/` and add a one-line sudoers entry for the API user). Then set
the path to `/usr/local/sbin/remotepower-server-update`.

The storage layout migrates itself transparently on first start after an upgrade
(including the v5.0.0 promotion of a few per-device blobs), so there's nothing to
run by hand.

## Agents

Clients self-update automatically within ~1 hour, or push from the dashboard with
the ↺ button. (Read-only audit-mode agents refuse the self-update; the containerized
agent upgrades by pulling a new image tag.)

---

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
