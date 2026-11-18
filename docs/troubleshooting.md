# Troubleshooting

**Start here: `sudo rp doctor`.** The `rp` node-control CLI runs one health check
across the whole stack — units, ports, storage-backend connectivity, the nginx
routes/upgrade map, the push daemon, and the agent self-update copy — and prints
the fix for each failure. Most issues below are diagnosed (and often fixed) by it:
`rp restart [component]`, `rp logs <component>`, or `rp repair` (re-deploy). Run
`rp tui` for a live dashboard, with a built-in `?` troubleshooting panel. Full
guide: **[cli.md](cli.md)**. The manual `systemctl`/`journalctl` recipes below are
the equivalents `rp` wraps.

**IPv6 error on nginx start**
```bash
sudo sed -i '/listen \[::\]/d' /etc/nginx/sites-available/remotepower
sudo nginx -t && sudo systemctl reload nginx
```

**502 from nginx / app server not answering**
```bash
sudo systemctl status remotepower-wsgi
sudo journalctl -u remotepower-wsgi -n 40
sudo systemctl restart remotepower-wsgi nginx
```

**Long-poll exec times out immediately**
- Check `proxy_read_timeout` in your Nginx config - must be ≥ 130 s
- gunicorn's own `--timeout` (in `remotepower-wsgi.service`) must also allow long-running requests

**Metrics not appearing**
```bash
pip install psutil --break-system-packages
sudo systemctl restart remotepower-agent
# Metrics only appear after the first sysinfo poll (~60s)
```

**Host shows offline after enrolling**
```bash
journalctl -u remotepower-agent -f
curl -v https://your-server/api/heartbeat
```

**A host has no ports, no disk health, no firewall or no temperatures**

Open the host, go to its **Audit** tab and open **What this agent can see** under **System**. A Linux agent reports it with its
system information (about every ten minutes). It shows:

- whether the agent runs as **root** (a firewall, a disk and the audit rules are unreadable otherwise), the agent's version and
  Python, the distribution, and the init system;
- each **missing tool**, the feature that needs it, and how to fix it: an install command for the host's package manager to copy,
  or a short sentence where no command is right for every host (`systemctl` comes with systemd, a package manager with the base
  system, and the package of Docker, OpenSCAP and CrowdSec differs by distribution). A tool a feature does not need on this host
  is not listed as missing: another distribution's package manager, `systemctl` on a host that does not run systemd, and the
  second of two tools that do the same job (`ufw` when `nftables` is there);
- the **logs the threat sensor found**, including any extra log you gave it, whether the agent can open each, and never a line of
  them.

A tool you install shows up at the agent's next report. A tool marked *optional* belongs to a feature most hosts do without
(Docker, IPMI, Lynis, OpenSCAP, auditd, fail2ban, CrowdSec). A Windows or macOS host has no such report, and neither does a Linux
agent from before this panel: it says "This agent has not reported what it can see" until you update the agent.

In a container the agent reads the host's files through the paths mapped into it, and the panel lists those paths. It cannot run
the host's own tools, so a missing tool says **not available in a container** and not an install command (see
[docker-agent.md](docker-agent.md)).

**Shutdown/reboot queued but nothing happens**
- Executes on the client's next poll (up to 60s by default)
- Agent must run as root: `systemctl cat remotepower-agent | grep User`

**Re-enroll creates a new host instead of updating**
- Use `sudo remotepower-agent re-enroll` (not `enroll`)
- The existing `device_id` from `/etc/remotepower/credentials` must be present

**Reset everything**

This deletes all of your data, so take a full backup first (**Settings → Backups →
Full backup**). `rp status` shows which storage backend you use. On the JSON and
SQLite backends the data lives in `/var/lib/remotepower`:

```bash
sudo systemctl stop remotepower-wsgi
sudo find /var/lib/remotepower -mindepth 1 -delete
sudo systemctl start remotepower-wsgi
sudo python3 /var/www/remotepower/cgi-bin/remotepower-passwd   # create the first admin
```

On PostgreSQL, which is the default of `install-server.sh`, the data lives in the
database, so emptying the folder does not reset it. Remove or recreate the RemotePower
database as well, then start the app server again.

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
