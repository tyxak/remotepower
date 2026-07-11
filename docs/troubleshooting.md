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

**Device shows offline after enrolling**
```bash
journalctl -u remotepower-agent -f
curl -v https://your-server/api/heartbeat
```

**Shutdown/reboot queued but nothing happens**
- Executes on the client's next poll (up to 60s by default)
- Agent must run as root: `systemctl cat remotepower-agent | grep User`

**Re-enroll creates a new device instead of updating**
- Use `sudo remotepower-agent re-enroll` (not `enroll`)
- The existing `device_id` from `/etc/remotepower/credentials` must be present

**Reset everything**
```bash
sudo rm -rf /var/lib/remotepower/
sudo systemctl restart nginx remotepower-wsgi
sudo python3 /var/www/remotepower/cgi-bin/remotepower-passwd
```

---

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
