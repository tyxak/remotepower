# Troubleshooting

**IPv6 error on nginx start**
```bash
sudo sed -i '/listen \[::\]/d' /etc/nginx/sites-available/remotepower
sudo nginx -t && sudo systemctl reload nginx
```

**fcgiwrap socket permission denied**
```bash
sudo chmod 660 /run/fcgiwrap.socket
sudo chown www-data:www-data /run/fcgiwrap.socket
sudo systemctl restart fcgiwrap nginx
```

**Long-poll exec times out immediately**
- Check `fastcgi_read_timeout` in your Nginx config - must be ≥ 130 s
- The CGI process holds the connection; fcgiwrap must not be configured with a process limit that kills long-running requests

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
sudo systemctl restart nginx fcgiwrap
sudo python3 /var/www/remotepower/cgi-bin/remotepower-passwd
```

---

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
