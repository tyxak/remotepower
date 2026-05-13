# Agent commands

```bash
remotepower-agent status        # Show enrollment info, version, all interfaces
sudo remotepower-agent enroll   # Enroll interactively
sudo remotepower-agent re-enroll  # Re-enroll preserving history/tags/group/notes
sudo remotepower-agent update   # Force self-update check immediately
sudo remotepower-agent integrity  # Verify binary SHA-256 vs server
sudo remotepower-agent run      # Run in foreground (debug)

systemctl status remotepower-agent
journalctl -u remotepower-agent -f
systemctl restart remotepower-agent
```

### Optional: metrics collection

```bash
pip install psutil --break-system-packages
sudo systemctl restart remotepower-agent
```

---

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
