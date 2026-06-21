# Windows client

The Windows agent uses the same heartbeat protocol as the Linux agent. It requires Python 3.8+ and runs as a Windows Service via [NSSM](https://nssm.cc).

### Install (PowerShell)

```powershell
# Run as Administrator
powershell -ExecutionPolicy Bypass -File install-client.ps1
```

The installer will:
1. Check for Python 3.8+
2. Install `psutil` for metrics (optional)
3. Run the enrollment wizard
4. Download NSSM and install the agent as a Windows Service

### Manual install

```powershell
# Copy agent
mkdir "$env:ProgramFiles\RemotePower"
copy client\remotepower-agent.py "$env:ProgramFiles\RemotePower\"

# Enroll
python "$env:ProgramFiles\RemotePower\remotepower-agent.py" enroll

# Run in foreground (for testing)
python "$env:ProgramFiles\RemotePower\remotepower-agent.py" run
```

### Windows agent commands

```powershell
python remotepower-agent.py status        # Show enrollment info
python remotepower-agent.py enroll        # Enroll interactively
python remotepower-agent.py re-enroll     # Re-enroll preserving history
python remotepower-agent.py integrity     # Verify binary SHA-256 vs server
python remotepower-agent.py run           # Run in foreground

# Service management (if installed via NSSM)
Get-Service RemotePowerAgent
Restart-Service RemotePowerAgent
Get-Content "$env:ProgramData\RemotePower\agent.log" -Tail 50 -Wait
```

### Windows-specific behavior

| Feature | Linux | Windows |
|---------|-------|---------|
| Shutdown | `systemctl poweroff` | `shutdown /s /t 30` |
| Reboot | `systemctl reboot` | `shutdown /r /t 30` |
| Patch info | apt/dnf/pacman | Windows Update COM API |
| Journal | journalctl | wevtutil (System event log) |
| Service | systemd | NSSM |
| Self-update | Automatic | Manual (logged when available) |
| HTTPS + TLS 1.2 floor | yes | yes |
| Read-only audit mode | `/etc/remotepower/audit-mode` | `%ProgramData%\RemotePower\audit-mode` |
| Per-command timeout (`exec:to=`) | yes | yes |
| Config path | `/etc/remotepower/` | `%ProgramData%\RemotePower\` |

---

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
