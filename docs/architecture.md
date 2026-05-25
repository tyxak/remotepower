# Architecture

```
Browser ──HTTPS──► Nginx (your server, bare metal or Docker)
                      │
                      ├─ /              → Dashboard (1 HTML + 1 CSS + 1 JS, no framework, no build)
                      ├─ /api/*         → Python CGI (via fcgiwrap)
                      ├─ /api/webterm/connect → wss://, proxied to remotepower-webterm daemon
                      ├─ /static/*      → Logos, CSS, JS
                      ├─ /agent/        → Agent binary (static, for self-update)
                      ├─ /swagger.html  → Interactive OpenAPI UI
                      ├─ /Manual.html   → Reference manual
                      └─ /var/lib/remotepower/   (state — flat JSON, hardened with flock + .bak fallback in v1.12.1)
                              ├── Identity:        users.json, tokens.json, apikeys.json, pins.json,
                              │                    enrollment_tokens.json
                              ├── Fleet state:     devices.json, metrics.json, packages.json,
                              │                    services.json, containers.json
                              ├── CMDB:            cmdb.json, cmdb_vault.json
                              ├── Operations:      commands.json, history.json, schedule.json,
                              │                    cmd_output.json, cmd_library.json, longpoll.json,
                              │                    update_logs.json, tasks.json, calendar.json
                              ├── Monitoring:      monitor_history.json, uptime.json, log_watch.json,
                              │                    log_rules_global.json, service_history.json
                              ├── Security:        cve_findings.json, cve_ignore.json,
                              │                    cve_details_cache.json
                              ├── TLS / DNS:       tls_targets.json, tls_results.json
                              ├── Webterm:         webterm_tickets.json, webterm-sessions/<id>.cast
                              ├── Other:           config.json, links.json, tunnels.json,
                              │                    maintenance.json, maint_suppressed.json,
                              │                    audit_log.json, webhook_log.json, ratelimit.json
                              └── (each .json gets a rolling .json.bak sibling on every save)

Optional sibling daemon (only if you install the web terminal):
  systemd: remotepower-webterm.service
  └─ asyncio Python (websockets + asyncssh)
       └─ Listens on 127.0.0.1:8765, proxied by nginx
            ├─ Validates one-time tickets minted by the CGI auth handler
            ├─ Pumps WebSocket bytes <-> SSH session
            └─ Records every session as asciinema v2 .cast file

Linux client (CachyOS, Ubuntu, Debian, Arch, Fedora, etc.)
  └─ systemd: remotepower-agent.service
       └─ Python daemon
            └─ POST /api/heartbeat every N seconds (configurable, default 60)
                 ├─ receives: shutdown | reboot | update | exec:<cmd> | poll_interval:<n>
                 ├─ sends sysinfo + journal every 10th poll (~10 min)
                 ├─ sends per-mount disk + swap + loadavg (v1.11.10+)
                 ├─ sends patch count every 180th poll (~3 hr)
                 └─ sends cpu/mem/disk metrics (if psutil installed)

Windows client (Windows 10/11, Server 2019+)
  └─ NSSM service: RemotePowerAgent
       └─ Python script (remotepower-agent.py)
            └─ Same heartbeat protocol as Linux agent
                 ├─ shutdown/reboot via shutdown.exe /s /r
                 ├─ patch info via Windows Update COM API
                 ├─ journal via wevtutil (System event log)
                 └─ metrics via psutil (optional)
```

---

```
remotepower/
├── README.md
├── CHANGELOG.md
├── LICENSE
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── install-server.sh
├── install-client.sh              # Linux client installer
├── install-client.ps1             # Windows client installer
├── deploy-server.sh
├── docker/
│   ├── nginx-docker.conf          # Nginx config for Docker
│   └── entrypoint.sh              # Docker entrypoint
├── server/
│   ├── html/index.html            # Dashboard (vanilla HTML/CSS/JS, no framework)
│   ├── cgi-bin/api.py             # REST API (Python 3, CGI via fcgiwrap)
│   ├── conf/remotepower.conf      # Nginx site config
│   └── remotepower-passwd         # User management utility
├── client/
│   ├── remotepower-agent          # Linux polling daemon (Python 3)
│   ├── remotepower-agent.py       # Windows polling daemon (Python 3)
│   └── remotepower-agent.service  # systemd unit (Linux)
├── tests/
│   ├── test_api.py
│   └── test_agent.py
└── docs/
    └── screenshots/
```

---

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
