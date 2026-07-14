# Architecture

```
Browser ──HTTPS──► Nginx (your server, bare metal or Docker)
                      │
                      ├─ /              → Dashboard (1 HTML + 1 CSS + 1 JS, no framework, no build)
                      ├─ /api/*         → Python app tier — gunicorn + Flask (server/cgi-bin/wsgi.py),
                      │                   the only server since v6.1.0; see docs/wsgi.md
                      ├─ /api/webterm/connect → wss://, proxied to remotepower-webterm daemon
                      ├─ /static/*      → Logos, CSS, JS
                      ├─ /agent/        → Agent binary (static, for self-update)
                      ├─ /swagger.html  → Interactive OpenAPI UI
                      └─ /var/lib/remotepower/   (state — PostgreSQL by default; flat JSON with --no-postgres, hardened with flock + .bak fallback)
                              ├── Identity:        users.json, tokens.json, apikeys.json, pins.json,
                              │                    enrollment_tokens.json
                              ├── Fleet state:     devices.json, metrics.json, packages.json,
                              │                    services.json, containers.json, hardware.json,
                              │                    drift_state.json, fleet_events.json
                              ├── CMDB:            cmdb.json, cmdb_vault.json
                              ├── Operations:      commands.json, history.json, schedule.json,
                              │                    cmd_output.json, cmd_library.json, longpoll.json,
                              │                    update_logs.json, tasks.json, calendar.json,
                              │                    backup_jobs.json, backup_state.json
                              ├── Monitoring:      monitor_history.json, uptime.json, log_watch.json,
                              │                    log_rules_global.json, service_history.json
                              ├── Alerts / posture: alerts.json, brute_force.json, secret_findings.json
                              ├── Security:        cve_findings.json, cve_ignore.json,
                              │                    cve_details_cache.json
                              ├── TLS / DNS:       tls_targets.json, tls_results.json
                              ├── Webterm:         webterm_tickets.json, webterm-sessions/<id>.cast
                              ├── Other:           config.json (holds monitors, custom_checks,
                              │                    exposure_mutes, backup_monitors, oncall, …),
                              │                    links.json, tunnels.json, maintenance.json,
                              │                    audit_log.json, webhook_log.json, ratelimit.json
                              └── (each .json gets a rolling .json.bak sibling on every save)

  Storage backends (one shared, backend-agnostic helper layer):
    • flat JSON  — the code-level default when nothing else is configured.
    • SQLite     — embedded, WAL mode, stdlib sqlite3 (v3.12.0+); hot data is
                   stored row-per-entity so a heartbeat updates one row instead
                   of rewriting a file. In-place, reversible migration.
    • PostgreSQL — automatic failover across a multi-host DSN, optional read
                   replicas, and a PgBouncer pooler (v4.0.0+). Default for a
                   single-node install via install-server.sh/docker-compose.yml
                   since v6.1.0 (--no-postgres opts down to the file backend).
  Switch under Settings → Advanced → Storage backend. See docs/scaling.md.

  Out-of-band maintenance scheduler (default since v6.1.0, v5.5.0+):
    • remotepower-scheduler.service runs the ~33 maintenance sweeps from one
      leader-elected process (file-lock + pg_advisory_lock on Postgres) instead
      of piggy-backing on request traffic. --no-scheduler opts back down to the
      request-path cadence. See docs/scaling.md.

  Scale-out (optional, v4.0.0+):
    • Relay satellites — agents in a segmented network reach a satellite that
      forwards to the server; the agent→satellite hop can run over HTTPS, and
      every hop refuses TLS below 1.2. See docs/satellites.md.
    • Load-balanced multi-node — several stateless app nodes behind a trusted
      proxy, all pointed at the shared PostgreSQL backend.

  Hard multi-tenancy (optional, v5.5.0):
    • App-layer — tenancy_enforced confines tenant admins to their own devices.
    • Postgres row-level security — tenancy_rls adds FORCE RLS on the devices
      table keyed on a per-request GUC, applied live; DB-enforced defense-in-depth
      beneath the app-layer scope. Both default off, flipped from Settings.

Optional sibling daemon (only if you install the web terminal):
  systemd: remotepower-webterm.service
  └─ asyncio Python (websockets + asyncssh)
       └─ Listens on 127.0.0.1:8765, proxied by nginx
            ├─ Validates one-time tickets minted by the app's auth handler
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
  └─ Scheduled Task: RemotePowerAgent (runs `--run` at startup, as SYSTEM)
       └─ Python script (remotepower-agent-win.py)
            └─ Same heartbeat protocol as Linux agent
                 ├─ shutdown/reboot via shutdown.exe /s /r
                 ├─ patch info via Windows Update COM API + winget (third-party)
                 ├─ services/processes/SMART/hardware via PowerShell + WMI
                 ├─ event log via Get-WinEvent (System/Application/Security, Event IDs)
                 ├─ signed self-update, file manager, config drift, containers
                 └─ metrics via psutil (optional)

macOS client (macOS 12+)
  └─ launchd: com.remotepower.agent (remotepower-agent-mac.py)
       └─ Same heartbeat protocol (TLS 1.2+ to the server/satellite)
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
├── install-windows.ps1            # Windows client installer
├── deploy-server.sh
├── docker/
│   ├── nginx-docker.conf          # Nginx config for Docker
│   └── entrypoint.sh              # Docker entrypoint
├── server/
│   ├── html/index.html            # Dashboard (vanilla HTML/CSS/JS, no framework)
│   ├── cgi-bin/api.py             # REST API (Python 3, served via gunicorn + wsgi.py)
│   ├── cgi-bin/integrations.py    # Homelab software integration connectors
│   ├── conf/remotepower.conf      # Nginx site config
│   └── remotepower-passwd         # User management utility
├── client/
│   ├── remotepower-agent.py       # Linux polling daemon (Python 3)
│   ├── remotepower-agent          # Linux daemon, byte-identical to the .py above
│   ├── remotepower-agent-win.py   # Windows polling daemon (Python 3)
│   ├── remotepower-agent-mac.py   # macOS polling daemon (Python 3)
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
