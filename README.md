# RemotePower

<div align="center">

<img src="docs/screenshots/logo-primary.png" alt="RemotePower" width="420">

**Self-hosted remote management for your Linux fleet — and your homelab.**
Web dashboard, push-based agents, no inbound ports. Set it up in five minutes.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)](https://kernel.org)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://hub.docker.com)
[![Nginx](https://img.shields.io/badge/server-Nginx-green.svg)](https://nginx.org)
[![Python](https://img.shields.io/badge/python-3.8+-yellow.svg)](https://python.org)
[![Version](https://img.shields.io/badge/version-3.3.0-blue.svg)](https://github.com/tyxak/remotepower/releases)

[Live demo](https://demoremote.tvipper.com) · [Install](docs/install.md) · [Features](docs/features.md) · [Docs](docs/)

![RemotePower dashboard](docs/screenshots/Index.png)

<details>
<summary><b>📸 Click-through gallery — more screenshots</b></summary>

<br>

<table>
<tr>
<td align="center"><b>Dashboard</b><br><a href="docs/screenshots/Dash.png"><img src="docs/screenshots/Dash.png" width="400"></a></td>
<td align="center"><b>Device drawer</b><br><a href="docs/screenshots/Click_menu.png"><img src="docs/screenshots/Click_menu.png" width="400"></a></td>
</tr>
<tr>
<td align="center"><b>Browser SSH terminal</b><br><a href="docs/screenshots/Terminal.png"><img src="docs/screenshots/Terminal.png" width="400"></a></td>
<td align="center"><b>Monitoring</b><br><a href="docs/screenshots/Monitoring.png"><img src="docs/screenshots/Monitoring.png" width="400"></a></td>
</tr>
<tr>
<td align="center"><b>Logs</b><br><a href="docs/screenshots/Logs.png"><img src="docs/screenshots/Logs.png" width="400"></a></td>
<td align="center"><b>CVEs</b><br><a href="docs/screenshots/CVE.png"><img src="docs/screenshots/CVE.png" width="400"></a></td>
</tr>
<tr>
<td align="center"><b>Patches</b><br><a href="docs/screenshots/Patches.png"><img src="docs/screenshots/Patches.png" width="400"></a></td>
<td align="center"><b>Custom scripts</b><br><a href="docs/screenshots/Scripts.png"><img src="docs/screenshots/Scripts.png" width="400"></a></td>
</tr>
<tr>
<td align="center"><b>CMDB</b><br><a href="docs/screenshots/CMDB.png"><img src="docs/screenshots/CMDB.png" width="400"></a></td>
<td align="center"><b>Proxmox snapshots</b><br><a href="docs/screenshots/Snapshots.png"><img src="docs/screenshots/Snapshots.png" width="400"></a></td>
</tr>
<tr>
<td align="center"><b>IaC generator</b><br><a href="docs/screenshots/IaC.png"><img src="docs/screenshots/IaC.png" width="400"></a></td>
<td align="center"><b>Settings</b><br><a href="docs/screenshots/Settings.png"><img src="docs/screenshots/Settings.png" width="400"></a></td>
</tr>
<tr>
<td align="center"><b>AI assistant</b><br><a href="docs/screenshots/AI.png"><img src="docs/screenshots/AI.png" width="400"></a></td>
<td align="center"><b>Claude (AI host integration)</b><br><a href="docs/screenshots/Claude.png"><img src="docs/screenshots/Claude.png" width="400"></a></td>
</tr>
</table>

</details>

</div>

---

## What is it?

A web dashboard that manages your Linux machines (and Windows, kind of) without
opening firewall ports on them. Each host runs a small Python agent that **polls**
the central server every 60 seconds — outbound HTTPS only. Enrolment is a 6-digit
PIN, like pairing a console controller.

Deliberately small: nginx + Python CGI + flat JSON files. No database, no Node.js,
no Redis, no Kubernetes. The whole `/var/lib/remotepower/` directory backs up with
`tar`. Tested on real homelabs running 5–50 devices, fine up to a few hundred.

## Quick start

```bash
# Server (gets you nginx + fcgiwrap + Python deps + an admin password)
git clone https://github.com/tyxak/remotepower && cd remotepower
sudo bash install-server.sh

# Or: Docker
docker compose up -d
```

The installer prints the URL and the auto-generated admin password. Log in,
change the password under **Settings → Account**, then enroll your first client:

```bash
# On the host you want to manage
sudo bash install-client.sh
# Paste the server URL and the 6-digit PIN from the dashboard.
```

Shows up in the dashboard within ~60 seconds.

Browser SSH terminal is one more command: `sudo bash packaging/install-webterm.sh`.

For longer install paths (Docker, demo vhost, Windows client, Ansible-driven
enrolment), see **[docs/install.md](docs/install.md)**.

### Try the live demo

A read-only demo deployment runs at **<https://demoremote.tvipper.com>** —
seeded with synthetic devices, alerts, CVE findings, and metrics so
you can poke around without installing anything.

```
URL:      https://demoremote.tvipper.com
Username: demo
Password: demo
```

The demo is reset every few hours, so feel free to break things.

## What you can do with it

- 🟢 **See what's up** — Live status every 60 s. CPU / RAM / disk sparklines. Service matrix. Containers. CVE findings.
- ⚡ **Run commands** — Shutdown, reboot, WoL, arbitrary shell, multi-line scripts with dry-run lint, batch across many devices, scheduled (cron) and one-shot.
- 🌐 **Browser SSH** — Real xterm.js terminal proxied through a hardened daemon. asciinema session recordings.
- 🐳 **docker compose** — Up / down / restart / pull / logs on projects the agent discovered under `/opt /home /docker /srv`.
- 🖥️ **Proxmox** — Connect a Proxmox VE node — start/stop QEMU VMs and LXC containers, manage snapshots, all server-to-API.
- 🔍 **Configuration drift** — Hashes `sshd_config`, `sudoers` and friends against a baseline; diff, accept, or ignore changes.
- 🚨 **Alerts inbox** *(v3.2)* — Every fired event lands in a mutable ledger with acknowledge / resolve / auto-resolve lifecycle. Recover events (device_online, service_recover, snmp_recover) clear the matching open row automatically. Per-event filter, bulk-resolve, clear-resolved.
- 🔔 **Outbound notifications** — Discord / ntfy / Slack / Pushover / Teams / Gotify / generic JSON webhooks, multi-destination with per-event filters. Email too. Skipped/disabled deliveries reported separately so quiet fleets don't show a phantom failure rate.
- 📥 **Inbound webhooks & syslog** *(v3.2)* — Receive alerts from Grafana, Alertmanager, Authelia/Authentik, n8n, Home Assistant. Ingest syslog from rsyslog `omhttp` / fluent-bit / curl. Both feed the same Alerts inbox.
- 📦 **CMDB built in** — Asset metadata, encrypted credentials vault (AES-GCM + PBKDF2), Markdown docs per asset, network topology map, agentless devices.
- 🛡️ **CVE scanning** — OSV.dev-backed, CVSS v3.1-scored, severity-ranked, per-CVE ignore list.
- 📡 **SNMPv2c polling** *(v3.2)* — Pure-stdlib client polls every 5 min: sys-group, hrProcessorTable per-CPU load, hrStorageTable filesystems, UCD-SNMP load averages, vendor MIBs (Mikrotik temp/voltage/CPU MHz, Ubiquiti UAP/UDM/USW model+firmware). Threshold-driven `metric_warning` / `metric_critical` / `snmp_unreachable` / `snmp_dead` events for agentless devices alongside agented hosts.
- 🔑 **Auth that scales** — bcrypt + TOTP 2FA. LDAP/AD. **OIDC / OpenID Connect** *(v3.2)* — Authelia, Authentik, Keycloak, Pocket-ID, Google. Named API keys (admin/viewer/mcp roles). Enrolment tokens for cloud-init / Ansible.
- ✨ **AI assistant** — Optional LLM integration (Ollama, LocalAI, Anthropic, OpenAI, DeepSeek). Explain output, triage CVEs, prioritise patches, generate scripts — all with regex-based secret redaction. Disabled by default.
- 🤖 **MCP server with write tools** *(v3.2 Stage 4)* — 12 read tools + 4 write tools (`reboot_device`, `run_saved_script`, `force_package_scan`, `force_acme_rescan`). Per-device `require_confirmation` queues destructive actions for human approval; audit log records the AI host name and natural-language prompt that triggered each call.
- 📈 **Metrics & integrations** — Prometheus `/api/metrics` for Grafana. `/api/status` for Uptime Kuma / Homepage. `/api/digest` for cron-driven email summaries.
- 📲 **Installable PWA** — Chrome install prompt in the header. Service worker pre-caches the app shell; API calls are always network-only. Works on desktop and mobile.
- 🔬 **Custom monitoring scripts** — Define bash health checks server-side, assign to devices — agent runs them every 5 minutes. Exit 0 = OK. Fleet results page, edge-triggered alerts, inline AI generation.
- 🗓️ **Calendar, schedule, maintenance windows** — Cron + one-shot scheduled commands, recurring calendar events (daily/weekly/monthly/yearly), maintenance windows that suppress webhook alerts globally or per-device.
- 📝 **IaC generator** — Terraform / Ansible / Pulumi / cloud-init / Salt from live host inventory across 18 categories. AI renders the output.
- 🩺 **Server self-monitoring** — Site-health card (load avg, memory %, sessions, devices-online %), disk usage breakdown, audit log size, scheduled backup state, webhook delivery rate (inbound + outbound, separate), MCP confirmation queue.

Full feature inventory: **[docs/features.md](docs/features.md)**.

## Security

v3.0.2 ships with an end-to-end security audit covering the server, agent,
WebTerm handshake, CMDB vault, LDAP, TOTP, API keys, AI provider, and Proxmox
integration. Posture in brief: PBKDF2-HMAC-SHA256 passwords at OWASP-2023
parameters, header-based session tokens (CSRF-safe by construction), AES-GCM
encryption for the CMDB vault, mandatory TLS verification for outbound calls,
hardened agent state-file handling against local symlink attacks. Full
posture, threat model, and operator hardening checklist:
**[docs/security.md](docs/security.md)**.

## Documentation

Everything lives in **[docs/](docs/)** — start with the index there. The
essentials:

| Topic | Where |
|---|---|
| **Install** (Linux, Docker, demo, Windows) | [docs/install.md](docs/install.md) |
| **Full feature inventory** | [docs/features.md](docs/features.md) |
| **Architecture + on-disk layout** | [docs/architecture.md](docs/architecture.md) |
| **API reference** (endpoints + OpenAPI) | [docs/api.md](docs/api.md) — interactive: `/swagger.html` |
| **Reference manual** | [docs/Manual.html](docs/Manual.html) |
| **Security notes** | [docs/security.md](docs/security.md) |
| **Troubleshooting** | [docs/troubleshooting.md](docs/troubleshooting.md) |
| **Upgrading** | [docs/upgrading.md](docs/upgrading.md) |

Full release history — every version, newest first — is in
**[CHANGELOG.md](CHANGELOG.md)**.

## TL;DR

Swiss army knife. Everything you need for your fleet or homelab.

CMDB, documentation, network map, Proxmox snapshots, remote management (with a
browser-based web terminal), fire off bash scripts or commands, monitoring,
custom monitoring scripts, logs with regex search, cert-expiry dashboard, ACME
integration, patch management, alerting, notifications, configuration drift
detection, audit log, calendar, tasks, maintenance windows, MCP server with
write tools, IaC generator, proper documentation, full API with Swagger,
LDAP, OIDC / OpenID Connect, fleet dashboard, agent auto-update… And the best
of it: heavily connected to your own local AI (Ollama, LocalAI) or online AI
(Anthropic, OpenAI, DeepSeek), if you like.

## License

MIT — see [LICENSE](LICENSE).

<div align="center"><sub>Made with ☕ and vi</sub></div>
