# RemotePower

<div align="center">

![RemotePower Dashboard](docs/screenshots/Index.png)

**Self-hosted remote management for your Linux fleet — and your homelab.**
Web dashboard, push-based agents, no inbound ports. Set it up in five minutes.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)](https://kernel.org)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://hub.docker.com)
[![Nginx](https://img.shields.io/badge/server-Nginx-green.svg)](https://nginx.org)
[![Python](https://img.shields.io/badge/python-3.8+-yellow.svg)](https://python.org)
[![Version](https://img.shields.io/badge/version-2.2.5-blue.svg)](https://github.com/tyxak/remotepower/releases)

[Live demo](https://demoremote.tvipper.com) · [Install](docs/install.md) · [Features](docs/features.md) · [Docs](docs/)

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

| | |
|---|---|
| 🟢 **See what's up** | Live status every 60 s. CPU / RAM / disk sparklines. Service matrix. Containers. CVE findings. |
| ⚡ **Run commands** | Shutdown, reboot, WoL, arbitrary shell, **multi-line scripts (v2.1)** with dry-run lint, batch across many devices, scheduled (cron) and one-shot. |
| 🌐 **Browser SSH** | Real xterm.js terminal proxied through a hardened daemon. asciinema session recordings. |
| 🐳 **docker compose** *(v2.1)* | Up / down / restart / pull / logs on projects the agent discovered under `/opt /home /docker /srv`. |
| 🚨 **Alerts** | Disk %, memory %, CPU load, service down, container stopped, patches piling up, CVEs found, TLS expiring. Discord / ntfy / Slack / generic JSON webhooks. |
| 📦 **CMDB built in** | Asset metadata, encrypted credentials vault (AES-GCM + PBKDF2), Markdown docs per asset, network topology map, agentless devices. |
| 🛡️ **CVE scanning** | OSV.dev-backed, severity-ranked, per-CVE ignore list. |
| 🔑 **Auth that scales** | bcrypt + TOTP 2FA. LDAP/AD. Named API keys. Enrolment tokens for cloud-init / Ansible. |
| 📈 **Time series** | Prometheus `/api/metrics` for Grafana. Per-device history. |

Full feature inventory: **[docs/features.md](docs/features.md)**.

## What's new in 2.2.5

Five UX fixes from live driving of the 2.2.4 dashboard.

- **Container width 1100 → 1300 px.** Dashboard data density grew
  through the 2.2 cycle; 1300 fits 4 Home tiles + wide tables
  comfortably on standard 1920 monitors.
- **Tables and grids gain scroll wrap above 20 rows.** Sticky
  thead keeps column headers pinned. Devices card-grid view also
  picks up the same threshold.
- **Home → Recent activity items are clickable.** Each event
  routes to the most relevant page or modal for its class. Drift,
  CVE, monitors, services, containers, logs, history — they all
  have explicit routing cases.
- **Favicon publishing fixed in deploy-server.sh.** The
  `*.html` glob in the deploy loop meant root favicon.png was
  never being copied to `/var/www/remotepower/`; `/favicon.png`
  returned 404. Now explicitly handled.
- **Detail / Logs / Run hover strip removed entirely.** The row
  dropdown chevron and the "click name → open detail" pattern
  cover the same actions without the hover-only fiddliness.

Release notes: **[docs/v2.2.5.md](docs/v2.2.5.md)**.

## What's new in 2.2.4

Two real-world bugs from live testing of the Home dashboard.

- **Recent fleet events panel was empty even after device_offline
  fired.** The previous implementation read from the webhook
  delivery log, which only records events that had at least one
  destination. Events firing on a server with only SMTP
  configured (and `device_offline` email not enabled by default)
  vanished into the void. v2.2.4 adds a dedicated
  `data/fleet_events.json` that records every fired event
  regardless of destinations, plus a new
  `GET /api/fleet/events?limit=N` endpoint readable by viewers.
  `test` events excluded; payload summarised.
- **Unmonitored devices appeared in "Needs attention".**
  Operators explicitly set `monitored: false` to silence a host
  (decommissioned, dev boxes, hosts being rebuilt) — these
  shouldn't drive the dashboard either. Now filtered out from
  offline detection, patch backlog, and drift cross-reference.

Release notes: **[docs/v2.2.4.md](docs/v2.2.4.md)**.

## What's new in 2.2.3

Hotfix to the Home dashboard activity panel. Operator-triggered
SMTP and webhook tests (event = `test`) were drowning real fleet
events under repeated rows like *"test (email) 1 recipient(s):
smtp_host is empty"*. v2.2.3 filters the activity feed to the
canonical fleet events only — device offline/online, drift
detected, CVE found, monitor down, container stopped, metric
critical, etc. Tests stay in the underlying webhook log
(Settings → Webhook log) but no longer pollute the dashboard.

Contract test (`test_v223.TestActivityFilter`) asserts the JS
allowlist is exactly equal to the server's `WEBHOOK_EVENTS`
tuple — if a future commit adds a new event to the server
without updating the JS, the dashboard silently dropping it
surfaces as a test failure.

Release notes: **[docs/v2.2.3.md](docs/v2.2.3.md)**.

**Older releases**: see [CHANGES.md](CHANGES.md) for the full history
or [docs/](docs/) for the per-release notes (v2.1.3, v2.1.2, v2.1.1, v2.1.0,
v2.0.x, etc.).

## Documentation index

| Topic | Where |
|---|---|
| **Getting started** (install, Docker, demo, Windows) | [docs/install.md](docs/install.md) |
| **Full feature inventory** | [docs/features.md](docs/features.md) |
| **Architecture diagram + file layout** | [docs/architecture.md](docs/architecture.md) |
| **API reference (endpoints + OpenAPI)** | [docs/api.md](docs/api.md) — interactive: `/swagger.html` |
| **HTTPS / TLS termination** | [docs/https.md](docs/https.md) |
| **Security notes** | [docs/security.md](docs/security.md) |
| **Troubleshooting** | [docs/troubleshooting.md](docs/troubleshooting.md) |
| **Upgrading** | [docs/upgrading.md](docs/upgrading.md) |
| **Script library** *(v2.1)* | [docs/scripts.md](docs/scripts.md) |
| **docker compose dropdown** *(v2.1)* | [docs/compose.md](docs/compose.md) |
| **v2.1.2 release notes** | [docs/v2.1.2.md](docs/v2.1.2.md) |
| **v2.1.1 release notes** | [docs/v2.1.1.md](docs/v2.1.1.md) |
| **v2.1.0 release notes** | [docs/v2.1.0.md](docs/v2.1.0.md) |
| **CMDB & credentials vault** | [docs/cmdb.md](docs/cmdb.md) |
| **Container awareness** | [docs/containers.md](docs/containers.md) |
| **Agentless devices** | [docs/agentless-devices.md](docs/agentless-devices.md) |
| **Network map** | [docs/network-map.md](docs/network-map.md) |
| **TLS / DNS expiry** | [docs/tls-monitor.md](docs/tls-monitor.md) |
| **Update history** | [docs/update-history.md](docs/update-history.md) |
| **Swagger / OpenAPI** | [docs/swagger.md](docs/swagger.md) |
| **Release history** | [CHANGES.md](CHANGES.md) · [CHANGELOG.md](CHANGELOG.md) |

## License

MIT — see [LICENSE](LICENSE).

<div align="center"><sub>Made with ☕ and vi</sub></div>
