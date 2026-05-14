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
[![Version](https://img.shields.io/badge/version-2.1.4-blue.svg)](https://github.com/tyxak/remotepower/releases)

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

## What's new in 2.1.4

**Fixed**: `JSON.parse: unexpected character at line 1 column 1`
error on every ✨ button when pointed at slow local Ollama models
(smallthinker / qwq / deepseek-r1, etc.). Bug was a 60s nginx
`fastcgi_read_timeout` cutting off requests that take 60–180s on
thinking models, returning HTML to the JS that expected JSON. Fix:
per-button `max_tokens` tuned to typical response length, HTTP
timeout bumped to 5 min, new tolerant fetch helper that surfaces
non-JSON server responses with a contextual fix hint. **Operator
action**: bump `fastcgi_read_timeout` to 300s for `/api/ai/` —
nginx snippet in `docs/v2.1.4.md`.

**Added**: AI Assistant **page** under the Planning group. Standalone
chat UI alongside the inline ✨ buttons. Status header showing
provider / version / reachability / currently-loaded models with VRAM
use (Ollama). Per-conversation model picker populated from the
provider's own list. Multi-turn chat with localStorage history. Two
new endpoints: `GET /api/ai/models`, `GET /api/ai/stats`.

Release notes: **[docs/v2.1.4.md](docs/v2.1.4.md)**.

## What's new in 2.1.3

**Optional AI assistant.** Five providers (Anthropic Claude, OpenAI
ChatGPT, DeepSeek, Ollama, LocalAI), disabled by default, configured
in Settings → AI assistant. Inline ✨ buttons on command output,
journal, the script editor, CVE findings, device dropdowns, and the
webhook log. Pure stdlib — no new pip dependencies. AI-generated
scripts go through the same dry-run + dangerous-pattern detection
as human-written ones.

Hostnames and IPs are redacted before leaving the building unless
the operator explicitly opts in. Bearer tokens, AWS keys, and long
hex strings are *always* redacted. Per-user-per-day request cap
prevents runaway cloud-provider invoices.

**Plus**: About-page version logic fix (was showing "Latest release
2.0.0 ✓ up to date" on a 2.1.2 install). Full release notes:
**[docs/v2.1.3.md](docs/v2.1.3.md)**.

## What's new in 2.1.2

**Critical fix.** v2.1.0's faster `save()` exposed a lost-update race
in the heartbeat handler: concurrent heartbeats from different devices
interleaved their load → mutate → save windows, clobbering each other's
`last_seen` updates. Devices drifted past TTL and got marked offline
despite heartbeating fine — exactly the symptom 2.1.0 was supposed to
fix, but caused by a completely different mechanism.

Fix in 2.1.2: new `_locked_update(path)` context manager that makes
read-modify-write atomic. `handle_heartbeat()` is rewritten around it.

If you're running 2.1.0 or 2.1.1 on a fleet of more than ~5 devices
polling at the same interval, **upgrade**. Full walkthrough:
**[docs/v2.1.2.md](docs/v2.1.2.md)**.

## What's new in 2.1.1

Bugfix release. The 2.1.0 heartbeat handler used the new non-blocking
save for *every* write, including the one that persists `last_seen`.
Under flock contention that save returned HTTP 202 silently *before*
`last_seen` was on disk → device drifts past TTL → marked offline
despite heartbeating fine. Plus the diagnostic logging was effectively
absent: nothing in nginx logs, nothing in agent logs, no way to
diagnose. Fixed in v2.1.1:

- **Offline regression fixed.** `last_seen` save is back to blocking
  (now microseconds-fast from the v2.1.0 fsync-outside-lock work).
- **Real logging.** Every offline/online transition logs to nginx's
  error log regardless of webhook config. Every heartbeat logs too.
  The `try: … except Exception: pass` blocks in `main()` now print
  the full traceback before continuing.
- **Default offline TTL bumped 3 → 5 min** (5 missed polls at the
  default 60s interval).
- **`log_alert` webhook includes the actual matched line.** The
  payload always had `sample`; the formatter just wasn't using it.
- **Per-container Start/Stop/Restart/Logs** buttons on the Containers
  page (`POST /api/devices/<id>/containers/action`).
- **Demo data updated** with v2.1 features for the public demo site.

Full release notes: **[docs/v2.1.1.md](docs/v2.1.1.md)**.

## What's new in 2.1.0

- **Script library** with `bash -n` syntax checking and dangerous-command
  detection. CRUD on the Scripts page; queue from a device dropdown or fan
  out to a multi-select batch. See **[docs/scripts.md](docs/scripts.md)**.
- **Multi-select script execution** via `POST /api/exec/batch` with a 1-hour
  job-status TTL at `GET /api/exec/batch/<id>`.
- **`docker compose` dropdown** on device cards. Agent reports projects under
  `/opt`, `/home`, `/docker`, `/srv` in its heartbeat; UI offers up / down /
  restart / pull / logs. See **[docs/compose.md](docs/compose.md)**.
- **Flock offline fluctuation fixed.** Heartbeat saves now hold the per-file
  lock only for the rename, not for the fsync; if the lock is briefly
  contended the agent gets HTTP 202 instead of stalling past its timeout.
- **Auto-refresh stability.** Device names with apostrophes no longer break
  inline event handlers on refresh; auto-refresh pauses while a modal is
  open or the tab is in the background.

Full release notes: **[docs/v2.1.0.md](docs/v2.1.0.md)**.

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
