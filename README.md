# RemotePower

<div align="center">

<img src="docs/screenshots/RP.png" alt="RemotePower" width="760">

**The Swiss-army-knife control plane for your Linux fleet — Windows and macOS
too — or your homelab.** Monitoring, alerting, a CMDB, CVE scanning, patching,
and remote management, all self-hosted in one place — with optional AI woven
through it. Push-based agents that run as a supervised service on every OS, zero
inbound ports. Up and running in five minutes.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)](https://kernel.org)
[![Docker](https://img.shields.io/badge/ghcr.io-remotepower-blue.svg)](docs/install.md#docker-one-liner-alternative)
[![Nginx](https://img.shields.io/badge/server-Nginx-green.svg)](https://nginx.org)
[![Python](https://img.shields.io/badge/python-3.8+-yellow.svg)](https://python.org)
[![Version](https://img.shields.io/badge/version-6.4.0-blue.svg)](https://github.com/tyxak/remotepower/releases)
[![Wiki](https://img.shields.io/badge/docs-wiki-blue.svg)](https://github.com/tyxak/remotepower/wiki)
[![Discussions](https://img.shields.io/badge/community-discussions-blueviolet.svg)](https://github.com/tyxak/remotepower/discussions)

[Live demo](https://demoremote.tvipper.com) · [Install](docs/install.md) · [Wiki](https://github.com/tyxak/remotepower/wiki) · [Changelog](CHANGELOG.md) · [Discussions](https://github.com/tyxak/remotepower/discussions) · [The story](HISTORY.md)

<a href="https://demoremote.tvipper.com"><img src="docs/screenshots/RemotePower.gif" alt="RemotePower — live dashboard tour" width="900"></a>

<details>
<summary><b>Screenshots</b></summary>
<br>
<table>
<tr>
<td align="center"><b>Dashboard</b><br><a href="docs/screenshots/Dash.png"><img src="docs/screenshots/Dash.png" width="400"></a></td>
<td align="center"><b>Fleet overview</b><br><a href="docs/screenshots/Index.png"><img src="docs/screenshots/Index.png" width="400"></a></td>
</tr>
<tr>
<td align="center"><b>Monitoring</b><br><a href="docs/screenshots/Monitoring.png"><img src="docs/screenshots/Monitoring.png" width="400"></a></td>
<td align="center"><b>Device metrics</b><br><a href="docs/screenshots/Metrics.png"><img src="docs/screenshots/Metrics.png" width="400"></a></td>
</tr>
<tr>
<td align="center"><b>CVEs</b><br><a href="docs/screenshots/CVEs.png"><img src="docs/screenshots/CVEs.png" width="400"></a></td>
<td align="center"><b>Patches</b><br><a href="docs/screenshots/Patches.png"><img src="docs/screenshots/Patches.png" width="400"></a></td>
</tr>
<tr>
<td align="center"><b>Compliance</b><br><a href="docs/screenshots/Compliance.png"><img src="docs/screenshots/Compliance.png" width="400"></a></td>
<td align="center"><b>Pentest</b><br><a href="docs/screenshots/Pentest.png"><img src="docs/screenshots/Pentest.png" width="400"></a></td>
</tr>
<tr>
<td align="center"><b>CMDB</b><br><a href="docs/screenshots/CMDB.png"><img src="docs/screenshots/CMDB.png" width="400"></a></td>
<td align="center"><b>Settings</b><br><a href="docs/screenshots/Settings.png"><img src="docs/screenshots/Settings.png" width="400"></a></td>
</tr>
<tr>
<td align="center"><b>AI assistant</b><br><a href="docs/screenshots/AI.png"><img src="docs/screenshots/AI.png" width="400"></a></td>
<td align="center"><b>Tickets (helpdesk)</b><br><a href="docs/screenshots/Tickets.png"><img src="docs/screenshots/Tickets.png" width="400"></a></td>
</tr>
<tr>
<td align="center"><b>Calendar</b><br><a href="docs/screenshots/Calendar.png"><img src="docs/screenshots/Calendar.png" width="400"></a></td>
<td align="center"><b>WG Access (VPN)</b><br><a href="docs/screenshots/WG.png"><img src="docs/screenshots/WG.png" width="400"></a></td>
</tr>
<tr>
<td align="center"><b>Browser SSH terminal</b><br><a href="docs/screenshots/Terminal.png"><img src="docs/screenshots/Terminal.png" width="400"></a></td>
<td align="center"><b>rp — node control (TUI)</b><br><a href="docs/screenshots/TUI.png"><img src="docs/screenshots/TUI.png" width="400"></a></td>
</tr>
</table>
</details>

</div>

---

## What is it?

Most teams stitch together a monitor, a CMDB, a wiki, a vulnerability scanner,
a patch tool and an SSH jump box. RemotePower is one self-hosted tool that
does all of it — monitoring & alerting, an asset CMDB, documentation with RAG
search over your own fleet, CVE scanning, patching, and remote management —
with AI as an entirely optional layer on top (bring your own local or cloud
model, or leave it off).

Each host runs a small Python agent that polls the server over outbound
HTTPS only — nothing opens on the client, ever. Enrolment is a 6-digit PIN,
like pairing a controller. It runs supervised on every platform — a systemd
service on Linux, a launchd agent on macOS, and a **Windows service**
(services.msc, auto-restarting) on Windows, installed by a single elevated
one-liner. See [docs/windows-client.md](docs/windows-client.md) for the Windows
specifics.

Deliberately small and readable: nginx + Python (gunicorn/Flask) on the
server, plain vanilla JS in the browser — no React/Vue, no build step, no
Node.js, no Redis, no Kubernetes. `install-server.sh` or `docker compose up`
provisions the full stack — PostgreSQL, the app server, a maintenance
scheduler, a scanner satellite — with no flags required. A single small box
handles a couple hundred devices out of the box, no tuning needed — and the
*same* box carries several thousand agents with just the poll-interval and
worker-count knobs turned, before you'd ever reach for load-balanced app
nodes, read replicas or relay satellites. See
**[docs/scaling.md](docs/scaling.md)** for the capacity table and
**[docs/requirements.md](docs/requirements.md)** for hardware sizing.

## Quick start

**Server — one command, HTTPS out of the box:**

```bash
# Docker (recommended). Self-signed HTTPS on first boot; the one-time admin
# password is printed to `docker logs remotepower`.
docker compose up -d

# Or bare-metal: one wizard installs nginx + the app + TLS + admin.
git clone https://github.com/tyxak/remotepower && cd remotepower
sudo bash install.sh
```

Open the printed URL and log in — HTTPS is automatic (self-signed by
default, or Let's Encrypt if you give it a public domain). No nginx editing.

On the box, manage the stack with **`rp`** (omd/checkmk-style): `rp status`, the
live `rp tui` dashboard, and `sudo rp doctor` for a one-shot health check — see
[docs/cli.md](docs/cli.md).

**Add a device — one line:**

*Add device → Quick install command* in the dashboard, then on the target host:

```bash
wget -qO- "https://your-server/install?t=<token>" | sudo sh
```

The host appears in the dashboard within ~60 seconds. Onboarding many hosts?
`install.sh agent push user@h1 user@h2 …` pushes it over SSH.

**Upgrading?** `git pull origin main && sudo bash install.sh update` handles
both a plain code update and a legacy pre-6.1.0 conversion. Full paths
(Windows/macOS agents, demo vhost, advanced TLS, uninstall) →
**[docs/install.md](docs/install.md)** · **[docs/upgrading.md](docs/upgrading.md)**.

**Try it first:** a read-only demo runs at
**[demoremote.tvipper.com](https://demoremote.tvipper.com)**, seeded with
synthetic devices/alerts/CVEs. Login `demo` / `demo`, reset every few hours.

## What you can do with it

- **Monitor & alert** — live metrics, a CheckMK-style Checks page, active
  monitors (HTTP/DNS/ICMP/TCP) with attachable SLA/SLO objects (availability
  targets + error budgets), an Alerts inbox with ack/auto-resolve/mute, and
  one filterable page to tune every alert threshold, grade and score weight.
- **See every signal** — SMART/hardware health, GPU, power/UPS, disk-fill
  forecasting, a per-host timeline, log search.
- **Manage remotely** — shell + Custom Scripts, a file manager and
  cron/systemd-timer control with zero inbound ports; plus a browser SSH
  terminal and VNC riding your existing SSH, and Proxmox/VMware/OpenShift
  guest lifecycle via the hypervisor's own API.
- **Lock it down** — passkeys/WebAuthn, SAML/OIDC/LDAP, TOTP, per-role MFA,
  a tamper-evident audit log, strict CSP.
- **Scan for CVEs** — OSV.dev-backed, CISA KEV + EPSS prioritized, SBOM
  export (CycloneDX/SPDX).
- **Pentest what you own** — authorized nuclei/nikto/nmap/ZAP/wapiti/lynis
  scans on a hardened scanner satellite.
- **CMDB + RAG search** — assets, an encrypted credentials vault, a
  Knowledge Base, and an AI assistant that cites *your* fleet's own data.
- **Stay compliant** — OpenSCAP CIS/STIG/PCI scans, PCI/HIPAA/SOC 2 mapping.
- **Integrate** — 44 connectors (homelab apps, hypervisors, and EDR — Wazuh,
  CrowdStrike, SentinelOne — cross-referenced to find hosts with no EDR at all)
  plus a code-free custom-HTTP-probe plugin, Prometheus/Grafana endpoints,
  webhooks, syslog, and an MCP server.
- **Deploy & automate** — a one-click app catalog, auto-patch policies,
  drift detection, ACME, backups, and a Terraform/Ansible provisioning catalog.

**Full feature inventory → [docs/features.md](docs/features.md).**
**Step-by-step recipes → [docs/cookbook.md](docs/cookbook.md).**

### Recent releases

- **v6.4.0 "Sh1eldMatters"** — the security-and-protection release. Integrity-
  guard and baseline checks now behave exactly as expected: **disable one and
  it stops evaluating on the host**, not just in the UI, and accept a
  legitimate change as the new baseline with one click. Backed by a full,
  public security review and pentest pass (nothing Critical, High or Medium
  ships). Plus **agentic diagnosis used defensively** — a bounded, secret-
  redacted log sweep and read-only alert triage that writes a verdict with its
  evidence trail — a data-binding sweep so everything the agent collects lands
  in the UI, RAG and AI context, **SLA/SLO objects** for remote probes
  (availability targets with error budgets, exported as Prometheus gauges), a
  WordPress connector showing the last logins with IP + geo, and a
  typography / box-overflow / performance polish wave.
- **v6.3.0 "Fl0wMatters"** — a fourteen-wave UX program: **undo instead of
  "are you sure?"** (topbar undo/redo, deferred-commit deletes, optimistic
  alert ack), a notification center, configuration history with rollback,
  draft autosave, shift-click range selection, chart crosshairs and a
  per-host posture radar — plus a native **syslog listener** for agentless
  appliances, **macOS agent self-update**, chassis-aware offline grace for
  laptops, weekly restore drills, laptop battery health, an "agents
  outdated" filter, a Postgres migration CLI, app-wide axe-verified
  accessibility, and deploy/self-update restarting the sidecar daemons.
- **v6.2.3 "Un1fyMatters"** — a consolidation and tidy-up pass: an optional
  listen port on Create tunnel, an ACME certificates page that loads on
  navigation (no manual Refresh), clearer feedback when a package snapshot
  captures nothing, and a removed duplicate dampening setting — on top of a
  project-wide sweep that collapsed repeated code idioms, deleted dead code and
  de-duplicated the docs.
- **v6.2.2 "Pu1seMatters"** — a performance and polish pass built around the
  heartbeat: agents skip re-sending unchanged inventory data (delta sysinfo)
  and reuse their HTTPS connection instead of a new TLS handshake per beat; a
  new always-on health check catches an agent whose sandbox hides kernel
  modules *before* patch day; re-running the installer now upgrades in place;
  and the UI gains a keyboard-driven alert inbox, device hover cards,
  tab-level device deep links and faster large-fleet tables.
- **v6.2.1 "In1tMatters"** — a critical fix for Linux hosts using initramfs
  (Debian/Ubuntu): systemd unit hardening could make upgrades run through
  RemotePower rebuild the initramfs **without kernel modules**, leaving the host
  unbootable at its next reboot. The unit is fixed, the upgrade command now
  refuses to run in that situation, and patch-window reboots verify the initrd
  (and a clean upgrade) before firing.
Full history, newest first → **[CHANGELOG.md](CHANGELOG.md)**.

## Security

Security-reviewed every release and pentested as hard as we can — the bar is
**nothing Critical, High or Medium ships, and nothing exploitable**. Every
release runs SAST (Bandit, gitleaks, and CodeQL — the same advanced-setup scan
GitHub runs, reporting clean), adversarial code review, DAST (OWASP ZAP, Nikto,
Nuclei, Wapiti, WhatWeb), and live probing of our own instance. bcrypt-hashed
passwords behind rate-limited login, TOTP/passkeys/SAML/OIDC/LDAP, a strict CSP
with no `unsafe-inline` (plus HSTS preload, frame-ancestors `none`, and a locked
permissions-policy), an AES-GCM CMDB vault, a tamper-evident audit log, signed
agent commands, and mandatory TLS verification with anti-DNS-rebinding on every
outbound call. Each release's write-up is public. Full posture, threat model
and review history → **[docs/security.md](docs/security.md)**.

## Documentation

The **[Wiki](https://github.com/tyxak/remotepower/wiki)** is the browsable,
topic-organised home for everything — install guides, the full feature
reference, architecture, and the changelog. Prefer the source? It's all in
**[docs/](docs/README.md)** too. Quick links:

| Topic | Where |
|---|---|
| Install (Linux, Docker, Windows, macOS) | [docs/install.md](docs/install.md) |
| Full feature inventory | [docs/features.md](docs/features.md) |
| Architecture + on-disk layout | [docs/architecture.md](docs/architecture.md) |
| API reference (OpenAPI) | [docs/api.md](docs/api.md) — interactive: `/swagger.html` |
| Security notes | [docs/security.md](docs/security.md) |
| Scaling & deployment | [docs/scaling.md](docs/scaling.md) |
| Minimum/recommended hardware | [docs/requirements.md](docs/requirements.md) |
| Troubleshooting / Upgrading | [docs/troubleshooting.md](docs/troubleshooting.md) · [docs/upgrading.md](docs/upgrading.md) |

## Contributing & community

- **Request a feature** — open a [Feature request](https://github.com/tyxak/remotepower/issues/new?template=feature_request.yml).
- **Report a bug** — open a [Bug report](https://github.com/tyxak/remotepower/issues/new?template=bug_report.yml).
- **Ask a question or float an idea** — head to [Discussions](https://github.com/tyxak/remotepower/discussions).
- **Found a security issue?** — report it privately per [SECURITY.md](SECURITY.md); don't open a public issue.
- **Contributing code or docs?** — see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).

<div align="center"><sub>Made with care and vi</sub></div>
