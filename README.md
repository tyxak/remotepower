# RemotePower

<div align="center">

<img src="docs/screenshots/RP.png" alt="RemotePower" width="760">

**The all-in-one, Swiss-army-knife control plane for your Linux fleet — and your homelab.**
Monitoring with alerting, a CMDB, documentation with RAG search, CVE scanning, patching
and remote management in one self-hosted place — with AI woven through all of it (optional).
Web dashboard, push-based agents, no inbound ports. Set it up in five minutes.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)](https://kernel.org)
[![Docker](https://img.shields.io/badge/ghcr.io-remotepower-blue.svg)](docs/install.md#docker-one-liner-alternative)
[![Nginx](https://img.shields.io/badge/server-Nginx-green.svg)](https://nginx.org)
[![Python](https://img.shields.io/badge/python-3.8+-yellow.svg)](https://python.org)
[![Version](https://img.shields.io/badge/version-5.4.0-blue.svg)](https://github.com/tyxak/remotepower/releases)
[![Wiki](https://img.shields.io/badge/docs-wiki-blue.svg)](https://github.com/tyxak/remotepower/wiki)
[![Discussions](https://img.shields.io/badge/community-discussions-blueviolet.svg)](https://github.com/tyxak/remotepower/discussions)

[Live demo](https://demoremote.tvipper.com) · [Install](docs/install.md) · [Features](docs/features.md) · [Wiki](https://github.com/tyxak/remotepower/wiki) · [Discussions](https://github.com/tyxak/remotepower/discussions) · [The story](HISTORY.md)

<a href="https://demoremote.tvipper.com"><img src="docs/screenshots/RemotePower.gif" alt="RemotePower — live dashboard tour" width="900"></a>

<details>
<summary><b>Click-through gallery — more screenshots</b></summary>

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
<td align="center"><b>Device metrics</b><br><a href="docs/screenshots/Metrics.png"><img src="docs/screenshots/Metrics.png" width="400"></a></td>
<td align="center"><b>Logs</b><br><a href="docs/screenshots/Logs.png"><img src="docs/screenshots/Logs.png" width="400"></a></td>
</tr>
<tr>
<td align="center"><b>CVEs</b><br><a href="docs/screenshots/CVE.png"><img src="docs/screenshots/CVE.png" width="400"></a></td>
<td align="center"><b>Patches</b><br><a href="docs/screenshots/Patches.png"><img src="docs/screenshots/Patches.png" width="400"></a></td>
</tr>
<tr>
<td align="center"><b>Custom scripts</b><br><a href="docs/screenshots/Scripts.png"><img src="docs/screenshots/Scripts.png" width="400"></a></td>
<td align="center"><b>Software center &amp; policy</b><br><a href="docs/screenshots/Software.png"><img src="docs/screenshots/Software.png" width="400"></a></td>
</tr>
<tr>
<td align="center"><b>Release signing</b><br><a href="docs/screenshots/Signing.png"><img src="docs/screenshots/Signing.png" width="400"></a></td>
<td align="center"><b>CMDB</b><br><a href="docs/screenshots/CMDB.png"><img src="docs/screenshots/CMDB.png" width="400"></a></td>
</tr>
<tr>
<td align="center"><b>IaC generator</b><br><a href="docs/screenshots/IaC.png"><img src="docs/screenshots/IaC.png" width="400"></a></td>
<td align="center"><b>Settings</b><br><a href="docs/screenshots/Settings.png"><img src="docs/screenshots/Settings.png" width="400"></a></td>
</tr>
<tr>
<td align="center"><b>AI assistant</b><br><a href="docs/screenshots/AI.png"><img src="docs/screenshots/AI.png" width="400"></a></td>
<td align="center"><b>Claude (AI host integration)</b><br><a href="docs/screenshots/Claude.png"><img src="docs/screenshots/Claude.png" width="400"></a></td>
</tr>
<tr>
<td align="center"><b>Tickets (helpdesk)</b><br><a href="docs/screenshots/Tickets.png"><img src="docs/screenshots/Tickets.png" width="400"></a></td>
<td align="center"><b>WG Access — tunnels</b><br><a href="docs/screenshots/WG1.png"><img src="docs/screenshots/WG1.png" width="400"></a></td>
</tr>
<tr>
<td align="center"><b>WG Access — client config &amp; QR</b><br><a href="docs/screenshots/WG2.png"><img src="docs/screenshots/WG2.png" width="400"></a></td>
<td></td>
</tr>
</table>

</details>

</div>

---

## What is it?

**One tool instead of six.** Most teams stitch together a monitor, a CMDB, a wiki,
a vulnerability scanner, a patch tool and an SSH jump box. RemotePower is the
Swiss-army-knife that does all of it from a single host you control — **monitoring
&amp; alerting**, an asset **CMDB**, **documentation with RAG search** over your own
fleet, **CVE scanning**, **patching**, and **remote management** — and it's **heavily
bound to AI as an option**: bring your own model (local Ollama/LocalAI or a cloud
provider) and ask questions answered from *your* infrastructure, or leave it off
entirely. Everything stays self-hosted.

A web dashboard that manages your Linux machines (and Windows, kind of) without
opening firewall ports on them. Each host runs a small Python agent that **polls**
the central server every 60 seconds — outbound HTTPS only. Enrolment is a 6-digit
PIN, like pairing a console controller.

Deliberately small and **readable**: nginx + Python CGI + flat JSON files — around
**~67,000 lines** of server Python, one HTML file, one CSS file and a handful of
vanilla JS files. No external database, no Node.js, no Redis, no Kubernetes,
**no build step, no bundler, no framework** — you can read every line. The whole
`/var/lib/remotepower/` directory backs up with `tar`. Tested on real homelabs
running 5–50 devices, fine up to a few
hundred — and for larger or write-heavy fleets you can switch to an optional
embedded **SQLite** backend, or scale all the way to **PostgreSQL** (failover +
read replicas), load-balanced **app nodes** and **relay satellites** for segmented
networks. That's an **advanced, heavy-fleet** track — most installs never touch
it. See **[docs/scaling.md](docs/scaling.md)**.

## Quick start

**Server — one command, HTTPS out of the box:**

```bash
# Docker (recommended). Self-signed HTTPS on first boot; the one-time admin
# password is printed to `docker logs remotepower`.
docker compose up -d

# Or bare-metal: a single wizard installs nginx + the app + TLS + admin.
# You never edit an nginx file — it writes the vhost and certificate for you.
git clone https://github.com/tyxak/remotepower && cd remotepower
sudo bash install.sh
```

Open the printed URL and log in. HTTPS is automatic — a self-signed CA by
default (agents pin it), or a real Let's Encrypt cert when you give a public
domain. No cert wrangling, no nginx editing.

**Add a device — one line, nothing to configure:**

In the dashboard, *Add device → Quick install command*, then on the target host:

```bash
wget -qO- "https://your-server/install?t=<token>" | sudo sh
```

It downloads the **signed** agent, verifies its checksum, enrols with the baked
one-time token, and the host appears in the dashboard **by its hostname** within
~60 seconds. Prefer Docker? *Add device → Generate Docker compose*. Onboarding
many hosts? Push the installer over SSH: `install.sh agent push user@h1 user@h2 …`.

**Uninstall:** `sudo bash install.sh uninstall` (server — keeps your data;
`--purge` to wipe it) · `wget -qO- https://your-server/install | sudo sh -s -- --uninstall` (agent).

For longer paths (Windows client, demo vhost, Ansible, advanced TLS), see
**[docs/install.md](docs/install.md)**.

### Try the live demo

A read-only demo deployment runs at **<https://demoremote.tvipper.com>** —
seeded with synthetic devices, alerts, CVE findings, and metrics so you can poke
around without installing anything. Login: **`demo`** / **`demo`** (reset every
few hours, so feel free to break things).

## What you can do with it

One tool instead of six — the ten things it does best:

| | |
|---|---|
| **Monitor everything** | Live 60-second metrics, a CheckMK-style per-host **Checks** page, active monitors (HTTP / DNS / ICMP / TCP + credential-less DB liveness), and a composable dashboard. Every fired event lands in an **Alerts inbox** with acknowledge / auto-resolve. |
| **See every signal** | SMART & hardware health, **GPU** (NVIDIA + AMD, trend sparklines + thermal alerts), power / UPS, disk-fill **forecasting**, a per-host **timeline**, and logs with regex search — telemetry the agent already reports, surfaced as first-class views. |
| **Manage remotely** | Shell, multi-line scripts with dry-run lint, batch & scheduled runs, a real **browser SSH terminal** and **VNC** over the same tunnel, an opt-in **agent file manager** (browse / view / edit host files, no SSH), **cron & systemd-timer** management, **Proxmox** VM / LXC create, and host user / key / firewall edits — all with **zero inbound ports**. |
| **Lock it down** | Passkeys / WebAuthn, SAML / OIDC / LDAP, TOTP + recovery codes, per-role **MFA enforcement**, a **tamper-evident** (hash-chained) audit log, strict CSP, and SSRF-guarded outbound calls. |
| **Scan for CVEs** | OSV.dev-backed, CVSS-scored, prioritized by CISA **KEV** + **EPSS** (exploited-in-the-wild first), with **SBOM** export (CycloneDX / SPDX, VEX-style vulnerabilities embedded). |
| **Pentest what you own** | Authorized vulnerability scanning of your own hosts & domains — nuclei / nikto / nmap / **OWASP ZAP** / wapiti / lynis — on a hardened scanner satellite, authorization-gated and schedulable. |
| **CMDB + RAG search** | Asset DB, **encrypted credentials vault**, Markdown docs per asset, network map — and an AI assistant whose **RAG** answers from *your* fleet and docs and cites the source (local or cloud model; off by default). |
| **Stay compliant** | **OpenSCAP** CIS / STIG / PCI scans with downloadable HTML reports, plus PCI / HIPAA / SOC 2 control mapping and scheduled posture reports. |
| **Integrate** | 26 **homelab-app** health connectors (Pi-hole, TrueNAS, the *arr suite, …) plus a code-free **custom HTTP-probe** plugin to turn any endpoint into a signal, Prometheus / Grafana / Uptime-Kuma endpoints, inbound webhooks & syslog, and an **MCP server** so an AI client can query your fleet. |
| **Deploy & automate** | An **app catalog** — one-click Docker Compose deploy of curated (or your own custom) self-contained apps to a host — auto-patch policies (cron, per group / tag / site, maintenance-aware), config-**drift** detection, ACME / Let's Encrypt, backup orchestration, and an **IaC generator** (Terraform / Ansible / Pulumi / …). |

**Full feature inventory → [docs/features.md](docs/features.md).**

### Recent releases

- **v5.4.0 — RacksMatters** — a lightweight **time-tracking + billing** layer on one shared time-entry ledger: log billable (debtable) or internal hours in 0.25-hour steps on tickets and a weekly **Timesheet**, then turn those hours plus per-customer **recurring fees** into invoices. **Billing** (Admin) gives a worksheet (hours × rate + fees → subtotal / VAT / total per customer per month), an invoice lifecycle (draft → sent → paid, with void) that **locks** the hours it bills so totals can't drift, and a named **rate card** with per-customer rate / VAT / billing details. A new read-only **finance** role views and exports billing without admin rights; export via CSV, JSON API and browser-PDF. No breaking changes.
- **v5.3.0 — ResolveMatters** — a built-in, opt-in **ticket system** (helpdesk) that turns alerts into owned, tracked, resolvable work: tickets typed Incident / Request / Change with P1–P4 priorities and per-priority **SLA targets**, ownership / teams / groups, master & sub-tickets, **alert → ticket → auto-resolve**, inbound-mail auto-create + reply threading (dedicated IMAP) and outbound via your SMTP with an HTML signature. Plus an internal **Contacts** directory, a `tickets` AI/RAG source + Helpdesk-triage advisor, and a whole-project security / performance / consistency sweep. No breaking changes.
- **v5.2.0 — AccessMatters** — **WG Access**, a built-in light WireGuard road-warrior VPN (Admin → WG Access): reach the dashboard and fleet over an encrypted tunnel instead of exposing services. Create tunnels with a reach scope (dashboard-only / entire fleet / site / group / tag), full- or split-tunnel egress and optional auto-expiry, then issue per-client `.conf` + QR configs whose keys are generated in your browser (the private key never leaves it). Connect/disconnect/stale-handshake are first-class events, and WG Access posture feeds the AI (a new Remote-access review advisor). No breaking changes.
- **v5.1.1 — ClusterMatters** — the Proxmox integration now lists guests across the **whole cluster** (resolving each guest's owning node so every lifecycle action targets the right host), the page you're on is restored from the URL hash on refresh, **LocalAI API keys** are accepted, and embeddings can run on a **different service than chat** (a separate provider / base URL / API key). Folds in community contributions from @tbouquet and @loryanstrant. No breaking changes.
- **v5.1.0 — UnityMatters** — fail2ban bans become a first-class alert/webhook event (the jail and banned IPs ride the payload, and repeat bans on a host coalesce into one live alert), Arabic gains a full right-to-left layout, and another batch of UI strings are localized — on top of the usual security and correctness finalize sweep. No breaking changes.

Full release history, newest first → **[CHANGELOG.md](CHANGELOG.md)**.

## Security

RemotePower is security-reviewed every few releases and **independently pentested
clean** — the latest full run (Bandit SAST; OWASP ZAP, Nikto, Nuclei, Wapiti,
WhatWeb DAST) reported **no exploitable findings**. Posture in brief: bcrypt
(cost 12, PBKDF2-HMAC-SHA256 fallback) behind rate-limited login; TOTP 2FA with
recovery codes; passkeys / SAML / OIDC / LDAP; 256-bit header session tokens
(CSRF-safe by construction); a strict CSP with no `'unsafe-inline'`; an AES-GCM
CMDB vault; a tamper-evident audit log; and mandatory TLS verification plus
connect-time anti-DNS-rebinding on every outbound call. Full posture, threat
model, review history and an operator hardening checklist:
**[docs/security.md](docs/security.md)**.

## Documentation

Browse the full docs in the **[Wiki](https://github.com/tyxak/remotepower/wiki)**
(generated from `docs/`, organised by topic). Prefer the source? Everything lives
in **[docs/](docs/)** — start with the index there. The essentials:

| Topic | Where |
|---|---|
| **Install** (Linux, Docker, demo, Windows) | [docs/install.md](docs/install.md) |
| **Full feature inventory** | [docs/features.md](docs/features.md) |
| **Architecture + on-disk layout** | [docs/architecture.md](docs/architecture.md) |
| **API reference** (endpoints + OpenAPI) | [docs/api.md](docs/api.md) — interactive: `/swagger.html` |
| **Security notes** | [docs/security.md](docs/security.md) |
| **Scaling & deployment** | [docs/scaling.md](docs/scaling.md) |
| **Troubleshooting / Upgrading** | [docs/troubleshooting.md](docs/troubleshooting.md) · [docs/upgrading.md](docs/upgrading.md) |

## TL;DR

A self-hosted Swiss-army knife for your Linux fleet or homelab: monitoring,
alerting, CMDB, docs with **RAG**, CVE scanning, authorized pentesting, patching,
compliance, and full remote management (browser SSH, Proxmox, files) — push-based
agents, **zero inbound ports**, optional **local or cloud AI** that answers from
*your* hosts. One tool instead of six.

## Contributing & community

- **Request a feature** — open a [Feature request](https://github.com/tyxak/remotepower/issues/new?template=feature_request.yml); it's labelled `enhancement` and triaged from there.
- **Report a bug** — open a [Bug report](https://github.com/tyxak/remotepower/issues/new?template=bug_report.yml).
- **Ask a question or float an idea** — head to [Discussions](https://github.com/tyxak/remotepower/discussions).
- **Found a security issue?** — please report it privately per [SECURITY.md](SECURITY.md); don't open a public issue.
- **Contributing code or docs?** — see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).

<div align="center"><sub>Made with care and vi</sub></div>
