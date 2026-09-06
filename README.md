# RemotePower

<div align="center">

<img src="docs/screenshots/RP.png" alt="RemotePower" width="760">

**Self-hosted fleet monitoring and remote management for Linux, Windows and
macOS.** One server, one small agent per host, and a web UI covering
monitoring and alerting, an asset CMDB, CVE scanning, patching, compliance
reporting, a helpdesk and remote access. Agents poll outbound only, so nothing
listens on the managed host.

[![CI](https://github.com/tyxak/remotepower/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tyxak/remotepower/actions/workflows/ci.yml)
[![CodeQL](https://github.com/tyxak/remotepower/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/tyxak/remotepower/actions/workflows/codeql.yml)
[![Downloads](https://img.shields.io/github/downloads/tyxak/remotepower/total.svg?label=downloads)](https://github.com/tyxak/remotepower/releases)
[![Latest release](https://img.shields.io/github/v/release/tyxak/remotepower?label=release)](https://github.com/tyxak/remotepower/releases/latest)
[![AUR](https://img.shields.io/aur/version/remotepower-agent?label=AUR)](https://aur.archlinux.org/packages/remotepower-agent)
[![Stars](https://img.shields.io/github/stars/tyxak/remotepower?style=flat)](https://github.com/tyxak/remotepower/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)](https://kernel.org)
[![Docker](https://img.shields.io/badge/ghcr.io-remotepower-blue.svg)](docs/install.md#docker-one-liner-alternative)
[![Nginx](https://img.shields.io/badge/server-Nginx-green.svg)](https://nginx.org)
[![Python](https://img.shields.io/badge/python-3.10+-yellow.svg)](https://python.org)
[![Version](https://img.shields.io/badge/version-7.0.3-blue.svg)](https://github.com/tyxak/remotepower/releases)
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
<tr>
<td align="center"><b>Containers</b><br><a href="docs/screenshots/Containers.png"><img src="docs/screenshots/Containers.png" width="400"></a></td>
<td align="center"><b>KMIP key server</b><br><a href="docs/screenshots/KMIP.png"><img src="docs/screenshots/KMIP.png" width="400"></a></td>
</tr>
</table>
</details>

</div>

---

## What is it?

Most teams run a monitor, a CMDB, a wiki, a vulnerability scanner, a patch
tool, a ticket system and an SSH jump box as separate services. RemotePower is
one self-hosted application that covers all of them: monitoring and alerting,
an asset CMDB, documentation with RAG search over your own fleet, CVE scanning,
patching, compliance reporting, a helpdesk with SLA clocks and email in and
out, and remote management. AI is an optional layer — bring your own local or
cloud model, or leave it switched off. With a model configured, it can also
triage an alert through a bounded read-only investigation and write a verdict
with its evidence.

Each host runs a small Python agent that polls the server over outbound HTTPS.
Nothing opens on the client. Enrolment is a 6-digit PIN. The agent runs
supervised on every platform: a systemd service on Linux, a launchd agent on
macOS, and a Windows service that auto-restarts, installed by one elevated
command. See [docs/windows-client.md](docs/windows-client.md) for the Windows
specifics.

The stack is small and readable: nginx and Python (gunicorn/Flask) on the
server, plain JavaScript in the browser. No React or Vue, no build step, no
Node.js, no Redis, no Kubernetes. `install-server.sh` or `docker compose up`
provisions PostgreSQL, the app server, a maintenance scheduler and a scanner
satellite, with no flags required.

A single small box handles a couple of hundred devices with no tuning. The
same box carries several thousand agents once you adjust the poll interval and
the worker count — before load-balanced app nodes, read replicas or relay
satellites come into it. See [docs/scaling.md](docs/scaling.md) for the
capacity table and [docs/requirements.md](docs/requirements.md) for hardware
sizing.

## Install

**Server — one command, HTTPS out of the box:**

```bash
# Docker (recommended). Self-signed HTTPS on first boot; the one-time admin
# password is printed to `docker logs remotepower`.
docker compose up -d

# Or bare-metal: one wizard installs nginx + the app + TLS + admin.
git clone https://github.com/tyxak/remotepower && cd remotepower
sudo bash install.sh
```

Open the printed URL and log in. HTTPS is configured for you — self-signed by
default, or Let's Encrypt if you give it a public domain. There is no nginx
config to edit.

On the box, manage the stack with `rp`: `rp status`, the live `rp tui`
dashboard, and `sudo rp doctor` for a one-shot health check. See
[docs/cli.md](docs/cli.md).

**Add a device — one line.** Take the command from *Add device → Quick install
command* in the dashboard, then run it on the target host:

```bash
wget -qO- "https://your-server/install?t=<token>" | sudo sh
```

The host appears in the dashboard within about 60 seconds, which is the default
poll interval. For several hosts at once,
`install.sh agent push --server <url> --token <token> user@h1 user@h2 …` pushes
the agent over your own SSH. A token enrols one host, so mint one per host.

**Upgrading.** `git pull origin main && sudo bash install.sh update` handles
both a plain code update and a conversion from a pre-6.1.0 install. Windows and
macOS agents, the demo vhost, advanced TLS and uninstall are covered in
[docs/install.md](docs/install.md) and
[docs/upgrading.md](docs/upgrading.md).

**Try it first.** A read-only demo runs at
[demoremote.tvipper.com](https://demoremote.tvipper.com), seeded with synthetic
devices, alerts and CVEs. Log in with `demo` / `demo`. It resets every few
hours.

## What you can do with it

- **Monitor and alert** — live metrics, a CheckMK-style Checks page, active
  monitors (HTTP, TCP, DNS, ICMP, traceroute, database liveness and multi-step
  HTTP flows) with attachable SLA/SLO objects carrying availability targets and
  error budgets, an Alerts inbox with ack, auto-resolve and mute, and one
  filterable page to tune every alert threshold, grade and score weight.
- **See every signal** — SMART and hardware health, CPU and board temperatures,
  GPU, power and UPS, disk-fill forecasting, a per-host timeline and log search.
  Agentless syslog, NetFlow/IPFIX/sFlow and SNMP receivers, plus an OID browser
  for walking a subtree, cover the switches, firewalls and printers that cannot
  run an agent.
- **Manage remotely** — shell and Custom Scripts on Linux, Windows and macOS, a
  file manager, and cron and systemd-timer control, all with no inbound ports.
  Plus a browser SSH terminal and VNC over your existing SSH, and
  Proxmox/VMware/OpenShift guest lifecycle through the hypervisor's own API.
- **Lock it down** — passkeys/WebAuthn, SAML, OIDC, LDAP, TOTP, per-role MFA, a
  tamper-evident audit log, a strict CSP, and an instance-wide view of who is
  signed in. A built-in KMIP key server keeps NAS and hypervisor encryption keys
  off the appliance they unlock. RemotePower also grades its own host's disk
  encryption, since that is where every device token and the credential vault
  live.
- **Scan for CVEs** — backed by OSV.dev, prioritised with CISA KEV and EPSS,
  with SBOM export in CycloneDX and SPDX.
- **Pentest what you own** — authorized nuclei, nikto, nmap, wpscan, ZAP and
  wapiti scans from a hardened scanner satellite, plus on-host lynis audits.
- **CMDB and RAG search** — assets, an encrypted credentials vault, a Knowledge
  Base, and an AI assistant that cites your own fleet's data.
- **Stay compliant** — OpenSCAP CIS/STIG/PCI scans, with control mapping for
  PCI DSS v4.0, the HIPAA Security Rule, SOC 2, the ACSC Essential Eight and
  SMB1001.
- **Integrate** — 48 connectors (homelab apps, hypervisors, and EDR — Wazuh,
  CrowdStrike, SentinelOne — cross-referenced to find hosts with no EDR at all),
  a custom HTTP probe that needs no code, Prometheus and Grafana endpoints,
  webhooks, syslog, and an MCP server.
- **Deploy and automate** — a one-click app catalog, auto-patch policies, drift
  detection, ACME certificates, backups, and a Terraform/Ansible provisioning
  catalog. Optional autonomous remediation sits on top: off for every tenant
  until you switch it on, with a shadow mode that writes a receipt for what it
  would have done so you can grade it first.

Full feature inventory → [docs/features.md](docs/features.md). Step-by-step
recipes → [docs/cookbook.md](docs/cookbook.md).

### Recent releases

- **v7.0.3 "C4useMatters"** — three failures that named the wrong cause. A
  monitor reported a host as down when a bot filter at the edge had turned the
  probe away; the probe was identifying itself as Python and putting an older
  TLS version back on the wire. That second half was a whole class: eleven places
  set a minimum TLS version where they meant to raise one, so a server hardened
  to TLS 1.3 was quietly handed a context that would still speak 1.2. Eight are
  fixed across the server, all three agents, the satellite, the scanner and the
  key server; the two left are appliances whose firmware negotiates nothing
  newer, each with its reason recorded.
- **v7.0.2 "Prec3dentMatters"** — the autonomy loop refused everything it looked
  at, and each reason named a cause it did not have. Precedent could only come
  from an AI verdict, so a fleet whose incidents people fix scored lower than one
  with no memory at all; two sweeps already knew when a fix had worked and threw
  the answer away; "only inside a maintenance window" called a function that does
  not exist; and `no_verified_backup` refused actions a backup has no bearing on.
  The catalog is 26 action classes now: two added, five dropped because the alert
  that triggers them names no host, or the command cannot fix what fired it.
  Receipts can be cleared, per row or in bulk.
- **v7.0.1 "C0llapseMatters"** — the sidebar collapses when you ask it to. Open
  alerts held it open in every mode, including a manual collapse with auto-hide
  switched off, so page content slid to the rail margin while the menu stayed
  full width on top of it. Between 721 and 768 pixels wide the Collapse button
  appeared and did nothing. Adds a per-browser option to keep hiding the sidebar
  while alerts are open.
- **v7.0.0 "Aut0nomyMatters"** — autonomous remediation, designed so you grade it
  before it can act. Every tenant starts off. You move one to shadow, where the
  loop reaches a real verdict and writes a receipt without touching anything, and
  you read those for a few weeks first. It acts on precedent from your own
  incident memory — what closed this exact signature on this fleet before — not
  on a model's improvisation, and before acting it works out what goes dark:
  monitors, containers, watched services and network neighbours, discounted when
  the host has healthy siblings. That blast-radius preview stands on its own
  whether or not autonomy is on. An event maps to an ordered ladder of actions,
  so which remedy runs is your decision, and commands go out in the same grammar
  an operator's own actions use, inheriting maintenance mode, quarantine, audit
  mode and the approval queue. Destructive actions require a backup proven
  recoverable by a restore drill that restored and verified, not one that merely
  ran. The rest of the release repaired the guardrails: six were reporting
  success while measuring nothing, and fixing them surfaced real defects behind
  them, including an encryption-at-rest compliance control that could never pass
  on a Linux fleet and an SSO login that could become a cross-tenant platform
  operator.
- **v6.4.2 "Ver1tyMatters"** — per-container alert mutes, so you can silence one
  container without silencing its host, and a real container log window. An
  adversarial audit closed a cross-tenant log-content leak, a governance switch a
  config import could flip, and a webhook credential that shipped in clear text.
  A data-binding sweep put Linux firewall, SSH and auto-update posture on the
  Checks page, into fleet-query and behind PCI 1.2.1, and made Windows and macOS
  endpoint posture feed the risk score. Security hardening became opt-in under
  Settings → Security: the advisory checks that flag things plenty of fleets
  choose on purpose stay quiet until you turn them on.

## Security

Every release gets a security review and a penetration test. The bar is that
nothing Critical, High or Medium ships, and nothing exploitable. Each release
runs static analysis (Bandit, gitleaks, Semgrep and CodeQL — the same advanced
setup GitHub runs, all reporting clean), adversarial code review, dynamic
analysis (OWASP ZAP, Nikto, Nuclei, Wapiti, WhatWeb) and live probing of our own
instance. Release tarballs are GPG-signed, and container images are signed with
cosign in keyless mode, verifiable against the release workflow's identity.

The product side: bcrypt-hashed passwords behind a rate-limited login,
TOTP/passkeys/SAML/OIDC/LDAP, a strict CSP with no `unsafe-inline` alongside
HSTS, `frame-ancestors 'none'` and a locked permissions-policy, an AES-GCM CMDB
vault, a tamper-evident audit log, signed agent commands, and mandatory TLS
verification with anti-DNS-rebinding on every outbound call. Each release's
write-up is public. Full posture, threat model and review history →
[docs/security.md](docs/security.md).

## Documentation

The [Wiki](https://github.com/tyxak/remotepower/wiki) is the browsable home for
everything — install guides, the full feature reference, architecture and the
changelog. The same content is in [docs/](docs/README.md).

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

Full history, newest first → [CHANGELOG.md](CHANGELOG.md).

## License

MIT — see [LICENSE](LICENSE).

<div align="center"><sub>Made with care and vi</sub></div>
