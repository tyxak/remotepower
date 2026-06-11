# RemotePower

<div align="center">

<img src="docs/screenshots/RP.png" alt="RemotePower" width="760">

**The all-in-one, Swiss-army-knife control plane for your Linux fleet — and your homelab.**
Monitoring with alerting, a CMDB, documentation with RAG search, CVE scanning, patching
and remote management in one self-hosted place — with AI woven through all of it (optional).
Web dashboard, push-based agents, no inbound ports. Set it up in five minutes.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)](https://kernel.org)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://hub.docker.com)
[![Nginx](https://img.shields.io/badge/server-Nginx-green.svg)](https://nginx.org)
[![Python](https://img.shields.io/badge/python-3.8+-yellow.svg)](https://python.org)
[![Version](https://img.shields.io/badge/version-4.3.0-blue.svg)](https://github.com/tyxak/remotepower/releases)

[Live demo](https://demoremote.tvipper.com) · [Install](docs/install.md) · [Features](docs/features.md) · [Docs](docs/)

![RemotePower dashboard](docs/screenshots/Index.png)

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
<td align="center"><b>Proxmox snapshots</b><br><a href="docs/screenshots/Snapshots.png"><img src="docs/screenshots/Snapshots.png" width="400"></a></td>
<td align="center"><b>IaC generator</b><br><a href="docs/screenshots/IaC.png"><img src="docs/screenshots/IaC.png" width="400"></a></td>
</tr>
<tr>
<td align="center"><b>Settings</b><br><a href="docs/screenshots/Settings.png"><img src="docs/screenshots/Settings.png" width="400"></a></td>
<td align="center"><b>AI assistant</b><br><a href="docs/screenshots/AI.png"><img src="docs/screenshots/AI.png" width="400"></a></td>
</tr>
<tr>
<td align="center"><b>Claude (AI host integration)</b><br><a href="docs/screenshots/Claude.png"><img src="docs/screenshots/Claude.png" width="400"></a></td>
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

Deliberately small: nginx + Python CGI + flat JSON files. No external database, no
Node.js, no Redis, no Kubernetes. The whole `/var/lib/remotepower/` directory backs
up with `tar`. Tested on real homelabs running 5–50 devices, fine up to a few
hundred — and for larger or write-heavy fleets you can switch to an optional
embedded **SQLite** backend (stdlib only, still no external server) with a live,
in-place, reversible migration from **Settings → Advanced → Storage backend**.

…and it scales all the way up. For large or multi-site fleets, point it at
**PostgreSQL** with **automatic failover + read replicas**, pool connections
through **PgBouncer**, run **load-balanced multiple app nodes** behind a trusted
proxy, and reach segmented networks through **relay satellites** — the same flat
front-end, just a bigger back-end. Same zero-inbound, push-based agents
throughout. See **[docs/scaling.md](docs/scaling.md)** and
**[docs/deployment.md](docs/deployment.md)**.

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
URL: https://demoremote.tvipper.com
Username: demo
Password: demo
```

The demo is reset every few hours, so feel free to break things.

## What you can do with it

- **See what's up** — Live status every 60 s. CPU / RAM / disk sparklines. Service matrix. Containers. CVE findings.
- **Run commands** — Shutdown, reboot, WoL, arbitrary shell, multi-line scripts with dry-run lint, batch across many devices, scheduled (cron) and one-shot.
- **Browser SSH** — Real xterm.js terminal proxied through a hardened daemon. asciinema session recordings.
- **docker compose** — Up / down / restart / pull / logs on projects the agent discovered under `/opt /home /docker /srv`.
- **Proxmox** — Connect a Proxmox VE node — start/stop QEMU VMs and LXC containers, manage snapshots, and **create or delete LXC containers** *(v3.4)* from a wizard (templates, storage, bridges, networking, root password/SSH key) — all server-to-API, admin-only and audited.
- **Configuration drift** — Hashes `sshd_config`, `sudoers` and friends against a baseline; diff, accept, or ignore changes.
- **Alerts inbox** *(v3.2)* — Every fired event lands in a mutable ledger with acknowledge / resolve / auto-resolve lifecycle. Recover events (device_online, service_recover, snmp_recover) clear the matching open row automatically. Per-event filter, bulk-resolve, clear-resolved.
- **Channel routing matrix** *(v3.3)* — Per-kind toggles for Needs Attention / Recent Activity / Alerts inbox / external webhook. One matrix replaces the prior scattered hide-this-kind toggles; lazy-migrates legacy `dashboard_hidden_*` config.
- **Outbound notifications** — Discord / ntfy / Slack / Pushover / Teams / Gotify / generic JSON / **GitHub issues** *(v3.3)* webhooks, multi-destination with per-event filters. Email too. Skipped/disabled deliveries reported separately so quiet fleets don't show a phantom failure rate.
- **Inbound webhooks & syslog** *(v3.2)* — Receive alerts from Grafana, Alertmanager, Authelia/Authentik, n8n, Home Assistant. Ingest syslog from rsyslog `omhttp` / fluent-bit / curl. Both feed the same Alerts inbox.
- **CMDB built in** — Asset metadata, encrypted credentials vault (AES-GCM + PBKDF2), Markdown docs per asset, network topology map, agentless devices.
- **CVE scanning** — OSV.dev-backed, CVSS v3.1-scored, severity-ranked, per-CVE ignore list.
- **SNMPv2c polling** *(v3.2)* — Pure-stdlib client polls every 5 min: sys-group, hrProcessorTable per-CPU load, hrStorageTable filesystems, UCD-SNMP load averages, vendor MIBs (Mikrotik temp/voltage/CPU MHz, Ubiquiti UAP/UDM/USW model+firmware). Threshold-driven `metric_warning` / `metric_critical` / `snmp_unreachable` / `snmp_dead` events for agentless devices alongside agented hosts.
- **Auth that scales** — bcrypt + TOTP 2FA. **Passkeys / WebAuthn** *(v4.2)* for phishing-resistant passwordless sign-in. LDAP/AD. **OIDC / OpenID Connect** *(v3.2)* — Authelia, Authentik, Keycloak, Pocket-ID, Google. **SAML 2.0** *(v4.2)* — Okta, Entra, OneLogin, Ping, ADFS — plus SCIM deprovisioning. Per-role **MFA enforcement**, concurrent-session caps and default API-key expiry *(v4.2)*. Named API keys (admin/viewer/mcp roles). Enrolment tokens for cloud-init / Ansible. **IP allowlist** *(v3.3)* gates UI/API behind CIDR ranges while exempting agent paths.
- **AI assistant** — Optional LLM integration (Ollama, LocalAI, Anthropic, OpenAI, DeepSeek). Explain output, triage CVEs, prioritise patches, generate scripts — all with regex-based secret redaction. Disabled by default.
- **MCP server** — a Model Context Protocol server exposes 18 tools so an MCP client such as Claude Desktop can answer questions about your fleet and take a few guarded actions. **14 read tools** (`list_devices`, `get_device`, `search_devices`, `search_fleet`, `get_journal`, `get_services`, `get_containers`, `get_cves`, `get_drift`, `get_recent_commands`, `get_runbook`, `get_patches`, `get_tls`, `get_snmp_data`) and **4 guarded write tools** (`reboot_device`, `run_saved_script`, `force_package_scan`, `force_acme_rescan`) that require a per-token server-side allow-list and are audit-logged — there is deliberately no arbitrary `run_command` (scripts must be pre-saved). See [docs/mcp.md](docs/mcp.md).
- **Metrics & integrations** — Prometheus `/api/metrics` for Grafana (status-token authenticated for stable scrape configs, v3.3). `/api/status` for Uptime Kuma / Homepage. **Healthchecks.io watchdog** *(v3.3)* — server pings hc.io on a fixed interval so an external monitor flips red when RemotePower itself stops responding.
- **Installable PWA** — Chrome install prompt in the header. Service worker pre-caches the app shell; API calls are always network-only. Works on desktop and mobile.
- **Custom monitoring scripts** — Define bash health checks server-side, assign to devices — agent runs them every 5 minutes. Exit 0 = OK. Fleet results page, edge-triggered alerts, inline AI generation.
- **Calendar, schedule, maintenance windows** — Cron + one-shot scheduled commands, recurring calendar events (daily/weekly/monthly/yearly), maintenance windows that suppress webhook alerts globally or per-device.
- **ACME / Let's Encrypt** — Per-device issuance, force-renew, revoke. **Central DNS-01 credentials** *(v3.3)* — operator stores Cloudflare/Hetzner/Route 53/etc. API tokens once on the server; injected into the queued `acme.sh` command at issue time, so device-side `account.conf` editing is no longer required.
- **IaC generator** — Terraform / Ansible / Pulumi / cloud-init / Salt from live host inventory across 18 categories. AI renders the output.
- **Server self-monitoring** — Site-health card (load avg, memory %, sessions, devices-online %), disk usage breakdown, audit log size, scheduled backup state, webhook delivery rate (inbound + outbound, separate), MCP confirmation queue.
- **Hash-driven agent self-update** *(v3.3)* — agents compare their own binary sha256 against the server's canonical hash; mismatch in either direction triggers a download. Replaces version-string comparison (which silently skipped same-version rebuilds and operator-initiated re-pushes).
- **Hardware & health** *(v3.4)* — per-disk SMART (alerts on failing / pre-fail drives), kernel-vs-newest-installed and livepatch status, and a passive hardware inventory (DIMMs, serials, temperatures, RAID), all in the device drawer's Health & Hardware card. The drawer's System Info tab also shows the host's top processes by CPU, each mount's filesystem type, reboot-required status, and per-container age.
- **Resource forecasting & "what changed"** *(v3.4)* — projects per-mount disk-fill ("/ fills in ~18 days") from a daily metrics snapshot, with a dedicated **Monitoring → Forecast** page (sortable fleet table + a scatter/regression-line chart per mount), and diffs the last day/week (packages, ports, units, disk growth) so you can see what moved.
- **On-demand diagnostics** *(v3.4)* — one-click network speed test (librespeed → Mbps) and a LAN discovery sweep (passive ARP or nmap) that flags unmanaged hosts on the wire.
- **Device quarantine** *(v3.4)* — a per-device switch that disables exec / reboot / all actions, enforced server-side at the command chokepoint and audited — isolate a suspect host in one click.
- **Compliance reports** *(v3.4)* — maps PCI DSS / HIPAA / SOC 2 controls to data RemotePower already collects and scores them pass / fail / N-A with evidence and remediation. An audit-prep aid, never a formal attestation.
- **Helm releases** *(v3.4)* — read-only visibility into Helm release status where Helm and a kubeconfig are present.
- **RAG over your infrastructure** *(v3.4)* — the AI assistant retrieves relevant facts from *your* fleet (device state, services, CVEs, containers, CMDB docs, runbooks, recent commands/alerts, and the product docs) and cites their sources. Lexical BM25 works with every provider; semantic search is opt-in with an embedding-capable provider. The credentials vault is never indexed.
- **On-demand AI insights** *(v3.4)* — fleet anomaly scan, a plain-English cron builder with a locally-validated next-run preview, RAG-aware per-device runbook suggestions, and CMDB doc drafts. All opt-in and disabled by default.
- **Per-device timeline** *(v3.4.1)* — a single chronological history per host (**Monitoring → Timeline**) that merges fleet events and command runs into one filterable stream, so you can read what happened to a box in order.
- **Fleet health score** *(v3.4.1)* — one 0–100 score per device and across the fleet on the home dashboard, rolled up from the same Needs Attention signals, with the lowest-scoring devices linking straight into their timelines.
- **Fleet posture reports** *(v3.4.1)* — one report binding patches, CVEs, the health score, and compliance (**Planning → Reports**): download as JSON/CSV on demand, or email it on a cron schedule.
- **OpenSCAP compliance scans** *(v3.4.2)* — auditor-grade scans on the endpoint: CIS / STIG / PCI-DSS on the SCAP Security Guide, plus Ubuntu Security Guide (USG) for CIS/STIG on Ubuntu and ANSSI BP-028 profiles on Debian/Ubuntu. Score, pass/fail tallies, failing rule ids — and a **downloadable full HTML report**. No new server dependency. Requires the `upgrade` permission.
- **AI Investigate** *(v3.4.2)* — one-click diagnose-and-suggest-a-fix on a Needs-Attention item, now including CVE findings and stopped/restarting containers alongside disk / memory / swap / cpu / patches / drift / service / reboot / brute-force alerts. Requires the `exec` permission.
- **Command Queue** *(v3.4.2)* — an Admin page listing every device's pending queued commands — even offline hosts — so you can see what's waiting and cancel it before the host comes back.
- **Per-device backups** *(v3.4.2)* — a Backups section in the device drawer showing each watched backup path's age and fresh/stale state.
- **Container health** *(v3.4.2)* — the per-device container list now shows each container's health badge (healthy/unhealthy/starting), live CPU%/memory, and published ports.
- **SBOM export** *(v3.5)* — generate a CycloneDX 1.5 or SPDX 2.3 Software Bill of Materials per host or for the whole fleet from the collected package inventory; each component carries a `purl`, and CycloneDX embeds a VEX-style vulnerabilities section from the host's current CVE findings, so one document is both inventory and vulnerability report. `GET /api/devices/<id>/sbom`, `GET /api/sbom` (fleet = ZIP).
- **Lifecycle expiry tracking** *(v3.5)* — record warranty / license / support-contract end dates per CMDB asset; expired or within 30 days → warning, within 90 → info, surfaced as dashboard attention items that feed the health score and are silenceable in channel routing.
- **Graphical remote access (VNC over SSH)** *(v3.5)* — a Remote desktop device action opens a browser VNC session (noVNC) tunnelled over the web-terminal daemon's SSH connection to the host's loopback VNC port — never network-exposed, no inbound firewall rules, no agent change. Linux VNC; RDP not yet supported.
- **Sites & teams** *(v3.5)* — a first-class fleet grouping above device groups, for organising hosts by location / team / customer (soft boundary — super-admins see all). Admin → Sites, an Assign-site device action, and a site filter on the Devices roster.
- **Remote file manager** *(v3.6)* — a Files device action browses and transfers files over SFTP, tunnelled through the same daemon + ticket + SSH path as the terminal and VNC (no inbound ports). Download/upload, mkdir, delete, as the SSH user.
- **Backup orchestration** *(v3.6)* — define a backup command per device (restic/borg/rsync) under Planning → Backups, run it on demand, or schedule it with cron. Closes the loop on the backup-freshness monitoring in each device drawer.
- **Host user, key & firewall management** *(v3.6)* — add/lock/unlock/delete users, add/revoke SSH keys, and allow/deny/delete ufw or firewalld ports straight from a device's drawer. All exec-gated, audited, quarantine-aware.
- **Endpoint AV posture** *(v3.6)* — ClamAV / rkhunter status (DB age, infected count, warnings) reported by the agent, with an on-demand scan action; infections raise a critical attention item.
- **Auto-patch policy** *(v3.6)* — Planning → Auto-patch applies updates automatically on a cron schedule across a group / tag / site / whole fleet, optional reboot, respecting maintenance windows.
- **Proxmox backup check** *(v3.6)* — per-guest vzdump backup recency from the node's backup storage; guests with no/stale backups become attention items, alongside the existing stale-snapshot check.
- **2FA recovery codes** *(v3.7)* — one-time backup codes generated at TOTP enrollment; a code logs you in if you lose your authenticator, then is consumed. Regenerate from Settings → Security.
- **Audit-log forwarding** *(v3.7)* — mirror every audit entry to a SIEM (HTTP JSON) or syslog collector (RFC 5424 UDP/TCP), SSRF-guarded and non-blocking, with a test button.
- **Credential rotation reminders** *(v3.7)* — per-credential "rotate every N days" policy in the CMDB vault; overdue credentials are flagged on the dashboard and badged in the asset view.
- **Desired-state enforcement** *(v3.7)* — opt-in "correct on drift" re-applies a host's desired config only when it drifts, beside the existing always-on enforce.
- **Change approval (maker-checker)** *(v3.7)* — optionally require a second admin to approve arbitrary command runs; the requester can't self-approve.
- **Proxmox VM create** *(v3.7)* — a Create VM wizard (cores/memory/disk/bridge/ISO) builds QEMU guests via the API, alongside the LXC create.
- **Ansible playbook runner** *(v3.7)* — store playbooks and run them against a group/tag/site/fleet with the server as the control node over SSH (needs ansible-core on the server).
- **AI Investigate — broadened** *(v3.8)* — the one-click diagnose-and-suggest-a-fix now covers ~21 Needs-Attention kinds: added malware/AV posture, stale agent version, end-of-life OS, hardware health, stale/missing backup, new SSH key, new listening port, agent integrity, log-pattern alerts, and **failed systemd units**, each with a tailored prompt (security-sensitive kinds never propose a blind destructive command).
- **More host signals surfaced** *(v3.8)* — **failed systemd units** (now a health-scored attention item, also revived in the Fleet Query filter and CIS compliance check) and **currently logged-in users** show in the device drawer; both were collected by the agent but previously dropped before reaching the UI.
- **Security hardening** *(v3.8)* — connect-time anti-DNS-rebinding on webhook / SIEM-forward / OIDC calls, maker-checker approval re-checks device state, opt-in mandatory signed agent updates, and a strict-CSP / header-inheritance pass on the nginx templates. See the **[security model & review history](docs/security.md)**.
- **Monitor SSRF closed + more signals bound** *(v3.9)* — the HTTP uptime monitor now uses the same connect-time SSRF guard as the other back-channels (closing IPv6 / integer-IP / DNS-rebinding bypasses), and three previously-collected-but-hidden signals surface: **CPU-load history** (Trends), **swap** on the metrics sparkline, **rkhunter last-run**, the **systemd alias** a watched unit resolved to, and **livepatch state**. See the **[security overview](docs/security.md)**.
- **Correctness & polish** *(v3.9)* — the post-upgrade "didn't take" badge no longer false-alarms on already-patched or offline hosts; a metric-threshold bug that could skip disk alerting is fixed; TLS-expiry alerts get the right severity; three more tables are sortable; typographic glyphs replaced with Lucide icons; close buttons gained aria-labels.
- **One-click image update + ACME in the Command Queue** *(v3.9)* — stale, compose-managed container rows get a one-click **Update** button (`docker compose pull` + `up -d`), and ACME certificate actions now log to the Command Queue's recently-dispatched view with **Clear all pending** / **Clear log** controls.
- **Container restart tracking, fleet-wide** *(v3.10)* — Docker and Podman containers now report a real **restart count** and **start time** (one batched `docker inspect` per heartbeat), so the *container restarting* alert fires on every host — not just Kubernetes — and the drawer shows container age. **ClamAV last-scan time** and **per-interface MAC addresses** now show in the device drawer; the config-drift alert title names the file/sections that drifted instead of "? file(s)".
- **Security hardening** *(v3.10)* — the container image-registry check now routes every fetch (manifest **and** the registry-controlled bearer-token realm) through the connect-time SSRF guard, closing a redirect / DNS-rebinding / credential-exfiltration gap; `GET /api/config` gained a recursive secret-scrub backstop so a newly-added config secret can never leak to a viewer/MCP key; the TCP uptime monitor and the Healthchecks.io ping picked up the same IP-class SSRF checks as the HTTP paths. See **[docs/security.md](docs/security.md)**.
- **Fleet posture batch** *(v3.11)* — seven features over data the agent already collects: an **Exposure** map that classifies every listening socket as world / LAN / local (and alerts when a service first becomes world-reachable); a **Software Policy** engine (banned / required / min-version package rules, optionally tag-scoped) over the existing package inventory; **Storage / RAID health** for ZFS, mdadm and btrfs (degraded-array + scrub-overdue alerts); **Access watch** (new-source-IP logins); **host firewall drift** (ufw/nftables/iptables ruleset fingerprint); a **scheduled-job failure** lens over systemd timers; and an opt-in **scheduled posture digest** email. See **[CHANGELOG.md](CHANGELOG.md)**.
- **Optional SQLite storage backend** *(v3.12)* — for large fleets with frequent writes, switch from flat-JSON files to an embedded **SQLite** database (WAL mode, stdlib only, no new dependencies) under **Settings → Advanced → Storage backend**. Hot data is stored row-per-entity, so a heartbeat updates one row instead of rewriting a whole file. The switch is in-place and reversible (snapshot → migrate → verify → flip), with a `tools/migrate_storage.py` CLI. Flat JSON stays the default. See **[docs/scaling.md](docs/scaling.md)**.
- **Bind it together — round four** *(v3.13)* — surfaces host signals the agent already collected but the UI never showed: per-device **recent logins & source IPs**, a failed-first **systemd timer** inventory, this host's own **ZFS/mdadm/btrfs storage health**, **bind address + world/LAN/local scope** on the drawer's listening-ports card, the **firewall ruleset fingerprint**, an active **brute-force lockout** badge, and Disk/Swap pressure pills. Plus every panel now caps at ~15 rows and scrolls; static assets cache immutably; and a security pass (sandboxed SCAP reports, OIDC id_token expiry/issuer/audience checks, syslog-forward DNS-rebinding fix). See **[docs/v3.13.0.md](docs/v3.13.0.md)**.
- **Operator quality-of-life batch** *(v4.0)* — **per-account sidebar favorites** (star any entry to pin under "Main"; synced across devices via `/api/me`); a **per-container stale-image badge** in the drawer (same digest join as the fleet Image Updates page); a fleet **Thermal "hottest hosts"** page; **CVE prioritization** with CISA **KEV** + **EPSS** (rank by exploited-in-the-wild, not just CVSS); **active session management** (list & revoke your signed-in sessions); **saved & shareable Devices views**; **SSD/NVMe wear** + projected end-of-life; **GPU monitoring**; a **local certificate-file** expiry inventory; a **local account audit** (extra UID 0 / stale / locked); and **power scheduling** (scheduled Suspend / Wake-on-LAN). Plus a **Predictive-health** page (SMART-trend disk-failure ETA + frequently-restarting hosts), a **Power** page (UPS via NUT/apcupsd + energy-cost estimate), an **SSH-key audit** (fleet authorized_keys with SHA256 fingerprints), on-demand **container log** fetch, **global omnisearch** (palette also searches alerts + CVEs), a **custom report builder** (pick sections, JSON/CSV, per-report schedule), **container images in SBOMs**, a **fleet drift-enforcement policy** by tag/group, **alerts** for the new posture signals (predicted disk failure, UPS-on-battery, expiring cert files, rogue UID-0), **Prometheus metrics push** to a Pushgateway, a **customizable dashboard** (show/hide & reorder Home widgets, saved per account), **GitOps** (sync drift-config profiles from a Git manifest — config-as-code, dry-run preview), an **interface language** switch (English / Mandarin / Hindi / Spanish / Arabic, saved per account), and **change-approval** coverage extended to reboot/shutdown/update/upgrade/uninstall/container actions. Most of it surfaces data the agent already reports. See **[docs/v4.0.0.md](docs/v4.0.0.md)**.

- **VisualMatters** *(v4.1)* — binds the telemetry the agent already reports into first-class views. A **CheckMK-style per-host Checks** page (under Monitoring) shows every signal on every host as OK / WARN / CRIT / UNKNOWN with output — sortable, filterable, per-check muteable, with *Hide muted* / *Hide unmonitored* on by default; **custom checks** (server-side process/port + agent-side file/job/log) assignable to host/tag/group, and your custom scripts surface as rows. More **active monitors**: DNS (with expected-address), ICMP latency + packet-loss, HTTP status + latency-SLA assertions, a credential-less **DB-liveness** probe (PostgreSQL/MySQL/Redis), and tag/group target fan-out. A **composable dashboard** — a 66-widget catalog you resize / reorder / show-hide / reset / align / share, with Upcoming, Tickets and actionable Alerts widgets. A **host-grouped alert inbox** that folds a host-down storm under its `device_offline` root cause. Plus a **TLS 1.2 floor** on the satellite (both hops), the agent, and server outbound HTTPS. Independently scanned (wapiti, nikto, nuclei, bandit, OWASP ZAP) — clean. See **[docs/v4.1.0.md](docs/v4.1.0.md)**.

- **5ecur1tyM4tter5** *(v4.2)* — security and integrations: making the fleet **defensible**, not just visible. **Authorized vulnerability scanning** (the *Pentest* page) scans the hosts and websites you own with industry tools (passive: nuclei / nikto / nmap; active: OWASP ZAP / wapiti; on-host: lynis) — targets are authorization-gated (enrolled hosts, or domains you prove you own via an ACME-style DNS-TXT / `.well-known` check), the toolchain runs on a hardened **scanner satellite**, the active tier is gated behind an authorization attestation + maintenance window, and scans can be **scheduled**. **Passkeys** (WebAuthn) bring phishing-resistant, passwordless sign-in that satisfies MFA; **SAML 2.0 SSO** adds enterprise IdP login (Okta / Entra / OneLogin / Ping / ADFS) alongside the existing OIDC / LDAP. A **tamper-evident** (hash-chained) audit log with one-click integrity verify and a protected clear; plus account guardrails — **enforce MFA per role**, **cap concurrent sessions**, **default API-key expiry**, and a graded **security-posture self-check**. Every control is opt-in. See **[docs/v4.2.0.md](docs/v4.2.0.md)**.
- **ImprovementMatters** *(v4.3)* — a refinement release, **no breaking changes**: sharpens what's already there. **Faster on bigger fleets** — on the SQLite / PostgreSQL backends the single-device endpoints (per-host Checks, per-device CVE detail, the heartbeat's host-config + watched-file lookups, and the firewall / compose / RouterOS / OPNsense device actions) read **one row** instead of reconstructing the whole fleet per request. **Self-observability** — download the gzipped **audit-log archive** from the Audit page, and see a last-ran + staleness badge for cadence jobs (monitors, KEV/EPSS refresh, scheduled scans) on **Server status**. **UX** — each security-posture warning links straight to the Settings section that fixes it, and tables share one skeleton loading state. Plus **regression guardrails** (tests) that catch a check reading an unpersisted sysinfo field, or a webhook event that half-registers, at commit time. See **[docs/v4.3.0.md](docs/v4.3.0.md)**.

Full feature inventory: **[docs/features.md](docs/features.md)**.

## Security

RemotePower is security-reviewed every few releases — the latest is
**[docs/security-review-4.2.0.md](docs/security-review-4.2.0.md)** (server +
agent), preceded by the 4.1.0 and 3.13.0 reviews. It is
also scanned with a combined **SAST + DAST** pipeline — **Bandit** (static
analysis of the Python), and **OWASP ZAP** (full active scan), **Nikto**,
**Nuclei**, **Wapiti** and **WhatWeb** (dynamic) — and the latest full run
reported **no exploitable findings** (only informational items and
false positives). Posture in
brief: bcrypt (cost 12, with a PBKDF2-HMAC-SHA256 fallback at OWASP-2023
parameters) passwords behind rate-limited login, TOTP 2FA with one-time
recovery codes; 256-bit header-based session tokens (CSRF-safe by
construction); a strict CSP with no `'unsafe-inline'`; AES-GCM CMDB vault
(fresh nonce per encrypt); mandatory TLS verification plus connect-time
anti-DNS-rebinding on every outbound call (webhooks, SIEM forwarder, OIDC);
optional maker-checker change approval; opt-in mandatory signed agent updates;
and hardened agent state-file handling against local symlink attacks. Full
posture, threat model, and operator hardening checklist (including an
internet-facing IP-allowlist guide): **[docs/security.md](docs/security.md)**.

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

CMDB, documentation, network map, Proxmox (snapshots, plus create/delete LXC),
remote management (with a browser-based web terminal), fire off bash scripts or
commands, monitoring, custom monitoring scripts, CVE scanning, disk SMART &
hardware health, resource forecasting ("/ fills in ~18 days"), compliance
reports (PCI / HIPAA / SOC 2), logs with regex search, cert-expiry dashboard,
ACME integration, patch management, alerting, notifications, configuration
drift detection, audit log, calendar, tasks, maintenance windows, MCP server
with write tools, IaC generator, proper documentation, full API with Swagger,
LDAP, OIDC / OpenID Connect, fleet dashboard, agent auto-update… And the best
of it: heavily connected to your own local AI (Ollama, LocalAI) or online AI
(Anthropic, OpenAI, DeepSeek), if you like — with **RAG** that retrieves facts
from your own fleet and docs so its answers cite your hosts, not generic advice.

## License

MIT — see [LICENSE](LICENSE).

<div align="center"><sub>Made with care and vi</sub></div>
