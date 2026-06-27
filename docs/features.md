# Features

Version tags (e.g. *v3.4.1*) mark when a feature landed. Complete history is in [`CHANGELOG.md`](../CHANGELOG.md).

## Fleet visibility & inventory

| Feature | Notes |
|---|---|
| Live status | Green/red per device, auto-refresh 60s, configurable per device (10–3600s) |
| OS icons | Auto-detected SVG glyphs — Linux, Windows, macOS *(v4.0.0)*, fallback |
| Uptime tracking | Online/offline state changes stored per device |
| Container awareness | Auto-detected Docker / Podman / Kubernetes pods — image, status, restart count, ports, namespace; read-only |
| Network map | Manual topology from per-device `connected_to`; agentless switches/APs; site/group/tag scope picker *(v5.0.0)* |
| Network metrics page | Per-device RX/TX from interface samples; fleet/group/tag/site scope, top-talkers, roll-ups *(v5.0.0)* |
| Pending-reboot indicator | Amber ⟳ **Pending Reboot** badge on Patches when `/run/reboot-required` exists *(v2.4.14)* |
| Timeline (fleet or device) | Merged fleet events + command runs, newest-first, filterable, scoped *(v3.4.1)* |
| Fleet health score | 0–100 per device and fleet from Needs-Attention signals; history sparkline + `health_degraded`/`health_recovered` *(v3.4.1)* |
| Fleet heat map | Home grid of device cells coloured by health score *(v3.4.2)* |
| Risk scoring | Per-asset 0–100 from CVEs, exposure, policy, lifecycle, mount health, with per-point breakdown |
| NOC Status Board | Fleet rolled into group/site/tag tiles + problem-host strip *(v5.0.0)* |
| Tasks | Operational checklist page for tracking fleet work items |
| Needs-Attention digest | Single ranked list merging every fleet signal *(v2.4.7)* |
| Software inventory search | "Which hosts run openssl < X" over collected inventory *(v3.4.1)* |
| Software center | Every installed package across the fleet, versions + host counts *(v3.13.0)* |
| End-of-life OS detection | Vendor-EOL table flags out-of-support hosts *(v3.4.1)* |
| Ad-hoc fleet query | Filter by group/tag/OS/online/pending/CVE/integrity/version/pkg-manager/has-package/failed-units/disk-mem%/offline-days; saved queries *(v3.4.2)* |
| Boot reason | Why a host last restarted, stored + shown *(v3.8.0)* |
| Failed systemd units + logged-in users | Persisted, shown in System Info tab *(v3.8.0)* |
| Unmonitored devices | Shown in telemetry/inventory views (thermal/power/storage/exposure/SMART/patches/ports/processes/GPU), flagged; only alerting suppressed *(v4.7.0)* |
| Decommissioned assets | Greyed across lists + CMDB with *DECOMMED* badge; fully silenced (no monitoring/alerts/health/SLA) *(v5.0.0)* |
| Tags & groups | Tag devices, namespace by group (`dc1/prod`); filter and batch by either |
| Device notes | Free-text per device, shown as tooltip |
| Sites & teams | First-class fleet grouping above groups (location/team/customer); super-admins see all *(v3.5.0)* |

## Device drawer signals

| Feature | Notes |
|---|---|
| System Info | Top processes by CPU, per-mount fs type, reboot-required+reason, 1-min loadavg, container age *(v3.4.0)* |
| Hardware pills | CPU model, kernel, total RAM, total disk beside live usage *(v4.6.0)* |
| Access — recent logins | Who logged in + distinct source IPs *(v3.13.0)*, with Last-seen timestamp *(v4.4.0)* |
| Scheduled jobs / timers | Failed-first table of every systemd timer — unit, target, state *(v3.13.0)* |
| Per-host storage / RAID | This host's ZFS / mdadm / btrfs pools (state, capacity, scrub) *(v3.13.0)* |
| Port bind + scope | Each socket's bind address + world / LAN / local badge *(v3.13.0)* |
| Firewall fingerprint | Active backend, rule count, drift baseline fingerprint *(v3.13.0)* |
| Pressure pills | Brute-force lockout badge; disk/swap pressure pills *(v3.13.0)* |
| Per-interface MAC | MAC per interface *(v3.10.0)* |
| Backups | Each watched backup path's age + fresh/stale state *(v3.4.2)* |

## Metrics, history & forecasting

| Feature | Notes |
|---|---|
| Metrics history | CPU/RAM/disk/swap/loadavg sparklines per device, full chart on click; up to 1440 snapshots (`metrics.json`) |
| Live metrics (Monitor page) | All-fleet current sysinfo, colour-coded by alert level *(v1.12.0)* |
| Metric trend modal | Time-series per device, one click from the fleet view *(v2.0)* |
| Per-mount disk | Each non-pseudo mount tracked individually *(v1.11.10)* |
| Network-mount trends | NFS/SMB/CIFS shares flow into daily history + disk-fill forecast *(v3.13.0)* |
| Resource forecasting | Per-mount least-squares trend → days-to-full + projected fill date; **Monitoring → Forecast** page *(v3.4.0)* |
| Statistical anomalies | Per-host mean/stdev baselines flag ≥2.5σ memory/swap/disk deviations *(v3.4.2)* |
| What changed (drift over time) | Diff oldest vs latest snapshot — package/port/unit/reboot/disk deltas *(v3.4.0)* |
| Trends charts | Zero-dep multi-series SVG — fleet health, compliance %, per-device resources, CPU-load saturation % *(v3.4.2)* |
| Prometheus metrics | `/api/metrics` exposition (Grafana); status-token auth; health/needs-attention/CVE gauges *(v3.4.1)*; metrics push *(v4.0.0)* |
| Capacity dashboard | Fleet-wide CPU/mem/disk rollup, top consumers, on Reports *(v3.4.1)* |

## Checks & custom checks *(v4.1.0)*

| Feature | Notes |
|---|---|
| Per-host Checks | Every monitored signal as OK/WARN/CRIT/UNKNOWN — reachability, CPU/mem/swap, per-mount disk + inode, fd/conntrack, failed units, timers, drift, exposed ports, updates, CVEs, SMART/UPS/temperature, clock, gateway, OOM, mail-queue, RO filesystems, disk-fill ETA, storage/RAID. Sortable, filterable, per-check muteable |
| Custom checks | Server-evaluated process/port-open/port-closed; host-evaluated file present/absent, job freshness, log error rate; editable *(v5.0.1)* |
| Custom monitoring scripts | Admin bash health checks, assigned per device, run every ~5 min; binary exit; fleet results page; `custom_script_fail`/`custom_script_recover`; AI generation in create modal; full guide [custom-scripts.md](custom-scripts.md) *(v2.5.0)* |
| Monitoring profiles | Named bundles of custom scripts applied to omnisearch-selected assets in one action; `/api/monitoring-profiles` + `/apply` |

## Active monitors & probes

| Feature | Notes |
|---|---|
| Ping / TCP / HTTP probes | ICMP, TCP, HTTP HEAD from the server; runs when dashboard closed *(v1.11.8)*; HTTP SSRF-guarded with connect-time recheck |
| DNS / ICMP / HTTP / DB monitors | DNS resolution with expected-address; ICMP latency + loss; HTTP status + latency-SLA; credential-less DB-liveness (PostgreSQL/MySQL/Redis); tag/group fan-out *(v4.1.0)* |
| Monitor history | Uptime %, sparkline, last 50 results per target |
| Service monitoring | Agent watches systemd units; matrix view; webhooks on transitions; shows resolved alias *(v3.9.0)* |
| Log tail + alerts | journalctl per watched unit; rolling 6-hour buffer; regex search; pattern-match alerts; per-rule template / exclude / snooze; matched line shown in NA card / inbox / webhook + Open-in-Logs deep link *(v3.3.0)* |
| Inbound syslog | HTTP receiver — point rsyslog `omhttp`/fluent-bit/`curl` at `POST /api/syslog/in/<token>`; parses RFC 3164/5424 into the device log buffer for `log_alert` rules *(v3.2.0)* |
| SNMP trap receiver | HTTP receiver — an `snmptrapd` handler POSTs decoded traps as JSON to `POST /api/snmp/trap/<token>`; traps attach to the pinned device's SNMP view and raise a coalesced `snmp_trap_received` alert |
| TLS / DNS expiry | Server-side probes against a watchlist; warn 14d / crit 3d |
| Resolver health monitor | Re-resolves a name across public resolvers; tracks latency + NXDOMAIN; `resolver_unhealthy`/`resolver_recovered` *(v4.9.0)* |
| Healthchecks.io watchdog | Server pings a URL on a cadence so an external monitor flips red if RemotePower stops |

## Alerts, events & routing

| Feature | Notes |
|---|---|
| Metric alerts | Disk/memory/swap/CPU-load thresholds with hysteresis *(v1.11.10)*; per-device + per-mount overrides *(v1.12.0)* |
| Webhook event registry | 86 event types, per-event toggles, test-event button |
| Channel routing matrix | Per event-kind, which surfaces it reaches — Needs Attention / Recent Activity / Alerts inbox / Webhook *(v3.3.0)* |
| Host-grouped alert inbox | Open alerts stacked per host (worst first), Ack-all/Resolve-all, symptoms folded under `device_offline` root cause *(v4.1.0)* |
| Alert correlation | Tags `_root_cause` / `_symptom_of` for the grouped inbox |
| Duplicate-alert coalescing | Repeat firings fold into the open alert (count bump) *(v5.0.1)* |
| Alert-resolution timeline (MTTR) | Time-to-resolve / ack mean+median 7/30/90d, per-host, close-classification *(v4.9.0)* |
| Quiet hours | Hold non-critical delivery during a daily window; critical always pages *(v3.4.1)* |
| Maintenance windows | Suppress alerts and/or gate command execution; per-device/group/fleet; one-shot or recurring cron+duration; audit trail *(v3.4.2)* |
| After-hours detection | Flag selected events firing outside business hours *(v3.4.2)* |
| On-call & escalation | Escalation tiers re-notify unacked alerts; on-call rotation names the contact *(v3.4.2)* |
| Automation rules engine | Event (at severity) on matching devices → run saved script and/or notify; per-rule cooldown, admin-only, audited *(v3.4.2)* |
| Device dependency map | Declare device→upstream deps; downstream alerts held while upstream offline *(v3.4.2)* |
| Patch alerts | Webhook when pending updates exceed a threshold |
| Admin-only alert mutation | Optionally require admin role to ack / unack / resolve (`viewers_can_ack_alerts`) *(v3.3.0)* |
| Ticket system | Opt-in built-in helpdesk (Advanced → `tickets_enabled`, default off): tickets typed Incident / Request / Change (alerts → Incident, reusing the alert id as `#RP000042`), statuses ongoing/pending-customer/pending-internal/resolved/closed; **priority P1 Major / P2 Critical / P3 Warning / P4 Low** (alert-derived tickets inherit the alert severity, Major manual-only); **assignee + take-ownership**; **multiple affected devices**; **master/sub parent-child links**; sortable list defaulting to unhandled → your own → ongoing; attach to alerts + devices; search; outbound email (existing SMTP) + dedicated-IMAP reply ingestion with a mail-loop guard; recipient parsed from CMDB contacts/notes; per-device + CMDB ticket indicators |
| Posture digest | Opt-in daily/weekly email summary over SMTP *(v3.11.0)* |
| Digest endpoint | `/api/digest` for cron-driven email summaries |
| Flap cap | Server-wide cap stops a flapping monitor flooding channels |

## Notification destinations

| Feature | Notes |
|---|---|
| Webhooks | Generic JSON, Discord, ntfy, Slack, Gotify, Microsoft Teams, Pushover; auto-format detection |
| GitHub issues | `github` destination opens an issue with labels *(v3.3.0)* |
| PagerDuty / Opsgenie | PagerDuty Events v2 (trigger + auto-resolve), Opsgenie Alerts v2 *(v3.4.1)* |
| ITSM (Jira / ServiceNow / Zendesk) | Ready-made ticket formats; "fire on ACK" opens a ticket, link shown on the alert *(v5.0.0)* |
| Ack → ticket webhook | Any destination can also fire on alert acknowledgement *(v3.12.0)* |
| Audit-log forwarding | Audit entries to a SIEM (HTTP) or syslog *(v3.7.0)* |

## Commands, actions & automation

| Feature | Notes |
|---|---|
| Reboot / shutdown | Queue actions, reported on next heartbeat |
| Suspend to RAM | Schedule (one-shot/cron) or queue `systemctl suspend`; warns if no MAC for WoL resume *(v4.0.0)* |
| Wake-on-LAN | Magic packet, unicast over routed networks/VPN |
| Custom commands | Arbitrary shell as root; output via heartbeat; 64 KB cap |
| Command library | Saved named snippets |
| Per-device allowlist | Whitelist of allowed exec commands per device |
| Scheduled commands | One-shot (datetime) or recurring (cron) |
| Per-command timeouts | Override default command timeout on a single run *(v5.0.0)* |
| Long-poll exec | `/api/exec/wait` holds the connection until output arrives |
| Update history | Rolling 10-run buffer of apt/dnf/pacman output per device |
| Command queue | View + cancel every device's pending queued commands; ACME actions logged; clear-all/clear-log *(v3.4.2)* |
| Bulk delete & re-tag | Select many devices, remove or tag in one action *(v5.0.0)* |
| Maker-checker approval | A second admin signs off arbitrary command runs; re-checks device state at approval *(v3.7.0)* |
| Quarantine | Per-device admin switch disabling every action, enforced at dispatch, audited *(v3.4.0)* |
| Audit (read-only) mode | `/etc/remotepower/audit-mode` makes the agent refuse every command (exec/scripts/reboot/config/self-update); operator-owned; AUDIT badge *(v4.10.0)* |
| Uninstall agent | Queues uninstall; agent removes unit/creds/state/binary *(v3.3.0)* |
| Ansible playbook runner | Run playbooks against group/tag/site/fleet, server as control node *(v3.7.0)* |
| App catalog | One-click deploy curated self-contained apps via Docker Compose; admin custom catalog entries *(v5.1.0)* |
| Cron & timer management | View/manage crontabs + systemd timers; audited, no-shell install *(v5.1.0)* |
| On-demand diagnostics | Network speed test + LAN discovery (ARP/nmap), flags unmanaged hosts *(v3.4.0)* |
| Diagnostics bundle | One downloadable scrubbed support bundle (no secrets) *(v4.3.0)* |

## Remote access

| Feature | Notes |
|---|---|
| Web terminal | Real xterm.js SSH in the browser via a hardened daemon; asciinema v2 recordings (output-only default, opt-in keystroke) *(v1.11.11)* |
| Graphical remote desktop | noVNC over the web-terminal daemon's SSH tunnel to loopback VNC; never network-exposed; Linux only *(v3.5.0)* |
| Remote file manager | Browse/view/edit files through the agent — no SSH/SFTP; allowlisted roots, exec-gated, audited; reads survive quarantine; opt-in per server *(v3.6.0)* |
| Host user/key/firewall mgmt | Add/lock/unlock/delete users, add/revoke SSH keys, allow/deny ufw/firewalld ports from the drawer; exec-gated *(v3.6.0)* |
| SSH links | Per-credential `ssh://user@host:port` + copy button; default SSH username *(v2.4.2)* |

## Patching & packages

| Feature | Notes |
|---|---|
| Install software | Install repo packages on a host or tag/group (apt/dnf/yum/zypper/pacman/apk) *(v3.4.2)* |
| Hold / unhold packages | Pin packages at current version (`apt-mark hold`, dnf/yum `versionlock`, `zypper addlock`); names only, no shell *(v4.0.0)* |
| Patch catalog | Pending updates aggregated by package across hosts; third-party (flatpak/snap/pip/npm) *(v3.4.2)* |
| Post-deploy verification | Confirm the pending count actually dropped (ok/stalled/pending) *(v3.4.2)* |
| Auto-patch | Cron-scheduled updates across group/tag/site/fleet, respecting maintenance windows *(v3.6.0)* |
| On-demand package scan | One-shot **Scan packages** now — fresh inventory + patch count *(v2.4.5)* |
| Software metering | Named-software install counts vs allowance, over-deployment flagged; aliases + reclamation *(v3.4.2)* |
| Fleet software policy | `banned` / `required` / `min_version` rules (tag-scoped) → `software_policy_violation` *(v3.11.0)* |
| Update-available notice | Checks GitHub for newer RemotePower releases; detection only *(v2.4.6)* |

## Vulnerabilities (CVE) & risk

| Feature | Notes |
|---|---|
| CVE scanner | Installed packages vs [OSV.dev](https://osv.dev) on a schedule; severity-ranked per device with fixed-version hints; per-CVE ignore list; Ubuntu-derivative mapping |
| KEV / EPSS prioritization | Re-ranked by CISA KEV (known-exploited) + FIRST EPSS (exploit-probability) *(v4.0.0)* |
| Distro security flag | Counts vendor-flagged security updates (apt `-security`, dnf/yum `--security`, `arch-audit`) as a "N sec" badge *(v5.0.0)* |
| CVE ↔ patch cross-link | Per device, how many critical/high CVEs a pending patch fixes *(v3.4.1)* |
| OSV circuit breaker | Scanner backs off when the OSV feed is unhealthy *(v5.0.0)* |
| SBOM export | CycloneDX 1.5 + SPDX 2.3 per host/fleet, with purls + VEX vulnerabilities; deterministic *(v3.5.0)* |

## Security scanning & pentest *(v4.2.0)*

| Feature | Notes |
|---|---|
| Authorized vuln scanning | *Pentest* page — scan hosts/websites you own with industry tools, orchestrated/scheduled/collected |
| Authorization-gated targets | Enrolled hosts (target derived server-side) or domains you prove you own via DNS TXT / `.well-known`; private/loopback refused |
| Passive profile | nuclei, nikto, nmap |
| Active profile | OWASP ZAP, wapiti — gated behind an authorization attestation + (enrolled) a maintenance window; audited |
| On-host audit | lynis hardening audit via the agent (read-only) |
| Scanner satellites | Toolchain runs on a hardened relay node; pin a scan to a satellite |
| Scheduled scans | Cron cadence; recurring findings notify a channel; quick/full intensity + vhost |

## Host security & hardening

| Feature | Notes |
|---|---|
| Exposure (attack surface) | Listening sockets classified local/lan/world; `port_exposed_world`; Exposure page *(v3.11.0)* |
| Secrets-on-disk scanning | Opt-in agent scan (~6h, configurable paths) for keys/cloud-keys/tokens; masked findings + dedup fingerprint on the Exposure page; `secret_exposed`; off by default *(v4.0.0)* |
| Firewall + fail2ban | Fleet page to view + edit host firewalls (nftables/iptables/ufw/firewalld) and fail2ban jails/bans; edits via the audited command queue, server-validated *(v4.10.0)* |
| Host firewall drift | Stable ruleset fingerprint → `firewall_changed` *(v3.11.0)* |
| Host configuration | Declare desired state per device — repos, netplan, nmcli, resolv.conf, /etc/hosts, enabled services, users + SSH keys, groups, sudoers, MOTD; agent applies on heartbeat (~60s), reports current state every 15 min; audit-only, never auto-remediates *(v2.6.0)* |
| Configuration drift | Hash a watch-list of config files (sshd_config/sudoers/…), diff vs baseline; `config_drift` edge-triggered *(v2.2.0)*; named reusable profiles *(v3.13.0)* |
| Desired-state enforcement | Correct-on-drift mode *(v3.7.0)* |
| Host-config collect & export | Drift page: collect all host configs fleet-wide + export one JSON bundle of desired/current/drift *(v3.13.0)* |
| SSH-key audit | Fleet-wide authorized_keys audit — fingerprints, weak-type flags, reuse counts *(v4.0.0)* |
| Endpoint AV posture | ClamAV / rkhunter status + on-demand scan; last-scan time *(v3.6.0)*; `av_infected` on rising infection *(v5.1.0)* |
| OpenSCAP scans | `oscap xccdf eval` — CIS/STIG/PCI-DSS, USG, ANSSI; score + failing rules; HTML report; by host/tag/group *(v3.4.2)* |
| CIS-style compliance baseline | Pass/fail checks, severity-weighted score + daily trend *(v3.4.2)* |
| Compliance frameworks | PCI DSS / HIPAA / SOC 2 controls mapped to collected data with evidence + remediation *(v3.4.0)* |
| Access watch | First-seen login source → `login_new_source`; brute force → `brute_force_detected` *(v3.11.0)* |
| Lifecycle expiry | Warranty / license / support end dates per asset → attention items *(v3.5.0)* |
| Container restart tracking | Real restart count/age via batched `docker inspect`, fleet-wide *(v3.10.0)* |

## Containers & virtualization

| Feature | Notes |
|---|---|
| Container detail | Per-device list — health badge, live CPU%/mem, published ports, stale pill *(v3.4.2)* |
| Container alerts | `container_stopped`, `container_restarting`, `containers_stale` *(v1.11.4)* |
| Image updates | Pulled-digest vs registry digest → stale flag on Image Updates page; one-click compose pull + up -d *(v3.3.4 / v3.9.0)* |
| Proxmox VE | Connect one node (scoped API token); QEMU VM + LXC start/shutdown, server-to-API *(v2.3.0)* |
| Proxmox snapshots | Create/list/roll-back/delete per guest; type-to-confirm rollback *(v2.4.0)* |
| Proxmox create / delete | LXC create wizard + delete *(v3.5.0)*; QEMU VM create wizard *(v3.7.0)* |
| Proxmox backup recency | Per-guest vzdump staleness check *(v3.6.0)* |
| Helm release status | Surfaces release status where Helm + kubeconfig present (visibility only) *(v3.4.0)* |

## Networking, DNS & email posture

| Feature | Notes |
|---|---|
| DNS dashboard | **Admin → DNS** read/write A/AAAA/CNAME/TXT/MX/NS/SRV/CAA via provider API (Cloudflare/DigitalOcean/Hetzner/deSEC/Porkbun); reuses ACME tokens / vault / agent import; admin-only, audited, SSRF-guarded *(v4.9.0)* |
| Live resolve / dig + propagation | Authoritative-NS vs public-resolver answers; per-record propagation check *(v4.9.0)* |
| Central ACME DNS-01 creds | Server-stored provider tokens injected into `acme.sh --issue`; redacted in audit/UI *(v3.3.0)* |
| RouterOS integration | MikroTik via REST (SSRF-guarded) — DHCP lease table, firewall filter/NAT counts, routes, interfaces, wireless clients; read-only *(v4.7.0)* |
| IP reputation (DNSBL) | Mail-sending IPs vs Spamhaus/SpamCop/Barracuda/SORBS/UCEPROTECT/PSBL; `ip_blacklisted`/`ip_blacklist_cleared`; partial state on unreachable *(v4.8.0)* |
| DMARC / SPF / DKIM | Published-record grading + aggregate (RUA) report ingestion over IMAP; per-source pass/fail tallies + mailbox health *(v4.8.0)* |

## Storage & hardware

| Feature | Notes |
|---|---|
| SMART / inventory | smartctl health + pre-fail attributes → `smart_failure`; DIMMs, serials, temperatures, RAID state *(v3.4.0)* |
| Storage / RAID page | ZFS/mdadm/btrfs pool state, capacity, last-scrub; `storage_degraded`/`storage_recovered`, `scrub_overdue` *(v3.11.0)* |
| One-click maintenance | Per-pool scrub/trim/error-clear/balance/status/snapshot from a fixed server-side template; audited *(v5.0.0)* |
| GPU monitoring | **Monitoring → GPUs** NVIDIA + AMD — util/VRAM/temp/power/fan, trend sparklines, fleet summary; amdgpu sysfs fallback; thermal alerting reuses temp_high *(v4.7.0)* |
| Thermal | Hottest hosts, per-sensor expand, ~24h trend sparkline, per-host warning/critical thresholds *(v4.0.0)* |
| Power / UPS | NUT (`upsc`) / apcupsd (`apcaccess`) — status, battery %, load %, runtime, input V, watts; Power page + energy cost; `ups_on_battery`/`ups_on_line` *(v4.0.0)* |
| Disk endurance + predictive health | SSD/NVMe endurance + predictive disk health *(v4.0.0)* |
| Certificate-file + account audit | Local certificate-file inventory + local-account audit *(v4.0.0)* |

## Backups & disaster recovery

| Feature | Notes |
|---|---|
| Per-device backups | Watched-path age + fresh/stale state in the drawer *(v3.4.2)* |
| Backup orchestration | Define a backup command per device (restic/borg/rsync); on-demand or cron *(v3.6.0)* |
| Backup integrity verification | Agent runs the tool's own check (`tar -tf` / `restic check` / `borg check`); `backup_verify_failed` *(v4.10.0)* |
| Controller backup & restore | Full DR tar.gz of the data dir (incl. encrypted vault) + restore with pre-restore safety snapshot *(v3.13.0)* |
| Encrypted DR backups | AES-256-GCM at rest, key from `RP_BACKUP_PASSPHRASE` (never on disk); web-UI "Encrypt existing backups" *(v5.0.0)* |
| Backup export | One-click redacted ZIP of all data JSON |

## CMDB, credentials & documentation

| Feature | Notes |
|---|---|
| Asset metadata | Asset ID, server function, hypervisor URL, SSH port |
| Network interfaces + NAT | Multiple NICs each with optional NAT/public IP, one primary (★), live preview tree *(v5.0.0)* |
| Multi-doc attachments | Multiple titled Markdown documents per asset (≤64 KB) *(v2.0)* |
| Credentials vault | AES-GCM 256 + PBKDF2-SHA256, shared admin passphrase, audit-logged reveals; key never persisted |
| Site/group/tag-scoped credentials | Shared login at a scope, inherited by member devices; same vault; admin-only, audited *(v4.10.0)* |
| Break-glass reveals | Two-person rule for sensitive secrets; `vault_break_glass` *(v5.0.0)* |
| Credential rotation reminders | Vault entries flagged for rotation *(v3.7.0)* |
| Agentless devices | Switches/APs/printers/IPMI/cameras — same CMDB/vault/SSH-link *(v1.11.0)* |
| In-app docs | Curated documentation page with substring search *(v2.0)* |

## Authentication & access

| Feature | Notes |
|---|---|
| bcrypt + PBKDF2 | Password hashing with transparent upgrade on login; legacy unsalted hashes rejected |
| TOTP 2FA | Per-user QR setup; recovery codes *(v3.7.0)* |
| Passkeys / WebAuthn | Phishing-resistant passwordless sign-in; refuses cloned authenticator; satisfies MFA policy *(v4.2.0)* |
| OIDC SSO | External IdP; group→role mapping; first-login provisioning |
| SAML 2.0 SSO | Okta/Entra/OneLogin/Ping/ADFS; signed assertions + replay protection; attribute→role *(v4.2.0)* |
| LDAP / AD + SCIM 2.0 | Bind-mode auth; IdP-driven create/deactivate so offboarding revokes access + sessions |
| MFA enforcement | Require MFA (TOTP or passkey) per role; forced before any other action *(v4.2.0)* |
| Roles | Admin, Viewer, Auditor (read-only + audit/compliance, reveals nothing) *(v4.10.0)*, plus custom scoped roles *(v3.4.2)* |
| Granular RBAC | Custom roles granting exec/reboot/upgrade scoped to groups/tags; roster filtered to scope *(v3.4.2)* |
| API keys | Named keys (`X-Token`); default expiry window *(v4.2.0)*; per-key rate limits *(v5.0.0)*; editable, secret immutable *(v5.0.1)* |
| Enrolment tokens | One-time tokens for Ansible/cloud-init/golden images; default group+tags at enrolment *(v1.11.10)* |
| PIN enrolment | 6-digit, single-use, 10-min expiry |
| Session caps | Limit concurrent sessions per user; oldest evicted *(v4.2.0)* |
| Active session management | Review/revoke live sessions *(v4.0.0)* |
| Rate limiting | Per-IP login throttle + per-username lockout; enroll/register throttle |
| IP allowlist | Per-IP/CIDR allowlist; loopback always allowed; agent paths exempt; can't lock yourself out *(v3.3.0)* |
| Login banner | Optional security notice above the sign-in form *(v5.0.0)* |
| Read-only demo mode | Rejects all mutations for public sandboxes *(v2.0)* |

## Audit & governance

| Feature | Notes |
|---|---|
| Audit log | Every admin action with actor, IP, timestamp |
| Tamper-evident audit log | Hash-chained entries; *Verify integrity*; clear requires re-prompt + immutable pre-wipe archive *(v4.2.0)* |
| Archived audit download | Gzipped archive of evicted entries *(v4.3.0)* |
| Security-posture self-check | Graded hardening checklist, each warning links to its fix *(v4.2.0)* |
| Maintenance mode | Runtime switch pauses command dispatch during upgrades without taking the dashboard offline *(v5.0.0)* |
| Disk-space watchdog | Server monitors its own free space → `server_disk_low`/`server_disk_ok` *(v5.0.0)* |
| Webhook dead-letter queue | Exhausted deliveries land in a DLQ you can inspect + replay *(v5.0.0)* |

## Staged rollouts & posture reporting

| Feature | Notes |
|---|---|
| Staged / ring rollouts | Canary → pilot → broad upgrade/script push, verified per ring, auto/manual promote *(v3.4.2)* |
| Health-gated rollouts | Auto-halt + `rollout_halted` if a host's health drops during verify; pauses, never auto-rolls-back *(v4.10.0)* |
| Rollout rollback | One-click rollback for a staged script rollout *(v5.0.0)* |
| Fleet posture reports | One report binding patches/CVEs/health/compliance; JSON/CSV or scheduled email *(v3.4.1)* |
| Custom report builder | Pick sections (devices/health/attention/patches/CVE/SLA/compliance), JSON/CSV, download or schedule *(v4.0.0)* |
| Per-site (customer) reports | Same report scoped to one site; RBAC-scoped *(v4.10.0)* |
| SLA / uptime reporting | Per-device + per-group uptime % over 7/30/90d *(v3.4.1)* |
| Print / Save as PDF | Self-contained posture report for native print/PDF *(v3.4.2)* |
| Public status page | Standalone `status.html` (no login) via status token *(v3.4.1)* |
| Status endpoint | `/api/status` machine-readable fleet summary (status token) *(v2.4.7)* |
| iCal feed | `/api/schedule.ics` — scheduled jobs + maintenance windows, recurring as RRULEs *(v3.4.1)* |

## WG Access (WireGuard VPN) *(v5.2.0)*

| Feature | Notes |
|---|---|
| Built-in road-warrior VPN | **Admin → WG Access** — userspace wireguard-go on the server host; no kernel module |
| Tunnel | Reach scope (dashboard-only / fleet / site / group / tag, RBAC-enforced via nftables), allow-internet toggle, optional pushed DNS, optional expiry; disabled = torn down |
| Client | Browser-generated keypair (private key never sent), `.conf` + QR once; live endpoint / last-handshake / transfer; tunnel pool + throughput rollups |
| Events + AI | `vpn_client_connected` / `vpn_client_disconnected` / `vpn_handshake_stale`; feeds RAG + a Remote-access-review AI advisor |

## AI assistant & RAG *(v2.1.3)*

| Feature | Notes |
|---|---|
| LLM integration | Optional — Ollama, LocalAI, Anthropic, OpenAI, DeepSeek; pure stdlib HTTP; disabled by default; full reference [ai.md](ai.md) |
| Context-aware actions | Investigate device, explain output, find the problem (journal), diagnose service, triage CVE/TLS, prioritise patches, explain/generate/audit scripts, explain events |
| AI Investigate / mitigate | Diagnose + suggested-fix on ~21 Needs-Attention kinds; requires `exec` *(v3.4.2 / v3.8.0)* |
| On-demand AI insights | Fleet anomaly scan, cron builder, runbook + CMDB doc drafts (RAG-aware) *(v3.4.0)* |
| AI Insights hub | One-click reports/advisors — proactive briefing, RCA, NL→config, planning, advisors (firewall/DNS/email/SBOM/host one-pager) *(v4.10.0)*; TLS/CVE/top-alert *(v5.0.1)* |
| Secret redaction | Regex pre-flight strips tokens/keys/hex; privacy toggles for hostnames/IPs/journal |
| Rate limiting | Per-user daily cap + per-response token cap |
| Free-form chat | Multi-turn chat page with model picker + local history |
| Local-model support | Ollama/LocalAI — no egress, no API key; shows loaded models + VRAM |
| RAG over your fleet | Cited `<retrieved_context>` from device state, services, CVEs, containers, firewall/fail2ban, integrations, backups, DNS/email, security posture, CMDB, runbooks, commands, alerts, product docs; BM25 lexical + optional semantic (RRF); vault never indexed *(v3.4.0)* |

## MCP server *(v2.2.1)*

| Feature | Notes |
|---|---|
| MCP server | 18 tools — 14 read (`list_devices`, `get_device`, `search_devices`, `search_fleet`, `get_journal`, `get_services`, `get_containers`, `get_cves`, `get_drift`, `get_recent_commands`, `get_runbook`, `get_patches`, `get_tls`, `get_snmp_data`) |
| Guarded write tools | `reboot_device`, `run_saved_script`, `force_package_scan`, `force_acme_rescan` — per-token allow-list + roles; arbitrary `run_command` intentionally absent |

## Homelab software integrations *(v4.7.0)*

| Feature | Notes |
|---|---|
| Integration subsystem | Read-only server-side polling, folded into Alerts + dashboard; `integration_down` (auto-resolved); SSRF-guarded; admin-only URLs; **Show Homelab software** kill switch |
| 26 connectors (+ Custom HTTP) | Pi-hole v6, AdGuard Home, TrueNAS, Unraid, Kubernetes/k3s, vCenter/ESXi, Proxmox Backup Server, UniFi, Traefik, Nginx Proxy Manager, Caddy, Netdata, Grafana, Uptime Kuma, Jellyfin, Plex, Home Assistant, Nextcloud, qBittorrent, Transmission, Deluge, SABnzbd, NZBGet, Servarr (Sonarr/Radarr/Prowlarr/Lidarr), Bazarr, Overseerr/Jellyseerr |
| Custom HTTP probe plugin | Declarative — turn an endpoint's status/body/JSON field into a health signal; SSRF-guarded *(v5.1.0)* |

## Agents

| Feature | Notes |
|---|---|
| Platforms | Linux, Windows, macOS *(v4.0.0)*; macOS loadavg + fd% + Windows NVIDIA GPU parity *(v4.8.0)* |
| Self-update | SHA-256-verified, atomic replace, no SSH; hash-driven decision *(v3.3.0)* |
| Signed updates | Detached GPG signature; pinned-key agents refuse unsigned/invalid; opt-in fail-closed `require-signed-updates`; Admin → Release Signing server-side key gen/sign + distribution + refused-agent list *(v3.4.2 / v3.8.0)* |
| Integrity attestation | Reports running-binary hash each heartbeat; mismatch flagged; `integrity` subcommand; signed-agent badge *(v3.4.2)* |
| mTLS agent authentication | Agents present a CA-verified client certificate per connection, pinned per device; optional/additive, fleet-wide enforceable *(v5.0.0)* |
| Version-compatibility checks | Server flags agents whose version is too far out of step before they cause surprises *(v5.0.0)* |
| Containerized agent | Run as a container monitoring its Docker host; shared PID/net ns, host rootfs read-only; multi-arch `ghcr.io/tyxak/remotepower-agent` *(v4.7.0)* |
| Re-enrolment | Preserves history, tags, group, notes |
| Adjustable poll interval | Per-device cadence (10–3600s), applied on next heartbeat |
| Mailbox monitor | Counts files in configured directories (Maildir unread); `mailbox_threshold` *(v2.4.3)* |
| SNMP polling | Periodic SNMP read — sysDescr/uptime/contact/processors/storage + vendor (Mikrotik/Synology); `snmp_unreachable`/`snmp_recover` |

## Platform, scale & storage backend

| Feature | Notes |
|---|---|
| Architecture | nginx + fcgiwrap + stdlib Python; one HTML + CSS + vanilla-JS modules; no build step |
| SQLite backend | Optional, WAL, stdlib; row-per-entity hot data; reversible migration *(v3.12.0)* |
| PostgreSQL backend | Optional, automatic failover + read replicas *(v4.0.0)* |
| Relay satellites | For segmented networks; agent→satellite over HTTPS; internal-CA trust *(v4.0.0)* |
| Load-balanced multi-node | Horizontal scale *(v4.0.0)* |
| Self-signed CA onboarding | `make tls-selfsigned` CA + leaf; agents trust the CA (client-free renew/migration); `--ca-fingerprint` installers *(v4.5.0)* |
| Hardened persistence | flock-serialised writes, per-process tmp, fsync, rolling `.bak` fallback + recovery *(v1.12.1)* |
| GitOps | Config-from-Git *(v4.0.0)*; Terraform via REST; Ansible runner |
| Swagger / OpenAPI | OpenAPI 3.1 at `/api/openapi.json`, interactive UI at `/swagger.html` with auto-injected token |
| Turnkey install | Unified `install.sh` wizard; one-command Docker (HTTPS, no default password); served `/install` quick-install agent; `install.sh agent push` SSH bootstrap; `install.sh uninstall` *(v4.8.0)* |
| Install update | **Settings → Install** version check + guided self-update via a server-side update script *(v5.0.0)* |
| Setup checklist | Settings → Install live getting-started checklist *(v3.4.2)* |

## UX, interface & accessibility

| Feature | Notes |
|---|---|
| Industrial "New UI" | Graphite/steel default (IBM Plex Mono sidebar) + New/Old toggle, per-browser, CSP-safe *(v4.6.0)* |
| Themes | 13 palettes + Follow system + accent presets, persisted per browser |
| Composable dashboard | Resizable widget grid, 67-widget catalog, size/reorder/show-hide/reset, import/export layout *(v4.1.0)* |
| Command palette | `/` or `Ctrl/Cmd-K` fuzzy launcher — pages, devices, open alerts, vulnerable hosts, scripts, bulk actions, command history *(v3.0.2)* |
| Filter & sort everywhere | Substring filter + multi-key clickable headers; sort persists |
| Density modes | Minimal / Compact / Comfortable / Spacious, synced per user |
| Multi-select | Batch actions on cards or minimal table; selection survives density switch *(v1.12.1)* |
| Post-it widget | A per-account freeform sticky note on the dashboard (composable widget, persists in `ui_prefs`) |
| Scoped notes | Free-text notes at device (tooltip), **site** (on the site record) and **fleet-wide** (shown as a dashboard card) scope |
| Contacts directory | Internal team phonebook (name/role/company/email/phone/notes) — searchable, sortable, admin-maintained; separate from the ticket system |
| Saved Devices views | Save + share named fleet filter views via URL *(v4.0.0)* |
| Edit everywhere | Edit on every operator-managed list — alert rules, monitors, TLS/backup targets, snippets, scheduled jobs, inbound tokens, users, ignore patterns *(v3.3.0)* |
| Did-you-know tips | About page surfaces lesser-known features |
| Collapsible sidebar | Main / Security / Planning / Admin / Help groups, alphabetised; state persists |
| My Account | Account menu + page — avatar, role/permissions, 2FA, default SSH user, acknowledged alerts *(v3.12.0)* |
| Box-overflow caps | Every variable panel caps ~15 rows and scrolls internally *(v3.13.0)* |
| Branding | Favicon + header logo, full-size logo on login *(v2.0)* |
| Interface language | 5 languages (en/zh/hi/es/ar); Arabic right-to-left layout *(v4.0.0 / v5.1.0)* |
| Accessibility | Modal accessible names, styled accessible confirm/prompt *(v4.8.0)*; `scope="col"` headers, icon-button `aria-label` *(v5.0.0)* |
| Mobile UX | ≤720/≤480px touch targets, full-viewport modals, scrollable tables |

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
