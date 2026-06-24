# Features

Day-to-day fleet operations, without leaving the browser:

| | |
|---|---|
| **See what's up** | Live online/offline status, every device every 60s. Sparklines for CPU / RAM / disk. Service health matrix. Containers (Docker/Podman/k8s pods). Patches pending. Open CVEs. |
| **Run commands** | Reboot, shutdown, Wake-on-LAN, run arbitrary shell commands as root, batch any of the above across many devices. Scheduled (cron-style) and one-shot. Saved-snippets library. Long-poll endpoint for waiting on output. |
| **SSH from your browser** | Click a device, get a real interactive xterm.js terminal proxied through a hardened daemon. Sessions are recorded as asciinema replayable casts. |
| **Alert on what matters** | Disk %, memory %, swap %, CPU load — per-device and per-mount thresholds. Service down. Container stopped/restarting. Patches piling up. CVEs found. TLS expiring. Webhooks to Discord, ntfy, Slack, or anything that takes a JSON POST. |
| **CMDB built in** | Asset metadata, server function, hypervisor URL. Encrypted credentials vault (AES-GCM, shared admin passphrase, audit-logged reveals). Multiple Markdown documents per asset. SSH-link buttons. Network topology map. Agentless devices for switches / APs / printers. |
| **Site / group / tag-scoped credentials** | Define a shared login once at a **site / group / tag** level — a customer's domain admin, a site's switch password — and it's inherited by every member device. Same encrypted vault (AES-GCM, key from the request header, never stored); admin-only; audit-logged reveals (v4.10.0) |
| **CVE scanning** | Installed packages cross-checked against [OSV.dev](https://osv.dev) on a schedule. Severity-ranked findings per device with fixed-version hints, re-prioritised by **CISA KEV** (known-exploited) and **FIRST EPSS** (exploit-probability) feeds so exploited-in-the-wild CVEs rank first. Per-CVE ignore list for accepted risk — reversible from Settings → Ignored items. Ubuntu derivatives (Zorin, Mint, Pop!_OS, elementary) map to the Ubuntu ecosystem. **Supplemented by the distro's own security flag** (v5.0.0): the agent counts how many pending updates the vendor itself marks as *security* — apt's `-security` pocket, `dnf/yum --security`, or `arch-audit` on Arch — shown as a "N sec" badge on the Patches page and the device drawer, all sourced locally with no extra external feed. |
| **Auth that scales** | Local users with bcrypt + TOTP 2FA. **Passkeys** (WebAuthn) for phishing-resistant passwordless sign-in. SSO via **OIDC** or **SAML 2.0** (Okta / Entra / OneLogin / Ping / ADFS), plus LDAP/AD and SCIM. Enforce MFA per role, cap sessions, expire keys. Named API keys for automation. Enrolment tokens for cloud-init / Ansible / golden-image stamping. |
| **Find your holes** | Authorized vulnerability scanning of the hosts and websites you own (the *Pentest* page) — nuclei / nikto / nmap / OWASP ZAP / wapiti / lynis, run from a hardened scanner satellite, with domain-ownership verification and scheduling. |
| **Time-series, the homelab way** | Every device's CPU/RAM/disk recorded; sparkline for the dashboard, full-size chart on click. Prometheus `/api/metrics` endpoint for Grafana. |
| **AI assistant** | Optional LLM integration (Ollama, LocalAI, Anthropic, OpenAI, DeepSeek). Explain command output, triage CVEs and TLS expiry, prioritise patches, diagnose failed services, generate and audit shell scripts, free-form chat. Disabled by default; no external calls unless you choose a cloud provider. Regex-based secret redaction before any bytes leave the process. |
| **MCP server** | Bundled Model Context Protocol server — lets any MCP-capable AI client (Claude Desktop, etc.) query fleet state through 18 tools: 14 read tools plus 4 guarded write tools (reboot, run saved script, force package/ACME scan), gated by a per-token allow-list. |
| **Custom monitoring scripts** | Define bash health checks server-side, assign to devices, run every 5 minutes. Exit 0 = OK, anything else = FAIL. Fleet-wide results table, edge-triggered webhooks (`custom_script_fail` / `custom_script_recover`). AI-assisted script generation built into the create modal. |
| **Host configuration** | Declare desired state per device: repos, netplan, nmcli, resolv.conf, /etc/hosts, enabled services, users + SSH keys, groups, sudoers, MOTD. Agent applies on heartbeat (~60 s), reports current state every 15 min. Drift detected and `config_drift` webhook fires edge-triggered. Audit-only — never auto-remediates. |

---

**It's small.** ~67,000 lines of Python on the server. ~7,000 lines of agent. The whole web UI is one HTML file, one CSS file, and a handful of vanilla JS files — no build step, no bundler, no framework. You can read every line.

**It's lightweight.** nginx + fcgiwrap + Python. RAM footprint is dominated by nginx itself (~10 MB). Per-request cost is whatever Python imports are needed. Idle CPU usage is zero. Tested on a Raspberry Pi 4 managing 12 devices.

**It's self-hosted, properly.** No telemetry. No "cloud sync" you have to opt out of. No license server. Backs up with `tar czf /var/lib/remotepower/`. Restores by un-tarring. The whole architecture is one diagram you can hold in your head.

**But the features aren't toys.** Browser SSH with session recording. Per-mount disk thresholds with hysteresis. Atomic JSON writes with flock-protected concurrency and `.bak` fallback recovery. Encrypted credentials vault with PBKDF2-derived keys. AES-GCM. OSV-backed CVE scanning. Prometheus exposition. OpenAPI spec with interactive Swagger UI. asciinema-format session recordings. fcgiwrap + per-process unique tmp filenames + fsync-before-rename atomic writes. None of this is "we'll add it later."

If you've been bouncing between Cockpit (no fleet view), Ansible (not real-time), Tactical RMM (heavy, Windows-first), and Wazuh (security-first, not management) — give RemotePower a try.

---

The complete list. Items marked with a version number indicate when they were added.

### Fleet visibility

| Feature | Notes |
|---|---|
| **Live status** | Green/red per device, auto-refreshes every 60s, configurable per device (10–3600 s) |
| **Metrics history** | CPU/RAM/disk/swap/loadavg sparklines per device, full-size chart on click |
| **Per-mount disk** | Each non-pseudo mount tracked individually (v1.11.10) |
| **Live metrics on Monitor page** | All-fleet view of current sysinfo, color-coded by alert level (v1.12.0) |
| **Metric trend modal from Monitor** | Time-series chart per device, one click from the fleet view (v2.0) |
| **OS icons** | Auto-detected SVG glyphs: Linux, Windows, fallback. Penguin, tile, question-mark |
| **Adjustable poll interval** | Per-device heartbeat cadence from dashboard |
| **Uptime tracking** | Online/offline state changes stored per device |
| **Container awareness** | Auto-detected Docker / Podman / Kubernetes pods. Read-only — image, status, restart count, ports, namespace. Alerts on stop / restart / stale data |
| **Network map** | Manual topology graph from per-device `connected_to` links. Switches and APs as agentless devices |
| ⟳ **Pending Reboot indicator** | Amber ⟳ Reboot badge next to hostname on the Patches page when `/run/reboot-required` exists on the host (Debian/Ubuntu). Tooltip explains the source (v2.4.14) |
| **Timeline (fleet or device)** | One chronological stream (**Monitoring → Timeline**): fleet events + command runs merged newest-first, filterable. Scope selector does whole-fleet (rows tagged by device) or a single host. `GET /api/fleet/timeline`, `GET /api/devices/<id>/timeline` (v3.4.1) |
| **Fleet health score** | A single 0–100 score per device and across the fleet on the home dashboard, weighted from the Needs Attention signals; worst devices link into their timelines. `GET /api/fleet/health` (v3.4.1) |
| **Risk scoring** | A dedicated **Risk** page scores each asset 0–100 from its CVEs, world-exposure, software-policy violations, certificate/lifecycle expiry and mount health, with a per-point breakdown so you can see *why* a host scores the way it does. `GET /api/risk` |
| **Tasks** | An operational checklist page for tracking fleet work items alongside the live signals. `data-page="tasks"` |
| **Health-score history & alerts** | Daily score samples with a home-panel trend sparkline (`GET /api/fleet/health/history`), plus an opt-in threshold that fires the edge-triggered `health_degraded` / `health_recovered` events (v3.4.1) |
| **CVE ↔ patch cross-link** | The Patches page shows per device how many critical/high CVEs a pending patch would fix (`cve_fixable`), linking to the device's CVE list (v3.4.1) |
| **Software inventory search** | "Which hosts run openssl < X" over the collected package inventory — name + ecosystem-aware version compare. `GET /api/inventory/search` (v3.4.1) |
| **End-of-life OS detection** | Built-in vendor-EOL table flags out-of-support hosts in Needs Attention (lowering the health score) and as a PCI/HIPAA/SOC 2 compliance control (v3.4.1) |
| **Prometheus health metrics** | `/api/metrics` exports fleet + per-device health score, needs-attention counts, 24h event counts by kind, and CVE-fixable total (v3.4.1) |
| **iCal feed** | `GET /api/schedule.ics?token=<status token>` — scheduled jobs + maintenance windows as a calendar subscription, recurring jobs as RRULEs (v3.4.1) |
| **Quiet hours** | Hold non-critical webhook/email delivery during a daily window (may cross midnight); events still recorded, critical always pages (v3.4.1) |
| **SLA / uptime reporting** | Per-device + per-group uptime % over 7/30/90 days from the uptime log, on the Reports page. `GET /api/fleet/sla` (v3.4.1) |
| **Capacity dashboard** | Fleet-wide CPU/mem/disk rollup (avg, peak, total disk, top consumers) on the Reports page. `GET /api/fleet/capacity` (v3.4.1) |
| **Public status page** | Standalone `status.html` (no login) — fleet health + monitor up/down via `GET /api/public/status?token=<status token>` (v3.4.1) |
| **PagerDuty / Opsgenie** | On-call notification destinations: PagerDuty Events API v2 (trigger + auto-resolve) and Opsgenie Alerts API v2 (v3.4.1) |
| **Automation rules engine** | When an event (at a severity) fires on matching devices → run a saved script and/or notify a destination; per-rule cooldown, admin-only, audited. `GET/POST /api/automation/rules` (v3.4.2) |
| **Device dependency map** | Declare device→upstream dependencies on the Network Map; downstream alerts are held while an upstream is offline (delivery-only, recoveries never held). `PUT /api/devices/<id>/depends-on` (v3.4.2) |
| **Statistical resource anomalies** | Model-free per-host mean/stdev baselines over metric history flag sharp memory/swap/disk deviations (≥2.5σ). `GET /api/fleet/anomalies` (v3.4.2) |
| **Agent integrity attestation** | Agents report their running binary hash each heartbeat; server flags a mismatch vs the canonical build (tamper/corruption) as a critical NA item. `GET /api/fleet/agent-integrity` (v3.4.2) |
| **Cryptographic release signing** | Detached GPG signature over the agent release (`tools/sign-agent-release.sh`); agents with a pinned public key refuse unsigned/invalid self-updates. Opt-in, fail-closed, `gpg`-based (v3.4.2) |
| **Agent audit (read-only) mode** | Touch `/etc/remotepower/audit-mode` and the agent becomes observe-only — it keeps collecting and reporting (read-only lynis/OpenSCAP/CVE assessments still run) but **refuses every command** (exec/scripts, reboot/shutdown, config apply, self-update). The flag is operator-owned so the server can't clear it; the server also refuses to queue actions for the host, which shows an **AUDIT** badge. Linux / Windows / macOS (v4.10.0) |
| **Bake & sign UI** | Admin → Release Signing: server-held key generate/sign/toggle + public-key distribution + a list of agents that refused an unsigned update. Convenient (server-side) mode (v3.4.2) |
| **Patch catalog** | Pending updates aggregated by package ("package X on N hosts") on the Patches page. `GET /api/patch-catalog` (v3.4.2) |
| **Post-deploy verification** | After an upgrade, confirm the pending count actually dropped (ok/stalled/pending) on the Patches table (v3.4.2) |
| **Software metering** | Named-software install counts vs an allowance, over-deployment flagged. Reports page. `GET /api/inventory/metering` (v3.4.2) |
| **Fleet heat map** | Home grid of device cells coloured by health score (v3.4.2) |
| **After-hours detection** | Flag selected events firing outside business hours as a NA item (Settings → Dashboard) (v3.4.2) |
| **Ad-hoc fleet query** | Fleet → Query: filter by group/tag/OS/online/pending/integrity/CVE, with saved queries. `GET /api/fleet/query` (v3.4.2) |
| **Signed-agent badge** | Green ✓ / red ⚠ next to a device's version showing whether it runs the canonical signed build (v3.4.2) |
| **Staged / ring rollouts** | Planning → Rollouts: push an upgrade/script canary → pilot → broad, verified per ring, auto- or manual-promote. `GET/POST /api/rollouts` (v3.4.2) |
| **Maintenance change-windows** | A maintenance window can gate command/upgrade execution (held until the window is active), not just suppress alerts (v3.4.2) |
| **CIS-style compliance baseline** | Compliance page: pass/fail checks (patches/reboot/units/disk/CVE/integrity), severity-weighted score + daily trend. `GET /api/compliance/baseline` (v3.4.2) |
| **Metering normalization + reclamation** | Meter aliases map name variants onto one entry; flags installs not seen running as reclaimable (v3.4.2) |
| **Print / Save as PDF** | Reports page: clean self-contained posture report for the browser's native print/PDF, zero dependency (v3.4.2) |
| **Granular RBAC** | Users & Roles: custom roles granting exec/reboot/upgrade scoped to device groups/tags; roster filtered to scope. `GET/POST /api/roles` (v3.4.2) |
| **OpenSCAP scans** | Compliance page: agent runs `oscap xccdf eval` — CIS/STIG/PCI-DSS on the SSG, plus Ubuntu Security Guide (USG) for CIS/STIG on Ubuntu and ANSSI BP-028 profiles on Debian/Ubuntu — reports score + failing rules. Download the full HTML report (`GET /api/scap/<id>/report`). Survives an agent self-update. Requires `upgrade`. `POST /api/scap/scan`, `GET /api/scap` (v3.4.2) |
| **AI Investigate / mitigate** | One-click diagnose + suggested-fix on a Needs-Attention item — playbooks for disk, memory, swap, cpu, patches, drift, service_down, reboot, brute_force, **cve** and **container** (v3.4.2); broadened in v3.8.0 to malware/AV posture, stale agent version, end-of-life OS, hardware health, stale/missing backup, new SSH key, new listening port, agent integrity, log-pattern alerts, and **failed systemd units** (~21 kinds total). Requires `exec` on an in-scope device. `POST /api/mitigate/<id>/investigate` + `/fix` |
| **Command Queue** | Admin → Command Queue: view every device's pending queued commands (incl. offline hosts) and cancel them; ACME certificate actions are logged to the recently-dispatched view, with **Clear all pending** and **Clear log** controls (v3.9.0). `GET /api/command-queue`, `DELETE /api/devices/<id>/command-queue` (v3.4.2) |
| **Per-device backups** | A Backups section in the device drawer shows each watched backup path's age + fresh/stale state. `GET /api/devices/<id>/backups` (v3.4.2) |
| **Container health detail** | Per-device container list shows each container's health badge (healthy/unhealthy/starting), live CPU%/memory, and published ports (v3.4.2) |
| **SMART / inventory detail** | SMART table adds drive serial + CRC/Uncorrectable counts; Helm releases list app version + last-updated; memory/RAID inventory adds DIMM manufacturer/serial and RAID member block devices (v3.4.2) |
| **CVE in timeline** | Current critical/high (non-ignored) findings surface as a synthetic per-device `cve` row, so a re-scan of known CVEs still shows (v3.4.2) |
| **Third-party patching** | Agent reports flatpak/snap/pip/npm updates; patch catalog aggregates them by manager (v3.4.2) |
| **On-call & escalation** | Settings → Notifications: escalation tiers re-notify unacked alerts; on-call rotation names the contact. `GET /api/oncall` (v3.4.2) |
| **Trends charts** | Planning → Trends: zero-dep multi-series SVG — fleet health, compliance %, per-device resources (memory / swap / busiest-mount disk, plus **CPU load saturation %** since v3.9.0). `GET /api/devices/<id>/metrics-history` (v3.4.2) |
| **Install software** | Patches page: install repo packages on a host or whole tag/group (apt/dnf/yum/zypper/pacman/apk). `POST /api/install` (v3.4.2) |
| **OpenSCAP by tag/group** | Scan form targets all / group / tag / device; profile is the parameter (v3.4.2) |
| **Setup checklist** | Settings → Install: live getting-started checklist. `GET /api/setup-status` (v3.4.2) |
| **Expanded Fleet Query** | + version, pkg-manager, has-package, monitored/agentless/quarantined, reboot, failed units, disk/mem %, offline-days (v3.4.2) |
| **Fleet posture reports** | One report binding patches, CVEs, health score, and compliance (**Planning → Reports**): JSON/CSV download or scheduled email. `GET /api/report/fleet`, `PUT /api/report/schedule` (v3.4.1) |
| **Per-site (customer) reports** | The same posture report scoped to one **site** — devices, patches, SLA, CVEs and health for that customer. "Report" button per site; `GET /api/report/site/{id}` (JSON/CSV), RBAC-scoped (v4.10.0) |
| **Backup integrity verification** | Beyond freshness: the agent runs the backup tool's **own check** (`tar -tf` / `restic check` / `borg check`), rate-gated + time-bounded; a failed check fires `backup_verify_failed`. Status in the device drawer (v4.10.0) |
| **Health-gated rollouts** | Opt-in canary safety net: auto-halt a staged rollout (and fire `rollout_halted`) if a dispatched host's health score drops below a floor during the verify window. Pauses for you to resume/cancel — never auto-rolls-back (v4.10.0) |
| **Access — recent logins (drawer)** | The device drawer lists who logged in and from which distinct source IPs (`auth.recent_logins`) — the data the `login_new_source` alert fires off (v3.13.0) |
| **Scheduled jobs / timers (drawer)** | Failed-first table of every systemd timer per device — unit, what it activates, current state (v3.13.0) |
| **Per-host storage / RAID (drawer)** | This host's own ZFS / mdadm / btrfs pools and arrays (state, capacity, scrub) in the drawer, not just on the fleet Storage page (v3.13.0) |
| **Port bind address + scope (drawer)** | The listening-ports card shows each socket's bind address and a world / LAN / local badge, matching the Exposure page (v3.13.0) |
| **Firewall ruleset fingerprint (drawer)** | The firewall card shows the active backend, rule count and fingerprint — the drift baseline the `firewall_changed` alert compares against (v3.13.0) |
| **Brute-force lockout badge** | Active brute-force sources show as a badge on the device card; Disk/Swap pressure pills added to the drawer (v3.13.0) |
| **Named drift profiles** | Reusable named sets of watched config files, created/edited/deleted on the Drift page and assigned to a device / tag / group; precedence device-override > profile (device > tag > group) > global default; drift detail explains which rule won. `GET/POST /api/drift/profiles`, `POST /api/drift/assign` (v3.13.0) |
| **Network-mount trends** | NFS/SMB/CIFS shares flow into the daily metrics history — each filesystem gets its own line on the Trends chart and disk-fill forecasting (v3.13.0) |
| **Controller backup & restore** | Full disaster-recovery backup (tar.gz of the whole data dir incl. the encrypted vault) and restore (with an automatic pre-restore safety snapshot + strict path validation), alongside the existing redacted ZIP export. `GET /api/backup/download`, `POST /api/backup/restore` (v3.13.0) |
| **Fleet host-config collect & export** | Drift page: "Collect all host configs" fans the agent re-collect command across the fleet; "Export all host configs" downloads one JSON bundle of every device's desired + current config and drift. `POST /api/host-config/collect-all`, `GET /api/host-config/export` (v3.13.0) |
| **Software center** | Browse every installed package across the fleet with versions + host counts; click a row to see which hosts run which version. `GET /api/inventory/catalog` (v3.13.0) |
| **Targeted AI buttons** | One-click context-scoped AI on exposed services, filling disks, failing compliance controls, config drift, failed units, unhealthy containers, packages, plus an "Ask about my fleet" omnibox on Home (v3.13.0) |

### Custom monitoring scripts *(v2.5.0)*

| Feature | Notes |
|---|---|
| **Script library** | Admin-defined bash scripts stored server-side in `custom_scripts.json`. Up to 50 fleet-wide, 10 per device |
| **Per-device assignment** | Each script is assigned to a set of devices. Assignments are pushed via heartbeat — no SSH needed |
| **5-minute cadence** | Agent runs all assigned scripts every 5 polls (~5 min at default 60 s). First poll after assignment is skipped; results start from poll 2 |
| **Binary exit code** | Exit 0 = OK, anything else = FAIL. No MRPE severity levels — deliberately simple |
| **Fleet results page** | Custom Scripts page shows all device × script results: status badge, last output snippet (click for full 4 KB), timestamp, duration |
| **Edge-triggered alerts** | `custom_script_fail` fires once on OK→FAIL transition (includes first output line). `custom_script_recover` fires once on FAIL→OK. Never re-fires on every failing run |
| **AI generation** | Inline in the create modal: describe the check in plain English, click Generate, review and save. Uses the existing AI assistant configuration |
| **Secure execution** | Script written to temp file (chmod 700), executed by `/bin/bash`, deleted after run. 30 s timeout. stdout+stderr merged, capped at 4 KB |

### Commands & automation

| Feature | Notes |
|---|---|
| **Reboot / shutdown** | Queue actions, reported success on next heartbeat |
| **Wake-on-LAN** | Magic packet from dashboard, unicast over VPN/routed networks |
| **Custom commands** | Run arbitrary shell as root; output returned via heartbeat. 64 KB cap |
| **Command library** | Saved named snippets, pick from dropdown |
| **Per-device allowlist** | Whitelist of allowed exec commands per device |
| **Scheduled commands** | One-shot (datetime) or recurring (cron) |
| **Maintenance windows** | Suppress webhook alerts during scheduled windows. Per-device, per-group, or fleet-global. Audit trail of suppressed events |
| **Update history** | Rolling 10-run buffer of `apt`/`dnf`/`pacman` output per device with timestamps, exit codes, durations |
| **Long-poll exec** | `/api/exec/wait` holds connection open until output arrives — useful for synchronous CI |
| **Web terminal** | Real xterm.js SSH terminal in the browser, proxied through a hardened daemon. asciinema v2 session recordings (output-only by default; opt-in keystroke capture) (v1.11.11) |

### Alerts & monitoring

| Feature | Notes |
|---|---|
| **Ping / TCP / HTTP probes** | ICMP, TCP port, HTTP HEAD checks from the server. Configurable schedule (v1.11.8: runs even when dashboard is closed). HTTP targets are SSRF-guarded with a connect-time peer recheck (v3.9.0) — RFC1918 LAN allowed, cloud-metadata/link-local always blocked |
| **Monitor history** | Uptime %, sparkline, last 50 results per target |
| **Metric alerts** | Disk / memory / swap / CPU load thresholds with hysteresis (v1.11.10) |
| **Per-device thresholds** | Override fleet defaults per device, plus per-mount disk overrides (v1.12.0 UI) |
| **Service monitoring** | Agent watches systemd units; matrix view; webhooks on transitions. Shows the canonical unit an alias resolved to (e.g. `mysql.service`→`mariadb.service`) since v3.9.0 |
| **Log tail + alerts** | Agent submits journalctl per watched unit; rolling 6-hour buffer with regex search; pattern-match alerts |
| **Webhooks** | Generic JSON, Discord, ntfy, Slack, Gotify. Auto-format detection. 82 event types, per-event toggles, test-event button |
| **CVE scanner** | OSV.dev-backed; severity-ranked findings per device; ignore list for accepted risk |
| **TLS / DNS expiry** | Server-side probes against a watchlist; alerts via existing webhooks |
| **Patch alerts** | Webhook when pending updates exceed configurable threshold |

### CMDB & documentation

| Feature | Notes |
|---|---|
| **Asset metadata** | Asset ID, server function, hypervisor URL, SSH port |
| **Multi-doc attachments** | Multiple titled Markdown documents per asset (v2.0) |
| **Credentials vault** | AES-GCM + PBKDF2-SHA256, shared admin passphrase, audit-logged reveals |
| **SSH-link buttons** | Per-credential `ssh://user@host:port` link + Copy button |
| **Agentless devices** | Manual records for switches, APs, printers, IPMI, cameras — same CMDB / vault / SSH-link as agented devices |
| **In-app docs** | Curated documentation page in the dashboard with substring search across all topics (v2.0) |

### Authentication & access

| Feature | Notes |
|---|---|
| **bcrypt** | Password hashing with transparent SHA-256 upgrade on login |
| **TOTP 2FA** | Per-user, scan-QR setup; required to disable |
| **Passkeys / WebAuthn** *(v4.2)* | Phishing-resistant, passwordless sign-in with a security key, phone or biometrics; refuses a cloned authenticator (sign-count regression); satisfies the MFA-required policy. Add under *My Account → Passkeys*. Optional `webauthn` dependency |
| **OIDC SSO** | Sign in via an external OpenID Connect IdP; group → role mapping; first-login provisioning |
| **SAML 2.0 SSO** *(v4.2)* | Enterprise IdP login (Okta / Entra / OneLogin / Ping / ADFS); SP metadata published, signed-assertion verification with replay protection, attribute → username + group → role mapping. Optional `pysaml2` + `xmlsec1` |
| **LDAP / AD** | Optional bind-mode auth; auto-creates local user record |
| **SCIM 2.0** | IdP-driven user create/deactivate so offboarding revokes access + live sessions |
| **MFA enforcement** *(v4.2)* | Require MFA (TOTP **or** a passkey) for chosen roles; enrolment is forced before any other action |
| **Roles** | Admin (full access), Viewer (read-only dashboard), and **Auditor** (read-only + audit log / hash-chain verify / evidence pack / security posture / compliance, runs nothing, never reveals a secret) per user, plus custom scoped roles (v4.10.0) |
| **PIN enrolment** | 6-digit, single-use, 10-minute expiry |
| **API enrolment tokens** | One-time-use tokens for Ansible / cloud-init / golden images. Default group + tags applied at enrolment (v1.11.10) |
| **API keys** | Named keys for scripts and CI; **default expiry window** for new keys (v4.2) |
| **Session caps** *(v4.2)* | Limit concurrent sessions per user; oldest evicted past the cap |
| **Tamper-evident audit log** *(v4.2)* | Hash-chained entries; one-click *Verify integrity*; clearing requires an admin re-prompt + writes an immutable pre-wipe archive |
| **Security-posture self-check** *(v4.2)* | Graded hardening checklist on the Audit page (MFA enforced, admins with MFA, session cap, key expiry, …) |
| **Rate limiting** | Per-IP login throttle, prevents brute force |
| **Read-only demo mode** | Config flag rejects all mutations with a friendly error. For public sandboxes (v2.0) |

### Security scanning *(v4.2)*

| Feature | Notes |
|---|---|
| **Authorized vulnerability scanning** | The *Pentest* page (under Monitoring) scans the hosts and websites you own with industry tools, orchestrated, scheduled and collected in one place — white-hat only |
| **Authorization-gated targets** | Enrolled hosts (target IP derived server-side from the device record), or non-enrolled **domains you prove you own** via an ACME-style **DNS TXT** record or **`.well-known`** file; private/loopback ranges refused |
| **Passive profile** | Safe to run any time: **nuclei**, **nikto**, **nmap** |
| **Active profile** | Intrusive: **OWASP ZAP**, **wapiti** — gated behind an explicit authorization **attestation** and, for enrolled hosts, a maintenance window (or recorded override); both audited |
| **On-host audit** | **lynis** system-hardening audit run through the agent (read-only) |
| **Scanner satellites** | The toolchain runs on a hardened relay node, not on scanned hosts — no production footprint, realistic external vantage; pin a scan to a specific satellite (e.g. one per segment) |
| **Scheduled scans** | Cron-style cadence; recurring findings can notify a channel. Per-scan quick/full **intensity** and a **vhost** field for name-based virtual hosts |

### Operational quality

| Feature | Notes |
|---|---|
| **Agent self-update** | SHA-256 verified, atomic replace, no SSH needed |
| **Agent integrity** | `integrity` subcommand compares binary SHA-256 vs server |
| **Re-enrolment** | Preserves device history, tags, group, and notes |
| **Backup export** | One-click ZIP of all data JSON files |
| **Hardened persistence** | flock-serialised writes, per-process unique tmp, fsync, rolling .bak fallback (v1.12.1). Recovery script for damaged files |
| **Audit log** | Every admin action logged with actor, IP, timestamp |
| **Prometheus metrics** | `/api/metrics` endpoint for Grafana scraping |
| **Digest endpoint** | `/api/digest` for cron-driven email summaries |
| **Swagger / OpenAPI** | OpenAPI 3.1 spec at `/api/openapi.json`, interactive UI at `/swagger.html` with auto-injected session token |

### UX

| Feature | Notes |
|---|---|
| **Themes** | 13 named palettes (Midnight, Tokyo Night, Catppuccin, Dracula, Nord, Gruvbox, Rosé Pine, Oceanic, Solarized Dark, Daylight, Paper, Solarized Light, Nord Light) plus *Follow system* and accent presets; switched in the header, persisted per browser |
| **Tags & groups** | Tag devices and namespace by group (e.g. `dc1/prod`, `homelab`); filter and batch by either |
| **Device notes** | Free-text per device, shown as tooltip |
| **Filter & sort everywhere** | Substring filter + clickable headers on every fleet table; multi-key sort with Shift-click |
| **Density modes** | Minimal (table), Compact, Comfortable, Spacious — synced per user |
| **Multi-select** | Batch actions on cards or minimal table; selection survives density switching (v1.12.1) |
| **Collapsible sidebar** | Main / Security / Planning / Admin / Help groups; state persists per browser (v2.0) |
| **Real branding** | Favicon + header logo, clickable logo returns home, full-size logo on login (v2.0) |

### AI assistant *(v2.1.3)*

| Feature | Notes |
|---|---|
| **LLM integration** | Optional. Five providers: Ollama, LocalAI, Anthropic (Claude), OpenAI, DeepSeek. Pure stdlib HTTP — no pip deps (v2.1.3) |
| **Context-aware buttons** | Investigate device, Explain command output, Find the problem (journal), Diagnose service, Triage CVE, Triage TLS, Prioritise patches, Explain/Generate/Audit scripts, Explain webhook events (v2.1.3–v2.1.5) |
| **Secret redaction** | Regex-based pre-flight strips bearer tokens, AWS keys, long hex strings before any request leaves the process. Privacy toggles for hostnames, IPs, journal content |
| **Rate limiting** | Per-user daily request cap + per-response max-token cap, both configurable in Settings |
| **Free-form chat** | Multi-turn chat page (Help → AI Assistant) with model picker and local conversation history |
| **Local-model support** | Ollama and LocalAI providers — no external egress, no API key. Shows loaded models and VRAM use |

Full reference: **[ai.md](ai.md)**.

### MCP server *(v2.2.1)*

| Feature | Notes |
|---|---|
| **MCP server** | Model Context Protocol server, 18 tools. 14 read tools: `list_devices`, `get_device`, `search_devices`, `search_fleet`, `get_journal`, `get_services`, `get_containers`, `get_cves`, `get_drift`, `get_recent_commands`, `get_runbook`, `get_patches`, `get_tls`, `get_snmp_data` |
| **Guarded write tools** | The 4 write tools (`reboot_device`, `run_saved_script`, `force_package_scan`, `force_acme_rescan`) require a server-side allow-list and per-token roles; arbitrary `run_command` is intentionally absent — scripts must be pre-saved in the library. |


---

### Container awareness *(v1.11.0, alerts in v1.11.4)*
Every agent v1.11.0+ detects Docker, Podman, and kubectl-accessible Kubernetes pods on its host and posts a normalised list to the server every ~5 minutes. The Containers tab in the sidebar shows fleet-wide status; per-device drill-down shows image, tag, ports, restart count, and namespace. Read-only — RemotePower surfaces what's running, doesn't manage it.

**v1.11.4** adds three webhook events: `container_stopped` (running container vanished or transitioned to exited), `container_restarting` (restart count climbed since last report — as of v3.10.0 the agent reports a real restart count for Docker/Podman too, via a batched `docker inspect`, so this fires fleet-wide rather than only for Kubernetes pods), and `containers_stale` (no fresh report within `container_stale_ttl`, default 15 min). Stale rows in the UI now get an amber `STALE` pill so old data is impossible to mistake for current data. Reference: **[containers.md](containers.md)**.

**Image updates (v3.3.4, one-click update v3.9.0).** The server compares each container's pulled image digest against the registry's current digest for that tag and flags stale images on the **Image Updates** page (notify-only — deduped across the fleet, one registry call per unique image). v3.9.0 adds a one-click **Update** button on stale, compose-managed rows that runs `docker compose pull` + `up -d` on the affected host to fetch the new image and recreate the container; the agent captures each container's compose working directory, recovers the real image name when `docker ps` shows a bare untagged ID (e.g. just after a pull), and the rows show the container name so they stay identifiable.

### Network map *(v1.11.0)*
Set `connected_to` on each device (Edit links button on the Network page) to record what plugs into what. The map renders nodes coloured by online/offline status and outlined by agent vs. agentless. Manual topology only — no auto-discovery. Reference: **[network-map.md](network-map.md)**.

### Agentless devices *(v1.11.0)*
"+ Agentless device" on the Devices toolbar adds a record for things that can't run the agent — switches, APs, printers, IPMI cards, cameras, smart plugs. Same CMDB metadata, vault credentials, SSH link as agented devices. Status is whatever you set it to. Reference: **[agentless-devices.md](agentless-devices.md)**.

### TLS / DNS expiry monitor *(v1.11.0)*
Add hostnames to the TLS / DNS page. The server runs a probe via `cgi-bin/remotepower-tls-check` (cron, every 6 hours suggested) or "Scan now" from the page. Default thresholds: warn at 14 days, critical at 3 days. Stdlib-only — no extra dependencies. Reference: **[tls-monitor.md](tls-monitor.md)**.

### API documentation (Swagger)
Click **API Docs** in the sidebar to open `/swagger.html` — Swagger UI rendering the OpenAPI 3.1 spec for every public endpoint. The page auto-injects your existing session token, so "Try it out" works without an Authorize step. The raw spec is at `/api/openapi.json`. Reference: **[swagger.md](swagger.md)**.

### SSH from credentials
Set the per-asset SSH port on the CMDB asset modal (Properties tab). Each credential row in the Credentials tab gets an SSH button that opens `ssh://user@host:port` in your default handler, plus a Copy button for the equivalent `ssh user@host -p port` command. Passwords are deliberately not in the URI.

### Update history
The device dropdown menu has an "Update history" link that opens the rolling buffer of the last 10 package-upgrade runs on that device — full output, exit codes, timestamps. Output is captured automatically on the next heartbeat after a run completes (~60s). Reference: **[update-history.md](update-history.md)**.

### CMDB & credential vault
The **CMDB** tab gives every enrolled device an asset record: free-text asset ID, server function (web, db, dc…) with autocomplete, optional hypervisor URL, and Markdown documentation up to 64 KB. Underneath that sits an opt-in encrypted credential vault: AES-GCM 256-bit, PBKDF2-SHA256 key derivation, shared admin passphrase, audit-logged reveals.

Setup is a one-time **Set up vault** click on the CMDB page. The passphrase is never persisted server-side — the derived key lives in the browser tab and clears on logout or page reload.

Full reference, threat model, API examples, and backup story: **[cmdb.md](cmdb.md)**.

### Device Groups
Assign a namespace to a device via the group button () on the device card. Groups like `dc1/prod`, `homelab`, `office` cause the device grid to sort and visually group by namespace. Batch commands (`device_ids`, `tag`, or `group` field) can target an entire group at once.

### Device Notes
Click the button on any device card to add free-text notes. Notes are shown as a tooltip on the device name. Useful for documenting quirks: "NAS in basement - WoL unreliable", "kids' PC - check before rebooting".

### Batch Commands
Click the device icon (top-left of a card) to select it - it turns into a checkmark. A batch action bar appears above the grid with Shut down all / Reboot all / Update all. The API also accepts `tag:` or `group:` targets directly:

```bash
curl -X POST https://your-server/api/reboot \
 -H "X-Token: YOUR_TOKEN" \
 -H "Content-Type: application/json" \
 -d '{"tag": "servers"}'
```

### Recurring Scheduled Commands
In the Schedule tab, leave the datetime blank and fill in a cron expression instead:

| Cron | Meaning |
|------|---------|
| `0 3 * * 0` | Every Sunday at 03:00 |
| `0 2 * * 1-5` | Mon–Fri at 02:00 |
| `*/30 * * * *` | Every 30 minutes |

One-shot jobs are removed after firing. Recurring jobs stay.

### Command Library
Save frequently-used commands in the Library page. When you open the exec modal (>_ button on a device card), a dropdown lets you pick from your saved snippets - no retyping.

### Command Allowlist
For higher-security devices, lock down which commands can be run via exec. Click the button on a device card, enter one command per line. When the list is non-empty, only those exact commands are accepted; all others return 403.

### Metrics (CPU / RAM / Disk)
Install `psutil` on client machines for automatic metrics collection:

```bash
pip install psutil --break-system-packages
sudo systemctl restart remotepower-agent
```

The server stores up to 1440 snapshots (~24 h at 60 s intervals) in `metrics.json`. Click the button on a device card to see sparkline charts.

### Adjustable Poll Interval
Click the button on a device card to change how often the agent checks in (10–3600 s). The new interval is queued as a `poll_interval:<n>` command and applied on the agent's next heartbeat - no restart needed.

### API Keys
Go to API Keys (nav) and create a named key. Keys are non-expiring and use the same `X-Token` header as session tokens. Assign `admin` for full access or `viewer` for read-only. Use them in scripts:

```bash
curl https://your-server/api/digest \
 -H "X-Token: YOUR_API_KEY"
```

Keys are shown once at creation. Store them in your secrets manager.

### Re-enrollment
When re-enrolling a device (e.g. after reinstalling the OS), use `re-enroll` instead of `enroll` to preserve the device's existing history, tags, group, and notes:

```bash
sudo remotepower-agent re-enroll
```

### Agent Integrity Check
Verify the running agent binary matches the server's known-good hash:

```bash
sudo remotepower-agent integrity
# OK - ok
# or: MISMATCH: local=abc123… server=def456…
```

Exit code 0 = OK, 1 = mismatch. Wire into a daily cron with a webhook alert if needed.

### Backup Export
Settings → Export backup downloads a ZIP of all data JSON files (excluding session tokens). Or via API:

```bash
curl https://your-server/api/export \
 -H "X-Token: YOUR_TOKEN" -o remotepower-backup.zip
```

### Digest for Email / Cron
```bash
# Add to cron for a daily status email
curl -s https://your-server/api/digest \
 -H "X-Token: YOUR_API_KEY" | jq .
```

Returns: `total`, `online`, `offline`, `pending_patches`, `recent_commands`.

### Long-Poll Exec
For near-interactive command output (instead of waiting 60 s for the next heartbeat):

```bash
curl -X POST https://your-server/api/exec/wait \
 -H "X-Token: YOUR_TOKEN" \
 -H "Content-Type: application/json" \
 -d '{"device_id": "DEVICE_ID", "cmd": "df -h", "timeout": 90}'
```

The connection stays open until the agent delivers the output (up to `timeout` seconds). On timeout, falls back to a `timeout: true` response; poll `/api/devices/:id/output` for the result.

### Wake-on-LAN
MAC is reported at enroll time. Sends unicast to the device's last known IP - works over routed networks and VPNs without broadcast forwarding.

### Offline Webhook Events

```json
{ "event": "device_offline", "name": "mypc", "last_seen": 1712345678 }
{ "event": "device_online", "name": "mypc" }
{ "event": "patch_alert", "name": "mypc", "upgradable": 15, "threshold": 10 }
{ "event": "command_queued", "name": "mypc", "command": "reboot", "actor": "admin" }
{ "event": "command_executed", "name": "mypc", "command": "exec:df -h" }
```

Compatible with Ntfy, Gotify, Slack, Discord, n8n, Home Assistant.

---

## Added in 2.2.x – 2.6.x

The features below were added across the 2.2 – 2.6 release series.
Full per-release notes — including the bug-fix releases not listed
here — are in [`CHANGELOG.md`](../CHANGELOG.md).

### Host configuration management *(v2.6.0)*
Declare the desired state of each host server-side across ten sections:
package repos, netplan, NetworkManager (nmcli), resolv.conf, /etc/hosts,
enabled systemd services, local users + SSH authorized_keys, groups,
sudoers rules, and the MOTD banner.
The agent applies changes on the next heartbeat (~60 s) and reports
current state every 15 minutes for drift detection. Drift fires a
`config_drift` webhook edge-triggered (once on first divergence, not
every heartbeat). Audit-only — the agent never auto-remediates.
Reference: **[host-config.md](host-config.md)**.

### Custom monitoring scripts *(v2.5.0)*
Define bash health checks server-side and assign them to devices.
The agent runs each check every 5 minutes; exit 0 = OK, anything
else = FAIL. Fleet-wide results on the Custom Scripts page, plus
edge-triggered `custom_script_fail` / `custom_script_recover`
webhook events. Inline AI generation in the create modal. No agent
update required to start using the feature — scripts are pushed
via the existing heartbeat channel. Reference:
**[custom-scripts.md](custom-scripts.md)**.

### Pending Reboot indicator on Patches page *(v2.4.14)*
When a Debian/Ubuntu host has a pending-reboot marker
(`/run/reboot-required`) the agent reports `reboot_required: true`
in its heartbeat. The Patches page now surfaces this as a small amber
**⟳ Reboot** badge inline with the hostname so you can see at a
glance which patched hosts still need a restart — without opening
each device individually. The badge shows a tooltip identifying the
source file. No agent change is required; the flag has been in the
heartbeat since v1.x. The patch-report API (`/api/patch-report`) also
exposes the field for external consumers.

### Configuration drift detection *(v2.2.0)*
RemotePower hashes a watch-list of critical config files on every
host — `sshd_config`, `sudoers`, and similar — and flags any change
against an accepted baseline. View a diff, accept a new baseline, or
mark an expected difference as ignored (per-file) so it stops raising
a red status. Watched-file lists are pushed to the agent in the
heartbeat. Drifted files surface on the dashboard and in the fleet
event log.

### MCP server *(v2.2.1)*
RemotePower ships an MCP (Model Context Protocol) server, letting an
MCP-capable AI client query fleet state through defined tools. Read
-oriented in this release.

### Dedicated fleet event log *(v2.2.7)*
A fleet-wide activity log — enrolments, commands, drift, Proxmox
actions, alert state changes — separate from per-device command
history.

### Proxmox virtualization *(v2.3.0)*
Connect one Proxmox VE node (Settings → Proxmox; uses a scoped API
token). The Virtualization page lists the node's QEMU virtual
machines with start / shutdown actions. Server-to-API — no agent runs
on the Proxmox node. Configure with a scoped token, not a
full-access one.

### Salted password hashing *(v2.3.2)*
Passwords are stored with PBKDF2 (600k iterations, per-user salt),
replacing the legacy unsalted-SHA-256 fallback. A default-password
warning banner prompts a change on first login. See
`docs/security.md`.

### Proxmox LXC containers *(v2.3.0)* and snapshots *(v2.4.0)*
LXC containers on the Proxmox node appear on the Containers page with
the same start / shutdown actions. Every Proxmox guest — QEMU and LXC
— has a Snapshots panel: create, list, roll back, and delete
snapshots. Rollback is destructive and requires typing the guest name
to confirm; delete does not affect the running guest. Disk-only
snapshots (no RAM state).

### CVE severity accuracy *(v2.3.4, v2.4.0, v2.4.1)*
CVE findings are scored with the real CVSS v3.1 formula, and each
finding records its severity source. Debian Security Tracker
`urgency` — a patching-priority signal, not a CVSS severity — is
capped at `medium` and never reported as high/critical. Stale cache
entries from before this work are detected and re-classified
automatically.

### Default SSH username + quick SSH link *(v2.4.2)*
Set a default SSH username per user (Settings → Security → SSH
preferences). Each device row on the Devices page gets an SSH icon
that builds an `ssh://user@host` link (device IP, or hostname as
fallback) and copies the `ssh user@host` command to the clipboard.

### Mailbox monitor *(v2.4.3, fixed v2.4.4)*
A lightweight mailbox monitor with no IMAP/SMTP. Configure a device
with one or more directory paths (Settings → Mailbox monitor); the
agent counts the regular files in each — for a Maildir `new/` folder
that file count is the unread-message count — and reports the numbers
in its heartbeat. Promote a device to add an "Unread mail" tile to
the Home dashboard. No email content is read, only files counted.

### On-demand package scan *(v2.4.5)*
"Scan packages now" in the device action menu sets a one-shot flag;
the device sends a fresh package inventory and patch count within a
heartbeat or two, instead of waiting for the periodic scan. Useful
right after patching a host.

### Update-available notice *(v2.4.6)*
RemotePower checks the project's GitHub repository for newer releases
and shows an in-app notice — with the commands to update — when the
running version is behind. Detection only; RemotePower never modifies
its own code.

### Needs Attention digest *(v2.4.7)*
The Home dashboard has a single ranked list that merges every
fleet-wide signal — offline devices, critical/high CVEs, configuration
drift, pending-patch pileups, mailbox threshold breaches — into one
prioritised view. Computed server-side (`/api/attention`); unmonitored
devices are excluded, the same gate the alert pipeline uses.

### Mailbox threshold alerting *(v2.4.7)*
A device's mailbox monitor can carry an alert threshold. When a
counted mailbox reaches it, RemotePower fires the `mailbox_threshold`
webhook — the same Discord / ntfy / Slack / JSON delivery used by
every other alert. The check is edge-triggered: it fires once on the
crossing, re-arms when the count drops back below.

### Status endpoint *(v2.4.7)*
A machine-readable fleet summary at `/api/status` for external
dashboards — Uptime Kuma, Homepage, Grafana. Authenticated by a
dedicated status token (generated in Settings), not a login session,
so a monitoring tool can poll it — but it is not public. Returns a
rolled-up health word, device online/offline counts, and attention
counts by severity.

### Newer offline webhook events
In addition to the events listed above, recent releases emit:

```json
{ "event": "drift_detected", "name": "mypc", "files": 2 }
{ "event": "cve_found", "name": "mypc", "severity": "high" }
{ "event": "proxmox_action", "guest_type": "qemu", "vmid": 100, "action": "snapshot_create" }
{ "event": "mailbox_threshold", "name": "mail01", "path": "...", "count": 51, "threshold": 50 }
```

---

## v3.3.0 additions

### Channel routing matrix
Settings → Dashboard exposes a single matrix that controls, per
event kind, which four surfaces an event reaches: **Needs Attention**
(home priority cards), **Recent Activity** (home feed), **Alerts**
(inbox), **Webhook** (external delivery). Replaces the prior pair of
hide-this-kind toggles plus implicit per-event webhook gating. Legacy
`dashboard_hidden_*` config auto-migrates on first read.

Several events that fired webhooks but never reached the Alerts inbox
in prior releases — `brute_force_detected`, `backup_stale`,
`snapshot_old`, `reboot_required`, `new_port_detected`,
`ssh_key_added`, `monitor_down` — now have `_ALERT_RULES` entries.
`monitor_up` auto-resolves the matching `monitor_down` row via
label+target sub-match.

### Hash-driven agent self-update
Agents compare their own binary `sha256` against the server's
canonical hash. Mismatch in either direction triggers a download.
Version strings stay in the response and the logs but the *decision*
is hash-based — same-version rebuilds and operator-initiated
re-pushes now reliably update. The server caches the canonical hash
to a sidecar `.sha256` file so CGI requests don't re-hash on every
poll.

### Log-alert improvements
- Sample-in-summary: Needs Attention cards, Alerts-inbox titles, and
  webhook subjects for `log_alert` now show the matched log line
  (truncated) rather than the rule regex. Hover the NA card to see
  the full pattern plus up to three captured matches.
- Per-rule `display_template` field with `{device}`, `{unit}`,
  `{pattern}`, `{count}`, `{sample}`, `{sample0..2}` placeholders.
- Per-rule `exclude_pattern` (regex) silences matching lines before
  the threshold count.
- Inline NA card actions: 24-hour snooze + "Open in Logs" deep link
  to the device + unit.

### Per-IP rate limits
`POST /api/enroll/register` is throttled at 10/min/IP (the 10⁶ PIN
namespace was brute-forceable from one IP in a few minutes).
`POST /api/login` is throttled at 20/min/IP on top of the existing
per-username lockout — blocks credential-stuffing across many
usernames from one source.

### SSRF defaults flipped
`webhook_block_local` now defaults to **true**, blocking link-local
targets (`169.254.169.254` cloud metadata) and unspecified addresses.
Loopback (`127.0.0.1`, `::1`) is still allowed by default via the
new `webhook_allow_loopback` flag so homelab Gotify/ntfy sidecars
keep working.

### Admin-only alert mutation (opt-in)
`viewers_can_ack_alerts` (default true for back-compat). When false,
`ack` / `unack` / `resolve` on alerts requires admin role.

### IP allowlist
Settings → Security gains a per-IP/CIDR allowlist (off by default).
Loopback always allowed (MCP-safe). Agent paths exempted
(`/api/heartbeat`, enrollment, agent download, CSP report,
public-info, health, `/api/metrics`, `/api/status`). The save handler
refuses to enable the gate if the caller's IP isn't already in the
list — operators can't lock themselves out with one click.

### Uninstall agent
Devices drawer → "Uninstall agent" queues an `uninstall` command.
Agent stops + disables its systemd unit, removes credentials + state
+ binary, exits via a detached trampoline. Device record stays. The
row shows "agent uninstalled" until a fresh heartbeat (operator
re-installed) clears it.

### Prometheus metrics: status-token auth
The existing `/api/metrics` Prometheus exposition endpoint now
accepts the status token via `?token=…` in addition to session
bearer. Compatible with stock `prometheus.yml` scrape configs:

```yaml
- job_name: 'remotepower'
  metrics_path: /api/metrics
  params:
    token: ['<status token>']
  static_configs:
    - targets: ['remote.example.com']
  scheme: https
```

### Healthchecks.io watchdog
Server pings a configurable URL on a fixed cadence (default 60 s,
min 30) so an external monitor flips red when RemotePower itself
stops responding. Settings → Notifications → "Healthchecks.io
watchdog". Off by default. The HTTP call has a 5 s timeout and
never raises into the request pipeline.

### GitHub issues as a webhook format
New `github` destination format. Card grows a single GitHub PAT
field (fine-grained, `issues:write` scope). Issue body shows the
human-readable alert on top with the raw payload in a `<details>`
JSON block. Labels = `["remotepower", "<event>", "<severity>"]`.

### Central ACME DNS-01 credentials
TLS / DNS page → "DNS provider credentials" — operator stores
Cloudflare / Hetzner / Route 53 / DigitalOcean / Gandi / OVH /
Porkbun / Hurricane Electric / deSEC / Namecheap / NameSilo /
RFC 2136 / acme-dns API tokens on the server. Values are injected as
env vars into the queued `acme.sh --issue` command — no more hand-
editing `~/.acme.sh/account.conf` on every device.
`_scrub_acme_credentials()` redacts the secrets from the audit log
and any UI surface that displays the queued command.

### Edit buttons everywhere
Log alert rules (per-device + global), maintenance windows,
monitors, TLS targets, backup monitors, command snippets, scheduled
jobs, inbound webhook tokens (label + scope), users (role),
log-ignore patterns — every operator-managed list now supports
Edit alongside Add and Delete.

### Mobile UX polish
Two media-query blocks (≤ 720 px and ≤ 480 px) bring touch targets
up to ~44 px, modals go full-viewport with a sticky action row,
device drawer action grid becomes 2-up (1-up under 480 px), settings
tabs wrap into a 3-up grid, all `.table-card` tables get horizontal
scroll with `-webkit-overflow-scrolling: touch`, form inputs use
16 px font size so iOS Safari doesn't zoom on focus.

### Audit-driven correctness fixes
- `process_service_report` + `_record_service_transition` now
  serialise their read-modify-write under `_LockedUpdate`. Two
  concurrent agent heartbeats can no longer lose service transitions
  or fire duplicate webhooks.
- `/api/status` "high load" flag was always firing when `os.cpu_count()`
  returned None — operator-precedence bug, fixed.
- `handle_device_delete` cleanup paths all use `_LockedUpdate`.
- `_compute_attention` loads `CONFIG_FILE` once per call instead of
  four times.
- TLS expiry events now land in the Alerts inbox (`tls_expiring`
  typo in `_ALERT_RULES` renamed to `tls_expiry`).
- `_wireHeaders` is idempotent — fixes the Monitoring → Processes
  browser-freeze where the static `<thead>` accumulated click
  handlers exponentially.
- Offline check exempts the device currently heartbeating — kills
  the false-positive `OFFLINE → ONLINE` flap that fired at the TTL
  boundary.
- Dashboard CVE tile now honours the operator's CVE ignore list
  (was: showed 3 critical while the CVE page showed 0).

### Dashboard performance
- `/api/home`: one endpoint serves slim devices, drift summary, CVE
  counts, fleet events, mailwatch, links, attention payload, and the
  handful of config flags the home renderer reads. Replaces seven
  parallel `/api/*` calls.
- `?slim=1` on `/api/devices` omits sysinfo / listening_ports / SNMP
  metrics / brute_force_active.
- `/api/devices/sysinfo?ids=a,b,c` batches the Monitoring page's
  per-device sysinfo pulls (was 1 + N requests).
- File-backed 10 s cache for `/api/attention` shared across CGI
  workers; busts when any underlying state file is newer than the
  cache.

---

## v3.3.1 & v3.3.2 additions

### OFFLINE detection hardening
The per-request offline sweep no longer marks a device down on a single
sample crossing the TTL — a late beat or a stale read used to produce an
`OFFLINE` → `ONLINE` flap in the same second. The cutoff is now
per-device, `max(global ttl, poll_interval * OFFLINE_MISSED_POLLS) +
grace`, and OFFLINE is debounced through an `offline_pending` candidate:
it fires only if a later sweep (≥1 poll interval on) still sees the
device silent. Recovery stays immediate. The bar is 5 missed polls
(300 s at the default 60 s poll). `offline_pending` is cleared wherever
`offline_notified` is, including on device delete.

### Maintenance windows show the hostname
A device-scoped maintenance window's Target column resolves the device
id to its name server-side (`target_name`) instead of showing the opaque
id.

### UI consistency + PWA polish
- Action buttons aligned across pages: paired Edit/Delete/Revoke buttons
  share one size class and icon style; the ACME force-renew button gets
  its missing refresh icon.
- Devices table no longer renders stray `…` dots: under
  `table-layout: fixed` a too-narrow container shrinks columns until
  Chrome paints an ellipsis on the clipped cell (Firefox clips
  silently). Cells now use `text-overflow: clip`, and the table sheds
  low-priority columns ~200 px earlier while the sidebar is docked
  (browser and installed PWA alike).
- PWA manifest defaults to `minimal-ui`; the docked-sidebar layout no
  longer clips the device table or the "MCP Confirmations" nav badge.
- "Did you know?" tips on the About page surface lesser-known features.
- The TOTP enrollment QR renders as a data-URL `<img>` so it doesn't
  trip the strict `style-src 'self'` CSP.

### Bug fixes
- Agent patch status no longer false-warns `pacman sync failed` on a
  fully-patched Arch/CachyOS host (`-Sy` and `-Qu` are now in separate
  try blocks).
- `/api/home` CVE and drift tiles match the detail pages — stale records
  for deleted devices no longer inflate the counts.
- Settings toggles reflect real runtime defaults even when the v3.3.0
  flags were never explicitly set (notably `webhook_block_local`).
- `/api/fleet/events` honours the `?event=` filter.

## v3.4.0 additions

### Hardware & health (SMART / kernel / inventory)
The agent runs `smartctl` on each disk and reports health plus the key
pre-fail attributes (reallocated / pending / offline-uncorrectable
sectors, temperature, power-on hours). A drive that reports a non-OK
status **or** has pre-fail sectors raises the `smart_failure` event and
a red health pill on the device card; drives `smartctl` can't assess
(USB bridges, virtual disks) report `UNKNOWN` and are *not* treated as
failures. The agent also compares the running kernel to the newest
installed one (`kernel_outdated` + livepatch status) and collects a
passive inventory — DIMMs, serial numbers, temperatures, RAID state.
Everything surfaces in the device drawer's **Health & Hardware** card.

The drawer's **System Info** tab rounds out the per-device picture with the
host's **top processes** by CPU, each mount's **filesystem type**, a
**reboot-required** indicator with the reason, the 1-minute **load average**, and
a container **age** column — all from data the agent already reports.

### Resource forecasting
A compact metrics snapshot is written **once per device per UTC day**
(per-mount used/total GB, memory, swap, plus a state fingerprint) and
retained for roughly six months in `metrics_history.json`. From that
history, `GET /api/devices/<id>/forecast` fits a least-squares trend of
used-GB-over-time **per mount** and extrapolates it to the mount's
capacity, yielding a **days-to-full** estimate and a projected fill date
(e.g. *"/ fills in ~18 days"*). Notes:

- Each mount is projected independently, so a fast-growing `/var`
  surfaces even while `/` looks healthy.
- Flat or shrinking mounts report **no fill** rather than a misleading
  far-future date.
- It's a straight-line trend, not a guarantee — a log burst or a big
  install shifts it; it's meant to give you lead time, not a precise
  date. Accuracy improves as daily samples accumulate, so a freshly
  added host shows little until it has a few days of history.
- The drawer's forecast view colour-codes urgency (under ~14 days,
  under ~45 days) and offers a one-click, context-prefilled AI runbook
  for an imminent fill.

There's also a dedicated **Monitoring → Forecast** page (`GET /api/forecast`)
that lists every projected mount across the fleet, soonest-to-fill first, in a
sortable table, with a scatter-plus-regression-line chart of the selected
mount's history extrapolated to capacity and the projected fill date marked.

### What changed (drift over time)
`GET /api/devices/<id>/changes?days=1|7` diffs the oldest snapshot in
the window against the latest and reports package deltas, opened/closed
listening ports, failed/recovered units, reboot edges, and per-mount
disk growth — a quick "what moved on this host since yesterday/last
week" without trawling logs.

### On-demand diagnostics
A one-click **network speed test** (librespeed → Mbps, with live
feedback) and a **LAN discovery** sweep (passive ARP table or an nmap
scan) that lists hosts on the device's network and flags ones not yet
managed by RemotePower.

### Device quarantine
A per-device admin switch that disables exec / reboot / every action,
enforced server-side at the command-dispatch chokepoint (not just hidden
in the UI) and audited. Freeze a suspect or sensitive host in one click,
then release it the same way.

### Compliance reports
`GET /api/compliance?frameworks=pci,hipaa,soc2` maps PCI DSS / HIPAA /
SOC 2 controls to data RemotePower already collects (patching, CVEs,
TLS, MFA, audit logging, backups, listening-port change detection, …)
and scores each **pass / fail / N-A** with evidence and remediation. The
score is pass ÷ (pass + fail), ignoring N-A — an honest "of what we can
measure, how much passes." An audit-prep aid, never a formal
attestation, and never a false pass.

### Helm release status
Where a host has Helm and a kubeconfig, RemotePower surfaces Helm
release status (visibility only — it doesn't install or upgrade).

### On-demand AI insights
All opt-in and disabled until you configure a provider:
- **Fleet anomaly scan** (`POST /api/ai/anomaly`) — ranks unusual
  signals across the fleet (odd ports, drift, failing disks) for review.
- **Cron builder** (`POST /api/ai/cron`) — plain-English → a cron
  expression, with the next run times previewed by local validation.
- **Runbook suggestions** (`POST /api/devices/<id>/runbook`) and **CMDB
  doc drafts** (`POST /api/devices/<id>/doc-draft`) — RAG-aware,
  pre-fillable from a finding (a failing disk, an imminent fill).

### RAG over your infrastructure
The AI assistant retrieves the most relevant facts from *your* fleet —
device state, watched services, CVEs, containers, firewalls, integrations,
backups, DNS/email posture, **security-control posture** (mutual-TLS
coverage, encrypted backups, audit-mode), CMDB metadata & asset docs,
per-device runbooks, recent commands and alerts, plus the RemotePower
product docs — and injects them into each request as a cited
`<retrieved_context>` block, so answers reference your hosts and cite
sources by id (e.g. `[live/web01#cves]`). Live-state coverage also includes
mount problems, failing custom checks, running process names and
file-descriptor / conntrack saturation, so the model can answer reliability
questions ("which host has a stalled mount / a failing check?") from real
data instead of guessing. Retrieval is **lexical-first**
(BM25, pure stdlib) so it works with every provider including Anthropic;
with an embedding-capable provider you can enable **semantic search**,
fused with lexical via Reciprocal Rank Fusion. Privacy by construction:
the encrypted credentials vault is never indexed (metadata + docs only),
history is redacted at index time, and embeddings egress is opt-in.
Managed under **Settings → AI → Knowledge index** (source toggles,
**Rebuild index**, and a **Test retrieval** box). See [rag.md](rag.md).

### Proxmox LXC create & delete
Beyond start / shutdown / snapshots, the Containers page → LXC section
gets a **Create container** wizard (live templates, root-disk storages,
Linux/OVS bridges, next free VMID; hostname, disk/cores/memory/swap,
DHCP or static network, root password and/or SSH key, start & on-boot
toggles) and a **Delete** button with a type-to-confirm guard that
force-stops a running container before removing it (no purge). Both are
admin-only, validated server-side, and audited.

### Security & hardening
`remotepower-passwd` and the installer use salted PBKDF2-HMAC-SHA256
when bcrypt isn't present (never bare SHA-256), and the server no longer
accepts legacy pre-2.3.2 unsalted-SHA-256 hashes (bcrypt/PBKDF2
auto-upgrade to bcrypt on login). A server-wide cap keeps a flapping
monitor from flooding webhook channels. Native browser pop-ups are
replaced with the app's own keyboard-friendly dialogs.

---

## v3.5.0 additions

### SBOM export (CycloneDX / SPDX)
Generate a Software Bill of Materials per host or for the whole fleet
from the package inventory RemotePower already collects — CycloneDX 1.5
(primary) and SPDX 2.3 JSON. Each component carries a package URL
(`purl`), and the CycloneDX output embeds a VEX-style `vulnerabilities`
section built from the host's current CVE findings, so one document is
both an inventory and a vulnerability report. Output is deterministic for
reproducible re-exports.

### Lifecycle expiry tracking
Warranty, license, and support-contract end dates per CMDB asset.
Expired or within 30 days → warning, within 90 days → info — dashboard
attention items that feed the fleet health score and are silenceable in
channel routing.

### Graphical remote access (VNC over SSH)
A **Remote desktop** device action opens a browser VNC session (noVNC)
tunnelled over the web-terminal daemon's SSH connection to the host's
loopback VNC port — never network-exposed, no inbound firewall rules.
Linux VNC; RDP isn't supported.

### Sites & teams
A first-class fleet grouping above device groups, for organising hosts by
location / team / customer (a soft boundary — super-admins always see
everything). Admin → Sites, an Assign-site device action, and a site
filter on the Devices roster.

## v3.6.0 additions

### Remote file manager (agent, no SSH)
A **Files** device action browses, views, and edits files on a host
straight through the agent — no SSH session, no SFTP, no inbound ports.
Every operation is confined to an allowlisted set of browse roots,
gated on the same `command` permission as remote exec, and fully
audited. Reads stay available under quarantine / audit-mode (useful for
incident response); writes, mkdir, and delete do not. The whole feature
is **opt-in per server** under Settings → Advanced (off by default).

### Backup orchestration
Define a backup command per device (restic / borg / rsync) under Planning
→ Backups, run it on demand, or schedule it with cron. Plus a Proxmox
per-guest **vzdump backup recency** check (distinct from snapshots) with
an adjustable staleness threshold.

### Host user, key & firewall management
Add / lock / unlock / delete users, add / revoke SSH keys, and allow /
deny / delete ufw or firewalld ports from a device's drawer — all
exec-gated, audited, quarantine-aware.

### Endpoint AV posture & auto-patch
ClamAV / rkhunter status reported by the agent with an on-demand scan
action; Planning → Auto-patch applies updates on a cron schedule across a
group / tag / site / fleet, respecting maintenance windows.

## v3.7.0 additions

### Account & governance
**2FA recovery codes**, **audit-log forwarding** to a SIEM (HTTP) or
syslog, **credential rotation reminders** in the CMDB vault,
**desired-state enforcement** (correct-on-drift), and **change approval**
(maker-checker — a second admin signs off arbitrary command runs).

### Infrastructure
**Proxmox QEMU VM create** (a wizard alongside LXC create) and an
**Ansible playbook runner** (run playbooks against a group / tag / site /
fleet with the server as the control node over SSH). Terraform is
supported via the REST API rather than a bespoke provider — see
[terraform-api.md](terraform-api.md).

## v3.8.0 additions

### Hardening & polish
A security pass over the v3.5–v3.7 work (change approval now enforces the
per-device command allowlist; the Ansible runner builds a safe inventory
and skips quarantined hosts; 2FA recovery codes consume atomically;
audit forwarding refuses SSRF redirects). **DNS-rebinding SSRF** is closed
across the webhook sender, audit→SIEM forwarder and OIDC discovery/token
fetches — the address actually connected to is re-validated, not just the
pre-flight DNS lookup (TLS verification unaffected). **Maker-checker
approval** re-checks device state, rejecting a parked action if the device
was deleted or quarantined while queued. Agents can opt in to **mandatory
signed updates** — a `require-signed-updates` marker file makes the agent
fail-closed, refusing any self-update that isn't pinned to a release key
and validly signed. v3.8.0 also passed an **external dynamic scan** (OWASP
ZAP full + nikto + nuclei); the two real findings — an error-disclosure 500
on the public status/calendar endpoints (a non-ASCII `?token=` is now
rejected cleanly) and security headers dropped on a couple of static nginx
paths — are fixed, and the shipped nginx templates gained a CSP / header /
TLS hardening pass. See `docs/security.md`.

**Boot reason** (why a host last restarted) is now stored and shown.
**Failed systemd units** and **logged-in users** were being silently
dropped and are now persisted — both shown in the device System Info tab;
failed units also drive a new failed-units Needs-Attention item that feeds
the fleet health score (and the previously dead-ended Fleet Query "failed
units" filter and CIS failed-units check now work). RAID member disks
render again, the Proxmox per-guest backup table is now sortable, and
**AI Investigate** gained playbooks for malware/AV posture, stale agent
versions, and failed systemd units (among others; ~21 kinds total).

## v3.9.0 additions

### Bind-it-together, hardening & polish (round two)
The **HTTP uptime monitor** moved to the same connect-time SSRF guard the
other back-channels use (closing IPv6-loopback / integer-IP / DNS-rebinding
bypasses); inbound-webhook alert links are scheme-validated. Correctness
fixes: the post-upgrade "didn't take" badge no longer false-alarms on
already-patched or offline hosts; a metric-threshold bug that could skip
disk alerting is fixed; TLS-expiry alerts get the right severity. More
collected-but-hidden signals surface: **CPU-load history** on Trends, **swap**
on the metrics sparkline, **rkhunter last-run**, the **systemd alias** a
watched unit resolved to, and **livepatch state**. Three more tables became
sortable; typographic glyphs were replaced with Lucide icons. The **Image
Updates** page gained a one-click **Update** button on stale, compose-managed
rows (`docker compose pull` + `up -d`), and the **Command Queue** now logs
ACME certificate actions with **Clear all pending** / **Clear log** controls.
See [`CHANGELOG.md`](../CHANGELOG.md).

## v3.10.0 additions

### Bind-it-together & security (round three)
A third consolidation sweep — agent data that was collected but stuck at
zero now flows through, two real SSRF / secret-disclosure gaps are closed,
and a couple of alert-label bugs are fixed.

**Container restart tracking, fleet-wide.** Docker/Podman containers
reported `restart_count`, `started_at` and `uptime_seconds` hardcoded to
zero, so the `container_restarting` alert only ever fired for Kubernetes
pods and the drawer's container age was blank. The agent now fills them
from a single batched `docker inspect` per heartbeat, so the alert fires
everywhere and container age renders. **ClamAV last-scan time** (parsed
from the scan summary) and **per-interface MAC addresses** now show in the
device drawer — both were collected/stored but never displayed.

**Security.** The container image-registry check — the one outbound path
not behind the connect-time SSRF guard — now routes every fetch (manifest
*and* the registry-controlled bearer-token realm) through the SSRF-safe
opener and forces the realm to HTTPS, closing a redirect / DNS-rebinding /
credential-exfiltration gap. `GET /api/config` gained a recursive
secret-scrub backstop so a newly-added config secret can't leak to a
viewer/MCP key. The TCP uptime monitor and the Healthchecks.io ping picked
up the same IP-class SSRF checks the HTTP paths already had. See
`docs/security.md`.

**Fixes.** The config-drift alert title named no file (every one read
"? file(s)") — it now names the file that changed or the number of sections
that drifted; the Devices table view's Hostname column showed a sort arrow
but never reordered — fixed.

## v3.11.0 additions

### Fleet posture batch
Seven features that turn data the agent already collects (or can collect
cheaply) into first-class security and operational signals — no new daemons,
no new dependencies. Every detection is edge-triggered with per-device state.

**Exposure (attack surface).** The agent kept each listening socket's port
but discarded its bind address. It now keeps the address and classifies an
exposure scope — `local` (loopback), `lan` (RFC1918 / link-local / ULA) or
`world` (wildcard or any global address). `port_exposed_world` fires when a
service first becomes world-reachable. New Exposure page with a
World/LAN/Local filter (`GET /api/exposure`).

**Fleet Software Policy.** Rules — `banned`, `required`, `min_version`,
optionally scoped to device tags — evaluated against the installed-package
inventory every host pushes (~6-hourly). `software_policy_violation` fires
edge-triggered. Policy editor + violations table
(`GET/POST /api/software-policy`, `GET /api/software-policy/violations`).

**Storage / RAID health.** New agent probe for ZFS / mdadm / btrfs pool
state, capacity and last-scrub. **One-click maintenance** *(v5.0.0)*: each ZFS
pool / btrfs filesystem on the Storage page has a **Maintain…** button that runs
a scrub, trim, error-clear, balance, status/usage check, snapshot listing, or a
named snapshot removal — the command is built server-side from a fixed template
(only the validated pool / mountpoint / snapshot is interpolated, no shell
metacharacters), queued through the audited, quarantine-aware command path
(`POST /api/devices/{id}/storage-action`, admin + `command` permission), with
output in the host's command view. `storage_degraded` / `storage_recovered`
(auto-resolving) and `scrub_overdue` (threshold `scrub_overdue_days`, default
35). New Storage page (`GET /api/storage`).

**Access watch.** Recent successful logins and their source IPs are
collected; `login_new_source` fires on a first-seen source address. (Brute
force keeps using `brute_force_detected`.)

**Host firewall drift.** A stable fingerprint of the active ufw / nftables /
iptables ruleset rides the heartbeat (iptables counters zeroed first);
`firewall_changed` fires when it diverges from baseline.

**Scheduled-job failure lens.** Systemd timers are inventoried;
`timer_failed` fires when a timer's backing job enters a failed state.

**Scheduled posture digest.** An opt-in daily/weekly email summarising
offline hosts, pending updates, critical CVEs, software-policy violations and
degraded storage, sent over the existing SMTP path. Configure in Settings →
Notifications; "Send test now" delivers immediately
(`POST /api/posture-digest/test`).

---

## v3.12.0 additions

### Pluggable storage backend
**Optional SQLite backend** alongside flat-JSON (Settings → Advanced → Storage
backend; WAL mode, stdlib only, no new dependencies). Hot, high-cardinality data
is stored row-per-entity so a heartbeat writes one row instead of rewriting a
file. In-place, reversible migration (snapshot → migrate → verify → flip) with a
`tools/migrate_storage.py` CLI; flat JSON stays the default.

### My Account + ack→ticket webhook
A top-right account menu and **My Account** page (avatar, role/permissions, 2FA,
default SSH user, your acknowledged alerts). Each webhook destination gains an
"also fire on ACK" option that POSTs the full alert to a ticket system on
acknowledgement.

## v3.13.0 additions

### Bind it together (round four)
Surfaces host signals already collected but never shown: per-device **recent
logins & source IPs**, a failed-first **systemd timer** inventory, this host's
own **ZFS/mdadm/btrfs storage health**, **bind address + world/LAN/local scope**
on the listening-ports card, the **firewall fingerprint**, an active
**brute-force lockout** badge, and Disk/Swap pressure pills. Every panel caps at
~15 rows and scrolls; static assets cache immutably; sandboxed SCAP reports;
OIDC id_token expiry/issuer/audience checks; syslog-forward DNS-rebinding fix.

## v4.0.0 additions

### Scale, encryption & deep visibility
Optional **PostgreSQL** backend with automatic failover + read replicas, **relay
satellites** for segmented networks, and **load-balanced multi-node**; the
agent→satellite hop can run over **HTTPS** and agents can trust an internal CA.
A **macOS agent** joins Linux + Windows. Surfaces much more agent data:
**Thermal** (hottest hosts — expand any host to see every sensor, a ~24h
temperature **trend sparkline**, and a per-host **Thresholds** button to set
warning / critical temperatures), **Power/UPS** + energy cost, **SSH-key audit**,
SSD/NVMe **endurance**, **predictive disk health**, **GPU monitoring**, local
**certificate-file** inventory, **local account audit**. **CVE prioritization**
via CISA **KEV** + **EPSS**. **Customizable dashboard**, **interface language**
(5 languages), **GitOps** config-from-Git, **custom report builder**,
**Prometheus metrics push**, **active session management**, and **saved Devices
views**. A security-hardening pass (session tokens hashed at rest, anchored
webhook-host matching, SSRF-safe cloud import).

## v4.1.0 additions — "VisualMatters"

### Per-host Checks (CheckMK-style)
A **Checks** page (under Monitoring) renders every monitored signal on every
host as **OK / WARN / CRIT / UNKNOWN** with output — reachability, CPU/mem/swap
load, per-mount disk **and inode**, file-descriptor & conntrack pressure, failed
units, timers, drift, world-exposed ports (respecting Exposed-page mutes),
pending updates, CVEs, SMART/UPS/temperature, clock sync, gateway, OOM kills,
mail-queue depth, read-only filesystems, disk-fill ETA, storage/RAID health.
Sortable, filterable, per-check muteable; *Hide muted* / *Hide unmonitored* on by
default. `GET /api/checks`, `/api/devices/<id>/checks`, `POST /api/checks/toggle`.

### Custom checks
Operator-defined checks assignable to a host, tag, group or the whole fleet:
server-evaluated **process running / port open / port closed**, and
host-evaluated **file present/absent**, **job freshness** and **log error rate**
(read-only on-host evaluation, pushed in the heartbeat). Custom monitoring
scripts also surface as check rows. `/api/checks/custom`.

### More active monitors
**DNS** resolution (with an expected-address assertion), **ICMP** latency +
packet-loss thresholds, **HTTP** status + latency-SLA assertions, a
credential-less **database-liveness** probe (PostgreSQL / MySQL / Redis), and
**tag/group** target fan-out for ping/ICMP/TCP monitors.

### Composable dashboard
A resizable widget grid with a **67-widget catalog** (alphabetical add-dropdown):
per-widget **size** (S/M/L), **reorder**, **show/hide**, **reset**, **align**,
and a shareable **import/export layout code**, saved per account. New
**Upcoming** (calendar + scheduler), **Tickets** (open quick-ack + recently
acknowledged) and actionable **Alerts** (ack/resolve/investigate) widgets; the
Ask-AI box is a toggleable widget.

### Host-grouped alert inbox
The inbox stacks open alerts under a per-host header (worst first) with
group-level **Ack-all / Resolve-all**, and folds a host's symptom alerts under
its `device_offline` **root cause** so a storm reads as one incident.

### Security & reliability
A **TLS 1.2 floor** on every hop (satellite both ways, agent, server outbound);
the SSH command builder rejects option-smuggling host/user values; the agent's
mail-queue probe backs off on a broken MTA; heavy dashboard widgets compute only
when displayed. Independently scanned with wapiti, nikto, nuclei, bandit and
OWASP ZAP — clean.

## v4.2.0 additions — "5ecur1tyM4tter5"

### Authorized vulnerability scanning (the Pentest page)
Scan the hosts and websites **you own** with industry tools — **nuclei, nikto,
nmap** (passive profile) plus **OWASP ZAP and wapiti** (active profile) and an
on-host **lynis** hardening audit — orchestrated from a hardened **scanner
satellite**, with quick/full intensity, a vhost field, and cron **scheduled
scans** that can notify a channel on recurring findings. Targets are
authorization-gated: enrolled hosts (target derived server-side, never typed
in) or non-enrolled domains you prove you own via a **DNS TXT** record or a
`/.well-known` file. Active scans require an explicit attestation and, for
enrolled hosts, a maintenance window — all of it audit-logged.

### Passkeys (WebAuthn)
Phishing-resistant, passwordless sign-in with a security key, phone or
biometrics. Enrol under **My Account → Passkeys**, then *Sign in with a
passkey*. A cloned authenticator (sign-count regression) is refused; a passkey
satisfies the MFA-required policy.

### SAML 2.0 single sign-on
Sign in through an enterprise IdP (Okta, Azure AD/Entra, OneLogin, Ping, ADFS)
alongside the existing OIDC / LDAP / local options: SP metadata published,
signed assertions verified with replay protection, users provisioned on first
login with admin-group → role mapping.

### Tamper-evident audit log
Audit entries are **hash-chained**; a *Verify integrity* button reports the
first broken link, and clearing the log requires an admin password re-prompt
plus an immutable pre-wipe archive.

### Account guardrails
Enforce **MFA per role** (TOTP or passkey), cap **concurrent sessions** per
user, set a **default API-key expiry**, and review a graded **security-posture
self-check** that scores the server's own configuration against secure
defaults.

## v4.3.0 additions — "ImprovementMatters"

A refinement release — no new headline subsystems, no breaking changes.

### Faster on bigger fleets
On the SQLite / PostgreSQL backends, the endpoints that need just one device —
per-host **Checks**, per-device **CVE** detail, the heartbeat's host-config and
watched-file lookups, and the firewall / compose / RouterOS / OPNsense device
actions — read a **single row** via `storage.device_get()` instead of
reconstructing the whole fleet on every request (O(fleet) `json.loads` → O(1)).
The flat-JSON backend is unchanged; the data returned is identical.

### Self-observability
**Download the archived audit log** — a button on the Audit page (and
`GET /api/audit-log/archive`) streams the gzipped archive of evicted entries, so
the full retained history is reachable without shell access. **Staleness at a
glance** — cadence jobs (monitors, the KEV/EPSS refresh, scheduled scans) show a
last-ran timestamp and a stale flag on the **Server status** page.

### UX polish
Each warning in the **security-posture self-check** links straight to the
Settings section that fixes it. Tables that flashed empty or showed a bare
"Loading…" now use the shared skeleton-row loading state.

### Regression guardrails
Two CI tests lock recurring bug-classes: a check reading a `sysinfo` field the
heartbeat sanitizer never persisted (the `proc_names` / `mailq` / `pkg_scan_ts`
class), and a webhook event that half-registers (fires but never lands in the
inbox). Both now fail at commit instead of in a later sweep.

## v4.4.0 additions — "FortifyMatters"

A security-hardening + bind-it-together release — no breaking changes.

### Security (audited + independently pentested clean)
Every server handler and all three agents were read end-to-end; the web surface
was scanned with **wapiti, nikto, nuclei, bandit and OWASP ZAP** with no
exploitable findings. Fixes: a **critical** admin-gate escalation (a custom
operator role could reach admin-only endpoints — the gate now checks the
resolved role's admin flag, not a name denylist); device-scope guards on the
mitigation status / AI-analysis routes; `shlex.quote` on the drift file-fetch
and ACME issue/renew/revoke command builders; an SSRF pre-flight on the RouterOS
REST integration; `/api/metrics` degrading to a minimal payload +
`remotepower_scrape_error` gauge instead of 500-ing on a malformed record; a
private-tempfile fix for the agent's on-host lynis audit (was a fixed `/tmp`
path); and **HTTPS + TLS 1.2 enforcement on the Windows and macOS agents** to
match Linux.

### Bind it together
The device drawer's **Access — recent logins** table gains a **Last seen**
timestamp column (the agent now reports per-login time), and the **Clock** pill
reflects the server's threshold-aware skew verdict ("skewed" vs "synced").

### Performance
The heartbeat's watched-files and host-config-enforce lookups are single-row
reads (O(1) on SQLite/PostgreSQL); the 15-second fleet-checks cache now honours
its TTL instead of being invalidated by every heartbeat; the agent memoizes its
OS string.

## v4.4.1 additions — "DocumentationMatters"

A documentation + static-analysis hygiene release — no functional changes.

### Static-analysis triage
Every static-analysis finding on the codebase was reviewed and mapped to the
feature that already covers it, with a written disposition for each. Two cheap
hardenings landed alongside: the two MD5 cache-fingerprint helpers are now
flagged `usedforsecurity=False` (they are integrity keys, not a security
primitive), making the intent explicit.

### Documentation coverage
A full pass to keep every user-facing surface — README, the in-app
Documentation page, the per-version docs and the "did-you-know"
tips — describing the current feature set.

## v4.5.0 additions — "TrustMatters"

TLS onboarding for instances where a public certificate is hard (internal,
airgapped, no public DNS) — no breaking changes. Full guide:
[tls-selfsigned.md](tls-selfsigned.md).

### Self-signed CA (not a bare cert)
`make tls-selfsigned HOST=rp.internal` (`tools/gen-ca.sh`) generates a private
**CA** plus a server leaf (ECDSA P-256, SAN, serverAuth), installs the leaf for
nginx, and prints the CA's SHA-256 fingerprint. Agents trust the **CA**, so
`make tls-renew` re-issues the server certificate **without touching any
client**, and a later self-signed → real-CA migration is server-only too
(agents trust system roots and the pinned CA additively).

### Fingerprint-verified rollout
The Linux / macOS / Windows installers take `--ca-fingerprint <sha256>`: they
fetch `/ca.crt` over plain HTTP at bootstrap and **refuse to trust it on a
fingerprint mismatch**. The CA is wired in via `RP_CA_BUNDLE`; full verification
(hostname + TLS 1.2 floor) is never weakened. Docker opt-in via
`RP_TLS_SELFSIGNED`, and you can also generate/import a cert straight from
**Settings → Security**.

## v4.6.0 additions — "RepellantMatters"

A visual-identity release paired with a project-wide reliability, security and
performance polish pass — no breaking changes.

### Industrial "New UI" (default) + New/Old toggle
A graphite/steel **Industrial** interface (keeping the RemotePower blue) is the
new default, with the sidebar/nav set in self-hosted IBM Plex Mono and
instrument-panel motifs (corner ticks, dashed rules, mono eyebrow labels,
tabular figures). A **Settings → Interface** tab — and a **My Account →
Appearance** control so non-admins can switch too — flips between the new look
and the classic one, per-browser, with no reload. Pure CSS plus one `data-ui`
attribute, fully CSP-safe; nothing functional changes.

### Navigation
A dedicated **Admin** group (Links now lives there), and every sidebar group is
alphabetically sorted.

### Bind it together
The device drawer now surfaces **CPU model, kernel, total RAM and total disk**
beside the live usage (previously CMDB-page-only). More lists and tables cap at
~15 rows then scroll internally, and the disk-forecast table sorts correctly by
both GB and percent.

### Security (independently pentested clean)
The server and all three agents were audited and the web surface re-scanned with
**wapiti, nikto, nuclei, bandit and OWASP ZAP** with no exploitable findings.
Fixes: SSRF pre-flights on the OPNsense, Proxmox, AI-provider and TLS-monitor
targets (matching the RouterOS guard); resolved-role checks on two read
endpoints (a custom operator role could previously see admin-only config /
counts); and hardened agent credential storage — restrictive ACLs on the
Windows agent's token file, atomic 0600 writes on macOS, and the Linux command
stash routed through the O_NOFOLLOW state-file helpers.

### Performance
The dashboard's 7-day uptime stripe is cached for 5 minutes instead of firing a
second round-trip every tick; the offline-sweep transition handler uses
single-row reads; and the agent heartbeat is lighter — memoized tool-path and
CPU-model lookups, a single memory read, and a non-blocking uptime probe (reads
`/proc/uptime`, no subprocess).

### Correctness
A batch of quiet bugs fixed: custom-script OK↔FAIL alerts no longer drop under
the SQLite backend, the device runbook now actually injects its RAG context and
recent-command history, the `kernel_outdated` device-list filter works again,
and the CMDB asset modal shows real free-memory / free-disk figures.

## v4.7.0 additions — "IntegrationsMatters"

### Homelab software integrations
A read-only, server-side **integration subsystem** polls popular self-hosted
software for health on a cadence and folds the result into the **Alerts** inbox
and the dashboard — nothing is installed on the target. **26 connectors** across
DNS (Pi-hole v6, AdGuard Home), storage/NAS (TrueNAS, Unraid),
virtualization/orchestration (Kubernetes / k3s, VMware vCenter/ESXi, Proxmox
Backup Server), network (UniFi), reverse-proxy/cert (Traefik, Nginx Proxy
Manager, Caddy), observability (Netdata, Grafana, Uptime Kuma), media (Jellyfin,
Plex), apps (Home Assistant, Nextcloud), download clients (qBittorrent,
Transmission, Deluge, SABnzbd, NZBGet), media automation (one **Servarr**
connector for Sonarr / Radarr / Prowlarr / Lidarr, plus Bazarr) and requests
(Overseerr / Jellyseerr). Configure under **Settings → Integrations** (type + URL
+ token + Test). An unhealthy or unreachable target raises an `integration_down`
alert (severity from the result, auto-resolved on recovery) routed through your
channels, plus an **Integration health** dashboard widget and live status badges.
Every outbound call goes through the **SSRF guard** (loopback / link-local /
cloud-metadata refused, RFC1918 LAN allowed, peer re-validated at connect time,
redirects refused); credentials are stored server-side and redacted from every
response, and the raw URL is admin-only. A **Show Homelab software** switch
(default on) is an instance-wide kill switch for enterprise instances. Reference:
**[integrations.md](integrations.md)**.

### Containerized agent
The Linux agent can run **as a container** that monitors its **Docker host** and
reports to the server with no host install (*Enroll device → Generate Docker
compose*). It reads the host's facts (shared PID/network namespaces, host rootfs
mounted read-only), names itself after the host, and persists credentials in a
volume. Published multi-arch at `ghcr.io/tyxak/remotepower-agent`; standard
capabilities, no `--privileged` (SMART/DMI and Docker-socket container inventory
are opt-in). Reference: **[docker-agent.md](docker-agent.md)**.

### Fleet GPU monitoring
A new **Monitoring → GPUs** page shows every GPU across the fleet in one rich view
— **NVIDIA and AMD** — with utilisation and VRAM meters, temperature, power and
fan, hottest-busiest first, plus a fleet summary (count, per-vendor, total power).
Hosts report via `nvidia-smi` / `rocm-smi`, with a tooling-free **amdgpu sysfs
fallback** for AMD hosts that have no ROCm tooling. Each GPU card carries
**temperature + utilisation trend sparklines** (the last ~4 hours). **Thermal
alerting:** a GPU at or above the temperature threshold (default 85 °C,
configurable) raises the standard **high-temperature** alert and auto-resolves
when it cools — it reuses the existing hardware-temperature alert, so there's no
new alert type. `GET /api/fleet/gpus`.

### Unmonitored devices visible everywhere
Telemetry and inventory views — thermal, power, storage, exposure,
predictive-health / SMART, patches, listening ports, processes and the GPU page —
now display **unmonitored** hosts too, flagged so the UI marks them. Only
**alerting** stays suppressed for unmonitored devices (the same gate the alert
pipeline already used), so you can see an unmonitored host's data without it
paging you.

### CSP report hygiene
The in-app CSP violation reporter now ignores reports whose source is a **browser
extension** (`moz-extension://`, `chrome-extension://`, `safari-web-extension://`,
…), so users' extensions can't pollute the security log with violations the app
didn't cause.

---

## v4.8.0 additions — "OnboardingMatters"

### Turnkey onboarding
Getting RemotePower running is now a single command. A unified **`install.sh`**
wizard provisions server, TLS and the admin account in one run; **one-command
Docker** (`docker compose up -d`) serves **HTTPS by default with no insecure
default password** (the generated admin password is printed to the container
log). Adding a host is one line — a self-hosted **`/install`** endpoint serves a
**"Quick install" agent** with the server URL, enrolment token and integrity
baked in, so the operator just downloads and runs it and the host appears in the
device list **by its hostname**. `install.sh agent push --server <url> --token
<token> user@host …` bootstraps agents over SSH to the hosts you name, and a clean
**`install.sh uninstall`** tears down server, agent or demo. Heavy-fleet scaling
(Postgres, HA, satellites, load balancing) is reframed as an explicit **advanced
track**. Reference: **[install.md](install.md)**, **[deployment.md](deployment.md)**.

### Reputation / DMARC monitor
A new **Reputation/DMARC** page (under Security) covers your mail-deliverability
posture in one place.

**IP reputation (DNSBL).** Add your mail-sending IPs and RemotePower checks each
against DNS blocklists (Spamhaus, SpamCop, Barracuda, SORBS, UCEPROTECT, PSBL),
re-scans periodically, and raises an `ip_blacklisted` alert (cleared with
`ip_blacklist_cleared`) when a monitored IP gets listed. A blocklist that can't
be reached is surfaced as a *partial* check, never folded into a false "Clean".
`GET/POST /api/reputation/targets`, `DELETE /api/reputation/targets/<id>`,
`POST /api/reputation/scan`.

**DMARC / SPF / DKIM.** Tracks the email-authentication posture of your domains —
published **SPF / DKIM / DMARC** DNS records, graded ok / weak / fail — *and*
ingests the **aggregate (RUA) reports** your receivers send back. Point it at the
IMAP mailbox that receives those reports; RemotePower polls it on a schedule and
on demand, parses the gzip/zip XML, and shows **per-source SPF/DKIM pass/fail
tallies** plus a **mailbox health** view (message + unseen counts).
`GET /api/dmarc/reports`, `POST /api/dmarc/fetch`, `GET /api/dmarc/imap`,
`POST /api/dmarc/imap`. Reference: **[dmarc.md](dmarc.md)**.

### Accessibility
Every modal dialog now carries an **accessible name**, and every native
`confirm()` / `prompt()` has been replaced with a **styled, accessible in-app
dialog** — consistent look, keyboard-navigable, screen-reader friendly.

### Agent parity
The **macOS** agent now reports the saturation metrics the Linux agent already
sends — **1-minute load average** and **file-descriptor utilisation %** — and the
**Windows** agent now reports **NVIDIA GPU telemetry**, so those hosts appear on
the fleet GPU page alongside Linux.

### Reliability & hardening
The CVE **"Scan all devices"** action no longer hangs the browser; the audit-log
**clear** action now explains *why* it was denied when it is. Plus a round of
security hardening: tighter scanner temp-workdir permissions, corrected
containerized-agent host reads, credential-file hardening on macOS/Windows, and
internal lock-safety fixes.
## v4.9.0 additions — "ResolutionMatters"

### DNS dashboard
A new **Admin → DNS** page reads and writes DNS records directly through your
provider's API — list, create, edit and delete A / AAAA / CNAME / TXT / MX / NS /
SRV / CAA records (TTL, MX/SRV priority, Cloudflare proxied flag) without leaving
RemotePower. Five providers: **Cloudflare, DigitalOcean, Hetzner DNS, deSEC,
Porkbun** (plain token-REST; deSEC's RRset model and Porkbun's subdomain/body-auth
are normalised behind one record shape). Credentials reuse the scoped API tokens
already stored for ACME DNS-01 issuance (`config['acme_dns_credentials']`) — set a
token once and it drives both certificates and this dashboard — or store them
encrypted in the CMDB vault, or import them on-demand from a device's `acme.sh`.
Admin-only, audit-logged, delete-confirmed, SSRF-guarded.
`GET /api/dns/providers|zones|records`, `POST /api/dns/records[/update|/delete]`.

### Live resolve / dig + propagation
Below the records table, a **Resolve / dig** panel queries a name live and shows
what the zone's **authoritative** nameservers serve next to what **public
resolvers** (Cloudflare, Google, Quad9, OpenDNS) return — surfacing drift between
provider state and what actually resolves. A per-record **propagation** check
polls the public resolvers and reports **propagated X/N** after an edit. Read-only;
queries only a fixed resolver allowlist and the zone's authoritative NS
(private / loopback / link-local / metadata addresses filtered).
`GET /api/dns/resolve`, `GET /api/dns/propagation`.

### Resolver health monitor
Turn a name into an ongoing check: it is re-resolved across the public resolvers
on a rate-limited cadence, tracking **latency** and **NXDOMAIN / failure** rates.
When a name stops resolving for two consecutive checks it raises a flap-dampened
`resolver_unhealthy` alert; when it resolves again `resolver_recovered` clears it.
`GET/POST /api/resolver-health/targets`, `DELETE …/<id>`, `POST …/scan`.

### Alert-resolution timeline (MTTR)
The **Alerts** page gains a **Resolution timeline (MTTR)** section: time-to-
resolution and time-to-ack across recently-resolved alerts (mean / median over
7 / 30 / 90 days), a per-host breakdown, and a timeline classifying how each alert
was closed — auto (recover event), manual (operator), or muted — with who and the
note. Pairs with the ack-webhook. `GET /api/alerts/resolution-stats`.

## v4.10.0 additions — "PerimeterMatters"

### Firewall + fail2ban (Security → Firewall)
A fleet-wide page that views *and* edits host firewalls and fail2ban. The
firewall table shows every host's posture (nftables / iptables / ufw / firewalld
— backend, default policy, active state, rule count, drift fingerprint); opening
a host shows its ruleset grouped by table/chain (volatile packet counters
stripped) with **add/delete** for ufw/firewalld port rules and raw
nftables/iptables rules. A second table lists fail2ban jails and banned IPs with
**ban / unban** and **start / stop jail**. Every edit rides the existing audited,
`command`-permission-gated, quarantine-aware command queue, and rule specs are
strictly validated server-side (no shell metacharacters). Read-only visibility
needs no special permission. The agent reports capped per-backend rule lists and
fail2ban status; the containerized agent reports fail2ban as not-available.

### AI Insights hub (20 features)
The AI Assistant page gains a grid of 20 one-click AI reports and advisors —
**Proactive** (daily briefing, log-anomaly digest, alert-noise tuning,
predictive-maintenance), **Incident** (RCA, group-related-alerts, change-risk
review), **Natural-language → config** (fleet query → filter, monitor/check from
text, reverse-IaC), **Planning** (CVE plan, compliance plan, capacity forecast,
DR-readiness) and **Advisors** (firewall auditor, DNS hygiene, email
deliverability, homelab assistant, supply-chain/SBOM, host one-pager). Each is a
tunable system prompt with RAG + fleet context attached, rate-limited, audited
and redaction-aware.

### Three new RAG sources
The fleet-knowledge index that powers "Ask my fleet" now also covers per-host
**firewall/fail2ban** posture, **homelab integration** health and **backup**
freshness (each with a fleet rollup; rule *counts* only, no secrets). Toggle
under Settings → AI → RAG.


---

← [Back to docs index](README.md) · [Back to main README](../README.md)

## What's new in v5.1.0 — "VigilMatters"

A security-signal and reach-outward release. No breaking changes.

- **App catalog.** One-click deploy of curated, self-contained apps to a host
  via Docker Compose — pick an app, pick a host, and RemotePower instantiates
  the compose stack through the proven, audited deploy path. v5.1.0 adds
  admin-managed **custom catalog entries**: paste your own compose template to
  add it to the shared catalog. Gated on the `containers` permission, audited.
- **Cron & timer management.** View and manage a host's crontabs and systemd
  timers. Edits ride the same audited, permission-gated command queue as remote
  exec; crontab content is installed via a temporary file, never a shell, and
  is quarantine- and audit-mode-aware.
- **Custom HTTP probe plugin.** A code-free, declarative integration plugin:
  point it at an HTTP endpoint and turn the response (status, body, or a JSON
  field) into a health / integration signal — no connector code to write. The
  target URL is SSRF-guarded like every other outbound integration.
- **Malware / AV alerting.** Active-infection detections from ClamAV or
  rkhunter now raise a first-class `av_infected` alert (edge-triggered when an
  infected count rises) instead of only surfacing as a posture card.
- **Arabic right-to-left layout** and additional UI translations across the
  Firewall, Reputation, AI, Alerts, and Checks pages.

## What's new in v5.0.1 — "TemperMatters"

A stability + polish release that tempers v5.0.0. No breaking changes.

- **Backend-correctness sweep.** Fixed a class of presence-checks that silently
  read empty under the optional SQLite/PostgreSQL backend — the SSH-key drift
  audit, Proxmox stale-snapshot alerts, and the device-drawer host-config view
  now work on every backend.
- **Quieter upgrades.** Duplicate open alerts for the same condition now coalesce
  into one row, and agent stop/start events no longer alert or webhook by default
  (they're expected upgrade churn — still in Recent Activity, re-enableable).
- **Edit in place.** API keys can be edited (name, role, expiry, rate limit)
  without regenerating the secret; custom checks gained an Edit button.
- **Backups survive redeploys.** `RP_BACKUP_PASSPHRASE` loads from
  `/etc/remotepower/api.env` (the unit's `EnvironmentFile`), so an upgrade can't
  wipe it; a turnkey self-update script ships for the "Run update now" button.
- **More AI advisors.** Three new one-click AI Insights — TLS/cert triage, CVE
  prioritisation, and "investigate the top alert."
- **Signature button + polish.** A distinctive chamfer button treatment, EPSS
  exploit-probability scores fixed (the feed had moved hosts), and a
  whole-project security + SAST/CodeQL review (see
  [security-review-5.0.1.md](security-review-5.0.1.md)).

## What's new in v5.0.0 — "CTRLMatters"

A control-plane hardening and scale release: stronger agent trust, encrypted
disaster-recovery backups, a two-person rule for revealing secrets, and a set of
reliability and fleet-management features for running RemotePower at scale. No
breaking changes, no schema changes.

### Mutual-TLS agent authentication
Agents can now present a CA-verified **client certificate** on every connection,
pinned per device, so the server only accepts heartbeats from a known agent and
not just anyone holding an enrolment token. Optional and additive — turn it on
per device, or enforce it fleet-wide once every agent has a certificate.

### Encrypted disaster-recovery backups
RemotePower can encrypt its data backups **at rest with AES-256-GCM**, with the
key derived (PBKDF2-SHA256) from a passphrase supplied in the environment — the
passphrase never lands on disk. Restore is symmetric: provide the same
passphrase and the bundle decrypts.

### Break-glass credential reveals (two-person rule)
Revealing a stored credential can require **two people**: one operator requests,
a second admin approves, and the whole exchange is written to the immutable
audit log and raises a `vault_break_glass` alert. For the most sensitive secrets,
no single account can read them alone.

### Per-API-key rate limits
Each named API key now carries its own request budget, so an automation key that
runs away — or is leaked — can't exhaust the server. Limits are configurable per
key and enforced independently of the per-IP login throttle.

### Reliability & operations
- **Disk-space watchdog** — the server monitors its own free space and fires
  `server_disk_low` / `server_disk_ok` before a full disk corrupts state.
- **Webhook dead-letter queue** — deliveries that exhaust their retries land in a
  dead-letter queue you can inspect and **replay** once the destination is back.
- **Maintenance mode** — a runtime switch that drains and **pauses command
  dispatch** during an upgrade, without taking the dashboard offline.
- **OSV circuit breaker** — the CVE scanner backs off automatically when the OSV
  feed is unhealthy instead of hammering it.

### Fleet management at scale
- **Bulk delete & re-tag** — select many devices and remove or tag them in one
  action.
- **Per-command execution timeouts** — override the default command timeout on a
  single run for jobs that legitimately take longer.
- **Version-compatibility checks** — the server flags agents whose version is
  too far out of step before they cause surprises.
- **Rollout rollback** — one-click rollback for a staged script rollout that went
  wrong.

### NOC Status Board & design refresh
A new **Status Board** rolls the fleet up into **group / site / tag tiles** with a
**problem-host strip** for an at-a-glance NOC wallboard view, alongside an
industrial visual refresh across the dashboard.

### CMDB: network interfaces + NAT mapping
Each asset can record **multiple network interfaces**, each with its own optional
**NAT / public IP** — a host with several NICs and several 1:1-NAT mappings is
fully expressible. One interface is flagged **primary** (★). The editor is a
simple add/remove row list with a live preview tree, and in the CMDB table every
NAT address shows nested under the asset as a child (`iface → NAT`). The legacy
single primary-interface/NAT fields stay in sync with the primary row for
backward compatibility.

### Decommissioned assets
Mark a retired server **Decommissioned** from its CMDB record. It greys out across
the device list (card and minimal views) and the CMDB table with a *DECOMMED*
badge, and is **fully silenced** — no monitoring, alerts, health scoring or SLA.
Clearing the flag restores monitoring. (Decommissioning forces monitoring off, so
nothing pages you about a box you've retired.)

### Network Metrics page
A new **Network metrics** page shows per-device throughput (RX/TX) from the
agents' interface samples, with a **fleet-wide / by-group / by-tag / by-site**
scope selector (a site represents a customer). It surfaces fleet totals, a
top-talkers table (sortable, with the busiest interface per host), and per-scope
roll-ups. Unmonitored and decommissioned hosts are shown but flagged.

### Accessibility
Every table column header now carries `scope="col"` so screen readers announce
the right column; icon-only buttons expose an `aria-label`, and purely decorative
icons are hidden from assistive tech.

### Encrypt backups from the web UI
Already have plaintext backup archives? Migrate them to **AES-256-GCM at rest**
from **Server status → Backup → "Encrypt existing backups"** — you supply a
passphrase that's used for that request only and never stored. (For ongoing
scheduled backups, set `RP_BACKUP_PASSPHRASE` so new snapshots are encrypted at
write time — put it in `/etc/remotepower/api.env`, which the SCGI worker unit
reads via `EnvironmentFile=`; don't add it as an inline `Environment=` line, that
file is overwritten on every redeploy.)

### Network map — scope to a slice
The topology map now has a **site / group / tag scope picker** so a big fleet
stays legible: pick a site (a site can represent a customer) and the map renders
just those nodes instead of all of them at once.

### Ticket-system integrations (Jira / ServiceNow / Zendesk)
A webhook destination can use a ready-made **Jira**, **ServiceNow** or **Zendesk**
format. Combined with "Also fire on alert ACK", acknowledging an alert opens a
ticket in your ITSM tool over its REST API (HTTP Basic auth over HTTPS), and the
new ticket's **link is shown right on the alert**.

### Install update
**Settings → Install** checks the running version against the latest published
release and shows the upgrade commands for your install method. For hands-off
upgrades you can point it at a server-side **update script** (absolute path) and
trigger a **guided self-update** from the button — your script pulls the new
version and restarts the service the way your install expects.

### Login banner
An optional **login banner / security notice** (e.g. "Authorized use only") shown
above the sign-in form, set in Settings.
