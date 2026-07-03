# RemotePower cookbook

Task-shaped recipes: "I want to do X — here are the steps." The rest of the docs
explain *what* each feature is; this page strings them into end-to-end workflows.
Each recipe is self-contained and links to the reference guide for the detail.

- [Monitor a new host end-to-end](#monitor-a-new-host-end-to-end)
- [Watch a service and get paged when it dies](#watch-a-service-and-get-paged-when-it-dies)
- [Set up 3-2-1 backups you can trust](#set-up-3-2-1-backups-you-can-trust)
- [Page me only for real problems (tame the noise)](#page-me-only-for-real-problems)
- [Monitor a Proxmox node and its guests](#monitor-a-proxmox-node-and-its-guests)
- [Watch a switch/printer with no agent (SNMP)](#watch-an-agentless-device-with-snmp)
- [Onboard a segmented site with a satellite](#onboard-a-segmented-site-with-a-satellite)
- [Watch a GitHub repo for new issues](#watch-a-github-repo-for-new-issues)
- [Keep certificates from expiring](#keep-certificates-from-expiring)
- [Roll out a patch or script safely](#roll-out-a-change-safely)

---

## Monitor a new host end-to-end

1. **Enrol the agent.** Dashboard → **Devices → Enroll device**. Copy the
   one-line install command (or generate a PIN) and run it on the target:
   ```bash
   wget -qO- "https://your-server/install?t=<token>" | sudo sh
   ```
   The host appears by hostname within ~60 s.
2. **Confirm it's reporting.** Open the device drawer → **System Info**: CPU,
   memory, disk, kernel, top processes. If it's a container host, the
   **Containers** section lists them.
3. **Set thresholds (optional).** Device drawer → **Settings** → metric warn/crit
   percentages. Fleet-wide defaults live in **Settings → Monitoring**.
4. **Add it to a group/site.** Device drawer → tags/group/site — this is what
   scopes reports, SLAs and maintenance windows later.

Reference: [agentless-devices.md](agentless-devices.md), [fleet-management.md](fleet-management.md).

## Watch a service and get paged when it dies

1. **Add the unit to the watch list.** Device drawer → **Services** → add the
   systemd unit (e.g. `nginx.service`). Or set a fleet default under
   **Monitoring → Service baselines** so every matching host watches it with no
   per-host editing.
2. **A stop fires `service_down`** — it lands in the Alerts inbox and routes to
   your channels. When it comes back, `service_up` auto-resolves it.
3. **Wire a channel** if you haven't: **Settings → Notifications** → add a webhook
   (Slack/Discord/Teams/ntfy/Telegram/Gotify/Matrix/…) or email/SMTP.
4. **One-click fix.** When a `service_down` alert is open, its row shows a **Fix**
   button → guided diagnostic → optional AI analysis → pre-approved restart.

Reference: [monitors.md](monitors.md), [mitigation.md](mitigation.md).

## Set up 3-2-1 backups you can trust

The rule: **3** copies, on **2** different media/targets, **1** off-site.

1. **Tell RemotePower which paths to watch.** **Settings → Advanced → Backup
   monitors** → add each backup destination path + a max-age threshold. The agent
   reports each path's freshness every heartbeat.
2. **Enable integrity verification** per monitor (v4.10.0) so a *present* backup
   is also proven *restorable*, not just fresh.
3. **Add an off-site leg** — a monitor whose target is a remote/PBS/S3/rsync
   destination. RemotePower infers the "off-site" leg from the target.
4. **Read the score.** Device drawer → **Backups**: the **3-2-1 rule** chip row
   shows which legs pass. It's informational — the `backup_stale` /
   `backup_verify_failed` events are what page you.

Reference: [backups.md](backups.md).

## Page me only for real problems

Noise is the #1 reason people stop reading alerts. Tune it:

1. **Mute a specific noisy alert.** On any alert row → **Mute** silences that exact
   (host, event) pair. Lift it later under **Monitoring → Tuning**, which also
   ranks your noisiest alerts.
2. **Route by kind.** **Settings → Notifications** → each event *kind* has
   per-channel toggles (inbox / activity feed / webhook / needs-attention). Turn
   webhook/push off for chatty kinds (new ports, GitHub issues) and keep them for
   outages.
3. **Set per-severity escalation.** **Settings → Notifications → Escalation** —
   only page after N minutes unacknowledged, per severity.
4. **Suppress during known work.** Create a **maintenance window** (below) so
   expected churn doesn't alert at all.

Reference: [alert-tuning.md](alert-tuning.md), [automations.md](automations.md).

## Monitor a Proxmox node and its guests

1. **Add the node as a device** (agent install on the PVE host, or agentless).
2. **Add a Proxmox Backup Server integration** — **Settings → Integrations** →
   type **Proxmox Backup Server**, point it at the PBS API with a token. Datastore
   health + fullest-datastore % show as a tile.
3. **Snapshot age alerts.** RemotePower flags Proxmox snapshots older than
   `proxmox_snapshot_warn_days`.
4. **Lifecycle control.** For vSphere/vCenter/OpenShift/Cloud Director, the
   **Virtualization** page lists VMs with power + snapshot actions.

Reference: [integrations.md](integrations.md), [virtualization.md](virtualization.md).

## Watch an agentless device with SNMP

For switches, APs, printers, IPMI/BMC cards, NAS boxes — anything that can't run
the agent.

1. **Add the device** with its IP (Devices → add, or import from a network scan).
2. **Enable SNMP.** Device drawer → **Settings → SNMP polling** → tick enable.
   - **SNMPv2c:** enter the community string.
   - **SNMPv3:** pick the version, set the user, auth protocol + password
     (MD5/SHA-1/SHA-2) and optional AES privacy. Passwords are write-only.
3. **Poll now** to confirm, then it re-polls every 5 min: sysDescr/uptime,
   CPU/storage tables, and vendor health (Mikrotik/Synology). Failures raise
   `snmp_unreachable`.

Reference: (SNMP section in) [features.md](features.md).

## Onboard a segmented site with a satellite

When agents can't reach the central server directly (isolated VLAN, remote site):

1. **Register a satellite** on the central server and deploy the relay in the
   segment.
2. **Point that segment's agents at the satellite** — it forwards their traffic to
   the server; the agent's own token still authenticates end-to-end.
3. Optionally let the satellite run **network scans** for its segment.

Reference: [satellites.md](satellites.md).

## Watch a GitHub repo for new issues

1. **Settings → Integrations** → type **GitHub Issues**.
2. **URL** = `https://api.github.com` (or your GitHub Enterprise `/api/v3` root).
3. **Repositories** = `owner/repo, owner/repo` (up to 10). Add a token for private
   repos / to lift the rate limit.
4. A newly opened issue raises `github_new_issue` in the Alerts inbox (PRs
   ignored; the first poll only baselines). To also get paged, enable the
   **GitHub new issues** kind's webhook/push routing under Notifications.

Reference: [integrations.md](integrations.md).

## Keep certificates from expiring

1. **Add the endpoints.** TLS / DNS page → **Add target** (hostname + port; set
   warn/critical days). DANE and STARTTLS are supported.
2. The server **re-probes every ~6 hours on its own** — no cron needed — and
   raises `tls_expiry` as a target crosses its warn/critical threshold.
3. For certs RemotePower *issues* (ACME), the **ACME** page handles renewal.

Reference: [tls-monitor.md](tls-monitor.md), [acme.md](acme.md).

## Roll out a change safely

Whether it's a script, a package upgrade or a config push, don't fan it to the
whole fleet at once:

1. **Use a health-gated rollout** (Provisioning / rollouts): define rings
   (canary → wave 2 → rest). Each ring dispatches, then RemotePower watches the
   dispatched hosts' health; if any drops below the floor, the rollout **halts**
   and fires `rollout_halted`.
2. **Gate reboots to a window.** Create a maintenance window with *exec gating* so
   the reboot leg waits until the window opens; the window also **suppresses** the
   predictable alert churn (metrics, drift, reboot-required, container restarts).
3. **Require a second admin** for destructive actions — enable change-approval so
   reboot/upgrade/uninstall park for a second admin's approval (no self-approve).

Reference: [provisioning.md](provisioning.md), [fleet-management.md](fleet-management.md).
