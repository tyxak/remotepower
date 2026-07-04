# Fleet & agent management

How to operate the fleet from the RemotePower dashboard — updating agents,
signing releases, watching the command queue, installing/uninstalling software,
and the other server-driven actions. (For the agent's local CLI, see
[agent-commands.md](agent-commands.md).)

## Updating agents (self-update)

Agents poll the server and compare their own binary's SHA-256 against the
server's canonical hash; a mismatch in either direction triggers a download and
restart. You don't push updates — you publish a new agent binary on the server
(`deploy-server.sh`) and agents converge within ~1 hour.

- **Force an update now, on the host:** `sudo remotepower-agent update`.
- **Force from the server:** the upgrade/exec flow can queue an `update` command
  to a device; it runs on the device's next heartbeat.
- **Verify integrity:** `sudo remotepower-agent integrity` compares the running
  binary's hash to the server's. The dashboard also shows an integrity badge per
  device (verified / mismatch).

## Restarting the agent

On the host: `systemctl restart remotepower-agent`. Logs:
`journalctl -u remotepower-agent -f`. A restart re-reads config and re-detects
watched units; it does not re-enrol (history/tags/group are preserved).

## Release signing (agents refuse unsigned updates)

RemotePower can cryptographically sign the published agent so agents refuse any
self-update that isn't validly signed by your key — defending against a
tampered/compromised file server.

- **Server-side signing (convenient):** Admin → Release Signing → *Generate
  signing key*, then *Sign current agent*. The server holds the private key and
  signs on demand. This protects against tampering at rest, not a full server
  compromise (the page says so).
- **Enforcement:** toggle it on so agents that have the public key pinned
  (`/etc/remotepower/release.pub`) reject unsigned/invalid updates. Disabling
  enforcement and signing both re-verify the admin password.
- **"signed but INVALID":** means the published binary changed after it was
  signed (every deploy republishes it). Click *Sign current agent* to re-sign;
  `deploy-server.sh` also re-signs automatically when a server key exists, so it
  stays valid across deploys. For the strongest guarantee, sign off-server in CI
  with `tools/sign-agent-release.sh` and only publish the public key here.

## Command queue (what's waiting for an agent)

**Admin → Command Queue** shows every device with commands still waiting to be
delivered on its next heartbeat — the type (exec / reboot / poll / compose /
acme / …) and a readable summary. Handy when a host is offline and you want to
see, or cancel, what's pending. You can cancel an individual queued command or
clear a device's whole queue. Anything already delivered to the agent has left
the queue. `GET /api/command-queue`,
`DELETE /api/devices/<id>/command-queue[?index=N]` (admin-only, audited).

## Install / uninstall software

From the **Patches** page (or the Rollouts page's one-time install): install or
remove repo packages on a device, or across a whole **group or tag**, through
the host's own package manager (apt / dnf / yum / zypper / pacman / apk). Targets
are chosen from dropdowns of the fleet's real groups/tags/devices. Each run is
tracked as a batch job with per-host status on the Rollouts page.

- **Install:** `POST /api/install`. **Uninstall:** `POST /api/uninstall` (removes
  the named packages only — no dependency auto-removal or config purge).
- Gated on the `exec` permission, and honours device quarantine and maintenance
  change-windows like any queued command.

## Reboot, shutdown, Wake-on-LAN

Per-device actions from the device drawer / Devices page. Reboot and shutdown are
power actions gated on the `reboot` permission and (for `require_confirmation`
devices) queued for human approval. Wake-on-LAN sends a magic packet to the
device's recorded MAC.

## Enrolment auto-placement rules

New agents don't have to land ungrouped. Under **Settings → Sites & teams →
Auto-placement rules**, define rules that stamp a device's **group**, **site**
and **tags** the moment it enrols, matched by either:

- **Hostname** — a regex tested against the reported hostname (`^web-`,
  `\.dc1\.` …).
- **Source IP** — a CIDR the enrolling agent's address must fall in
  (`10.20.0.0/16`).

The **first** matching rule applies. Precedence is deliberate: an enrolment
**token**'s `default_group` / `default_tags` always win — a rule only fills a
group that would otherwise be empty and *adds* tags, and freely sets the site
(tokens have no site). Rules run **only at first enrolment**; they never
re-place an already-known device (re-enrolment preserves its group/site/tags).
Stored in config (`enrol_rules`); hostname regexes and CIDRs are validated when
you save.

## Quarantine

A per-device switch that disables exec / reboot / all actions, enforced
server-side at the command-dispatch chokepoint and audited — isolate a suspect
host in one click. Quarantined devices drop queued commands rather than running
them when quarantine lifts.

## SLA targets

On the **Reports → Uptime (SLA)** card you can set a target uptime % per device,
tag, group, or a fleet default (most specific wins); each row shows whether it's
met or breached. `GET`/`PUT /api/fleet/sla-targets`.

## OpenSCAP compliance scans

Queue an `oscap` scan by device / group / tag with a chosen profile. The content
must match the host's OS: Ubuntu uses Canonical's `usg` (install it; the agent
drives it automatically for CIS/STIG profiles), Debian uses `ssg-debian` + the
ANSSI BP-028 profiles, RHEL/Fedora use `scap-security-guide`. A scan that finds
no applicable rules reports why and what to install.

## Investigate (AI mitigation) from Needs Attention

Items in Needs Attention that have a mitigation playbook show an **Investigate**
button: it queues a read-only diagnostic on the device, then runs an AI analysis
that proposes a fix command (which you confirm before it runs). Roughly 21 kinds
are covered: disk, memory, swap, cpu, pending patches, config drift, service
down, reboot required, brute-force attempts, CVE findings, and stopped/restarting
containers — plus malware / antivirus posture, stale agent version, end-of-life
OS, hardware health, stale/missing backup, a new SSH key, a new listening port,
agent integrity, log-pattern alerts, and failed systemd units.
