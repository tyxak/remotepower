# Settings — the complete guide

Everything under **Admin → Settings** in one place: what each tab holds, the key
knobs, and where to read more. On wide screens Settings is a left-hand list of
tabs, grouped into four sections: **Setup**, **Monitoring**, **Connections** and
**System**. On narrow screens it is a horizontal strip.

> Almost every section has a short hint and, where a deeper guide exists, a
> **Documentation** link. This page is the map. The per-topic guides are the detail.

## Saving, permissions and bookmarks

- **Save settings** at the bottom saves the whole form. **Reload** discards what you
  typed and reads the saved values again. **Send test webhook** next to them tests
  your webhook destinations.
- Settings need an **admin**. Other roles can open the page but cannot save. With
  multi-tenancy on, only the platform operator saves instance settings, and a tenant
  admin gets "Instance settings are managed by the platform operator".
- A few switches decide who can do what. Changing change approval, the roles that
  need MFA, SSO-only sign-in, the IP allowlist, the audit-log sink, retention or
  forwarding, tenancy enforcement or the litigation hold asks you to confirm your
  password or a one-time code first (a "step-up"). So does restoring a backup, and
  restoring a configuration revision that changes one of these. The confirmation
  stays valid for ten minutes.
- Blank a threshold field to go back to its default.
- Every tab has an address you can bookmark: `#settings/general`,
  `#settings/install`, `#settings/dashboard` (Alerting), `#settings/alertparams`,
  `#settings/ignored`, `#settings/notifs`, `#settings/mailbox`,
  `#settings/integrations`, `#settings/proxmox` (Virtualization), `#settings/ai`,
  `#settings/security`, `#settings/backups`, `#settings/tickets` and
  `#settings/advanced`.
- Every change that alters something is kept in **Advanced → Configuration history**,
  and you can restore an earlier state from there.

---

## Setup

### General
The instance basics:

- **Server identity.** The server name (shown in the page title, push
  notifications and webhook payloads), an optional **login banner** shown above the
  sign-in form, and an optional **fleet-wide note** shown on the dashboard.
- **Default poll interval** (10 to 3600 seconds, default 60). How often newly
  enrolled agents check in. Existing hosts keep theirs. Change those from the host
  drawer.
- **Online TTL** (150 to 7200 seconds, default 300). A host with no heartbeat for this
  long counts as offline. The limit for a host is never shorter than five of its own
  poll intervals plus 10 seconds, so a slow poll does not flap it. Keep the TTL at
  least twice the poll interval. A lower value than 150 is refused.
- **Monitor check interval** (60 to 3600 seconds, default 300). Cadence for the
  synthetic monitors (TCP, HTTP, TLS, DNS, ping). A switch allows monitor targets on
  loopback and link-local addresses. It is off by default so monitors cannot probe
  the server itself or a cloud metadata address. See [monitors.md](monitors.md).
- **Wake-on-LAN.** The broadcast address and port for magic packets.
- **RDP remote access.** Off by default. Lets you reach a Windows host's desktop from
  the host drawer through an SSH tunnel to your own RDP client.

### Install
- **Getting started.** A checklist of the essentials for a new install. Each step
  shows your current state and links to where to do it.
- **Install update.** Compares the running version with the latest release.
  **Guided self-update** runs an update script you name, and **Restart server**
  restarts the app server when your install allows it. See
  [upgrading.md](upgrading.md) and [install.md](install.md).

---

## Monitoring

### Alerting
Detection and escalation rules that are not plain thresholds: **brute-force
detection**, **quiet hours** (hold non-critical notifications overnight),
**after-hours activity detection**, **service-dependency link alerts**, **on-call and
escalation tiers**, **backup file monitoring**, **process thresholds**, **log ignore
patterns** and the **channel routing** matrix that sets, for every alert kind,
whether it shows on Needs Attention, Recent Activity, the Alerts inbox or goes out
by webhook. See [alerts.md](alerts.md) and [oncall.md](oncall.md).
The same page holds **time periods**: named sets of hours that quiet hours, after-hours
detection, the ticket SLA clock and maintenance windows can share. See
[time-periods.md](time-periods.md).

### Alert parameters
The one filterable home for the numeric alert thresholds, the health-grade, risk
and reliability cutoffs, and the per-factor score weights. Blank a field to
restore its default. This is different from the Tuning page, which mutes noisy
alerts. See [alert-parameters.md](alert-parameters.md).

### Ignored items
Things you hid with the **×** button on Needs Attention cards or on the Containers
page. **Restore** brings one back. See [attention.md](attention.md).

### Notifications
Where alerts go:

- **Webhook destinations**, any number at once, each with its own format
  (Slack, Mattermost, Rocket.Chat, Google Chat, Discord, Microsoft Teams, Telegram, Matrix, ntfy, Gotify,
  Pushover, Apprise, PagerDuty, Opsgenie, GitHub, Jira, ServiceNow, Zendesk or generic JSON) and an optional
  event filter. The older single **Legacy webhook URL** still works.
- **Email (SMTP)** and **additional email routes**, each list with its own scope.
- **Per-event toggles** that switch each event kind on or off.
- **Webhook log**, with recent deliveries and the dead-letter queue of deliveries
  that failed for good.
- **Alerts inbox** (whether acknowledging asks for a comment) and **Incident
  auto-promotion** (open a status-page incident when the same alert fires on many
  hosts at once).
- **Healthchecks.io watchdog** and the **reboot and shutdown guardrail**, a cap on
  how many hosts one batch may restart or power off.

Secrets such as webhook URLs and SMTP passwords are stored on the server and never
shown again. Type a new value to change one. See [webhooks.md](webhooks.md).

### Mailbox monitor
Counts messages in a mailbox without IMAP or SMTP. Pick a host and give it the
directories to watch. The agent counts the files in each (in a Maildir, the `new`
folder holds one file per unread message). You can show the count on the dashboard
and set a threshold that fires a webhook.

---

## Connections

### Integrations
Everything that connects RemotePower to other systems:

- **Homelab software integrations** and **connector plugins** (third-party
  connectors dropped into `connectors.d/` on the server, with no upload from the
  browser).
- **Cloud import** (AWS EC2, Hetzner, DigitalOcean), **metrics push** (Prometheus),
  and **GitOps** for drift profiles.
- **Status endpoint** and **Public status page**, see
  [status-board.md](status-board.md).
- **Inbound webhooks and syslog** tokens, **SNMP trap rules** and **relay
  satellites**.
- Identity: **OIDC**, **SAML 2.0**, **SCIM** provisioning and **LDAP/LDAPS**, see
  [sso.md](sso.md).
- **SIEM event streaming**, **OpenTelemetry (OTLP)** export and **browser push
  notifications**.

Every outbound call goes through the SSRF-safe path. Instance URLs and secrets are
admin-only and withheld on read. See [integrations.md](integrations.md).

### Virtualization
Proxmox VE, plus VMware vSphere/vCenter, VMware Cloud Director and OpenShift
Virtualization: list guests, power actions and snapshots. See
[virtualization.md](virtualization.md).

### AI assistant
The AI provider, what is sent to it (hostnames and addresses are removed by
default), context, the knowledge index (RAG), spending limits, automatic alert
triage and prompt customization. See [ai.md](ai.md) and [rag.md](rag.md).

---

## System

### Security
The trust-boundary controls and the security opt-ins:

- Access: **IP allowlist**, **change approval** (a second admin approves chosen
  commands), **account guardrails**, **password policy**, **session length**, **agent
  mutual TLS**, **agentless SSH**.
- **Multi-tenancy**, its isolation-coverage report and the tenant list.
- **Audit log**, **audit log forwarding**, **compliance exports** and **Config as
  code**.
- Host checks and opt-in agent jobs: **security hardening**, **disk encryption** and
  **Secure Boot** checks, **listening-port and firewall audit**, **certificate file
  expiry**, **secrets-on-disk scanning**, **disk-usage explorer**, **regulated-data
  (PII) scan**, **canary files**, **container image scanning**, **service flap
  detection**, **Compose drift watch**, **Internet (WAN) watch**, **LAN service
  discovery (mDNS)**, **appliance config archive**, **warranty auto-lookup** and
  **login geolocation**.
- **Credential checkout** (just-in-time access to CMDB credentials), **UPS
  auto-shutdown**, **CVE details cache** and **CVE counts**.
- **Maintenance mode**, **Content-Security-Policy reporting**, **active sessions**.
- **Self-signed certificate**, **Import a certificate (.p12 / .pfx)** and the
  **Transport security (HSTS)** report.

Sign-in providers are under **Connections → Integrations**, not here. See
[security.md](security.md) and [admin-guide.md](admin-guide.md).

### Backups
**Scheduled backup** (on or off, output folder, retention, an off-host copy, RPO and
RTO targets, and **Test restore**), **Debug logging**, and **Backup & restore**: a
redacted ZIP export, a full backup of the data directory (which can rebuild the
whole server, so keep it private), and **Restore…**. See
[self-monitoring.md](self-monitoring.md#restoring-from-a-backup) and
[backups.md](backups.md).

### Tickets
The built-in helpdesk: mailbox polling and threading, **auto-reply**,
**satisfaction survey**, **business hours** and holidays for SLA timing, **SLA
targets** per priority, **canned replies**, **recurring tickets** and the **customer
portal**. See [ticket-system.md](ticket-system.md).

### Advanced
Instance-wide switches. Read the hint before you change anything here.

- **Configuration history.** The last 10 states, with restore.
- **Optional modules.** Turn off what you do not use: Alerts, Tickets, Billing,
  Knowledge base, Compliance, Pentest, AI executor, Autonomous remediation and SSH
  Gateway. A disabled module disappears from the sidebar and its API stops
  answering. Nothing is deleted, and switching it back on restores your data.
  Billing, Knowledge base, AI executor and SSH Gateway start off.
- **Provisioning, server-side execution**, the **agent push channel**,
  **white-label branding** (the product name, the default accent, a default
  look, which you can lock so that everyone uses it, and a default typeface),
  **audit-log retention**,
  the **storage backend**
  (JSON files, SQLite or PostgreSQL), **data retention and maintenance** and the
  **litigation hold**.

---

## Related

- **Server Status** (RemotePower watching itself): [self-monitoring.md](self-monitoring.md).
- **Scaling** (PostgreSQL, the out-of-band scheduler, satellites): [scaling.md](scaling.md).
- **Roles and permissions**: [admin-guide.md](admin-guide.md).
- What changed in each release: [../CHANGELOG.md](../CHANGELOG.md).

## With multi-tenancy

GitOps, metrics push and the other pages of Settings that act on the whole installation are for the platform operator. A tenant's administrator reads the numbers and switches its own pages draw, and nothing else of the settings document.
