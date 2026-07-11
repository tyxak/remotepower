# Settings — the complete guide

Everything under **Settings** in one place: what each tab does, the key knobs,
and where to read more. Settings is a left-nav on wide screens (a horizontal
strip on narrow ones), grouped into four sections — **Setup**, **Monitoring**,
**Connections**, and **System**. Most changes require an admin role; read-only
roles see the pages but can't save.

> Tip: almost every section has a short inline hint and, where a deeper guide
> exists, a link to it. This page is the map; the per-topic docs are the detail.

---

## Setup

### Install
Enrolment and agent lifecycle. Copy the one-line install command for a new host
(it embeds the server URL and a single-use, 10-minute enrolment PIN), see the
agent versions in your fleet, and trigger a guided server self-update when one is
configured. See [install.md](install.md) and [agent-commands.md](agent-commands.md).

### General
The instance basics:

- **Server identity** — the display name and base URL used in links and the
  agent install command.
- **Default poll interval** / **Online TTL** — how often agents heartbeat and how
  long before a silent agent counts as offline.
- **Monitor check interval** — cadence for the synthetic monitors (TCP/HTTP/TLS/
  DNS/ping). See [monitors.md](monitors.md).
- **Wake-on-LAN**, **RDP remote access**, **Healthchecks.io watchdog**.
- **Reboot / shutdown blast-radius guardrail** — a fleet-wide cap so a bulk
  reboot/shutdown can't take out more hosts than you intend.

---

## Monitoring

### Notifications
Where alerts go. Configure **webhook destinations** (Slack/Discord/Teams/generic,
and ntfy/gotify/Pushover), **email (SMTP)**, and the **per-event toggles** that
route each event kind to the right channel. Secrets (webhook URLs, SMTP
passwords) are stored server-side and never echoed back — re-enter to change. The
**webhook log** shows recent deliveries. See [webhooks.md](webhooks.md).

### Alerting
The alerts inbox behaviour and dashboard widgets: **incident auto-promotion**,
ack-comment prompts, alert correlation/host-folding, and the customizable
dashboard widget set. On multi-tenant instances the inbox and its badge counts
are scoped to your tenant. See [alerts.md](alerts.md).

### Mailbox monitor
Optional IMAP mailbox watch (queue depth, unread age) surfaced as fleet health.
See [monitors.md](monitors.md).

### Ignored items
Mute rules and exposure mutes — silence a specific (host, event) pair or an
expected open port without losing the underlying record (the Tuning page can
still surface and lift them).

---

## Connections

### Integrations
Homelab and infrastructure connectors — a `health(instance, client)` parser per
platform, plus third-party **connector plugins** dropped into `connectors.d/` on
the server (filesystem-only, root-owned; reload without a restart). Every
outbound call uses the SSRF-safe path (connect-time peer-IP recheck, no redirects,
metadata/loopback blocked). Cloud import (AWS/Hetzner/DigitalOcean), metrics push
(Prometheus), GitOps, and the public status page live here too. Instance URLs and
secrets are admin-gated and withheld on read. See
[integrations.md](integrations.md).

### Virtualization
Proxmox plus VMware vSphere/vCenter, VMware Cloud Director and OpenShift
Virtualization (KubeVirt): list guests, power actions, and snapshots, all through
the same SSRF-guarded client. See [virtualization.md](virtualization.md).

### AI assistant
The AI advisor and RAG knowledge base: pick a provider (or a separate embedding
provider), choose which fleet-knowledge **sources** feed the vector store, and
enable the inline "AI review" buttons. Operator-authored fields with
secret-shaped names are filtered out of the corpus before embedding. See
[ai.md](ai.md) and [rag.md](rag.md).

---

## System

### Security
The trust-boundary controls: **tokens** and API keys, **relay satellites**,
SSO/identity (**OIDC**, **SAML 2.0**, **SCIM** provisioning, **LDAP/LDAPS**),
**SIEM event streaming** and **OpenTelemetry (OTLP)** export, browser push,
**IP allowlist**, session/step-up policy, mutual-TLS agent auth, and the
break-glass credential rules. See [security.md](security.md) and
[admin-guide.md](admin-guide.md).

### Tickets
The built-in ticketing/ITSM module: SLA policy per type, auto-routing, portal
approval gate, and email-to-ticket. See [ticket-system.md](ticket-system.md).

### Backups
Scheduled, optionally AES-256-GCM-encrypted data backups (passphrase from the
environment, never persisted), retention/RPO grading, and restore. See
[backups.md](backups.md).

### Advanced
Instance-wide toggles and less-common knobs: the homelab kill switch, IaC
execution gate, the agent-push (wake-nudge) channel, data-retention and
litigation hold, and other feature flags. Changing anything here affects the
whole instance — read the inline hint first.

---

## Related

- **Server status / self-monitoring** (RemotePower watching itself, plus the
  distributed-subsystem health card): see [self-monitoring.md](self-monitoring.md).
- **Scaling** (Postgres, the out-of-band scheduler, relay/scan-worker
  satellites): [scaling.md](scaling.md).
- **Roles & permissions**: [admin-guide.md](admin-guide.md).
- Full dated history of settings changes: [../CHANGELOG.md](../CHANGELOG.md).
