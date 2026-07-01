# Virtualization

RemotePower manages virtual machines across several hypervisors from one
**Virtualization** page in the sidebar. Proxmox VE has always been supported
through its own dedicated client; **v5.6.0** brings VMware and OpenShift up to
the same lifecycle level.

Supported platforms:

| Platform | How it connects | Lifecycle |
|---|---|---|
| **Proxmox VE** | Scoped API token (Settings → Virtualization) | List, start / shutdown / reboot, snapshots, clone / migrate, VM & LXC create/delete |
| **VMware vSphere / ESXi / vCenter** | Username + password, vCenter REST API | List, power (start / stop / shutdown / reboot / reset / suspend), snapshots |
| **VMware Cloud Director** | Username + password (org), Cloud Director API | List, power, snapshots |
| **OpenShift Virtualization (KubeVirt)** | ServiceAccount bearer token | List, start / stop / restart, snapshots |

## Configuring a platform

Everything is configured under **Settings → Virtualization**:

- **Proxmox** — one node, via a scoped API token. See the Proxmox card.
- **VMware / OpenShift / Cloud Director** — added as integration instances (URL,
  username/token, verify-TLS). They also appear as read-only homelab connectors
  so their health shows on the dashboard.

All outbound calls go through RemotePower's SSRF-guarded HTTP client: the target
IP is re-validated at connect time (anti-rebinding), redirects are refused, and
loopback / link-local / cloud-metadata addresses are blocked.

## Using the Virtualization page

When more than one platform is configured, a **platform picker** appears at the
top of the page. Pick a platform to list its guests. Each guest shows its name,
power state, vCPU / memory and host (or namespace, for OpenShift).

- **Power** — buttons are filtered to what the platform actually supports (for
  example OpenShift offers start / stop / restart). Hard actions (stop, reset)
  are styled as destructive and always ask for confirmation.
- **Snapshots** — open the snapshot dialog to create, revert (type-to-confirm,
  since revert is destructive) or delete snapshots.
- **Search** — filter the guest list by name or id.

## Security & permissions

- **Reads** (listing guests and snapshots) are available to any authenticated
  user.
- **Mutations** (power and snapshot actions) require the **admin** role and are
  written to the audit log.
- VM and snapshot identifiers supplied to the API are reduced to a single
  URL-quoted path segment (OpenShift `namespace/name` is validated as an
  RFC-1123 label pair), so a crafted id can never redirect an authenticated call
  to a different host or API path.

## REST API

| Method & path | Purpose |
|---|---|
| `GET /api/virt/platforms` | Lifecycle-capable platforms for the page picker (no secrets) |
| `GET /api/virt/{id}/vms` | List guests on platform `{id}` |
| `POST /api/virt/{id}/power` | `{vm_id, action}` — power action (admin) |
| `GET /api/virt/{id}/snapshots?vm=<id>` | List snapshots for one guest |
| `POST /api/virt/{id}/snapshot` | `{vm_id, action, name, desc}` — create / revert / delete (admin) |

`{id}` is the integration instance id from `GET /api/virt/platforms`. Proxmox
keeps its own `/api/proxmox/*` endpoints.
