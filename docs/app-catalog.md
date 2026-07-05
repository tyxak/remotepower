# App catalog

**Patching → App catalog** is one-click deployment of curated,
self-contained applications to a host via **Docker Compose**.

## How it works

- Pick an app from the catalog and a target device; RemotePower renders its
  compose stack and deploys it over the host's existing compose path.
- The target device must have **compose deploys enabled** — a per-device opt-in
  set from the device drawer (Devices → drawer). Hosts without it opted in are
  not eligible.
- Each app is **self-contained** (its own compose file and defaults), so a
  deploy is reproducible and easy to remove.

## Safety

- Deploys are **gated on the `containers` permission** and fully **audited**.
- The deploy rides the same audited command pipeline as any other container
  action — quarantined / audit-mode hosts are skipped.

## Related

- Manage running containers (start / stop / logs, compose stacks) on the
  [Containers](containers.md) page.
- For your *own* infrastructure templates (Terraform / cloud-init / Ansible),
  see [Provisioning](provisioning.md).

## Permissions

Deploying from the catalog requires the **containers** action permission (or
admin), and the target device must have compose deploys enabled. Every deploy is
audit-logged.
