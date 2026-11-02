# App Catalog

**Automation → App Catalog** is one-click deployment of curated,
self-contained applications to a host via **Docker Compose**.

## How it works

- Pick an app from the catalog and a target host; RemotePower renders its
  compose stack and deploys it over the host's existing compose path.
- The target host must have **compose deploys enabled**, a per-host opt-in
  set from the host drawer. Hosts without it are not eligible.
- An admin can add **custom apps** to the shared catalog: a name, a compose
  YAML, and optionally a category, description and port. Adding one only
  stores a template. Deploying it still goes through the same permission-gated,
  audited path.
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

Any signed-in user can browse the catalog. Deploying from it requires the
**containers** action permission (or admin), and the target host must have
compose deploys enabled. Adding or deleting a custom app is admin-only. Every
deploy is audit-logged.
