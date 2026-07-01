# Provisioning — infrastructure blueprints

*(v5.6.0 "HeapMatters")*

**Provisioning** (Admin → Provisioning) is an opt-in catalog of infrastructure
**blueprints** organised in a folder tree: Terraform, cloud-init, Ansible and
iPXE templates. You fill in a blueprint's variables and either **render** it to
copy/download, or — for Terraform — **run** it on the server.

Enable it under **Settings → Advanced → Optional features → Provisioning**. The
former standalone **Ansible** page now lives here as an *Ansible playbooks* card.

## Blueprints

A blueprint has a **name**, a **folder** (path-like, e.g. `aws/dev`), a **kind**
(`terraform` / `cloud-init` / `ansible` / `ipxe`), the template **content**, and
optional declared **variables** (one per line in the editor:
`name | Label | default`, append `| secret` to mask).

## Render (all kinds)

Fill in the variables and **Render** to get the finished text to copy or
download. Two macros are always available:

- `${rp_server_url}` — this server's base URL.
- `${rp_agent_install}` — the real agent install one-liner
  (`curl -fsSL <server>/install | sudo sh -s -- --token <enrollment-token>`), so
  a cloud-init blueprint can bake the agent and a provisioned box auto-enrols.

Rendering is pure string substitution — nothing is executed. (Terraform
blueprints are returned **verbatim** on Render, because Terraform owns the
`${…}` interpolation syntax; Terraform values are supplied natively as
`var.<name>` at Run time, below.)

## Run Terraform (plan / apply / destroy)

Terraform blueprints can be executed **server-side** when you also enable
**Settings → Optional features → "Allow server-side execution"**
(`iac_execute_enabled`, default off) and `terraform` is installed on the server.

- Each blueprint runs in its own persistent workdir under the data directory
  (`iac_runs/<id>/`), so **state survives** — Destroy and re-apply work.
- A **per-blueprint lock** prevents two operations racing one blueprint.
- **Variables**: non-secret values are written to an auto-loaded `tfvars.json`;
  **secret** variables are passed as **environment** (`TF_VAR_<name>` plus the
  bare name, so cloud credentials like `AWS_ACCESS_KEY_ID` work) and are **never
  written to disk or the command line**.
- **Admin-only** and **audited**. Deleting a blueprint that still has live
  Terraform state is refused until you Destroy it first.

cloud-init and iPXE stay render-only — a booting machine consumes them, so there
is nothing to execute on the server.

## API

| Method & path | Purpose |
| --- | --- |
| `GET /api/provisioning/blueprints` | List blueprints (+ exec availability flags) |
| `POST /api/provisioning/blueprints` | Create a blueprint |
| `PUT /api/provisioning/blueprints/{id}` | Update |
| `DELETE /api/provisioning/blueprints/{id}` | Delete (refused if live state) |
| `POST /api/provisioning/blueprints/{id}/render` | Render with supplied vars |
| `POST /api/provisioning/blueprints/{id}/run` | Run terraform `{op: plan\|apply\|destroy}` |

## Security notes

Server-side Terraform runs arbitrary infrastructure code with your cloud
credentials — that is why it sits behind two switches (the page toggle *and*
`iac_execute_enabled`), is admin-only, audited, and keeps secrets out of files
and process arguments. Leave execution off to use Provisioning purely as a
render-only template catalog.
