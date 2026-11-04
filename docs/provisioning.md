# Provisioning — infrastructure blueprints

**Provisioning** (**Automation → Provisioning**) is a catalog of infrastructure
**blueprints** organised in a folder tree: Terraform, cloud-init, Ansible and
iPXE templates. You fill in a blueprint's variables and either **render** it to
copy/download, or — for Terraform — **run** it on the server.

The catalog and rendering are always available. Running Terraform on the server is
a separate switch, described below. Ansible playbooks live here too, in an
*Ansible playbooks* card (see [Ansible playbooks](#ansible-playbooks)).

## Blueprints

A blueprint has a **name** (up to 120 characters), a **folder** (path-like, e.g.
`aws/dev`), a **kind** (`terraform` / `cloud-init` / `ansible` / `ipxe`), the template
**content**, and optional declared **variables** (one per line in the editor:
`name | Label | default`, append `| secret` to mask). A secret variable keeps no
default.

Limits: a template is up to 256 KiB, a blueprint declares up to 50 variables, and you
can keep up to 300 blueprints. Each folder segment keeps letters, digits, spaces and
`. _ -`, and a folder path is cut at 200 characters. Only admins can see or change
blueprints. The **AI review** button on the page opens the AI Insights advisor for
provisioning, which reads your blueprints and flags drift between them and your live
hosts (the AI assistant has to be set up first, see [ai.md](ai.md)).

## Render (all kinds)

Fill in the variables and **Render** to get the finished text to copy or
download. Two macros are always available:

- `${rp_server_url}` — this server's base URL.
- `${rp_agent_install}` — the agent install one-liner
  (`curl -fsSL <server>/install | sudo sh -s -- --token <enrollment-token>`), so
  a cloud-init blueprint can bake the agent in. The text `<enrollment-token>` stays
  in the output: replace it with a one-time token from **Hosts → Enroll host**
  (one token enrols one host) and the provisioned machine enrols itself.

Rendering is pure string substitution — nothing is executed. A `${name}` that has
no value is left as it is, and the page lists it after the render. (Terraform
blueprints are returned **unchanged** on Render, because Terraform owns the
`${…}` interpolation syntax; Terraform values are supplied natively as
`var.<name>` at Run time, below.)

## Run Terraform (plan / apply / destroy)

Terraform blueprints can be executed **server-side** when you tick **Allow
server-side execution** under **Settings → Advanced → Provisioning — server-side
execution** (`iac_execute_enabled`, default off) and `terraform` is installed on
the server.

- Each blueprint runs in its own persistent workdir under the data directory
  (`iac_runs/<id>/`), so **state survives** — Destroy and re-apply work.
- A **per-blueprint lock** prevents two operations racing one blueprint. A second run
  while one is going is answered with a 409.
- **Variables**: non-secret values are written to an auto-loaded
  `rp.auto.tfvars.json`; **secret** variables are passed as **environment**
  (`TF_VAR_<name>` plus the bare name, so cloud credentials like `AWS_ACCESS_KEY_ID`
  work; names such as `PATH` or `HOME` get only the `TF_VAR_` form) and are **never
  written to disk or the command line**.
- The **Run** button on a Terraform blueprint offers **Plan**, **Apply** and
  **Destroy**. Apply and Destroy ask you to confirm first and run with
  `-auto-approve`. The first run does `terraform init`.
- A run is cut off after 5 minutes for `init`, 15 for `plan` and 30 for `apply` or
  `destroy`. The page shows the last 64 KiB of the output.
- **Admin-only** and **audited**. Deleting a blueprint that still has live
  Terraform state is refused until you Destroy it first.

cloud-init and iPXE stay render-only — a booting machine consumes them, so there
is nothing to execute on the server. An Ansible *blueprint* is render-only too; the
runner for playbooks is the separate card below.

## Ansible playbooks

The **Ansible playbooks** card, under the blueprints, runs a playbook against your
hosts with this server as the control node. It needs `ansible-playbook` (the
`ansible-core` package) on the server; the card says whether it found it.

- **Define a playbook** with **New playbook**: a name (up to 80 characters) and the
  YAML (up to 256 KiB). You can keep up to 100. Only admins can create, edit or
  delete one, because a playbook is code that may run as root.
- **Run it** with **Run** on the row. Pick the target (**All hosts**, **Group**, **Tag**
  or **Site**, with its value), the SSH user (`root` by default), whether to **become
  (sudo)** (on by default), and either an SSH private key or an SSH password (a
  password needs `sshpass` on the server). The credentials are not stored.
- The hosts are written to an inventory group called `targets`, so a playbook starts
  with `- hosts: targets`. A host needs a known IP address; hosts without one and
  quarantined hosts are skipped. The SSH port comes from the host record or its
  CMDB entry.
- The first connection to a host accepts its host key. The key is recorded in a
  temporary file that is deleted when the run ends, so every run starts fresh.
- The SSH key and password are written to temporary files that only the server user
  can read, and the files are deleted after the run. The run is cut off after 15
  minutes and the page shows the last 64 KiB of output, the exit code and how many
  hosts it ran on.
- Running needs the **script** permission (the older `exec` permission includes it)
  on every target host, within the role's scope, or an admin. The card shows the last
  run time and result for each playbook, and every create, edit, delete and run is
  audited.

## API

Every blueprint route needs an admin. The Ansible routes say who can call them.

| Method & path | Purpose |
| --- | --- |
| `GET /api/provisioning/blueprints` | List blueprints (+ exec availability flags) |
| `POST /api/provisioning/blueprints` | Create a blueprint |
| `PUT /api/provisioning/blueprints/{id}` | Update |
| `DELETE /api/provisioning/blueprints/{id}` | Delete (refused if live state) |
| `POST /api/provisioning/blueprints/{id}/render` | Render with supplied vars |
| `POST /api/provisioning/blueprints/{id}/run` | Run terraform `{op: plan\|apply\|destroy}` |
| `GET /api/ansible/status` | Whether `ansible-playbook` is installed on the server (any signed-in user) |
| `GET /api/ansible/playbooks` | List playbooks, with their YAML (any signed-in user) |
| `POST /api/ansible/playbooks` | Create a playbook (admin) |
| `PUT /api/ansible/playbooks/{id}` | Update (admin) |
| `DELETE /api/ansible/playbooks/{id}` | Delete (admin) |
| `POST /api/ansible/playbooks/{id}/run` | Run `{target, ssh_user, ssh_key or ssh_password, become}` |

## Security notes

Server-side Terraform runs arbitrary infrastructure code with your cloud
credentials — that is why it sits behind its own switch (`iac_execute_enabled`),
is admin-only, audited, and keeps secrets out of files and process arguments.
Leave execution off to use Provisioning purely as a render-only template
catalog.

## Related

- [Driving RemotePower from Terraform](terraform-api.md) — manage RemotePower itself as code, which is a different thing from running Terraform here.
- [Scripts](scripts.md) and [Custom scripts](custom-scripts.md) — run commands and checks on hosts through the agent instead of over SSH.
