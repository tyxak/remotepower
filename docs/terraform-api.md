# Driving RemotePower from Terraform

RemotePower does **not** ship its own Terraform provider. A provider would be a
separate project with its own release cycle, and it would mostly re-wrap the REST
API that RemotePower already exposes. Everything a provider would manage is
reachable today through the API with a scoped API key.

If you want Infrastructure-as-Code management of RemotePower itself, use a generic
REST provider such as the community
[`Mastercard/restapi`](https://registry.terraform.io/providers/Mastercard/restapi/latest)
provider, or the `http` data source for read-only lookups.

> RemotePower also has a built-in **IaC Generator** (Automation → IaC Generator)
> that *emits* Terraform, Ansible, Pulumi and cloud-init from your live
> inventory. That scaffolds host configuration. This page is about managing
> RemotePower itself as code. Do not confuse it with **Provisioning** (Automation →
> Provisioning), which can run Terraform for you. See [provisioning.md](provisioning.md).

## 1. Create an API key

Open **Admin → API Keys**, click **New key**, and pick a role: `admin` (can write),
`viewer` (read-only) or `mcp` (read-only plus a short list of vetted actions for AI
tools). Send the key in the `X-Token` header. You can also give the key a rate
limit, a scope (some groups, tags or sites), a source-IP allowlist and an expiry.
RemotePower shows the key once, so copy it when you create it, and keeps at most 50
keys. A key for Terraform should have the narrowest scope that works.

## 2. How the API behaves, in one place

The resources below are collections with the same shape:

| Action | Request |
|---|---|
| List | `GET /api/<resource>` returns an object that wraps the list under a key |
| Create | `POST /api/<resource>` returns `{"ok": true, "id": "..."}` |
| Update | `PUT /api/<resource>/{id}` |
| Delete | `DELETE /api/<resource>/{id}` |

**There is no `GET /api/<resource>/{id}`.** A single object is read by listing the
collection and picking it out. Tools that read each object back from
`<path>/<id>` after creating it get a 404 or 405 on these resources, so tell them
to read from the list instead. The REST provider below does this with
`read_search`.

| Resource | Path | Wrapped list key | Notes |
|---|---|---|---|
| Sites | `/api/sites` | `sites` | `{name, note?, lat?, lng?}`. Admin. |
| Auto-patch policies | `/api/autopatch` | `policies` | `{name, target, cron, reboot?}`. Admin. |
| Backup jobs | `/api/backup-jobs` | `jobs` | Admin to create or edit. |
| Ansible playbooks | `/api/ansible/playbooks` | `playbooks` | `{name, content}`. Admin. |
| Hosts | `/api/devices` | | List only, plus per-host sub-resources. Hosts enrol through the agent. |

The machine-readable contract for every route is the OpenAPI document at
`/api/openapi.json` (shown at `/swagger.html`, see [swagger.md](swagger.md)).
Generate a typed client from it if you would rather not write resources by hand.

## 3. Configure the provider

```hcl
terraform {
  required_providers {
    restapi = { source = "Mastercard/restapi", version = "~> 1.20" }
  }
}

provider "restapi" {
  uri                  = "https://remote.example.com"
  write_returns_object = true
  headers = {
    X-Token      = var.remotepower_token   # the API key
    Content-Type = "application/json"
  }
  # Create responses carry the new object's id in the `id` field
  id_attribute = "id"
}

variable "remotepower_token" {
  type      = string
  sensitive = true
}
```

## 4. Examples

These show the shape of each call. Check them against the provider version you use,
because the provider's arguments are its own and can change between releases.

A **site**:

```hcl
resource "restapi_object" "london" {
  path = "/api/sites"
  data = jsonencode({ name = "London DC" })
  # No GET /api/sites/{id}: find the object in the list
  read_search = {
    search_key   = "name"
    search_value = "London DC"
    results_key  = "sites"
  }
}
```

An **auto-patch policy**:

```hcl
resource "restapi_object" "weekly_prod_patch" {
  path = "/api/autopatch"
  data = jsonencode({
    name   = "Weekly prod security updates"
    target = { type = "group", value = "prod" }
    cron   = "0 3 * * 0"
    reboot = false
  })
  read_search = {
    search_key   = "name"
    search_value = "Weekly prod security updates"
    results_key  = "policies"
  }
}
```

`target.type` is one of `all`, `device`, `group`, `tag` or `site`, and `cron` is a
five-field expression. See [auto-patch.md](auto-patch.md).

Read fleet state with a data source:

```hcl
data "http" "hosts" {
  url             = "https://remote.example.com/api/devices"
  request_headers = { X-Token = var.remotepower_token }
}
```

## Things to watch

- **State holds the key's reach.** An `admin` key can change anything it can reach.
  Keep the Terraform state private, rotate the key from **Admin → API Keys**, and
  give CI a `viewer` key for plan-only jobs.
- **Changes are audited.** Every write shows up in the audit log under the key's
  name.
- **Rate limits.** A key with a rate limit answers 429 when exceeded. Raise the limit
  or run fewer parallel resources (`-parallelism=2`).
- **Multi-tenancy.** A key belongs to the tenant of the admin who created it and sees
  only that tenant's data.
