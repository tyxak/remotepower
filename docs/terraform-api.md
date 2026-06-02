# Driving RemotePower from Terraform

RemotePower does **not** ship a bespoke Terraform provider — and deliberately so.
A provider is a separate Go project with its own release cadence, and it would
mostly re-wrap the REST API that RemotePower already exposes. Everything a
provider would manage is reachable today through the API + a scoped API key.

If you want Infrastructure-as-Code-style management, use the community
[`Mastercard/restapi`](https://registry.terraform.io/providers/Mastercard/restapi/latest)
provider (or `http` data sources for read-only lookups) against the API.

> RemotePower also has a built-in **IaC generator** (Planning → IaC) that
> *emits* Terraform/Ansible/Pulumi/cloud-init from your live inventory. That's
> for scaffolding host config; the pattern below is for managing RemotePower
> itself as code.

## 1. Create an API key

Admin → API Keys → **New key**, role `admin` (write) or `viewer` (read-only).
Authenticate with the `X-Token` header.

## 2. Configure the provider

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
  # RemotePower IDs come back as the `id` field on most objects
  id_attribute = "id"
}

variable "remotepower_token" { type = string, sensitive = true }
```

## 3. Examples

Manage a **site** (v3.5.0):

```hcl
resource "restapi_object" "london" {
  path = "/api/sites"
  data = jsonencode({ name = "London DC" })
}
```

Manage an **auto-patch policy** (v3.6.0):

```hcl
resource "restapi_object" "weekly_prod_patch" {
  path = "/api/autopatch"
  data = jsonencode({
    name   = "Weekly prod security updates"
    target = { type = "group", value = "prod" }
    cron   = "0 3 * * 0"
    reboot = false
  })
}
```

Read fleet state with a data source:

```hcl
data "http" "devices" {
  url = "https://remote.example.com/api/devices"
  request_headers = { X-Token = var.remotepower_token }
}
```

## API surface

Most list/create/update/delete resources follow the same shape:

| Resource        | Path                          | Methods            |
|-----------------|-------------------------------|--------------------|
| Sites           | `/api/sites`                  | GET POST PUT DELETE|
| Auto-patch      | `/api/autopatch`              | GET POST PUT DELETE|
| Backup jobs     | `/api/backup-jobs`            | GET POST PUT DELETE|
| Ansible playbooks | `/api/ansible/playbooks`    | GET POST PUT DELETE|
| Devices         | `/api/devices`                | GET (+ PATCH sub-resources) |

The full machine-readable contract is the OpenAPI spec at `/api/openapi.json`
(rendered at `/swagger.html`). Generate a typed client from that if you'd
rather not hand-write resources.
