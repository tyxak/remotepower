# Homelab software integrations

RemotePower can poll popular self-hosted software for health and fold the result
into its **Alerts** inbox and dashboard activity feed — so a degraded TrueNAS
pool, a Pi-hole that stopped answering, or a Sonarr with a failing indexer shows
up next to the rest of your fleet's signals.

Each integration is a **server-side connector**: RemotePower reaches out to the
target's HTTP API on a cadence (default every 5 minutes), records an
ok / warning / critical / unknown result, and raises an `integration_down` alert
on a downward transition (auto-resolved by `integration_recovered` when it comes
back). Nothing is installed on the target.

## Setting one up

**Settings → Integrations → Homelab software integrations.**

1. Pick a type from the dropdown and click **Add**.
2. Give it a **Name**, the service **URL** on your LAN (e.g.
   `https://truenas.lan`), and the credential the connector needs (an API token,
   or username + password — the form shows the right fields per type).
3. For a service with a self-signed certificate, untick **Verify TLS**. The
   SSRF/IP guard still applies — only certificate verification is relaxed.
4. Click **Test** to probe it immediately, then **Save integrations**.

Saved secrets are never sent back to the browser (the form shows a "set" hint and
leaving a credential blank keeps the stored value). Configuration is admin-only.

## Binding an instance to a host *(v6.4.2)*

An integration watches a **service**; that service runs on a **machine**. Until
you say which machine, RemotePower has no way to connect the two — a poll result
carries the instance's label and nothing else, so `integration_down` fired as a
fleet-level event with no device attached to it.

An instance now takes an optional **`device_id`** (a host already enrolled in
RemotePower) and an optional **`site`**, set on the instance object you send to
`POST /api/integrations` and returned by `GET /api/integrations`. Both default to
empty, and an unbound instance behaves exactly as it always did. Binding is
admin-only and validated against the fleet — an unknown id is rejected, and one
belonging to a device you cannot see is refused rather than confirmed to exist.

Everything binding buys follows from one change: the `integration_down` and
`integration_recovered` payloads now carry that `device_id` (and `site`), which
is what the rest of the alert pipeline keys on.

- **Maintenance windows suppress it.** Both events joined the suppressible set,
  so a **device** or **group** window covering the bound host now holds the
  outbound notification (webhook and e-mail) the same way it holds a
  `device_offline`. This is the case worth binding for: rebooting one box during
  a declared window used to notify once per self-hosted app running on it — five
  services on that NAS, five pages, inside the window the operator had just
  declared. Only a *global* window could ever catch them, because a device-scoped
  one had no device to match against.
- **Per-(host, event) mutes reach it.** A mute is keyed `(device_id, event)`, so
  an unbound integration alert had no host to mute it *against* — the row's mute
  button had nothing to send. Bound, muting `integration_down` for that host from
  [Alert tuning](alert-tuning.md) silences it across the inbox, webhooks, e-mail
  and browser push, while the activity feed and the SIEM stream keep recording.
- **Unmonitored hosts stay quiet.** Marking the bound host `monitored: false`
  (decommissioning, a known-broken box) now suppresses its integrations' alerts
  too, instead of leaving them as the one signal that kept paging.
- **The inbox says where the service lives.** `device_id` and `site` are stored
  on the alert, so a failing service is attributable to a machine and a location
  rather than to a bare label.

Recovery still matches on the integration id, deliberately: if you bind an
instance *after* its down-alert was recorded, the stored alert has no device
while the recovery carries one, and requiring both to match would strand that
alert open forever.

## Security model

- Every outbound request goes through RemotePower's **SSRF guard**: the target
  must resolve to a normal address. Loopback (`127.0.0.0/8`), link-local and
  cloud-metadata (`169.254.169.254`) are refused; RFC1918 LAN is allowed because
  that's where homelab services live. The peer IP is re-checked at connect time
  (anti-rebinding) and redirects are not followed.
- Credentials are stored server-side and redacted from `GET /api/config` and
  `GET /api/integrations` (a `*_set` boolean is returned instead of the value).
- Polling is read-only — RemotePower never changes the target's state. The one
  deliberate exception is **DNS-blocker control** (Pi-hole / AdGuard): an admin
  can pause blocking for a bounded window (30 s – 4 h, always self-re-enabling,
  audit-logged) from the Integrations page — see [dns-control.md](dns-control.md).

## Supported targets

| Category | Targets |
|----------|---------|
| DNS | **Pi-hole** (v6), **AdGuard Home** |
| Storage / NAS | **TrueNAS** (CORE/SCALE), **Unraid** |
| Virtualization / orchestration | **Kubernetes / k3s**, **VMware vSphere / ESXi / vCenter**, **Red Hat OpenShift**, **VMware Cloud Director**, **Proxmox Backup Server** |
| Network | **UniFi Network** |
| Reverse proxy / certs | **Traefik**, **Nginx Proxy Manager**, **Caddy** |
| Observability | **Netdata**, **Grafana**, **Uptime Kuma**, **RemotePower (peer instance)** |
| Security / EDR | **Wazuh**, **CrowdStrike Falcon**, **SentinelOne** — each reports the hosts it protects, cross-referenced by `GET /api/edr/coverage` to name the machines with no EDR at all (see [edr-coverage.md](edr-coverage.md)) |
| Media | **Jellyfin**, **Plex**, **Immich**, **Frigate** |
| Apps | **Home Assistant**, **Nextcloud**, **GitHub Issues**, **WordPress** (site health + the last 5 logins with source IP, via an Application password and the Simple History plugin's REST API; IPs geo-enriched when a GeoIP MMDB is configured), **Paperless-ngx**, **Vaultwarden**, **Gitea / Forgejo**, **Syncthing**, **OctoPrint**, **ESPHome** (dashboard), **Homebridge** |
| Download clients | **qBittorrent**, **Transmission**, **Deluge**, **SABnzbd**, **NZBGet** |
| Media automation | **Servarr** (Sonarr / Radarr / Prowlarr / Lidarr — one connector), **Bazarr** |
| Requests | **Overseerr / Jellyseerr** |
| Custom | **Custom HTTP probe** — declarative, code-free: turn any endpoint's status code / JSON field into a health signal (see [writing-a-connector.md](writing-a-connector.md) for going beyond it) |

### Credentials at a glance

- **API token / key** (Bearer or header): TrueNAS, Home Assistant, Kubernetes,
  PBS, Jellyfin, Plex, SABnzbd, Servarr, Bazarr, Overseerr/Jellyseerr, Netdata
  (optional), Grafana (optional), Unraid, Immich, Paperless-ngx, Syncthing,
  OctoPrint, Gitea/Forgejo (optional).
- **Username + password** (Basic / login): AdGuard, UniFi, vCenter, NPM,
  NZBGet, Nextcloud, qBittorrent, Homebridge; Traefik / Transmission only if
  protected.
- **No credential / public**: Caddy admin API, Uptime Kuma (a published
  status-page slug), Vaultwarden (`/alive` liveness), Frigate, ESPHome
  dashboard (protect it at your proxy).

### Notes per category

- **Pi-hole** uses the v6 API (an *app password* under Settings → Web interface
  / API). v5 instances aren't supported.
- **Caddy**'s admin API listens on `:2019` and is usually localhost-only — it
  must be reachable from the RemotePower server for this to work.
- **Uptime Kuma** has no official API, so this reads a **published status page**;
  set the page slug rather than a token.
- **RemotePower (peer instance)** turns another, off-site RemotePower into a tile
  beside your homelab integrations ("federation-lite"). Point URL at the peer's
  base (`https://peer.example.com`) and paste a **viewer-role API key** generated
  on that instance (Settings → API keys) as the secret. It reads only the peer's
  **public health** — `GET /api/nav-counts` (device count, offline hosts, open
  alerts, control-plane health) plus the no-auth `/api/public-info` for the
  version — and shows the tile OK when the peer is reachable and healthy,
  WARNING when the peer reports offline devices / open alerts / a degraded
  control-plane, and CRITICAL only when it's unreachable or the key is rejected.
  This is **read-only off-site visibility, not federation**: there is no shared
  identity and no cross-instance control.
- **Servarr** is a single connector for any *arr app — it **auto-detects the API
  version** (`/api/v3` for Sonarr/Radarr, `/api/v1` for Prowlarr/Lidarr/Readarr)
  and surfaces the app's own health-check warnings/errors. **Bazarr** uses a
  different API and is its own type.
- **Standalone ESXi** exposes only SOAP; point the vCenter connector at a
  vCenter instance.
- **OctoPrint** reports a disconnected printer as a *warning* (OctoPrint itself
  is still up), and only unreachability as critical. **ESPHome** warns when a
  node's deployed firmware is behind the dashboard's current version.
- **WordPress** needs the URL to be the **site root** (`https://blog.example`,
  not `/wp-admin` and not the REST path). Without credentials it reports REST
  reachability and the site title; add a username and an **Application
  password** (Users → Profile → Application Passwords, WordPress 5.6+) and it
  also lists the last logins from the free **Simple History** plugin. Paste the
  password exactly as WordPress shows it — the spaces are stripped for you.
  Things that make it report a problem, and what each means:

  | What you see | What it means |
  |---|---|
  | `HTTP 404 … no REST API at /wp-json/ or ?rest_route=/` | The URL is not a WordPress site root, or the REST API is disabled by a plugin. Both forms are tried, so permalinks set to *Plain* are fine. |
  | `returned HTML, not JSON` | Something answered instead of WordPress — a login wall, a "checking your browser" interstitial, or a parked domain. |
  | `refusing anonymous requests` | A security plugin or host rule blocks the REST API for logged-out callers. |
  | `the site did not accept the login … Authorization header` | The credentials never reached PHP. Many CGI/FastCGI hosts drop the `Authorization` header; the fix is a host/`.htaccess` rule, not a new password. |
  | `credentials rejected` | WordPress genuinely rejected them. Application Passwords also require HTTPS. |
  | `sent output before its JSON` | A theme or plugin is emitting a PHP notice. RemotePower reads past it, so this only appears when the rest failed to parse too. |
  | `login history unavailable` | The site is healthy; Simple History just isn't installed. |

- **GitHub Issues** watches repositories for **newly opened issues** rather than
  service health. URL is the API root (`https://api.github.com`, or your GitHub
  Enterprise `/api/v3` root); list repos as `owner/repo, owner/repo` (up to 10);
  the token is optional (needed for private repos, and lifts the anonymous rate
  limit). A new issue raises a `github_new_issue` alert in the Alerts inbox —
  pull requests are ignored and the first poll only baselines, so attaching a
  repo never floods with its existing backlog. The **GitHub new issues** channel
  kind defaults to inbox + activity feed only; enable webhook/push routing in
  Settings → Notifications if you want to page on it.

## What you see

- **Settings → Integrations**: each card shows a live status badge + the last
  detail line (e.g. "2 pools, DEGRADED: cold" or "1000 queries today, 10% blocked").
- **Alerts**: `integration_down` (severity from the result — critical → high,
  warning → medium) lands in the inbox and routes through your channels
  (the **Integration health** channel kind); it auto-resolves on recovery.
- **Dashboard activity feed**: up/down transitions appear and click through to
  the Integrations settings.

## API

- `GET  /api/integrations` — instances (redacted) + the connector catalog.
- `POST /api/integrations` — replace the instance list (admin).
- `POST /api/integrations/test` — probe one instance without saving (admin).
- `GET  /api/integrations/status` — latest poll result + history per instance.

Adjust the poll cadence with the **Poll interval** field (minimum 60 s).

## Hiding the feature (enterprise)

The **Show Homelab software** checkbox (Settings → Integrations, default on) is an
instance-wide kill switch for enterprise deployments that don't use any of this.
Unchecking it **disables the feature wholesale** — no polling, so no
`integration_down` alerts; the configuration section is hidden; and the
*Integration health* dashboard widget disappears from the grid, the widget
catalog, and the data the dashboard requests. Re-checking it resumes polling on
the next cycle.
