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

## Security model

- Every outbound request goes through RemotePower's **SSRF guard**: the target
  must resolve to a normal address. Loopback (`127.0.0.0/8`), link-local and
  cloud-metadata (`169.254.169.254`) are refused; RFC1918 LAN is allowed because
  that's where homelab services live. The peer IP is re-checked at connect time
  (anti-rebinding) and redirects are not followed.
- Credentials are stored server-side and redacted from `GET /api/config` and
  `GET /api/integrations` (a `*_set` boolean is returned instead of the value).
- All polling is read-only — RemotePower never changes the target's state.

## Supported targets

| Category | Targets |
|----------|---------|
| DNS | **Pi-hole** (v6), **AdGuard Home** |
| Storage / NAS | **TrueNAS** (CORE/SCALE), **Unraid** |
| Virtualization / orchestration | **Kubernetes / k3s**, **VMware vCenter/ESXi**, **Proxmox Backup Server** |
| Network | **UniFi Network** |
| Reverse proxy / certs | **Traefik**, **Nginx Proxy Manager**, **Caddy** |
| Observability | **Netdata**, **Grafana**, **Uptime Kuma** |
| Media | **Jellyfin**, **Plex** |
| Apps | **Home Assistant**, **Nextcloud** |
| Download clients | **qBittorrent**, **Transmission**, **Deluge**, **SABnzbd**, **NZBGet** |
| Media automation | **Servarr** (Sonarr / Radarr / Prowlarr / Lidarr — one connector), **Bazarr** |
| Requests | **Overseerr / Jellyseerr** |

### Credentials at a glance

- **API token / key** (Bearer or header): TrueNAS, Home Assistant, Kubernetes,
  PBS, Jellyfin, Plex, SABnzbd, Servarr, Bazarr, Overseerr/Jellyseerr, Netdata
  (optional), Grafana (optional), Unraid.
- **Username + password** (Basic / login): AdGuard, UniFi, vCenter, NPM,
  NZBGet, Nextcloud, qBittorrent; Traefik / Transmission only if protected.
- **No credential / public**: Caddy admin API, Uptime Kuma (a published
  status-page slug).

### Notes per category

- **Pi-hole** uses the v6 API (an *app password* under Settings → Web interface
  / API). v5 instances aren't supported.
- **Caddy**'s admin API listens on `:2019` and is usually localhost-only — it
  must be reachable from the RemotePower server for this to work.
- **Uptime Kuma** has no official API, so this reads a **published status page**;
  set the page slug rather than a token.
- **Servarr** is a single connector for any *arr app — it **auto-detects the API
  version** (`/api/v3` for Sonarr/Radarr, `/api/v1` for Prowlarr/Lidarr/Readarr)
  and surfaces the app's own health-check warnings/errors. **Bazarr** uses a
  different API and is its own type.
- **Standalone ESXi** exposes only SOAP; point the vCenter connector at a
  vCenter instance.

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
