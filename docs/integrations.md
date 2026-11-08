# Homelab software integrations

RemotePower can poll popular self-hosted software for health and fold the result
into its **Alerts** inbox and dashboard activity feed. A degraded TrueNAS pool, a
Pi-hole that stopped answering or a Sonarr with a failing indexer shows up next to
the rest of your fleet's signals.

Each integration is a **server-side connector**. RemotePower reaches out to the
target's HTTP API on a cadence (every 5 minutes by default), records an
ok / warning / critical / unknown result, and raises an `integration_down` alert
when the result turns bad. `integration_recovered` resolves it when the service
comes back. Nothing is installed on the target.

You see the result in two places:

- **Monitoring → Integrations** shows one tile per integration with its status and key
  figures. **Refresh** reloads it, and **Manage integrations** opens the settings. Pi-hole
  and AdGuard Home also get a card of the top blocked domains and clients (and the
  [pause control](dns-control.md)), and WordPress gets its last logins.
- **Settings → Integrations → Homelab software integrations** is where you set them up.

## Setting one up

**Settings → Integrations → Homelab software integrations.**

1. Pick a type under **Add integration** and click **Add**.
2. Give it a **Name** and the service **URL** on your LAN (for example
   `https://truenas.lan`). Fill in the credential the connector needs (an API token,
   or a username and password). The form shows the right fields for each type.
3. For a service with a self-signed certificate, untick **Verify TLS**. The
   address guard still applies. Only certificate verification is relaxed.
4. Click **Test** to probe it at once, then **Save integrations**.

**Guide me**, next to **Add**, does the same in steps: pick the service from a searchable list, give the address and the fields, see it answer, and add it (see [wizards.md](wizards.md)).

Saved secrets are never sent back to the browser. The form shows "set" and a blank
box keeps the stored value. Only admins can change the configuration. The **Poll
interval (s)** box sets the cadence (60 seconds at least, 300 by default), and the tick
box on each card enables or disables that integration.

VMware vSphere / vCenter, Red Hat OpenShift and VMware Cloud Director are
virtualization platforms. You add them under **Settings → Virtualization**
(see [virtualization.md](virtualization.md)). They use the same connectors and show on the
same Integrations page.

## Binding an instance to a host

An integration watches a **service**, and that service runs on a **host**. Say which
host in the optional **Runs on host** box (and a **Site** if you use sites) on the card. An
unbound instance works as it always has. A bound one carries its `device_id` and `site`
on the `integration_down`, `integration_recovered` and metric events, which is what the
rest of the alert pipeline keys on:

- **Maintenance windows hold it.** A **host** or **group** window covering the bound host
  holds the outbound notification (webhook and email), as it does for `device_offline`.
  Rebooting one box during a declared window then does not page once for every app that
  runs on it.
- **Mutes reach it.** A mute is keyed to a host and an event. Bound, muting
  `integration_down` for that host in [Alert tuning](alert-tuning.md) silences it in the inbox,
  webhooks, email and browser push, while the activity feed and the SIEM stream keep recording.
- **Unmonitored hosts stay quiet.** Marking the bound host unmonitored suppresses its
  integrations' alerts too.
- **The inbox says where the service lives.** The alert stores the host and site.

Recovery matches on the integration, not the host. If you bind an instance after its
down-alert was recorded, the recovery still closes that alert.

You must bind to a host you can see. An unknown ID is rejected.

### On the host's card

A host with no agent and no SNMP, such as a Hubitat hub, takes its health from the integrations
bound to it. Open the host, go to the **Audit** tab, and **Integrations on this host** lists every
instance bound to it, worst first: the status, when it was last checked, the latest values the
connector read, a trend line for each number, and how the last checks went. The section opens
by itself when something is bound to the host and stays shut when nothing is. The address and
the credentials of an instance are never part of what the card is given.
`GET /api/devices/<id>/integrations` returns the same rows.

- **How much trend.** Each number has a line drawn from the last 100 checks, about eight hours
  at the default cycle. Behind it a second line shows the average of each clock hour for up to
  seven days. The second line shows once a number reaches back an hour or more further than the
  first. Both start when you bind the instance, because numbers are kept only for an instance
  bound to a host, and unbinding it drops what was kept. A check that returns text rather than a
  number has a status history and no trend.
- **A value that is not a number.** A service that prints `NaN` when a sensor read fails does not
  stop the other results from being saved. Such values are stored as empty.

## Alerting on a metric

Every connector reads numbers as well as a status. A Pi-hole whose blocklist silently empties still
reports OK, with `blocked_pct` falling from 23 to 0. To catch that, open **Alert on a metric** on
the card and write one rule per line:

```
blocked_pct lt 5 high
queries_today gt 1000000
```

The form is `metric operator value [severity]`. Operators are `gt`, `lt`, `gte`, `lte`, `eq` and
`ne`. Severity is `critical`, `high`, `medium` (the default) or `low`. After a poll, the card
lists the metric names that connector reported. A rule can have up to 20 lines. It runs whatever the
connector's own status is.

A breach raises `integration_metric_alert`, once, and `integration_metric_recovered` resolves
it when the value is back within bounds. Two rules on one integration do not clear each other.

## What changed in 8.0.0 for seven connectors

Each was read against the product's own API documentation or source, and checked against
fixtures built from it, not against the product.

- **Pi-hole** gives its session back. Pi-hole v6 holds at most 16 API sessions by default
  (`webserver.api.max_sessions`), a session that is not ended lives for 30 minutes
  (`webserver.session.timeout`), and a login is denied when they are all taken. The connector
  and the DNS-blocker control logged in on every call and never ended the session, so a poll
  every minute used up the seats and the web login with them. Both now end it with
  `DELETE /api/auth` as soon as they have read, and the control uses one session for a change
  and for the answer it reads back.
- **Immich** reads how full the disk under the library is (`GET /api/server/storage`; 80%
  warns, 90% is critical) and the job queues (`GET /api/queues` from 2.4.0, `GET /api/jobs`
  before). The failed-job count is shown and does not change the status, because a failed
  job stays counted until somebody clears it. The key needs `server.about` and
  `server.statistics` as before, plus `server.storage` and `queue.read` (`job.read` before
  2.4.0) for the new readings; a key without them gets the old answer.
- **Proxmox Backup Server** reads datastore errors, mount state, bad chunks and the tasks that
  failed in the last day, and shows a fill forecast only when it is in the future. See
  [backups.md](backups.md#proxmox-backup-server).
- **Paperless-ngx** reports its own health. The tile only counted documents and could never
  be anything but OK. It now also reads `GET /api/status/`: a database, redis or celery in
  error is critical, and a celery that no worker answers, a search index, classifier, sanity
  check or LLM index in error, or migrations that were not applied is a warning. A classifier,
  sanity check or LLM index that has not run yet (a new install) is not a problem. Paperless
  answers that route only to a staff or superuser account or one with the
  `view_system_monitoring` permission, and a plain-text 403 otherwise: the counts still show
  and the detail says what the token's user needs.
- **Syncthing** shows its own error list (`GET /rest/system/error`, the red banner of its
  page) as a warning with the number and the newest message. Folder states are not read:
  Syncthing documents `/rest/db/status` as an expensive call.
- **ESPHome** counts the nodes that do not answer (`GET /ping`), says so in the detail and
  does not alert on it, because a node that sleeps is offline most of the time. The built-in
  ESPHome dashboard has been removed from ESPHome; **ESPHome Device Builder** replaced it and
  keeps `/devices` and `/ping` for compatibility (its authors mark them deprecated), so the
  connector works against either. It also takes a user name and password now, sent as HTTP
  Basic, for a dashboard that has them set.
- **Grafana** counts the alerts firing now when the token may read alert instances
  (`GET /api/alertmanager/grafana/api/v2/alerts`; only *active* alerts that are not silenced or
  inhibited count) and names up to three of them. Any firing alert makes the tile a warning.
  Without a token, or with one that may not read them, the tile is what it was.

## Security model

- Every outbound request goes through RemotePower's **address guard**: the target
  must resolve to a normal address. Loopback (`127.0.0.0/8`), link-local and
  cloud-metadata (`169.254.169.254`) are refused. Private LAN ranges (RFC 1918) are
  allowed, because that is where homelab services live. The address is checked again
  when the connection opens, which stops DNS rebinding, and redirects are not followed.
  A service on the RemotePower server itself needs the server's LAN address, not
  `127.0.0.1`.
- Credentials are stored on the server and left out of `GET /api/config` and
  `GET /api/integrations`, which return a `*_set` flag instead of the value.
- Polling is read-only. RemotePower never changes the target's state. The one
  exception is **DNS-blocker control** (Pi-hole and AdGuard Home): an admin
  can pause blocking for a bounded window (30 seconds to 4 hours, always
  self-re-enabling, audit-logged) from the Integrations page. See
  [dns-control.md](dns-control.md).
- A response is read up to 2 MB, and a poll that takes too long is cut off so one slow target
  cannot stall the rest.

## Supported targets

RemotePower ships connectors for these. You can add your own (see below).

| Category | Targets |
|----------|---------|
| DNS | **Pi-hole** (v6), **AdGuard Home** |
| Storage and NAS | **TrueNAS** (CORE and SCALE), **Unraid** |
| Virtualization and orchestration | **Kubernetes / k3s**, **VMware vSphere / ESXi / vCenter**, **Red Hat OpenShift**, **VMware Cloud Director**, **Proxmox Backup Server** |
| Network | **UniFi Network**, **Tailscale**, **Headscale**, **Cloudflare Tunnel** |
| Reverse proxy and certificates | **Traefik**, **Nginx Proxy Manager**, **Caddy** |
| Observability | **Netdata**, **Grafana**, **Uptime Kuma**, **RemotePower (peer instance)**, **Prometheus** (a PromQL query), **Prometheus exporter** (a `/metrics` scrape) |
| Security and EDR | **Wazuh**, **CrowdStrike Falcon**, **SentinelOne**. Each reports the hosts it protects, and `GET /api/edr/coverage` cross-references them to name the hosts with no EDR at all (see [edr-coverage.md](edr-coverage.md)) |
| Media | **Jellyfin**, **Plex**, **Immich**, **Frigate** |
| Apps | **Home Assistant**, **Nextcloud**, **GitHub Issues**, **WordPress**, **Paperless-ngx**, **Vaultwarden**, **Gitea / Forgejo**, **Syncthing**, **OctoPrint**, **ESPHome** (dashboard), **Homebridge** |
| Download clients | **qBittorrent**, **Transmission**, **Deluge**, **SABnzbd**, **NZBGet** |
| Media automation | **Sonarr**, **Radarr**, **Prowlarr**, **Lidarr**, **Readarr** (all on one Servarr connector), **Bazarr** |
| Requests | **Overseerr / Jellyseerr** |
| Custom | **Custom HTTP probe**: no code, turns any endpoint's status code or JSON field into a health signal |

The *Connector plugins* section of Settings → Integrations lists every connector type, built in or
third-party. A third-party connector is a Python file you drop into `connectors.d/` on the
server, and the *Reload connectors* button picks it up without a restart. There is no upload from
the browser, on purpose, so a stolen session cannot add code. See
[writing-a-connector.md](writing-a-connector.md).

### Credentials at a glance

- **API token or key** (bearer or header): TrueNAS, Unraid, Home Assistant,
  Kubernetes, OpenShift, Jellyfin, Plex, Immich, SABnzbd, Sonarr, Radarr, Prowlarr,
  Lidarr, Readarr (the Servarr entry too), Bazarr, Overseerr/Jellyseerr, Paperless-ngx,
  Syncthing, OctoPrint, SentinelOne, Tailscale, Headscale, Cloudflare Tunnel, the RemotePower peer. Optional for Netdata, Grafana,
  Gitea/Forgejo and GitHub.
- **Token ID and secret**: Proxmox Backup Server. **Client ID and secret**: CrowdStrike Falcon.
- **Username and password** (Basic or a login): AdGuard Home, vCenter, Cloud Director,
  Nginx Proxy Manager (an email), NZBGet, Nextcloud, qBittorrent, Homebridge, Wazuh. Optional
  for Traefik and Transmission. Pi-hole and Deluge take a password only. **UniFi** takes an API
  key (below) or, for the older login, a username and a password.
- **Application password**: WordPress (optional; it unlocks the login list).
- **Optional Basic or bearer**: Prometheus and Prometheus exporter. A user name and a password
  send Basic auth, a password alone is sent as a bearer token, and leaving both empty suits a
  server on your LAN with no login.
- **No credential**: Caddy, Uptime Kuma (a published status-page slug), Vaultwarden (`/alive`),
  Frigate (protect these at your proxy). **ESPHome** takes an optional user name and
  password (Basic) for a dashboard that has them set.

### Notes per target

- **Pi-hole** uses the v6 API with an *app password* (Settings → Web interface / API in
  Pi-hole). Version 5 is not supported.
- **Caddy**'s admin API listens on `:2019` and is usually reachable only from its own host. It
  must be reachable from the RemotePower server for this to work.
- **Uptime Kuma** has no official API, so this reads a **published status page**. Set the page
  slug instead of a token.
- **Tailscale** reads your tailnet through the Tailscale API. The URL starts as `https://api.tailscale.com`.
  Create an access token under *Settings → Keys* in the admin console and paste it as the secret. Leave
  *Tailnet* blank to use the token's own tailnet. The tile is critical when a host's key has run out and the
  host was seen in the last 30 days, a warning when a key ends within 14 days or a host waits for approval,
  and OK otherwise. A host that is only offline is not a warning, because phones and laptops come and go.
  Hosts shared in from another tailnet, and hosts with key expiry turned off, are left out of the key counts.
- **Headscale** reads your own server through its API. Point the URL at the server and create a key with
  `headscale apikeys create`. The verdicts are the same as for Tailscale: a key that has run out is critical,
  one that ends within 14 days is a warning, an offline node is neither.
- **Cloudflare Tunnel** reads the tunnels of one account. The URL starts as `https://api.cloudflare.com`. Give
  it an API token that can read Cloudflare Tunnel and the **account ID** (the 32-character string on the
  account's overview page). A tunnel with no connection is critical, one with some connections missing is a
  warning, and a tunnel that has never run is counted and left alone.
- **RemotePower (peer instance)** turns another, off-site RemotePower into a tile beside your
  homelab integrations. Point the URL at the peer's base (`https://peer.example.com`) and paste a
  **viewer-role API key** from that instance (Admin → API Keys) as the secret. It reads only the
  peer's public health: `GET /api/nav-counts` (host count, offline hosts, open alerts,
  control-plane health) and the no-auth `/api/public-info` for the version. The tile is OK when
  the peer is reachable and healthy, a warning when the peer reports offline hosts, open alerts or
  a degraded control plane, and critical only when it is unreachable or rejects the key. This is
  read-only visibility from another site, not federation: there is no shared identity and no
  cross-instance control.
- **Prometheus** and **Prometheus exporter** read named values from something that already speaks
  Prometheus, such as an OPNsense firewall running node_exporter. You write one line for each
  value, `name = …`, up to 12 for each instance. The first sample becomes a metric under that
  name, so you can alert on it under **Alert on a metric**. Bound to a host with **Runs on host**,
  the value and its trend show on that host's card. A line that cannot be read is refused when you
  save, with its line number.
  - **Prometheus (PromQL query)**: the URL is the Prometheus server (`http://prometheus.lab:9090`).
    Each line is a name and a PromQL expression, for example
    `mem_active = node_memory_active_bytes{instance="192.168.0.1:9100"}`. The first sample of
    the answer is the value, and a scalar works too. A query that returns nothing counts as a
    problem, so write one that always answers, such as `down = count(up == 0) or vector(0)`.
  - **Prometheus exporter (/metrics scrape)**: the URL is the exporter (`http://192.168.0.1:9100`)
    and the path is `/metrics` unless you change it. Each line is a name and a metric, with `=` or
    `!=` label matchers if you need them: `root_free = node_filesystem_avail_bytes{mountpoint="/"}`.
    Leave the name out and the metric's own name is used. The first matching sample on the page is
    the value. Regular expressions are not supported on a scrape. For those, or for a calculation
    across metrics, use the query form against a server.
  - The status is *OK* when every value was read, *warning* when some were not (the detail names
    them) and *critical* when none were, when the server cannot be reached or when it refuses the
    login.
- **TrueNAS** uses the REST API (`/api/v2.0`) with an API key. TrueNAS 26 removed that API, and its
  replacement is a WebSocket API (JSON-RPC 2.0 at `/api/current`) that this connector does not speak
  yet. On a TrueNAS that has no REST API the card says so, in words, instead of "HTTP 404"
  *(8.0.0)*. Releases that still have it work as before.
- **UniFi Network** uses the Integration API *(8.0.0)*. Make an API key under **Integrations** in
  the Network application and paste it as the key; it works on a UniFi OS console (UDM, UDR,
  Cloud Gateway, Cloud Key) and on a Network application from 9.0. The connector lists the adopted
  devices of the site and goes **critical** when one is offline, interrupted or isolated, naming
  up to three; a device with an incorrect U5G topology is a **warning**. It also shows how many
  clients are connected and how many firmware updates are available (an update does not change the
  status). Leave **Site** empty for the console's only site, or give the site's name as the older API
  knew it (`default` on a single-site install). Fill in a **username** and the older login is used
  instead (`/api/login` of a self-hosted controller, which UniFi OS consoles do not answer).
- **Servarr** is one connector for any *arr app. It **detects the API version** (`/api/v3` for
  Sonarr and Radarr, `/api/v1` for Prowlarr, Lidarr and Readarr) and shows the app's own
  health-check warnings and errors. For Sonarr, Radarr, Lidarr and Readarr it also reads the
  download queue (`queue/status`): it shows how many items are in it, and a queue that holds a
  download with an error or a warning turns the integration to **warning**, which the app's own
  health list does not say *(8.0.0)*. Prowlarr has no queue and is unchanged. The named entries (Sonarr, Radarr and the rest) use the same
  connector, so pick one per instance. **Bazarr** has a different API and is its own type.
- **Standalone ESXi** exposes only SOAP. Point the vCenter connector at a vCenter instance.
- **OctoPrint** reports a disconnected printer as a *warning* (OctoPrint itself is still up) and
  only unreachability as critical. **ESPHome** warns when a node's deployed firmware is behind the
  dashboard's current version, and counts the nodes that do not answer without alerting on them.
- **WordPress** needs the URL to be the **site root** (`https://blog.example`, not `/wp-admin` and
  not the REST path). Without credentials it reports REST reachability and the site title. Add a
  username and an **Application password** (Users → Profile → Application Passwords, WordPress
  5.6 or later) and it also lists the last five logins, with source IP, from the free **Simple
  History** plugin. The IPs get a country when a GeoIP database is configured. Paste the password
  as WordPress shows it. The spaces are stripped for you. What each problem message means:

  | What you see | What it means |
  |---|---|
  | `HTTP 404 … no REST API at /wp-json/ or ?rest_route=/` | The URL is not a WordPress site root, or a plugin disabled the REST API. Both forms are tried, so permalinks set to *Plain* are fine. |
  | `returned HTML, not JSON` | Something answered instead of WordPress: a login wall, a "checking your browser" page or a parked domain. |
  | `refusing anonymous requests` | A security plugin or host rule blocks the REST API for logged-out callers. |
  | `the site did not accept the login … Authorization header` | The credentials never reached PHP. Many CGI and FastCGI hosts drop the `Authorization` header. The fix is a host or `.htaccess` rule, not a new password. |
  | `credentials rejected` | WordPress rejected them. Application Passwords also require HTTPS. |
  | `sent output before its JSON` | A theme or plugin prints a PHP notice. RemotePower reads past it, so this appears only when the rest failed to parse too. |
  | `login history unavailable` | The site is healthy. Simple History is not installed. |

- **GitHub Issues** watches repositories for **newly opened issues** rather than service health.
  The URL is the API root (`https://api.github.com`, or your GitHub Enterprise `/api/v3` root).
  List repositories as `owner/repo, owner/repo` (up to 10). The token is optional: you need it for
  private repositories, and it lifts the anonymous rate limit. A new issue raises a
  `github_new_issue` alert in the Alerts inbox. Pull requests are ignored, and the first poll only
  sets a baseline, so attaching a repository never floods you with its backlog. At most 10 issues
  alert per poll, and a summary line covers the rest. The **GitHub new issues** channel kind sends to
  the inbox and activity feed only by default. Tick its **Webhook** column under Settings →
  Alerting → Channel routing if you want to be paged.

## What you see

- **Monitoring → Integrations**: a tile for each integration with its status badge, the last
  detail line (for example "2 pools, DEGRADED: cold" or "1000 queries today, 10% blocked") and key
  figures. Tiles sort worst first.
- **Alerts**: `integration_down` (severity comes from the result: critical maps to high, warning to
  medium) lands in the inbox and routes through your channels (the **Integration health** kind). It
  resolves when the target recovers.
- **Dashboard activity feed**: up and down transitions appear and click through to the
  Integrations page.

## API

- `GET  /api/integrations`: instances (secrets left out) and the connector catalog.
- `POST /api/integrations`: replace the instance list (admin).
- `POST /api/integrations/test`: probe one instance without saving (admin).
- `GET  /api/integrations/status`: latest poll result and history for each instance.
- `GET  /api/devices/<id>/integrations`: the instances bound to a host.

## Hiding the feature (enterprise)

**Show Homelab software on this instance** (Settings → Integrations, on by default) is a switch for
enterprise installs that do not use any of this. Unticking it **disables the feature entirely**:
nothing is polled, so there are no `integration_down` alerts, the configuration section is
hidden, and the *Integration health* dashboard widget disappears from the grid, the widget
catalog and the data the dashboard requests. Ticking it again resumes polling on the next cycle.

## Troubleshooting

| Problem | What to check |
| --- | --- |
| The tile says *no URL configured* | The card has no URL. Fill it in and save. |
| *target is a blocked address* | The URL points to loopback, link-local or a cloud-metadata address. Use the service's LAN address. |
| A certificate error | Untick **Verify TLS** for a self-signed certificate. |
| A tile stays *unknown* | Click **Test** on the card to see the reason, and check that the integration is enabled. |
| A slow target makes others late | One poll cycle has a time budget, and the longest-waiting instance goes first next time. A very slow target is the one to fix. |
| Alerts keep firing during a reboot | Bind the instance to its host with **Runs on host**, then use a maintenance window on that host. |

## With multi-tenancy

The integrations are the operator's own. With tenant isolation on, only users of the default tenant can list them or see their status, and a tenant's administrator cannot add or test one.

## See also

[dns-control.md](dns-control.md), [edr-coverage.md](edr-coverage.md),
[writing-a-connector.md](writing-a-connector.md), [virtualization.md](virtualization.md),
[alert-tuning.md](alert-tuning.md), [alerts.md](alerts.md).
