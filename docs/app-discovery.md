# App discovery

The agent on a Linux host looks at what the host runs and tells the server which
well-known apps it found. For each one you can monitor its port from the host itself,
connect it to read its health, or hide it. Nothing is created until you press a button.

## What is looked at

The agent reads three things it already has, or one read-only call away:

- the **listening sockets** (the same list the host reports under ports),
- the **containers** (Docker and Podman),
- the **services** systemd says are running (one `systemctl list-units`).

Nothing is probed. No request is sent to an app, so an app's own log stays as it was.

## How an app is recognised

An app is recognised by what it is, not by where it listens. A process name, a container
image or a service is a sign on its own. A port is a sign only when it belongs to one app
(8096 is Jellyfin's) or when another sign agrees (a listener on 80 that is called nginx).
8080, 3000 and 80 are anybody's, so a listener on them recognises nothing by itself.

- **Windows and macOS hosts** are not covered: the catalog knows the process names and
  services of Linux, and those agents do not send the list.
- **An older Linux agent** (before 8.0.0) does not send the list either. The server works
  the apps out from the ports and containers that agent did report, so it misses what only
  a service name would show.
- The catalog is `server/cgi-bin/app_catalog.py`. The agent has a copy that
  `tools/sync-app-catalog.py` writes, and a test fails when the copy is stale. An app that
  is not in it is not found; adding one is one line there and a run of the tool.

| Kind | Apps (✱ has a connector) |
|---|---|
| Web servers and proxies | nginx, Apache HTTP Server, Caddy, Traefik ✱, Nginx Proxy Manager ✱, HAProxy, Authelia, Keycloak |
| Databases and caches | PostgreSQL, MariaDB / MySQL, Redis / Valkey, MongoDB, InfluxDB, Elasticsearch / OpenSearch, memcached |
| Messaging | RabbitMQ, Mosquitto (MQTT) |
| Monitoring | Grafana ✱, Prometheus ✱, Prometheus node exporter ✱, Grafana Loki, Netdata ✱, Uptime Kuma ✱ |
| DNS and network | Pi-hole ✱, AdGuard Home ✱, Headscale ✱, Unbound, Cloudflare Tunnel ✱, Tailscale ✱ |
| Media and photos | Jellyfin ✱, Plex Media Server ✱, Sonarr ✱, Radarr ✱, Lidarr ✱, Readarr ✱, Prowlarr ✱, Bazarr ✱, Overseerr ✱, Immich ✱, Frigate ✱ |
| Downloads | qBittorrent ✱, Transmission ✱, Deluge ✱, SABnzbd ✱, NZBGet ✱ |
| Home and printing | Home Assistant ✱, Homebridge ✱, ESPHome ✱, OctoPrint ✱, Node-RED, Zigbee2MQTT |
| Files and secrets | Nextcloud ✱, Vaultwarden ✱, Paperless-ngx ✱, HashiCorp Vault |
| Development | Gitea / Forgejo ✱, Ollama |
| Storage | Syncthing ✱, Samba, MinIO |
| Orchestration | Kubernetes (k3s) ✱, Portainer, HashiCorp Consul |

## On a host: Discovered on this host

Open a host and look in **Actions & settings**, under the quick actions. The section is
there when the agent found something, and each app has one row:

| The row says | What it means |
|---|---|
| **Monitor** | Nothing looks at its port yet. The button makes a TCP monitor named "*app* on *host*" that the host's own agent runs against its loopback every minute. It needs a Linux agent that runs probes and is not in audit mode, and an administrator of the install. The port is the one the host reports now, never one from the request. |
| **Monitored** | A monitor already looks at that port, one the host's agent runs or one the server runs against the host's address or name. |
| **Connect** | A connector reads this app and no integration does yet. The button opens **Add an integration** on its Connection step with the address filled in (the host's address and the app's port) and the instance bound to the host, so it shows on the host's card as **Runs on host**. You still type the key. |
| **Connected** | An integration of that connector is bound to this host or points at its address and port. |
| *listens on this host only, so the server cannot read it* | The app is bound to the loopback. A monitor from the host's agent still works; a connector, which the server runs, cannot reach it. |
| **Hide** | Takes the app out of the list. **Hidden apps** shows them with **Show** to bring one back. The choice is kept in the settings, for everybody, and is made by an administrator. |

## On the Integrations page: Found on your hosts

A card on **Integrations** lists the apps that a connector could read and nothing reads
yet, across the hosts you may see, with a **Connect** and a **Hide** on each. It is not
there when there is nothing to offer. With **Show homelab software** switched off
(Settings → Integrations) no connector is offered anywhere; the **Monitor** buttons stay,
because a monitor is not an integration.

## API

| | |
|---|---|
| `GET /api/devices/<id>/apps` | The apps of a host with their state, what each offers, `source` (`agent`, or `server` for an older agent), `monitor_problem` (why no monitor can run from this host, or empty) and the hidden ones apart. Any signed-in role. |
| `GET /api/app-discovery` | The apps worth a connector, across the hosts the caller may see, at most 200. |
| `POST /api/devices/<id>/apps/monitor` `{app}` | Makes the monitor. Answers the one that is there instead of a second. Administrator. |
| `POST /api/devices/<id>/apps/dismiss` `{app, dismissed}` | Hides an app, or shows it again with `dismissed: false`. Administrator. |

The agent sends what it found as `sysinfo.discovered`, a list of `{id, via, port, scope,
container}` in which `via` names the signs (`process`, `container`, `unit`, `port`). The
server keeps only entries whose id is in the catalog.

## What it does not do

- It does not read versions or ask an app anything. A version needs a request to the app,
  which is a different feature and would be opt-in.
- It does not make anything by itself: no monitor, no integration.
- It does not look beyond the catalog, and there is no setting that turns the reading off:
  it is three lists and costs nothing worth a switch.

## Checked with

The matcher, the cleaner and the routes are tested against facts built from each catalog
entry's own signs, and the agent's copy is compared with the module on four hundred
random fact sets. The agent's read of the running services was run on a real systemd (a
desktop with 25 services and 17 listeners, where it found no catalog app, as it should).
No app from the catalog was installed to test it, and the connectors that **Connect**
starts are the ones described in [integrations.md](integrations.md), checked against
fixtures.
