"""A catalog of the apps a host is likely to run, and the matcher that recognises them (8.0.0).

The Linux agent looks at what its host runs (the sockets that listen, the containers that run, the services systemd runs) and says which of these apps it found; the server
runs the same matcher on what an older agent reported, and offers, for each app found, a monitor of its own port and the connector that reads its API. Both sides use this one
catalog: the agent has a copy of everything from the marker line below (tools/sync-app-catalog.py writes it and `--check` fails when the copy is stale, as for the protocol
probes), and the server imports this file.

An app is recognised by what it is, not by where it listens. A process name, a container image or a systemd service is a sign by itself. A port is a sign only when it belongs to
one app (8096 is Jellyfin's, 8080 is anybody's), or when another sign agrees. Nothing is guessed from a port that many apps use.
"""

# ── shared with the Linux agent from the next line on ─────────────────────────────────────────────────────────────────────────────────────────────────

VIAS = ("process", "container", "unit", "port")
SCOPES = ("local", "lan", "world")


def _app(
    app_id,
    name,
    kind,
    ports=(),
    procs=(),
    images=(),
    units=(),
    connector="",
    distinct=False,
    scheme="",
):
    """One entry. `ports` are the app's own TCP ports, the one its API answers on first; `procs` the names of its process as `ss` prints them (the first 15 characters);
    `images` the last path segment of its container image, or `org/name` where the plain name belongs to other things; `units` the name of its systemd service without
    `.service` (and without `@instance`); `connector` the id of the connector that reads it, if there is one; `distinct` says that a listener on one of its ports is
    enough to recognise it, and `scheme` that its API answers TLS by default ('https'; empty is http).
    """
    return {
        "id": app_id,
        "name": name,
        "kind": kind,
        "ports": tuple(ports),
        "procs": tuple(procs),
        "images": tuple(images),
        "units": tuple(units),
        "connector": connector,
        "distinct": bool(distinct),
        "scheme": scheme,
    }


APPS = (
    _app("nginx", "nginx", "web", (80, 443), ("nginx",), ("nginx",), ("nginx",)),
    _app(
        "apache",
        "Apache HTTP Server",
        "web",
        (80, 443),
        ("apache2", "httpd"),
        ("httpd",),
        ("apache2", "httpd"),
    ),
    _app("caddy", "Caddy", "web", (80, 443), ("caddy",), ("caddy",), ("caddy",)),
    _app(
        "traefik",
        "Traefik",
        "web",
        (8080, 80, 443),
        ("traefik",),
        ("traefik",),
        ("traefik",),
        "traefik",
    ),
    _app("npm", "Nginx Proxy Manager", "web", (81,), (), ("nginx-proxy-manager",), (), "npm"),
    _app(
        "postgres",
        "PostgreSQL",
        "database",
        (5432,),
        ("postgres",),
        ("postgres", "postgis"),
        ("postgresql",),
        distinct=True,
    ),
    _app(
        "mariadb",
        "MariaDB / MySQL",
        "database",
        (3306,),
        ("mariadbd", "mysqld"),
        ("mariadb", "mysql"),
        ("mariadb", "mysql", "mysqld"),
        distinct=True,
    ),
    _app(
        "redis",
        "Redis / Valkey",
        "database",
        (6379,),
        ("redis-server", "valkey-server"),
        ("redis", "valkey"),
        ("redis", "redis-server", "valkey"),
        distinct=True,
    ),
    _app(
        "mongodb",
        "MongoDB",
        "database",
        (27017,),
        ("mongod",),
        ("mongo",),
        ("mongod",),
        distinct=True,
    ),
    _app(
        "influxdb",
        "InfluxDB",
        "database",
        (8086,),
        ("influxd",),
        ("influxdb",),
        ("influxdb",),
        distinct=True,
    ),
    _app(
        "elasticsearch",
        "Elasticsearch / OpenSearch",
        "database",
        (9200,),
        (),
        ("elasticsearch", "opensearch"),
        ("elasticsearch", "opensearch"),
        distinct=True,
    ),
    _app(
        "rabbitmq",
        "RabbitMQ",
        "messaging",
        (5672,),
        ("beam.smp",),
        ("rabbitmq",),
        ("rabbitmq-server",),
        distinct=True,
    ),
    _app(
        "memcached",
        "memcached",
        "database",
        (11211,),
        ("memcached",),
        ("memcached",),
        ("memcached",),
        distinct=True,
    ),
    _app(
        "mosquitto",
        "Mosquitto (MQTT)",
        "messaging",
        (1883,),
        ("mosquitto",),
        ("eclipse-mosquitto", "mosquitto"),
        ("mosquitto",),
        distinct=True,
    ),
    _app(
        "grafana",
        "Grafana",
        "observability",
        (3000,),
        ("grafana", "grafana-server"),
        ("grafana",),
        ("grafana-server",),
        "grafana",
    ),
    _app(
        "prometheus",
        "Prometheus",
        "observability",
        (9090,),
        ("prometheus",),
        ("prometheus",),
        ("prometheus",),
        "prometheus",
    ),
    _app(
        "node_exporter",
        "Prometheus node exporter",
        "observability",
        (9100,),
        ("node_exporter",),
        ("node-exporter",),
        ("prometheus-node-exporter", "node_exporter"),
        "prometheus_exporter",
        True,
    ),
    _app(
        "loki",
        "Grafana Loki",
        "observability",
        (3100,),
        ("loki",),
        ("loki",),
        ("loki",),
        distinct=True,
    ),
    _app(
        "netdata",
        "Netdata",
        "observability",
        (19999,),
        ("netdata",),
        ("netdata",),
        ("netdata",),
        "netdata",
        True,
    ),
    _app(
        "uptimekuma",
        "Uptime Kuma",
        "observability",
        (3001,),
        (),
        ("uptime-kuma",),
        (),
        "uptimekuma",
        True,
    ),
    _app(
        "pihole",
        "Pi-hole",
        "network",
        (80, 443),
        ("pihole-FTL",),
        ("pihole",),
        ("pihole-FTL",),
        "pihole",
    ),
    _app(
        "adguard",
        "AdGuard Home",
        "network",
        (3000, 80),
        ("AdGuardHome",),
        ("adguardhome",),
        ("AdGuardHome",),
        "adguard",
    ),
    _app(
        "headscale",
        "Headscale",
        "network",
        (8080,),
        ("headscale",),
        ("headscale",),
        ("headscale",),
        "headscale",
    ),
    _app("unbound", "Unbound", "network", (), ("unbound",), ("unbound",), ("unbound",)),
    _app(
        "jellyfin",
        "Jellyfin",
        "media",
        (8096, 8920),
        ("jellyfin",),
        ("jellyfin",),
        ("jellyfin",),
        "jellyfin",
        True,
    ),
    _app(
        "plex",
        "Plex Media Server",
        "media",
        (32400,),
        ("Plex Media Serv",),
        ("pms-docker", "plex"),
        ("plexmediaserver",),
        "plex",
        True,
    ),
    _app(
        "sonarr", "Sonarr", "media", (8989,), ("Sonarr",), ("sonarr",), ("sonarr",), "sonarr", True
    ),
    _app(
        "radarr", "Radarr", "media", (7878,), ("Radarr",), ("radarr",), ("radarr",), "radarr", True
    ),
    _app(
        "lidarr", "Lidarr", "media", (8686,), ("Lidarr",), ("lidarr",), ("lidarr",), "lidarr", True
    ),
    _app(
        "readarr",
        "Readarr",
        "media",
        (8787,),
        ("Readarr",),
        ("readarr",),
        ("readarr",),
        "readarr",
        True,
    ),
    _app(
        "prowlarr",
        "Prowlarr",
        "media",
        (9696,),
        ("Prowlarr",),
        ("prowlarr",),
        ("prowlarr",),
        "prowlarr",
        True,
    ),
    _app("bazarr", "Bazarr", "media", (6767,), (), ("bazarr",), ("bazarr",), "bazarr", True),
    _app(
        "overseerr",
        "Overseerr",
        "media",
        (5055,),
        (),
        ("overseerr",),
        ("overseerr",),
        "overseerr",
        True,
    ),
    _app(
        "immich",
        "Immich",
        "media",
        (2283,),
        (),
        ("immich-server",),
        ("immich-server", "immich"),
        "immich",
        True,
    ),
    _app("frigate", "Frigate", "media", (5000, 8971), (), ("frigate",), ("frigate",), "frigate"),
    _app(
        "qbittorrent",
        "qBittorrent",
        "download",
        (8080,),
        ("qbittorrent-nox",),
        ("qbittorrent", "qbittorrent-nox"),
        ("qbittorrent-nox",),
        "qbittorrent",
    ),
    _app(
        "transmission",
        "Transmission",
        "download",
        (9091,),
        ("transmission-da",),
        ("transmission",),
        ("transmission-daemon",),
        "transmission",
    ),  # 9091 is Authelia's default too, so it is no sign by itself (8.0.0)
    _app(
        "deluge",
        "Deluge",
        "download",
        (8112,),
        ("deluged", "deluge-web"),
        ("deluge",),
        ("deluged", "deluge-web"),
        "deluge",
        True,
    ),
    _app(
        "sabnzbd",
        "SABnzbd",
        "download",
        (8080,),
        (),
        ("sabnzbd",),
        ("sabnzbd", "sabnzbdplus"),
        "sabnzbd",
    ),
    _app(
        "nzbget",
        "NZBGet",
        "download",
        (6789,),
        ("nzbget",),
        ("nzbget",),
        ("nzbget",),
        "nzbget",
        True,
    ),
    _app(
        "homeassistant",
        "Home Assistant",
        "home",
        (8123,),
        (),
        ("home-assistant", "homeassistant"),
        ("home-assistant", "hass", "homeassistant"),
        "homeassistant",
        True,
    ),
    _app(
        "homebridge",
        "Homebridge",
        "home",
        (8581,),
        ("homebridge",),
        ("homebridge",),
        ("homebridge",),
        "homebridge",
        True,
    ),
    _app("esphome", "ESPHome", "home", (6052,), (), ("esphome",), ("esphome",), "esphome", True),
    _app(
        "octoprint",
        "OctoPrint",
        "home",
        (5000, 80),
        (),
        ("octoprint",),
        ("octoprint",),
        "octoprint",
    ),
    _app("nextcloud", "Nextcloud", "cloud", (80, 443, 8080), (), ("nextcloud",), (), "nextcloud"),
    _app(
        "vaultwarden",
        "Vaultwarden",
        "cloud",
        (80, 8000, 8080),
        ("vaultwarden",),
        ("vaultwarden/server", "vaultwarden"),
        ("vaultwarden",),
        "vaultwarden",
    ),
    _app(
        "paperless",
        "Paperless-ngx",
        "cloud",
        (8000,),
        (),
        ("paperless-ngx",),
        ("paperless-webserver",),
        "paperless",
    ),
    _app(
        "gitea",
        "Gitea / Forgejo",
        "dev",
        (3000,),
        ("gitea", "forgejo"),
        ("gitea", "forgejo"),
        ("gitea", "forgejo"),
        "gitea",
    ),
    _app(
        "syncthing",
        "Syncthing",
        "storage",
        (8384,),
        ("syncthing",),
        ("syncthing",),
        ("syncthing",),
        "syncthing",
        True,
    ),
    _app("samba", "Samba", "storage", (445, 139), ("smbd",), ("samba",), ("smb", "smbd"), "", True),
    _app(
        "k3s",
        "Kubernetes (k3s)",
        "orchestration",
        (6443,),
        ("k3s-server", "k3s"),
        ("k3s",),
        ("k3s",),
        "kubernetes",
        True,
        "https",
    ),
    # 8.0.0, second tranche: each sign below is the product's own name for itself (its binary, its image, its systemd unit) and each port its documented default. Authelia's 9091 is Transmission's
    # too, so neither lists it as `distinct`: it is a sign only when another one agrees.
    _app("authelia", "Authelia", "web", (9091,), ("authelia",), ("authelia",), ("authelia",)),
    _app("keycloak", "Keycloak", "web", (8080, 8443), (), ("keycloak",), ("keycloak",)),
    _app("haproxy", "HAProxy", "web", (80, 443), ("haproxy",), ("haproxy",), ("haproxy",)),
    _app(
        "portainer",
        "Portainer",
        "orchestration",
        (9443, 9000),
        ("portainer",),
        ("portainer-ce", "portainer-ee"),
        ("portainer",),
        "",
        False,
        "https",
    ),
    _app("minio", "MinIO", "storage", (9000, 9001), ("minio",), ("minio",), ("minio",)),
    _app(
        "vault",
        "HashiCorp Vault",
        "cloud",
        (8200,),
        ("vault",),
        ("hashicorp/vault", "vault"),
        ("vault",),
        "",
        True,
    ),
    _app(
        "consul",
        "HashiCorp Consul",
        "orchestration",
        (8500,),
        ("consul",),
        ("hashicorp/consul", "consul"),
        ("consul",),
    ),
    _app("nodered", "Node-RED", "home", (1880,), (), ("node-red",), ("nodered",), "", True),
    _app("zigbee2mqtt", "Zigbee2MQTT", "home", (8080,), (), ("zigbee2mqtt",), ("zigbee2mqtt",)),
    _app("ollama", "Ollama", "dev", (11434,), ("ollama",), ("ollama",), ("ollama",), "", True),
    _app(
        "cloudflared",
        "Cloudflare Tunnel",
        "network",
        (),
        ("cloudflared",),
        ("cloudflared",),
        ("cloudflared",),
        "cloudflare_tunnel",
    ),
    _app(
        "tailscaled",
        "Tailscale",
        "network",
        (),
        ("tailscaled",),
        ("tailscale",),
        ("tailscaled",),
        "tailscale",
    ),
)

_BY_ID = {a["id"]: a for a in APPS}


def _repo(image):
    """The repository of a container image reference, lower-case, without registry-independent noise: 'lscr.io/linuxserver/jellyfin:latest' is 'lscr.io/linuxserver/jellyfin'."""
    ref = str(image or "").strip().lower()
    ref = ref.split("@", 1)[0]
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        ref = ref[: len(ref) - len(last)] + last.split(":", 1)[0]
    return ref


def _image_is(image, wanted):
    """Whether the image's repository is `wanted`: the whole path, or the end of it after a slash ('nginx' is 'docker.io/library/nginx' and not 'jc21/nginx-proxy-manager')."""
    repo = _repo(image)
    return bool(repo) and any(repo == w or repo.endswith("/" + w) for w in wanted)


def _published_ports(refs):
    """The host ports a container publishes, from docker's own text ('0.0.0.0:8096->8096/tcp, :::8096->8096/tcp'), in the order given and each once."""
    out = []
    for ref in refs or []:
        for part in str(ref).split(","):
            part = part.strip()
            if "->" not in part or not part.endswith("/tcp"):
                continue
            host = part.split("->", 1)[0].rsplit(":", 1)[-1]
            if host.isascii() and host.isdigit() and 0 < int(host) < 65536 and int(host) not in out:
                out.append(int(host))
    return out


def _running(container):
    state = str((container or {}).get("status") or "").strip().lower()
    return not state.startswith(("exited", "dead", "created", "removing", "paused"))


def discover(ports, containers, units):
    """The apps these three facts say are running. `ports`: [{port, proto, process, scope}] (the sockets that listen), `containers`: [{image, ports: [text], status}], `units`:
    the running systemd services, with or without `.service` and `@instance`. Returns [{id, via, port, scope, container}] in the catalog's order, each app once, `via` the signs
    that found it in the order process, container, unit, port."""
    ports = ports if isinstance(ports, list) else []
    containers = containers if isinstance(containers, list) else []
    units = units if isinstance(units, list) else []
    listening = {}
    for p in ports:
        if (
            isinstance(p, dict)
            and str(p.get("proto") or "tcp").lower().startswith("tcp")
            and isinstance(p.get("port"), int)
            and not isinstance(p.get("port"), bool)
        ):
            listening.setdefault(p["port"], p)
    stems = set()
    for u in units:
        u = str(u)
        stems.add(u[:-8] if u.endswith(".service") else u)
    stems = {u.split("@", 1)[0] for u in stems}
    boxes = [c for c in containers if isinstance(c, dict) and _running(c)]
    found = []
    for app in APPS:
        via, port, container = [], None, ""
        names = {n.lower() for n in app["procs"]}
        for number, p in sorted(listening.items()):
            if names and str(p.get("process") or "").lower()[:15] in names:
                via.append("process")
                port = number
                break
        for c in boxes:
            if _image_is(c.get("image"), app["images"]):
                via.append("container")
                container = str(c.get("name") or "")[:64]
                for number in _published_ports(c.get("ports")):
                    if number in app["ports"]:
                        port = number
                        break
                else:
                    published = _published_ports(c.get("ports"))
                    if port is None and published:
                        port = published[0]
                break
        if any(u in stems for u in app["units"]):
            via.append("unit")
        mine = [number for number in app["ports"] if number in listening]
        if mine and (via or app["distinct"]):
            via.append("port")
            if port is None:
                port = mine[0]
        if not via:
            continue
        if port is None and mine:
            port = mine[0]
        found.append(
            {
                "id": app["id"],
                "via": via,
                "port": port,
                "scope": (
                    str((listening.get(port) or {}).get("scope") or "") if port is not None else ""
                ),
                "container": container,
            }
        )
    return found


# ── end of what the agent shares ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def clean_found(raw):
    """What an agent says it found, as the entries this server knows: the id must be in the catalog, `via` is the signs it names that exist, the port a real port or None,
    the scope one of the three, and the container a short name. Anything else is dropped, and a list that is not a list is nothing. Bounded; never raises.
    """
    out, seen = [], set()
    if not isinstance(raw, list):
        return out
    for row in raw[
        : len(APPS) * 2
    ]:  # a list is looked at only so far: each app is kept once, so what is kept is no longer than the catalog
        if not isinstance(row, dict):
            continue
        app = row.get("id")
        if not isinstance(app, str) or app not in _BY_ID or app in seen:
            continue
        seen.add(app)
        via = row.get("via")
        via = [v for v in VIAS if isinstance(via, list) and v in via]
        port = row.get("port")
        port = (
            port
            if isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536
            else None
        )
        scope = row.get("scope") if row.get("scope") in SCOPES else ""
        cont = row.get("container")
        cont = cont[:64] if isinstance(cont, str) and all(32 < ord(ch) < 127 for ch in cont) else ""
        out.append({"id": app, "via": via, "port": port, "scope": scope, "container": cont})
    return out


def describe(app_id):
    """The catalog's entry for an app id, or None. A value that is not text is no id: a list cannot even be looked up."""
    return _BY_ID.get(app_id) if isinstance(app_id, str) else None
