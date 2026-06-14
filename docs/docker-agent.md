# Monitoring a Docker host with the containerized agent

The RemotePower agent can run as a container that monitors **its Docker host** and
reports to your server — no package install on the host. It's published as a
separate image from the server:

```
ghcr.io/tyxak/remotepower-agent:latest      # the agent (this page)
ghcr.io/tyxak/remotepower                    # the server
```

The container reads the **host's** facts (not the slim image's): the host rootfs
is bind-mounted read-only at `/host`, and the host PID/network namespaces are
shared, so processes, ports, packages, disks and config all reflect the host.

## Quick start (two values, one command)

1. In the RemotePower UI: **Enroll device → Generate Docker compose**. Copy the
   generated `docker-compose.yml` (your server URL and a one-time token are
   already filled in).
2. On the Docker host, save it and run:

```bash
docker compose up -d
docker compose logs -f          # watch it enroll, then heartbeat
```

The agent enrolls on first boot — **named after the host**, not the container id —
persists its credentials to the `rp-agent-creds` volume, and reports from then on.
Restarts reuse the saved credentials. There's no PIN to type.

Prefer not to use the UI? Mint a token via the API (`POST /api/enrollment-tokens`,
admin) and use [`docker/docker-compose.agent.yml`](../docker/docker-compose.agent.yml)
from the repo, setting `RP_SERVER` and `RP_ENROLL_TOKEN`.

## Configuration (environment variables)

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `RP_SERVER` | first boot | — | Server URL, e.g. `https://remote.example.com` |
| `RP_ENROLL_TOKEN` | first boot | — | One-time enrollment token (also accepts `REMOTEPOWER_ENROLL_TOKEN`) |
| `RP_DEVICE_NAME` | no | host's hostname | Device display name |
| `RP_CA_FINGERPRINT` | no | — | Pin a self-signed server's CA (SHA-256); the agent fetches `/ca.crt` and refuses a mismatch |
| `RP_INTERVAL` | no | `60` | Heartbeat interval (seconds) |
| `HOST_ROOT` | no | `/host` | Where the host rootfs is mounted |

After enrollment only the `rp-agent-creds` volume matters; the env vars can be
removed on later `up`s.

## Capability profiles

**Standard (default in the shipped compose)** — no `--privileged`. Targeted caps:
`NET_RAW` (ping), `NET_ADMIN` (read firewall state), `DAC_READ_SEARCH` (read
root-only host files for the account audit), plus `pid: host`, `network_mode:
host` and a read-only host rootfs. This covers the large majority of telemetry:

- Resource usage (CPU, memory, disk, load, uptime)
- Listening ports, network connections, interfaces, routes, gateway reachability
- Host processes / top talkers
- **Host package inventory + CVE scanning** (read directly from the host's package DB)
- Disk usage, RAID/ZFS/Btrfs health, mounts
- Local accounts, SSH authorized_keys
- Firewall rules, config/drift inventory (fstab, sysctl, cron, repos, netplan, …)
- Docker/Podman container inventory (**opt-in** — see the Docker-socket warning below)

> ### ⚠ Docker socket = effective host root
> Container inventory needs the Docker socket, which is **commented out by
> default**. Mounting `/var/run/docker.sock` — **even with `:ro`** — grants
> anything that can talk to this container **full control of the Docker daemon**,
> i.e. **root on the host** (it can create a privileged container that bind-mounts
> host `/`). `:ro` only makes the socket *file* read-only; the API stays fully
> usable, and Docker has no read-only API scope. Enable it **only** if you need
> container inventory and trust this image — and prefer fronting it with a scoped
> **socket-proxy** (e.g. `tecnativa/docker-socket-proxy` with `CONTAINERS=1` and
> every other capability `0`) rather than the raw socket.

**Full (opt-in)** — uncomment the `devices: [/dev:/dev]` and the extra
`SYS_RAWIO`/`SYS_ADMIN` caps in the compose to add **SMART disk health** and
**DMI/firmware inventory**. These need raw device access, a much broader grant
than the standard caps — enable only if you want hardware-health telemetry.

## What the containerized agent does NOT do (v1)

By design it reports honest "not available" instead of misleading host data for:

- **Host compliance scans** (lynis hardening score, OpenSCAP/CIS) — these grade
  the *running* system, which inside a container is the container, not the host.
  They are skipped and reported as not-available rather than scored falsely.
- **systemd units, timers and the journal** — the slim agent image does not ship
  `systemctl`/`journalctl`, so unit state and journal collection are unavailable
  from the container. (Install the native agent on the host if you need these.)
- **Self-update** — the binary is baked into the image; upgrade by pulling a
  newer image tag, never in place.
- **`upgradable` count on non-Debian hosts** — installed-package inventory and
  CVE matching work on Debian/Ubuntu, Arch and RHEL/Fedora hosts; the "updates
  available" count is computed for apt hosts and left as *unknown* (never a false
  `0`) for dnf/pacman hosts in this version.

For full host coverage (including systemd and compliance scans), install the
native agent with `install-client.sh`. The containerized agent is the
low-friction option for Docker hosts where you want the core monitoring without
touching the host OS.

## Upgrading

```bash
docker compose pull && docker compose up -d
```

Credentials persist in the volume, so the agent comes straight back up enrolled.

## Uninstall

```bash
docker compose down
docker volume rm <project>_rp-agent-creds     # also forget the enrollment
```
Then delete the device in the RemotePower UI.
