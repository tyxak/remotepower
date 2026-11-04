# Monitoring a Docker host with the containerized agent

The RemotePower agent can run as a container that monitors **its Docker host** and
reports to your server, with no package install on the host. It is published as a
separate image from the server:

```
ghcr.io/tyxak/remotepower-agent:latest      # the agent (this page)
ghcr.io/tyxak/remotepower                    # the server
```

The container reads the **host's** facts (not the slim image's): the host rootfs
is bind-mounted read-only at `/host`, and the host PID/network namespaces are
shared, so processes, ports, packages, disks and config all reflect the host.

## Quick start (two values, one command)

1. In the RemotePower UI, open **Hosts → Enroll host → Generate Docker compose**. Copy the
   generated `docker-compose.yml`. Your server URL and a one-time token (valid for 24 hours)
   are already filled in.
2. On the Docker host, save it and run:

```bash
docker compose up -d
docker compose logs -f          # watch it enroll, then heartbeat
```

The agent enrolls on first boot — **named after the host**, not the container id —
persists its credentials to the `rp-agent-creds` volume, and reports from then on.
Restarts reuse the saved credentials. There's no PIN to type.

Prefer not to use the UI? Mint a token through the API (`POST /api/enrollment-tokens`,
admin; it lasts 24 hours unless you send `expires_in` in seconds, at most 7 days) and use
[`docker/docker-compose.agent.yml`](../docker/docker-compose.agent.yml)
from the repo, setting `RP_SERVER` and `RP_ENROLL_TOKEN`.

The enrolment window also shows the **Windows and Linux/macOS** one-liners. Use the compose
file when you want the host watched by a container and the host OS left alone.

## Configuration (environment variables)

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `RP_SERVER` | first boot | — | Server URL, e.g. `https://remote.example.com` |
| `RP_ENROLL_TOKEN` | first boot | — | One-time enrollment token, good for 24 hours (also accepts `REMOTEPOWER_ENROLL_TOKEN`) |
| `RP_DEVICE_NAME` | no | host's hostname | Host display name |
| `RP_CA_FINGERPRINT` | no | — | Pin a self-signed server's CA (SHA-256). The agent fetches `/ca.crt` over plain HTTP and refuses it unless the fingerprint matches. Add it when your server uses its own CA. |
| `RP_INTERVAL` | no | `60` | Heartbeat interval (seconds) |
| `HOST_ROOT` | no | `/host` | Where the host rootfs is mounted |

After enrollment only the `rp-agent-creds` volume matters. You can remove the variables on later
`up`s.

## Capability profiles

**Standard (default in the shipped compose)** — no `--privileged`. Targeted caps:
`NET_RAW` (ping), `NET_ADMIN` (read firewall state), `DAC_READ_SEARCH` (read
root-only host files for the account audit), plus `pid: host`, `network_mode:
host` and a read-only host rootfs. This covers the large majority of telemetry:

- Resource usage (CPU, memory, disk, load, uptime)
- Listening ports, network connections, interfaces, routes, gateway reachability
- Host processes / top talkers
- **Host package inventory + CVE scanning** on Debian, Ubuntu and Arch hosts (read directly from the host's package DB; see the RHEL and Fedora note below)
- Disk usage, RAID/ZFS/Btrfs health, mounts
- Local accounts, SSH authorized_keys
- Firewall rules, config/drift inventory (fstab, sysctl, cron, repos, netplan, …)
- Docker/Podman container inventory (**opt-in** — see the Docker-socket warning below)

> ### Warning: Docker socket = effective host root
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

## What the containerized agent does not do

It reports "not available" instead of misleading host data for:

- **Host compliance scans** (lynis hardening score, OpenSCAP/CIS) — these grade
  the *running* system, which inside a container is the container, not the host.
  They are skipped and reported as not-available rather than scored falsely.
- **systemd units, timers and the journal** — the slim agent image does not ship
  `systemctl`/`journalctl`, so unit state and journal collection are unavailable
  from the container. (Install the native agent on the host if you need these.)
- **Self-update** — the binary is baked into the image; upgrade by pulling a
  newer image tag, never in place.
- **Pending-update count on non-Debian hosts** — the installed-package inventory works on
  Debian/Ubuntu and Arch hosts, but the "updates available" count is computed for
  apt hosts only. For dnf and pacman hosts it stays *unknown*, never a false `0`. CVE scanning
  needs the package inventory and the OSV ecosystems described in [cve.md](cve.md).
- **Package inventory on RHEL and Fedora hosts** — the rpm database is a binary store, and the
  agent image does not ship the `rpm` tool. The agent sends no package list for such a host, so
  CVE scanning has nothing to check. Install the native agent there.
- **SSH Gateway and applying host config** — the agent refuses the gateway tunnel when it runs in a
  container (see [sshgw.md](sshgw.md)), and it does not apply a [host config](host-config.md)
  push.

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
Then delete the host in the RemotePower UI.

## Troubleshooting

| Problem | What to check |
| --- | --- |
| The container exits at start with `RP_SERVER is required` or `RP_ENROLL_TOKEN ... is required` | First boot needs both values. Check the compose file, or the `rp-agent-creds` volume if it should already be enrolled. |
| `CA fingerprint mismatch` | The server presented a different CA than the one you pinned. Re-copy the fingerprint, and check you are talking to the right server. |
| The host never appears | The token may have expired (24 hours) or been used. Generate a new compose file. Then read `docker compose logs`. |
| The host is named after a container id | Set `RP_DEVICE_NAME`, or make sure the host rootfs is mounted at `HOST_ROOT` so the agent can read `/etc/hostname`. |
| No containers are listed | The Docker socket is not mounted. It is off by default (see the warning above). |
| SMART and firmware data are missing | They need the **Full** profile. |

## See also

[install.md](install.md), [containers.md](containers.md), [deployment.md](deployment.md).
