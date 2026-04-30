# Container awareness

*Introduced in v1.11.0.*

Every enrolled agent detects Docker, Podman, and Kubernetes pods on
the host it's running on, normalises the output across runtimes, and
posts the list back to the server. The Containers tab shows fleet-
wide status with per-device drill-down. RemotePower's job here is
visibility — what's running and is it healthy. Starting, stopping,
exec'ing, log-streaming: that's Portainer, k9s, and kubectl. They
exist, they're good at it, and reproducing them inside RemotePower
would be inventing a different product.

---

## What you'll see

The Containers page lists every device that has reported containers,
with summary counts per device:

- **Total** — every container the agent could see
- **Running** — anything with status containing "running" or "Up"
- **Stopped** — exited / dead / terminated
- **Restarting** — anything with `restart_count >= 5` (gets a red badge)
- **Runtimes** — which runtimes contributed to the count

Click into a device to see the full list. Each entry shows the
image and tag (e.g. `nginx:1.25-alpine`), status, restart count,
namespace (for Kubernetes pods), runtime tag, and ports. Containers
with five or more restarts get an amber badge; more concerning
behaviour gets red.

---

## How detection works

The agent probes three runtimes independently:

1. **Docker** — `docker ps --no-trunc --format '{{json .}}'`
2. **Podman** — same command, just `podman` instead of `docker`
3. **Kubernetes** — `kubectl get pods --all-namespaces -o json` if
   `kubectl` is on PATH and a kubeconfig can be found

Each probe is wrapped in try/except with a five-second timeout. A
stuck or absent runtime never breaks the heartbeat — it just doesn't
contribute entries. If you have Docker installed but Podman isn't,
you get Docker entries; both installed gives you both, with each
container tagged by the runtime that listed it.

For Kubernetes, the agent checks `$KUBECONFIG` first, then falls
back to a few common locations: `/etc/rancher/k3s/k3s.yaml`,
`/var/lib/k0s/pki/admin.conf`, `~/.kube/config`. If none of those
work or the agent can't read them, kubectl listing is silently
skipped. The agent runs as root by default, so the standard
single-node k3s setup works out of the box.

---

## Cadence

Every five polls, which is five minutes at the default 60-second
poll interval. The first heartbeat after enrollment is skipped (it
fires fractions of a second after the agent starts, before
containers have settled), and listing happens on the second
heartbeat onward. So a fresh enrollment shows containers within
about ninety seconds.

If you want it more often, change `CONTAINER_CHECK_EVERY` near the
top of `client/remotepower-agent`. The probes are cheap on the
agent side (about 100 ms total when all three runtimes are
present); the limit is mostly avoiding pointless heartbeat
bandwidth on devices where containers don't change often.

---

## Caps

- 100 entries per device, per runtime (agent-side)
- 100 entries per device, total (server-side, applied again as
  defence in depth)
- 256 chars per container name, 512 chars per image string,
  20 ports per container

These match what people actually run. If you have more than a
hundred containers on one host, you have bigger questions than
"will RemotePower display them all" — the per-host cap is in
`server/cgi-bin/containers.py` if you want to change it.

---

## What's not captured

- **No live state.** The list is overwritten on every heartbeat;
  there's no history of "container X went down at 14:32." If you
  need that, look at the host's Docker logs or Kubernetes events.
- **No exec, logs, restart, stop, or start.** Out of scope by
  design. Use the SSH link on the device, then `docker logs <name>`
  or whatever your usual tool is.
- **No image scanning.** RemotePower's CVE scanner runs against
  installed packages, not container images. For container CVE
  scanning, Trivy and Grype both work well as complements.
- **No restart policy or compose state.** The agent reads `docker
  ps` output, which doesn't include the compose file the container
  came from or its restart policy. Both are visible via `docker
  inspect`, which we don't run for performance reasons.

---

## API

`GET /api/containers` — fleet-wide overview, one entry per device
with summary counts. Same shape used by the Containers page:

```json
[
  {
    "device_id": "dev-abc123",
    "name": "web-1",
    "os": "Ubuntu 22.04",
    "reported_at": 1714377550,
    "summary": {
      "total": 12,
      "running": 11,
      "stopped": 1,
      "restarting": 0,
      "by_runtime": {"docker": 12}
    }
  }
]
```

`GET /api/devices/{id}/containers` — full list for one device:

```json
{
  "device_id": "dev-abc123",
  "name": "web-1",
  "reported_at": 1714377550,
  "summary": {...},
  "items": [
    {
      "name": "nginx-proxy",
      "image": "nginx",
      "tag": "1.25-alpine",
      "status": "Up 2 days",
      "namespace": "",
      "runtime": "docker",
      "ports": ["443/tcp", "80/tcp"],
      "started_at": 0,
      "uptime_seconds": 0,
      "restart_count": 0
    }
  ]
}
```

The `started_at` and `uptime_seconds` fields are usually zero for
Docker/Podman because `docker ps` doesn't expose start timestamps
directly — `docker inspect` does, but we skip that for performance.
For Kubernetes pods, both fields are populated from the
`containerStatuses[].state.running.startedAt` field.

---

## Troubleshooting

**Containers page is empty.** The agent reports every five polls,
so wait ~5 minutes after upgrading the agent. Check the agent
journal: `journalctl -u remotepower-agent -e | grep -i container`.

**One container is missing.** Most likely the agent's runtime probe
hit the 5s timeout. Check `docker ps` from the device manually — if
that hangs or takes >5s, the agent will skip the listing entirely
that heartbeat and try again on the next.

**Kubernetes pods missing on a known cluster.** Kubectl needs a
kubeconfig. Run `sudo -u root kubectl get pods --all-namespaces` on
the device — if that fails, the agent's listing will too. For
single-node k3s, the kubeconfig is at `/etc/rancher/k3s/k3s.yaml`
and only readable by root by default; the agent runs as root, so
this is usually fine.

**Restart count always 0 for Docker.** `docker ps` doesn't show
this; only `docker inspect` does, and we don't call it for every
container. For Kubernetes pods the field works because k8s
exposes it directly. If Docker restart counts matter for your
alerting, monitor them via `docker events` separately.

**Wrong status string.** The agent passes through whatever the
runtime returned. Different Docker versions render status
differently ("Up 2 hours" vs "running" depending on `--format`),
and the server-side `summarise()` handles common variants but
isn't exhaustive. Look at the per-device modal — the raw status
string is shown verbatim there.
