# Container awareness

*Introduced in v1.11.0. Alerts and stale-data detection added in v1.11.4.*

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

**v1.11.4:** rows with stale data (no fresh heartbeat report within
the configured TTL) are dimmed and tagged with an amber `STALE`
pill next to the timestamp. The per-device modal also shows a
prominent banner explaining what stale means and where to look.

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

**v1.11.4:** when a runtime is detected on the host, the agent
**always** sends the `containers` field — even when the list is
empty. Pre-v1.11.4 agents skipped sending on empty lists, which
caused stuck stale data on hosts where every container had been
stopped. The server-side ingest path always handled empty lists
correctly; the bug was purely on the client. After upgrading
agents, the dashboard will refresh to the actual current state on
the next heartbeat.

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

## Alerts (v1.11.4)

Three webhook events fire on container-state changes. All three
respect the per-event toggle in Settings → Notifications, default
to enabled, and route through the same payload pipeline as every
other RemotePower webhook.

### `container_stopped`

Fired when a container that was running on the previous heartbeat
is now either gone entirely or has a non-running status (Exited,
Dead, Terminated, etc.). Detected by diffing the new heartbeat's
container list against the previous one, keyed on
`(runtime, namespace, name)` — so two containers named `nginx`
in different k8s namespaces are tracked separately, and a
docker container and a k8s pod with the same name don't collide.

Already-stopped containers don't generate noise: if the previous
report already had it as Exited, the next report's continued
absence isn't a transition.

Webhook payload:

```json
{
  "device_id": "dev-abc123",
  "name": "web-1",
  "group": "prod",
  "container": "nginx-proxy",
  "runtime": "docker",
  "namespace": "",
  "image": "nginx",
  "previous_status": "Up 2 hours",
  "status": "gone"
}
```

### `container_restarting`

Fired when a container's `restart_count` increased by 1 or more
since the last report. Almost exclusively useful for Kubernetes
pods — Docker `ps` doesn't expose the restart count without
`docker inspect`, which the agent doesn't run for performance
reasons (one extra subprocess per container per heartbeat
adds up).

Webhook payload:

```json
{
  "device_id": "dev-abc123",
  "name": "web-1",
  "group": "prod",
  "container": "api-deployment-7d5f4-xyz",
  "runtime": "kubernetes",
  "namespace": "default",
  "image": "company/api",
  "restart_count": 5,
  "delta": 2
}
```

### `containers_stale`

Fired when a device hasn't reported container data within
`container_stale_ttl` seconds (default 900s = 15 min). Fires
once per stale period — the notification flag is cleared the
moment fresh container data arrives, so the next stale event
will fire a new alert.

Two suppression rules:

- **Skip offline devices.** If the device hasn't sent any
  heartbeat at all (so `device_offline` already fired or will
  fire), the staleness of its container data isn't a separate
  alert — the device is dead, you already know.
- **Skip unmonitored devices.** Devices flagged
  `monitored=false` are deliberately ignored by all RemotePower
  alerting; this stays consistent.

Webhook payload:

```json
{
  "device_id": "dev-abc123",
  "name": "web-1",
  "hostname": "web1.lan",
  "reported_at": 1714377550,
  "age_seconds": 4231,
  "age_minutes": 70,
  "ttl_minutes": 15
}
```

### Tuning the stale TTL

```bash
curl -X POST https://your-server/api/config \
     -H "X-Token: $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"container_stale_ttl": 1800}'
```

Range: 300–86400 seconds. The 300s floor is enforced at read time
even if a lower value is somehow in the JSON (prevents
alert-storms from misconfiguration during normal poll-interval
jitter). 900s (15 min) is the default, which gives comfortable
headroom over the agent's 5-minute report cadence.

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
    "is_stale": false,
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
  "is_stale": false,
  "stale_ttl": 900,
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

The `is_stale` and `stale_ttl` fields are new in v1.11.4.

---

## Clearing stored container data

There are two ways the dashboard's container list gets cleared:

**Automatic (the common case).** Every heartbeat the agent sends the
current container list — including an empty list when nothing is
running. The server overwrites the stored entry, so removing a
container with `docker rm` (or stopping the daemon, or anything else
that takes a container off the host) shows up on the dashboard
within one report cycle, default ~5 minutes.

**Manual.** Click "Clear data" in the per-device modal, or call:

```bash
curl -X DELETE https://your-server/api/devices/{id}/containers \
     -H "X-Token: $TOKEN"
```

Admin-only. Removes the device's entry from `containers.json` and
clears the `containers_stale_notified` flag (so the next time it
goes stale, you get a fresh webhook). The actual containers on the
host are not touched — this is a dashboard-state operation only.

The agent will repopulate the list on its next heartbeat if it's
still alive. If the agent is dead or removed, the entry stays
gone. Use this when:

- Decommissioning a host but keeping the device record (e.g.
  converting to agentless).
- You just ran `docker rm` and don't want to wait the ~5 minutes
  for the next heartbeat to refresh the dashboard.
- You acknowledged a `containers_stale` webhook and want to
  re-arm it for the next stale event without waiting for fresh
  data → stale → notified again.

Deleting the entire device via `DELETE /api/devices/{id}` also
cleans up the container entry and the stale-notified flag (new in
v1.11.4 — pre-v1.11.4 these were left as orphans).

---

## Troubleshooting

**Containers page shows old data that never refreshes.** This was
the v1.11.4 bug — pre-v1.11.4 agents stopped sending the
`containers` field once their list went empty (e.g. you stopped
the last container). Upgrade the agent (auto within ~1 hour, or
press the ↺ button on the dashboard); next heartbeat will
overwrite with current state.

**Containers page is empty.** The agent reports every five polls,
so wait ~5 minutes after upgrading the agent. Check the agent
journal: `journalctl -u remotepower-agent -e | grep -i container`.

**STALE pill on a device that's clearly online.** Most likely the
agent is on an old version that doesn't send empty lists, but the
device currently has zero containers running. Upgrade the agent.
If the agent is already v1.11.4+ and the device shows STALE, look
at `journalctl -u remotepower-agent` — the container probes
might be hitting their 5-second timeout.

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

**`container_stopped` fires when a container restarts.** If a
restart happens between heartbeats and the new instance has the
same name (typical for `docker run --name X` and Kubernetes
deployments), we see the old one disappear and the new one
appear and fire the webhook. In practice this is the alert you
want — restarts that aren't expected are exactly what you wanted
to know about. To suppress for known-flappy containers, disable
the event globally in Settings → Notifications.

**No `container_stopped` alerts despite restarts I can see.** Are
the containers actually transitioning to a non-running status,
or are they restarting too fast for the 5-minute heartbeat
cadence to catch? Try `CONTAINER_CHECK_EVERY=1` in the agent
(every poll = every 60s) for a host where this matters. Heartbeat
bandwidth cost is small for fleets under 50 hosts.
