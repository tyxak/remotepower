# Update history

*Introduced in v1.10.0.*

The Patches feature has been a one-way street since v1.7 — push an
upgrade and hope. v1.10.0 captures the output and lets you read it.

---

## What this is

Every time you trigger a package upgrade on a device — via the
**Upgrade packages** button or `POST /api/upgrade-device` — the agent
runs the appropriate distro command (`apt-get upgrade`, `dnf upgrade`,
`pacman -Syu`), captures the combined stdout+stderr, and posts it
back on the next heartbeat (~60s after the run completes). The
server stores the last 10 runs per device in `update_logs.json`
along with timestamps and exit code.

The device dropdown menu has an **Update history** link that opens
a modal with each run as a collapsible entry. The most recent run is
expanded; older runs are collapsed but one click away. The entry
shows: timestamp, package manager (`apt`/`dnf`/`pacman`), duration,
exit code (green dot for success, red for failure), and the full
captured output.

For scripting access, `GET /api/devices/{id}/update-logs` returns
the same data as JSON.

---

## Why it works the way it does

A few design decisions worth understanding:

**Heartbeat-based, not streaming.** When you trigger an upgrade, the
output isn't visible immediately. You wait until the next heartbeat
(default 60 seconds after the run completes), then the dashboard has
it. Live streaming via long-poll or SSE was discussed and rejected
for this release: it's much more code, and the actual use case
("what did `apt upgrade` install last night?") is post-hoc review,
not live tailing. If you need live tailing for a specific run, hit
**Refresh** in the modal — it polls the same endpoint every time.

**Larger output cap on the agent.** The agent's exec output cap was
4 KB before v1.10.0 — fine for `systemctl status nginx`, useless for
`apt -y upgrade` which routinely produces 30-80 KB. v1.10.0 detects
upgrade commands by string match (`apt-get -y upgrade`, `dnf -y
upgrade`, `pacman -Syu`) and bumps the cap to 256 KB for those
specifically. The server independently caps at 256 KB so a
misbehaving agent can't make `update_logs.json` unbounded.

**Dual-routing on the server.** The output lands in both the
existing `cmd_output.json` (which the Patches page already reads) and
the new `update_logs.json` (which the Update history modal reads).
This keeps backward compatibility — nothing existing breaks — at the
cost of a small write amplification, which doesn't matter for a
flat-file CGI app handling tens of writes per minute.

**Rolling buffer, not append-only.** 10 runs per device. New run,
oldest evicted. If you want long-term retention, scrape the endpoint
and store the results elsewhere — that's what the audit log is for
on the security side, and it's a perfectly fine pattern here too.
The cap is at `MAX_UPDATE_LOGS_PER_DEVICE` in `api.py` if you want
to bump it.

---

## What's captured, what's not

**Captured**:
- Combined stdout+stderr (merged — apt prints progress on stderr)
- Exit code (0 = success, anything else = failure)
- Timestamps (started_at = ~heartbeat-ago, finished_at = heartbeat ts)
- Package manager (detected from the queued command string)

**Not captured**:
- Live progress while the run is in progress
- Anything that goes to `journald` rather than the script's stdio
- The user who triggered it (this is in the audit log under
  `command_queue` — cross-reference by timestamp if needed)
- Unrelated noise from the same heartbeat

**Approximate**:
- `started_at` is set to `finished_at - 1` because the agent doesn't
  currently report a separate start time. Treat the absolute value
  as "this run finished at X"; the duration is essentially always
  shown as the gap to the previous heartbeat, which is a wall-clock
  upper bound rather than the actual run time.

---

## API

### `GET /api/devices/{device_id}/update-logs`

```bash
curl -sSf -H "X-Token: $TOKEN" \
  https://your-server/api/devices/dev-abc123/update-logs | jq
```

```json
{
  "device_id": "dev-abc123",
  "name":      "web-1",
  "capacity":  10,
  "logs": [
    {
      "started_at":      1714377550,
      "finished_at":     1714377610,
      "exit_code":       0,
      "package_manager": "apt",
      "triggered_by":    "",
      "output": "Reading package lists...\nBuilding dependency tree...\nReading state information...\nCalculating upgrade...\nThe following packages will be upgraded:\n  ..."
    }
  ]
}
```

`logs` is ordered oldest-first. The Update history modal reverses it
client-side so the most recent shows first.

---

## Troubleshooting

**"No update runs captured yet" but I just ran an upgrade.**
Wait for the next heartbeat. The agent posts on a fixed interval
(default 60s) — if you triggered the upgrade 5 seconds ago, give it
a minute. Hit **Refresh** in the modal.

**Output is truncated.**
The agent's cap for upgrade commands is 256 KB. If your `apt upgrade`
genuinely produces more than that — a major distribution upgrade,
maybe — it'll be cut off. Bump `MAX_CMD_OUT_BYTES` cap detection in
`client/remotepower-agent` and re-deploy the agent if you need more.

**Output is empty / shows "(no output captured)".**
Either the run hasn't completed yet (it's still in flight), or the
agent died before it could post. Check the agent's systemd journal:
`journalctl -u remotepower-agent -e` on the device.

**Old agents work?**
Yes. Pre-v1.10.0 agents will truncate at 4 KB but still post the
output, and the server will route it correctly. You'll just lose the
tail of long upgrades until you upgrade the agent. The agent self-
update path (`Agent update` in the dropdown) handles this.

---

## File format

`update_logs.json`:

```json
{
  "dev-abc123": [
    {
      "started_at":      1714377550,
      "finished_at":     1714377610,
      "exit_code":       0,
      "output":          "...",
      "package_manager": "apt",
      "triggered_by":    ""
    }
  ]
}
```

Keyed by `device_id`. Each device gets a list capped at 10 entries
(by default; tunable via `MAX_UPDATE_LOGS_PER_DEVICE` in `api.py`).
Entries within the list are oldest-first. The file is created lazily
on first heartbeat with upgrade output — there's no migration step
when upgrading from v1.9.x.

Safe to back up. Safe to delete (you'll just lose history; it'll
repopulate from the next upgrade run).
