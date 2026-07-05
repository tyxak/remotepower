# Bulk operations

Run an operation across many devices at once. Reachable from the command palette (`/` → "Bulk actions"), Settings → Advanced → Bulk actions, or via the existing checkbox-selection batch bar on the Devices page.

## Available operations

| Action | Backend | Notes |
|---|---|---|
| Upgrade packages | `_queue_command_batch(ids, 'update')` | apt/dnf/yum/pacman, agent picks the right one |
| Reboot | `_queue_command_batch(ids, 'reboot')` | Requires typing `RUN` to confirm |
| Shut down | `_queue_command_batch(ids, 'shutdown')` | Requires typing `RUN` to confirm |
| Force package scan | per-device `POST /devices/<id>/scan-packages` fan-out | Useful before a CVE re-scan |
| Force ACME rescan | per-device `POST /devices/<id>/acme/force-rescan` fan-out | After issuing/renewing via CLI |
| Bulk delete *(v5.0.0)* | `POST /api/devices/bulk-delete` | Admin only. Removes many devices in one audited call. |
| Bulk tag *(v5.0.0)* | `POST /api/devices/bulk-tags` | Admin only. Add and/or remove tags across the selection. |

## Filtering targets

The modal lets you scope to a subset:

- **All monitored** — every device with `monitored !== false`. Default.
- **By group** — devices grouped under the same package-manager family (apt/dnf/yum/pacman) or your custom group label. Useful for distro-specific operations.
- **By tag** — devices carrying a specific tag. Tags are a free-form array on each device; up to 12 distinct tags surface in the modal.

The preview line shows exactly which devices will receive the command, so there's no surprise. If the preview is empty, the filter excluded everything — adjust before clicking Run.

## Safety

**Reboot and shutdown** require typing the literal string `RUN` in a follow-up prompt. The other actions just need a one-click confirm.

Bulk commands aren't queued instantly atomic — they're appended to each device's command queue in a single loop, but if the page crashes mid-loop some devices might miss the command. Sample one device's `command_executed` event in Recent Activity to confirm the round trip completed.

## Audit trail

Every queued command is logged to `audit_log.json` with `actor`, `action`, and a `device=<id>` detail line. Filter the audit log by `action=batch_command` (legacy name from the existing batch path) to find every bulk run.

## When to prefer this over a script

The bulk modal is for ad-hoc operations across the UI's mental model — "patch everything in production today" or "force ACME rescan on the four web servers because I just renewed certs". It's not a replacement for:

- **Scheduled maintenance** — use the Schedule page; it has cron-like recurrence and maintenance window suppression
- **CI/CD-style rollouts** — use the API directly with an API key, with proper rollout staging (canary → 10% → 50% → 100%)
- **Recurring health checks** — use the existing custom-scripts feature

## Limits

- Sequential fan-out for per-device endpoints (force_pkg_scan, force_acme_rescan) — N agent heartbeats means N round-trips before everything is queued. Future improvement: bulk endpoint for these.
- No "wait for completion" — the modal closes once commands are queued. Watch Recent Activity or the device drawer for execution results.
- No undo. Once shutdown/reboot/upgrade is queued, the operator must contact the agent some other way to cancel (e.g. SSH in and stop the agent before the next heartbeat picks up the command).
