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

**Reboot and shutdown** require typing the literal string `RUN` in a follow-up prompt. The other actions just need a one-click confirm. The Devices-page batch bar's confirmation dialog lists the selected device **names** (not just a count), so you can catch a mis-selection before anything is queued.

Reboot, shutdown and upgrade go out as a single API call and are queued atomically under one lock server-side. The per-device fan-out actions (force package scan, force ACME rescan) are queued one request at a time — if the page closes mid-way, the remaining devices are skipped. Sample one device's `command_executed` event in Recent Activity to confirm the round trip completed.

## Audit trail

Every queued command is recorded in the command history (the Recent Commands view) with the actor, device and command, and fires a `command_queued` event into the activity feed — so a bulk run leaves one row per target device.

## When to prefer this over a script

The bulk modal is for ad-hoc operations across the UI's mental model — "patch everything in production today" or "force ACME rescan on the four web servers because I just renewed certs". It's not a replacement for:

- **Scheduled maintenance** — use the Schedule page; it has cron-like recurrence and maintenance window suppression
- **CI/CD-style rollouts** — use the API directly with an API key, with proper rollout staging (canary → 10% → 50% → 100%)
- **Recurring health checks** — use the existing custom-scripts feature

## Limits

- Sequential fan-out for per-device endpoints (force_pkg_scan, force_acme_rescan) — N agent heartbeats means N round-trips before everything is queued. Future improvement: bulk endpoint for these.
- No "wait for completion" — the modal closes once commands are queued. Watch Recent Activity or the device drawer for execution results.
- No undo once a command has been *delivered* — but while it's still waiting, **Admin → Command Queue** shows every pending command per device and lets you cancel one or clear a device's whole queue (`DELETE /api/devices/<id>/command-queue`).
