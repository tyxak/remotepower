# Bulk operations

Run an operation across many hosts at once. Open it from the **Bulk actions** button on the Hosts page, from the command palette (`/` or `Ctrl/Cmd-K`, then "Bulk actions"), or from the checkbox batch bar on the Hosts page.

## Available operations

| Action | API | Notes |
|---|---|---|
| Upgrade packages | one batch call | apt/dnf/yum/pacman, the agent picks the right one |
| Reboot | one batch call | Requires typing `RUN` to confirm |
| Shut down | one batch call | Requires typing `RUN` to confirm |
| Force package scan | per-host `POST /devices/<id>/scan-packages` | Useful before a CVE re-scan |
| Force ACME rescan | per-host `POST /devices/<id>/acme/force-rescan` | After issuing or renewing via CLI. Linux hosts only. |
| Bulk delete | `POST /api/devices/bulk-delete` | Admin only. Removes many hosts in one audited call. |
| Bulk tag | `POST /api/devices/bulk-tags` | Admin only. Add and/or remove tags across the selection. |

## Filtering targets

The modal lets you scope to a subset:

- **All monitored** — every host with `monitored !== false`. Default.
- **By group** — hosts that share a group label. Hosts with no group are listed under `devices`.
- **By tag** — hosts carrying a specific tag. Tags are a free-form array on each host; up to 12 distinct tags surface in the modal.
- **By smart group** — the members of a saved smart group, shown as `smart:<name>` (see [sites.md](sites.md)).

The preview line shows exactly which hosts will receive the command, so there's no surprise. If the preview is empty, the filter excluded everything — adjust before clicking Run.

## Safety

**Reboot and shutdown** require typing the literal string `RUN` in a follow-up prompt. The other actions just need a one-click confirm. The Hosts-page batch bar's confirmation dialog lists the selected host **names** (not just a count), so you can catch a mis-selection before anything is queued.

Reboot, shutdown and upgrade go out as a single API call and are queued atomically under one lock server-side. The per-host fan-out actions (force package scan, force ACME rescan) are queued one request at a time — if the page closes mid-way, the remaining hosts are skipped. Sample one host's `command_executed` event in Recent Activity to confirm the round trip completed.

## Audit trail

Every queued command is recorded in the command history (the Recent Commands view) with the actor, host and command, and fires a `command_queued` event into the activity feed — so a bulk run leaves one row per target host.

## When to prefer this over a script

The bulk modal is for ad-hoc operations across the UI's mental model — "patch everything in production today" or "force ACME rescan on the four web servers because I just renewed certs". It's not a replacement for:

- **Scheduled maintenance** — use the Schedule page; it has cron-like recurrence and maintenance window suppression
- **CI/CD-style rollouts** — use the API directly with an API key, with proper rollout staging (canary → 10% → 50% → 100%)
- **Recurring health checks** — use the existing custom-scripts feature

## Limits

- Sequential fan-out for per-host endpoints (force_pkg_scan, force_acme_rescan) — N agent heartbeats means N round-trips before everything is queued. Future improvement: bulk endpoint for these.
- No "wait for completion" — the modal closes once commands are queued. Watch Recent Activity or the host drawer for execution results.
- No undo once a command has been *delivered* — but while it's still waiting, **Automation → Command Queue** shows every pending command per host and lets you cancel one or clear a host's whole queue (`DELETE /api/devices/<id>/command-queue`).
