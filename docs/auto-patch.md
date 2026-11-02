# Auto-patch

**Patching → Auto-patch** applies package updates **automatically on a schedule**
across a group, tag, site, or the whole fleet — hands-off patching with guardrails.

## Policies

A policy has:

- **Name** — up to 80 characters.
- **Target** — a single host, a group, a tag, a site, or the whole fleet.
- **Schedule** — a cron expression (server timezone), validated on save.
- **Reboot** — whether to reboot after upgrades that require it. *Requires it*
  is checked for real: Linux reboots only on the Debian/Ubuntu `/var/run/reboot-required`
  marker, a `needs-restarting -r` verdict (dnf/yum), or a newer installed
  kernel than the running one (covers Arch); Windows consults its
  pending-reboot registry signals; macOS never needs one for brew upgrades, so
  it never reboots from a policy. A run that upgraded nothing keeps the host
  up, with "reboot SKIPPED" in the patch log.
- **Enabled** — toggle a policy without deleting it.
- **Upgrade mode** is a setting of each host, not of the policy. A host in Extended mode runs
  `apt-get upgrade --with-new-pkgs` when the policy fires, so it also installs the new packages an
  update needs; every other host runs `apt-get upgrade`. See the upgrade mode
  section of [Patches](patches.md).

At each scheduled run, the policy queues an upgrade to every matching host
through the audited [command pipeline](agent-commands.md).

## Guardrails

- Queued upgrades **respect [maintenance windows](maintenance.md) and host
  quarantine** — a quarantined or out-of-window host is skipped, not forced.
- Upgrades ride the same per-host permission and 4-eyes controls as a manual
  patch from the [Patch Report](patches.md).

## When to use which

- **Auto-patch** — recurring, unattended upgrades on a cadence.
- **[Rollouts](rollouts.md)** — a one-off upgrade you want staged in canary →
  pilot → broad rings with verification between them.
- **[Patches](patches.md)** — ad-hoc, see-what's-pending and install now.

## API

`GET /api/autopatch` lists policies (any signed-in user). `POST /api/autopatch`,
`PUT` and `DELETE /api/autopatch/{id}` manage them, and `POST
/api/autopatch/{id}/run` fires one now. A target is `{"type": "all|device|group|tag|site",
"value": "..."}`.

## Permissions

Creating, editing and enabling auto-patch policies is admin-only; each policy run
and its per-host upgrades are audit-logged.
