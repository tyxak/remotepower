# Rollouts

**Patching → Rollouts** pushes a change to the fleet in **ordered rings** —
canary, then pilot, then broad — so a bad change is caught on a few hosts before
it reaches everything. A rollout does one of four things:

- an **OS package upgrade** (*New rollout → OS package upgrade*),
- an **agent self-update** (*Agent self-update, hash-verified*),
- a **saved script** (*Run a saved script*), or
- a **reboot**, from the *Rolling reboot* panel (see [Rolling reboot](#rolling-reboot)).

A new rollout is a draft until you press **Start**. With change approval on and the
rollout's action among the kinds that need approval (upgrade, reboot and agent update
by default; a script is **Run command**), **Start** parks the rollout for a second admin
and it stays a draft until they approve it. Resuming a paused rollout asks nothing, and
a rollback that runs a script waits the same way when **Run command** is gated.

## Ring model

- You define the rings (which hosts are canary, pilot, broad). A ring targets a
  **group**, a **tag**, a **site**, a **smart group**, a **percentage of the
  fleet**, the **first N hosts**, a pasted **host-id list** (up to 500), or
  **everything else** — which takes every host the rings above it did not, so
  the last ring can't silently omit ungrouped hosts or hosts enrolled after the
  rollout was created. Up to 10 rings.
- Percentages and counts are of the whole fleet and resolve in host-id order,
  so `1 %` → `10 %` → everything else is disjoint and adds up. They are
  re-resolved when the ring is released, not frozen at creation — a host-id
  list is the one selector that *is* frozen.
- A ring is released, then **verified** before the next ring starts. The **verify
  window** is 30 minutes per ring unless you change it (1 to 1,440 minutes). What
  "verified" means depends on the action:
  - **OS package upgrades** compare each host's pending-update count with the
    count when the ring was released. Lower counts as verified, and the same
    count after an hour counts as stalled. A host with nothing pending when the
    ring is released has nothing to compare, so it does not count as verified.
  - **Agent self-update** verifies that each host heartbeats again *on the
    new agent version* — an agent that took the update command but never came
    back within 10 minutes counts as stalled, and a canary ring that goes silent
    halts the rollout instead of promoting.
  - **Scripts** and **reboots** are confirmed as *delivered* only: the command
    left the host's queue. The exit status is not checked, and a script's
    success is not verified.
- Progression can be **automatic** (advance when a ring passes) or **on your
  approval** (hold between rings for a manual go/no-go with **Promote**).
- If none of a ring's hosts verifies within the verify window, the rollout
  **halts** so you can investigate rather than propagating the failure.
- The optional **health gate** halts a rollout early: if a host the ring was
  released to drops below a health score (70 by default) during the verify window,
  and was not already below it, the rollout halts. A halt raises the
  `rollout_halted` event. Nothing rolls back on its own.
- A saved-script rollout can carry a **rollback script**. **Rollback** then
  creates and starts a new rollout that runs that script on exactly the hosts the
  first one reached. Agent self-updates and package upgrades have no rollback.

## Rolling reboot

The *Rolling reboot* panel reboots a scope in **dependency-ordered waves**: hosts
that nothing depends on go first and upstreams go last, following each host's
declared `depends_on`. A dependency cycle lands in the final wave. Pick the whole
fleet, a group, a tag or a smart group, choose whether to health-gate and
auto-promote the waves, and press **Preview waves**. The preview is read-only;
creating the rollout is a second step, so you can check the wave order first.
Agentless hosts are left out. Each wave is a ring of the rollout and is verified
like any other (a reboot is confirmed as delivered).

## When to use which

- **Rollouts** — a single change you want staged and verified across the fleet.
- **[Auto-patch](auto-patch.md)** — recurring unattended upgrades on a schedule.
- **[Scripts](custom-scripts.md)** — author and lint the script a rollout pushes.
- **One-time install** — the button next to *New rollout* installs a package
  straight away through each target's package manager (apt, dnf, yum, zypper,
  pacman or apk), on one host or a whole tag, with no rings. See
  [Patches](patches.md#acting-on-updates).

## Related

- Progress and per-host results also appear in the batch-jobs view; live status
  updates while a rollout runs.
- Rollouts skip quarantined hosts. The commands a ring queues wait in each
  host's queue like any other, so a
  [maintenance window](maintenance.md) with **Gate command/upgrade execution**
  ticked holds them until it opens.
- An [auto-patch](auto-patch.md) policy with rings starts one of these rollouts
  when it fires, and never a second while the first is still running or paused. A [package snapshot](patch-snapshots.md) promoted to a tag
  does not stop a rollout from reaching that tag's hosts.

## Permissions

Creating, advancing and deleting rollouts is admin-only, and every ring release
and approval is audit-logged. Everyone who is signed in can see them. With tenant
isolation on, a rollout belongs to the tenant of the administrator who created it:
a tenant's administrator sees and changes only those, and a ring only reaches that
tenant's hosts.
