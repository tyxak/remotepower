# Rollouts

**Patching → Rollouts** pushes an **agent upgrade or a saved script** to the
fleet in **ordered rings** — canary, then pilot, then broad — so a bad change is
caught on a few hosts before it reaches everything.

## Ring model

- You define the rings (which hosts are canary, pilot, broad). A ring targets a
  **group**, a **tag**, a **site**, a **smart group**, a **percentage of the
  fleet**, the **first N hosts**, a pasted **device-id list** (up to 500), or
  **everything else** — which takes every host the rings above it did not, so
  the last ring can't silently omit ungrouped hosts or hosts enrolled after the
  rollout was created. Up to 10 rings.
- Percentages and counts are of the whole fleet and resolve in device-id order,
  so `1 %` → `10 %` → everything else is disjoint and adds up. They are
  re-resolved when the ring is released, not frozen at creation — a device-id
  list is the one selector that *is* frozen.
- A ring is released, then **verified** before the next ring starts:
  - **Upgrades** use post-deploy verification (the agent confirms the new
    version is healthy after updating).
  - **Agent self-update** verifies that each device heartbeats again *on the
    new agent version* — an agent that took the update command but never came
    back counts as stalled, and a canary ring that goes silent halts the
    rollout instead of promoting.
  - **Scripts** check the exit status across the ring.
- Progression can be **automatic** (advance when a ring passes) or **on your
  approval** (hold between rings for a manual go/no-go).
- If a ring fails its verification, the rollout **halts** so you can investigate
  rather than propagating the failure.

## When to use which

- **Rollouts** — a single change you want staged and verified across the fleet.
- **[Auto-patch](auto-patch.md)** — recurring unattended upgrades on a schedule.
- **[Scripts](custom-scripts.md)** — author and lint the script a rollout pushes.

## Related

- Progress and per-host results also appear in the batch-jobs view; live status
  updates while a rollout runs.
- Rollouts honour [maintenance windows](maintenance.md) and quarantine.

## Permissions

Creating and advancing rollouts requires the **upgrade** action permission (or
admin); every ring release and approval is audit-logged.
