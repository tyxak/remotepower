# Rollouts

**Patching → Rollouts** pushes an **agent upgrade or a saved script** to the
fleet in **ordered rings** — canary, then pilot, then broad — so a bad change is
caught on a few hosts before it reaches everything.

## Ring model

- You define the rings (which hosts are canary, pilot, broad — by group / tag /
  site / count).
- A ring is released, then **verified** before the next ring starts:
  - **Upgrades** use post-deploy verification (the agent confirms the new
    version is healthy after updating).
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
