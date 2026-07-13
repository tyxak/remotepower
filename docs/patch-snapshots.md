# Package snapshots

**Monitoring → Package Snapshots**

A package snapshot freezes the exact package versions your fleet is running right
now into a named, dated record. Later you can diff two snapshots, nominate one as
the reference state for a tag, and see which hosts have drifted away from it.

The problem it solves is the one that only shows up at 2am: *"this worked last
Tuesday — what changed?"* A snapshot lets you answer that with a list instead of a
guess.

## Taking a snapshot

Give it a name and click **Create snapshot**. The name is the only thing you have to
decide — the contents are whatever the fleet is running at that moment, as last
reported by each agent. Good names describe the *moment*, not the date (the date is
recorded for you):

- `before-kernel-upgrade`
- `known-good-2026-Q3`
- `pre-postgres-16`

A snapshot is a point-in-time copy. Taking one changes nothing on any host.

## Diffing two snapshots

Pick two snapshots and click **Show diff**. You get the packages that were added,
removed, or changed version between them, per device.

This is the fastest way to answer "what actually landed in last night's patch run"
— take a snapshot before, take one after, diff them.

## Promoting a snapshot as a tag's reference state

**Promote** nominates a snapshot as the *reference* for a tag — the versions those
hosts are supposed to be on. Once promoted, the **drift** view lists every device
carrying that tag whose packages no longer match the reference, and what differs.

Typical use: you qualify a set of versions on a staging host, snapshot it, promote
it as the reference for `role:web`, and from then on any web host that wanders off
that set shows up as drifted.

Promotion is admin-only and audited. Promoting a different snapshot replaces the
reference; demoting (promote with no tag) clears it.

## Enforcing a reference

Drift reporting is read-only by default — it tells you a host has moved, it does not
move it back. **Enforce** is the explicit, admin-only action that queues a command to
bring a drifted device back to the reference versions.

Enforce it deliberately, per device, when you have decided that the reference really
is what that host should be running. Rolling a package *backwards* is not always
safe (a downgrade can be blocked, or can break a dependency that has since moved),
so this is a decision, not a background job.

## What it does *not* do

Package snapshots are a **reporting and reference** tool. They are deliberately
separate from patching:

- Taking or promoting a snapshot **does not change what
  [auto-patch](auto-patch.md) installs**. Auto-patch policies decide what gets
  installed; snapshots record and compare what *is* installed.
- Drift from a reference is **not** an alert by default — it is a view you go and
  look at.
- A snapshot is not a backup. It records package *versions*, not package contents,
  and not your data.

## Related

- **[patches.md](patches.md)** — pending patches, per-package pinning, patch SLA.
- **[auto-patch.md](auto-patch.md)** — automatic patching policies and staged rings.
- **[drift.md](drift.md)** — *configuration* drift (files and settings), which is a
  different thing from *package* drift.

## API

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/patch-snapshots` | | List snapshots (metadata only) |
| `POST` | `/api/patch-snapshots` | admin | Freeze current fleet package state into a new named snapshot |
| `GET` | `/api/patch-snapshots/{id}` | | One snapshot, with its entries |
| `DELETE` | `/api/patch-snapshots/{id}` | admin | Delete a snapshot |
| `GET` | `/api/patch-snapshots/diff` | | Diff two snapshots (`?a=`&`?b=`) |
| `POST` | `/api/patch-snapshots/{id}/promote` | admin | Promote as a tag's reference state (`{tag}`; empty body demotes) |
| `GET` | `/api/patch-snapshots/{id}/drift` | | Devices on the promoted tag that have drifted from this reference |
| `POST` | `/api/patch-snapshots/{id}/enforce` | admin | Queue a command to bring a drifted device back to the reference (`{device_id}`) |
