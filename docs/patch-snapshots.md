# Package snapshots

**Automation → Package Snapshots**

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

A snapshot holds **one version per package name**: the newest version found on any host
you can see. It is one list for the whole fleet, not a list per host. If no host has
reported its packages yet, the snapshot is empty and the page tells you so; run a package
scan first.

A snapshot is a point-in-time copy. Taking one changes nothing on any host. Only admins
can take one, the name is up to 80 characters, and you can keep up to 200 snapshots.

## Diffing two snapshots

Pick two snapshots and click **Show diff**. You get a table of the packages that were
added, removed, or changed version between them. Because a snapshot keeps one version
per package for the whole fleet, the table does not say which host changed.

This is the fastest way to answer "what actually landed in last night's patch run"
— take a snapshot before, take one after, diff them.

## Promoting a snapshot as a tag's reference state

**Promote to tag…** nominates a snapshot as the *reference* for a tag — the versions
those hosts are supposed to be on. Once promoted, **Drift** lists every host
carrying that tag whose packages no longer match the reference, and what differs: the
host, the package, the pinned version and the installed version. A package the host
does not have is not reported. On a snapshot that is not promoted, the button reads
**Drift (whole fleet)** and compares every host you can see.

Typical use: you bring your web hosts to a set of versions you have tested, take a
snapshot, promote it as the reference for the `web` tag, and from then on any web host
that wanders off that set shows up as drifted. Take the snapshot when the hosts run the
versions you want. A host that runs an older version than another host counts as
drifted from the start, because the snapshot keeps the newest version it found.

Promotion is admin-only and audited. A tag has one reference at a time: promoting a
different snapshot to the same tag replaces the old one. **Change tag** moves a
snapshot to another tag, and **Demote** (the API: promote with no tag) clears it.

**Promoting also pauses [auto-patch](auto-patch.md) for that tag.** While a snapshot is
promoted to a tag, auto-patch policies skip every host that carries the tag, even when
the policy names the host or the tag directly. Demote the snapshot to let auto-patch
touch those hosts again. Policies with rings and [rollouts](rollouts.md) pick their
hosts on their own and do not check this.

## Enforcing a reference

Drift reporting is read-only by default — it tells you a host has moved, it does not
move it back. **Enforce** is the explicit, admin-only action that queues a command to
bring a drifted host back to the reference versions. The snapshot has to be promoted
to a tag first. There is no button for it on the page yet: call
`POST /api/patch-snapshots/{id}/enforce` (see the API table below). With a `device_id`
it targets that host; without one it targets every drifted host that carries the tag.

Enforce it, per host, when you have decided that the reference really
is what that host should be running. Rolling a package *backwards* is not always
safe (a downgrade can be blocked, or can break a dependency that has since moved),
so this is a decision, not a background job.

The queued command is a normal `exec:` command, so it goes through the same checks as
any other: a quarantined host or a host in audit mode is skipped, and change approval
(**Settings → Security**) parks it for a second admin when **Run command** is among the
actions that require approval. It installs the exact pinned
versions with `apt-get`, `dnf` or `yum`. On a host that uses another package manager
(pacman, for example) the command exits with an error and changes nothing.

## What it does *not* do

Package snapshots are a **reporting and reference** tool. Two actions reach further
than a report: promoting a snapshot holds auto-patch back from the tag's hosts, and
**Enforce** queues a command. Apart from those, they are separate from patching:

- Taking a snapshot **does not change what [auto-patch](auto-patch.md) installs**.
  Auto-patch policies decide what gets installed; snapshots record and compare what
  *is* installed. Promoting a snapshot never makes auto-patch install the pinned
  versions, it only holds auto-patch back.
- Drift from a reference is **not** an alert — it is a view you go and
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
| `GET` | `/api/patch-snapshots/{id}/drift` | | Hosts on the promoted tag that have drifted from this reference |
| `POST` | `/api/patch-snapshots/{id}/enforce` | admin | Queue a command to bring a drifted host back to the reference (`{device_id}`, optional; without it every drifted host on the tag) |
