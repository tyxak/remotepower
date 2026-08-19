# Autonomous remediation

RemotePower can fix recurring problems on its own. The page is there from the
start so you can read it; the loop is **inert** until you say otherwise. Every
tenant begins at **off**, which records nothing and acts on nothing. You move a
tenant to **shadow** to have it write down what it *would* have done, grade
that, and only then let it act.

Visibility and permission are separate on purpose. Hiding the page would not
have made anything safer — the per-tenant mode is what holds the loop still —
and a feature nobody can find is a feature nobody can audit.

This page explains what it will and will not do, and why the answer to "why did
it do that?" is always a receipt rather than a shrug.

## The short version

1. An alert fires that maps to a known action — a failed unit, a restarting
   container, a disk filling with logs.
2. The loop looks up what fixed **this exact signature on your fleet before**.
3. It works out what goes dark if it acts: monitors, containers, watched
   services, network neighbours — discounted if the host has healthy siblings.
4. It checks the whole safety envelope you configured.
5. In shadow it writes a receipt and stops. With autonomy enabled it acts
   through the same audited command path an operator uses, then re-runs that
   host's own checks 15 minutes later to decide whether it worked.

## It acts on precedent, not on a guess

The proposal comes from **incident memory** — the durable record of resolved
incidents and what closed them. Two prior incidents minimum with the same
signature, and at least 70% of them must have actually been resolved.

Three things count as a prior fix, and none of them needs an AI provider:

* **A fix an operator ran** that cleared its alert. You press Fix on an alert
  row; the verify sweep checks a few minutes later whether the alert closed. It
  did, so that is now on record as something that works on this fleet.
* **An automation rule** whose remediation verified the same way.
* **One of this loop's own actions** that a person approved and that came back
  verified against the host's own checks.
* Plus, as before, a resolution note you wrote when closing an alert, or an AI
  triage verdict if you have one configured.

An outcome a person confirmed counts double one written by the AI advisor. An
AI verdict nobody contradicted is weaker evidence than an engineer writing down
what fixed it, and the arithmetic reflects that.

Precedent is matched to the **event and the remedy**, not to a family of alerts.
A prior fix recorded against a different action still counts as an incident this
fleet resolved, and not as evidence for the action on the table — so a history of
rotating logs does not argue for running `fstrim`. Evidence that names no
particular remedy, like a resolution note, counts as it always did.

Where there is no precedent, the loop does nothing. It does not improvise — but
you can decide that the curated command catalog is enough of a plan on its own,
by unticking **Only act where this fleet has fixed the same thing before**. That
is a real decision with a real trade-off, which is why it is a switch you have
to flip rather than something that quietly happens.

## The safety envelope

Configured per tenant on the **Autonomy** page. One customer opting in never
enables anything for another.

| Setting | What it does |
|---|---|
| **Mode** | `off` records nothing at all · `shadow` records, never acts · `enabled` acts within every limit below |
| **Maximum blast radius** | How much may go dark. Refuses above this. |
| **Actions per hour** | A ceiling per tenant, so a flapping host cannot become a storm. |
| **Proven-recoverable backup** | Actions that can lose data require a restore drill that actually restored and verified, within 30 days — not a backup that merely ran. |
| **Change window** | Holds action on hosts covered by a maintenance window with change gating switched on, until that window is open. A host no such window covers is never held. |
| **Second pair of eyes** | Destructive actions escalate for approval instead of running. |
| **Prior fixes required** | Act only where this fleet has fixed the same signature before. On by default. |
| **Permitted actions** | An explicit allow-list. Anything not on it is refused. |

### What counts as recoverable

Two kinds of evidence, strongest first:

* **A restore drill** — one that actually restored a sample and verified it,
  within 30 days. Your agent reports these; they appear against the backup paths
  you monitor.
* **A recent Proxmox backup or snapshot** of the guest this host is. A vzdump
  archive is a backup; a snapshot is a rollback point on the same storage rather
  than a backup. Neither has been proven to restore — but for the question this
  gate actually asks, *if this upgrade breaks the host, can I get it back*, both
  are real answers, and restoring either is a mechanical operation Proxmox
  guarantees.

Recency for the Proxmox evidence uses **your own thresholds** — the same
`proxmox_backup_warn_days` and `proxmox_snapshot_warn_days` that decide whether a
guest is flagged as under-protected. A backup this product is already telling you
is stale is not what lets it patch.

The guest is matched by name: `pmg01.tvipper.com` is the guest called `pmg01`. If
two guests share a name, nothing matches — a guess is not a safety precondition.
Set `proxmox_guest` on the device record to pin it explicitly. Whichever evidence
applied is written on the receipt, naming the guest and the age, because "this
host is recoverable" is not a claim worth making without saying which machine's
backup said so.

**"Can lose data" and "destructive" are separate questions.** Restarting
networking is destructive — it can take a host off the network — and a backup is
not what makes it safe or unsafe. Patching, rebooting, remounting a filesystem
the kernel forced read-only and rotating a credential are the ones where a
proven restore is the thing standing between you and a bad day, so those are
the ones the backup setting applies to. Each row in the allow-list says which it
is.

## Blast radius

Before acting the loop counts what depends on the host: monitors bound to it,
containers it runs, watched services, and its network neighbours.

A host with healthy siblings — same group, same CMDB function — scores lower,
because taking one of three replicas is not the same as taking the only one. It
never discounts to zero.

You can use this on its own, without enabling anything: **what breaks if I
reboot this host?** is worth answering for a human about to do it by hand.

## What it can do

Twenty-six action classes, each with a fixed command and a declared list of the
platforms whose agent can actually carry it out. The allow-list on the page is
grouped the same way and has a filter, because twenty-six machine names in one
column is a wall:

| Group | Actions |
|---|---|
| Services and containers | restart / start a service, restart a failed timer, restart / start a container |
| Reclaiming disk | vacuum the journal, force a log rotation, clean temporary directories, clear the package cache, prune unused container images, `fstrim`, drop page cache |
| Nudges | re-sync the clock, flush the mail queue, update AV definitions, start an overdue scrub, take a ZFS snapshot |
| Posture that drifted off | turn real-time malware protection back on, turn Gatekeeper back on |
| Destructive | terminate a runaway process, remount a read-only filesystem, restart networking, turn the firewall back on, reboot, patch, rotate a credential |

### One alert, several conditions

A few alerts describe more than one thing and say which in their payload.
`metric_critical` is the per-host resource alert — the one that fires when a
fleet host fills its disk — and it covers seven different resources. The remedy
for a full filesystem is not the remedy for CPU saturation, so those events map
through the payload field that distinguishes them:

| Alert | Reads | Acts on |
|---|---|---|
| `metric_critical` / `metric_warning` | `metric` | a full **disk** takes the disk ladder; **inodes** take the rungs that delete files rather than free bytes; **memory** and **swap** drop reclaimable cache |
| `snapshot_stale` | `kind` | a **zfs** pool gets a timestamped snapshot |

A value with no entry is not a candidate at all. Nothing in the catalog frees
CPU, and a btrfs snapshot needs a source subvolume and a destination path that no
alert carries — so those are left alone rather than given a remedy that would not
work.

Every one is checked against what the three agents actually implement, and
against whether the event that triggers it names a host — an action mapped to a
server-side check, or to an alert that does not say which machine, is a checkbox
that can never do anything. Five were removed in v7.0.2 for exactly that.

An event maps to an **ordered ladder**, not one action. A host low on disk has
half a dozen plausible remedies of escalating nerve; the loop takes the first
one *you* have permitted. That is what makes the allow-list a real control
rather than an on/off switch — the choice of remedy is yours, not the source
code's.

Commands go out in the same grammar an operator's own actions use (`svc:`,
`container:`, `exec:`, `ps:`), so autonomy inherits every gate they pass:
maintenance mode, quarantine, audit mode, the approval queue. Nothing here has
a private path to a host.

## What it will not do

* Act on an event class nobody has analysed. The event→action map is explicit;
  an unmapped alert is never a candidate.
* Act on an action class absent from your allow-list, or one this build does not
  recognise. A policy naming an unknown action has that action discarded.
* Build a command out of alert text. Command templates live in the source beside
  the safety analysis — a command assembled from remote data is how an alert
  becomes an injection vector. An alert may supply a *parameter* (which unit,
  which container), and only one that survives sanitising: a name containing a
  colon would re-split the wire format into a different action, so it is
  refused rather than cleaned up.
* Send a host's agent a verb it does not implement. `svc:` is Linux and
  Windows; `ps:` is Windows only. An agent handed an unknown verb answers
  *success* and does nothing, so the loop refuses with `unsupported_platform`
  instead of writing a receipt that claims it acted.
* Act on an alert that does not say *which* thing broke. "A service failed"
  with no unit name refuses as `missing_parameter`.
* Touch a device outside the acting tenant.
* Decide for itself whether it worked. That judgement belongs to the same
  per-host checks engine you already use; if failing checks increase, the
  receipt says so and `remediation_failed` fires. It does not undo anything —
  see below for why there is no rollback.

## Receipts

Every decision produces one, whether it acted, refused, escalated or was in
shadow. A receipt carries the trigger, the action, the verdict, a
machine-readable reason, the blast radius, and the precedent that justified it.

It is self-contained. The alert will be pruned and the fleet will
have changed by the time somebody asks why this happened, so the receipt does
not point at that context — it holds it.

Refusal reasons are a closed set, so the page can tell you *"blocked 41 times
for blast_radius"* instead of showing you forty-one paragraphs.

You can delete a receipt, or clear every receipt you can see, from the toolbar
on that card. It is admin-only and audited — who cleared it, how many rows, and
how many of those were still waiting on their verification sample. It changes
nothing the loop decided and does not stop it running.

## Recommended rollout

1. Open the **Autonomy** page. It is empty, because nothing is recording yet.
2. Set one tenant to **shadow**. Leave it for a few weeks.
3. Read the receipts. For each one ask: would I have done that?
4. Narrow the allow-list to the actions you agreed with, set a blast-radius
   limit you are comfortable with, and switch that tenant to **enabled**.
5. Keep reading the receipts.

Step 3 is the point of the whole design. You are not asked to trust it — you are
asked to check its homework for a month first.

## What happens when it acts

1. The command is queued through **the same channel an operator's own commands
   use**. Every guard they pass, it passes: maintenance mode, quarantine, audit
   mode, the four-eyes gate. A refusal is reported as a refusal, not as success.
2. A **snapshot of the host's own checks** is taken first.
3. Dispatch is asynchronous — the agent collects the command on its next
   heartbeat — so a second checks sample is taken **15 minutes later**.
4. The agent returns the command's **exit code**, and that outranks everything
   else: a non-zero code is the action telling you it did not do the thing, and
   no amount of unchanged checks argues otherwise. A command the agent never
   reported at all — the host was offline, or its poll interval is longer than
   the verify window — is recorded as exactly that.
5. If failing checks went **up**, the receipt is marked unverified and
   `remediation_failed` fires. If they did not, and the command came back clean,
   the receipt is verified.

Only an action that reported **rc 0** *and* whose alert then closed becomes
precedent. An alert that cleared on its own while a command sat uncollected in
the queue is not evidence about that command.

An **escalated** action becomes a real entry in the Confirmations queue, with a
reason saying it was proposed by autonomous remediation. Approving it dispatches
through the ordinary path; ignoring it does nothing.

## There is no rollback, and the receipt no longer implies one

You cannot un-restart a service, un-vacuum a journal or un-reboot a host. Almost
nothing this loop does is reversible, so a `rolled_back` field that was always
false was claiming a capability that does not exist — an operator reading a
receipt could reasonably have concluded a failed action had been undone.

What you get instead is the honest version: it tells you the fix made things
worse, promptly and with the numbers, and leaves the host in the state it is
actually in. If you want a change reversed, you reverse it — with the full
picture in front of you.

That is also the argument for the blast-radius limit and the allow-list being
tight to begin with. An action you would not want to have to undo by hand is one
to leave switched off.
