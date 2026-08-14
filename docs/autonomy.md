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

An outcome a person confirmed counts double one written by the AI advisor. An
AI verdict nobody contradicted is weaker evidence than an engineer writing down
what fixed it, and the arithmetic reflects that.

Where there is no precedent, the loop does nothing. It does not improvise.

## The safety envelope

Configured per tenant on the **Autonomy** page. One customer opting in never
enables anything for another.

| Setting | What it does |
|---|---|
| **Mode** | `off` records nothing at all · `shadow` records, never acts · `enabled` acts within every limit below |
| **Maximum blast radius** | How much may go dark. Refuses above this. |
| **Actions per hour** | A ceiling per tenant, so a flapping host cannot become a storm. |
| **Proven-recoverable backup** | Destructive actions require a restore drill that actually restored and verified, within 30 days — not a backup that merely ran. |
| **Maintenance window** | Restricts action to the window, or waive it deliberately. |
| **Second pair of eyes** | Destructive actions escalate for approval instead of running. |
| **Permitted actions** | An explicit allow-list. Anything not on it is refused. |

## Blast radius

Before acting the loop counts what depends on the host: monitors bound to it,
containers it runs, watched services, and its network neighbours.

A host with healthy siblings — same group, same CMDB function — scores lower,
because taking one of three replicas is not the same as taking the only one. It
never discounts to zero.

You can use this on its own, without enabling anything: **what breaks if I
reboot this host?** is worth answering for a human about to do it by hand.

## What it can do

Twenty-four action classes, each with a fixed command and a declared list of
the platforms whose agent can actually carry it out:

| Group | Actions |
|---|---|
| Services and containers | restart / start a service, restart a failed timer, restart / start a container |
| Reclaiming disk | vacuum the journal, force a log rotation, clean temporary directories, clear the package cache, prune unused container images, `fstrim`, drop page cache |
| Nudges | re-sync the clock, restart the resolver, flush the mail queue, update AV definitions, start an overdue scrub |
| Destructive | terminate a runaway process, remount a read-only filesystem, restart networking, turn the firewall back on, reboot, patch, rotate a credential |

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

It is deliberately self-contained. The alert will be pruned and the fleet will
have changed by the time somebody asks why this happened, so the receipt does
not point at that context — it holds it.

Refusal reasons are a closed set, so the page can tell you *"blocked 41 times
for blast_radius"* instead of showing you forty-one paragraphs.

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
4. If failing checks went **up**, the receipt is marked unverified and
   `remediation_failed` fires. If they did not, the receipt is verified.

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
