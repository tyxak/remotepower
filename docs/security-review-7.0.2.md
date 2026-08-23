# Security review — v7.0.2 "Prec3dentMatters"

Every release gets a review before it ships. This one found **twenty-seven** issues
worth reporting, all **caught before release** and all fixed in the release they
are described in. None came from the field.

Most are older than this release. That is the more useful thing to say about
them: they had been present through several prior versions, and the scans, tests
and reviews that ran on each of those did not surface them.

The bar this project holds itself to is that nothing Critical, High or Medium
ships. That bar is met.

## What was reviewed

- The full v7.0.1 → v7.0.2 diff, read adversarially rather than for correctness.
- **The whole project, not the diff** — because the previous release learned
  that the diff is the wrong unit. Four separate passes over multi-tenancy,
  the three agents, the data path from collection to screen, and the tooling.
- The recurring weakness classes this project keeps a written list of, each
  re-checked by enumerating every call site and printing the ratio rather than
  asking whether the rule "looks applied".
- Static analysis: CodeQL (the same query suites and configuration the
  production scan uses), semgrep across Python and JavaScript, bandit, gitleaks,
  a strict type check, and a JavaScript correctness rule set.
- Property-based testing over the release's new safety helpers — thousands of
  generated inputs against stated invariants, rather than a handful of examples.
- The full test suite on all three storage backends.

## The pattern worth naming

Nine of the fifteen are the same shape, and it is the shape this project keeps
finding: **a rule already written down and applied in most places, missed in one
or two.**

Multi-tenancy was applied to the config READ path and not the write path. It was
applied to auto-patch policies and not to the maintenance windows they generate.
Two of three agents refused an unsigned update. Two of three stripped a command
prefix. Four of eight Windows posture fields reached a screen; four of five
macOS ones did.

A half-applied rule is harder to see than a missing one, because every correct
site makes the file read as though the rule is enforced. Reading for "is this
rule followed?" returns yes. The only reliable method is to enumerate every
site mechanically and count.

## Multi-tenancy — four ways one tenant could reach another

Each needed a tenant-administrator account and nothing else. On a single-tenant
install — the common case — none of them applies, because the checks involved
are inert when tenancy is off.

### Instance settings could be rewritten by any tenant administrator

**Critical.** Settings are one instance-wide store, and the save handler
required an administrator — which a tenant administrator is. A single request
could switch multi-tenancy off entirely, which makes every isolation check in
the product inert at once. The same handler owns proxy trust (which decides
whether the address allowlist can be bypassed), maintenance mode, and audit
forwarding.

The equivalent restriction had been applied to the settings READ path in
v6.4.3, where the consequence is smaller, and never to the write path.

*Fixed:* instance settings are refused to a non-platform administrator whenever
tenancy is enforced. A tenant's own settings are unaffected.

### Automation rules carried no tenant

**Critical.** Rules fire on every event on every device and match on an
operator-supplied device filter. An empty filter matched every device on the
instance, and one of the actions a rule can take queues a saved script that the
agent runs with full privileges.

The equivalent policy object had carried a tenant since v6.4.0, for exactly this
reason, with a milder payload.

*Fixed:* rules record the tenant that created them, are confined to it when they
fire, and are invisible to other tenants for reading, editing and deleting. The
request body cannot supply its own tenant. Rules created before this release keep
their prior behaviour, because assigning them an owner would be a guess about who
wrote them.

### The saved-script library was shared by everyone

**High.** A script body is code that runs with full privileges on a host, and in
practice holds credentials, internal hostnames and API endpoints. Any role in any
tenant could list the library and read every body; any tenant administrator could
repoint or delete another tenant's script, which is code execution on that
tenant's hosts the next time it runs.

*Fixed:* scripts belong to the tenant that saved them, across listing, reading,
editing, deleting, scheduling and batch execution. Older scripts take their owner
from the recorded author, which the store already held. One whose author has since
been deleted stays shared and is flagged in the list, so it can be claimed by
re-saving rather than silently disappearing.

### A maintenance window from one tenant covered every tenant

**High.** A window suppresses alerts, and with change gating enabled holds
commands until it opens. A `global` window from one tenant therefore silenced
every other tenant's alerting, or froze their changes. Editing and deleting were
unscoped too.

*Fixed:* windows carry their tenant, and `global` means everything the operator
who wrote it can see. The scope-matching rule had five separate copies across
alert suppression, change gating, scan gating, availability accounting and
integrity checking; they now share one. Auto-patch policies stamp their tenant
onto the windows they generate, which had been the one place that stamp was
dropped.

## The agents

### macOS would install an unsigned update

**High.** Pinning a release key means "install only builds signed by this key".
The Linux and Windows agents both fetch the detached signature and refuse without
a valid one. The macOS agent verified only the checksum the server advertised —
which confirms the download arrived intact and says nothing about who produced
it. An operator who pinned the key had two of three agents enforcing it, and
nothing to indicate the third did not.

Both server endpoints already existed; only the agent never called them.

*Fixed:* the macOS agent performs the same three-step verification, failing
closed. macOS and Windows also gained the refuse-to-downgrade guard the Linux
agent has had since v5.0.1.

### A compliance report could be a decompression bomb

**Medium.** The upload was limited to 30 MB *compressed*, which bounds nothing —
compression reaches roughly 1000:1 on repetitive input, so that limit admitted an
archive expanding to tens of gigabytes. Nothing decompressed it on the way in, so
it was stored and expanded later, when an operator opened the report. Submitting
one required only a device credential, which is the lowest-privilege credential
in the product and is held by every agent.

*Fixed:* both ends decompress incrementally against a hard output limit. A
truncated archive is refused rather than served as a blank report — a defect found
by property testing, not by example.

### A signed command could be replayed

**Medium.** The signature binds a command to one device and an issue time, and
anything inside the freshness window verified. The same signed command, re-sent,
ran again — for the length of that window. The feature's own documentation stated
that replaying a command at a later time executes nothing, which was true only
past expiry.

*Fixed:* agents remember which signatures they have accepted and refuse a repeat.
The server signs each dispatch afresh, so re-issuing a command is unaffected.

### Decoy files were an unchecked way to change a host

**Medium.** Planting a decoy writes a privileged file at an operator-chosen path
with operator-chosen content. Audit (read-only) mode and require-signed-commands
both exist to stop the server changing a host, and this path honoured neither —
so on a fleet where a stolen administrator credential cannot sign a command, it
could still place a file.

*Fixed:* audit mode skips planting and records why in the arming report; paths in
locations where the system executes what it finds are refused at both ends, with
the reason given; and the parent directory is never created. A decoy that
imitates a private key remains legal — it is one of the more effective ones.

### A tagged command became a comment on Windows and macOS

**Low**, but it produced a false success. Two paths prefix a command so its
output can be filed against the action that caused it. The Linux agent has
removed that prefix since v3.0.1; the other two passed it to the interpreter,
where the prefix character begins a comment. The command became a comment, exited
successfully, and reported success for something that never ran.

*Fixed:* both agents remove the prefix, and the tag is retained on the reported
command so output is still filed correctly.

### The agent log was world-readable

**Low.** The Linux agent's log is created at the process default permissions,
which made it readable by any local account — while recording every command
executed and the first part of its output. Operators paste commands carrying
credentials. The macOS agent has restricted this since v6.4.0.

*Fixed:* owner-and-group readable, set at file creation so rotation preserves it.

## Data handling

### The AI security brief carried internal hostnames

**Medium.** The button that sends a security summary to the configured AI
provider states that it sends titles, severities and host counts and never the
evidence. The redaction is performed on the server for the right reason — the
provider may be off-site. Four finding titles embedded a hostname, an
operator-written check name, or an external scanner's own text. The certificate
monitor in particular exists to watch internal hosts, so those were internal DNS
names.

*Fixed:* findings whose title can carry more than a count declare a redacted
title, which is what the brief sends. Your own screen still names the certificate.
The guard covers the whole class rather than the four instances, so a new finding
of the same shape is caught.

### A read-only role could publish to everyone

**Low.** Saved queries can be private or shared. Creating one required only
authentication, which the read-only roles satisfy, so a read-only account could
add an entry to a list every user sees. It discloses nothing the account could
not already read.

*Fixed:* private saved queries are unchanged and remain available to every role;
publishing a shared one requires a role with at least one action permission.

### A malformed request could return a server error

**Low.** Nine endpoints read a caller-supplied list with an expression that fails
on a value of the wrong type, producing a server error rather than a rejection.

*Fixed:* one shared helper, applied to all nine, returns an empty list for
anything that is not a list.

## A second pass over the whole project

After the review above was written, the release was held open for a full pass
over the entire codebase rather than the changes in it. That pass found twelve
more security issues. All are fixed here, none came from the field, and the same
bar applies: nothing Critical, High or Medium ships.

It is worth saying why a second pass found so much. The first one read the diff
and the recurring weakness list. The second one started by asking a different
question — not "is this rule followed?" but "how many places does this rule
apply, and what is the ratio?". Nearly every finding below is a rule this project
had already written down and applied nearly everywhere.

### The fix button skipped every gate

RemotePower has one function that queues a command to a host, and it applies six
protections: maintenance windows, four-eyes approval, the refusal to touch a
quarantined host, read-only audit mode, a per-device queue limit, and a check
that the target platform can carry the command out. Separately, a device can
carry an allow-list naming the only commands it will accept.

The fix button on an alert did not use that function. It wrote to the queue
directly, so none of the seven applied. An operator could run a command on a
quarantined host, on a host in read-only mode, during a maintenance freeze, and
past an allow-list that named something else — with the approval requirement
turned on and never triggered.

The same two routes also sat outside the path prefix that carries the tenant
check, and the permission check they did use returns early for an administrator.
A tenant administrator is an administrator. So on a multi-tenant install, those
routes reached another tenant's hosts.

Both entry points now go through the one gated path. Their own read-only sibling
already had the tenant check, with a comment explaining why it was needed there.

### Editing a file-integrity check could delete files

A file-integrity check records a baseline on the host and reports what changed
against it. The baseline was filed under the check's identifier without recording
which path it was taken from.

Change that path in the interface, or widen the pattern, and the agent compared
the new location against the old baseline. Everything under the new path looked
new — and a check set to quarantine moves what it considers new, as root. The
only limit was a cap on mass changes, which a small directory never reaches.

Baselines now record their scope and start fresh when it changes, and say so.

### A hostile server could switch off command signing

Command signing exists for one scenario, stated in the agent's own source: a
server or database an attacker now controls. With it on, the agent refuses any
instruction that is not signed.

It covered three of the six channels that can change a host. One of the three it
missed can move files as root — which means it could move the signing marker
itself, and the release key, and the read-only audit flag. The control meant to
survive a compromised server was removable by a compromised server.

Three fixes, each independent of the others: the channel is now covered; moving
files is refused for anything inside the agent's own directories no matter who
asks, symlinks included; and read-only audit mode now covers every channel its
own comment claimed it did.

### A data-protection erasure request could delete more than it named

The subject-access and erasure endpoints took the person's name from the request
and used it to find their files. It went into a filename pattern rather than
being treated as a name, so a request naming a wildcard matched every avatar on
the instance and the erasure removed all of them while reporting one. A name
containing a parent-directory reference reached outside the folder.

Names are resolved to an explicit list now.

### Four more ways one tenant could reach another

- An Ansible playbook aimed at "everything" or at a site resolved across the
  whole fleet instead of what the caller can see.
- Network-scan schedules were listed across tenants, and could be deleted across
  tenants.
- A task could be pinned to any device on the instance. The handler that edits a
  task already checked this; the one that creates it did not, and they share a
  validator.
- A read-only account could write to the shared billing ledger. The write goes
  through a helper that takes the lock one call deeper than the check that looks
  for locks, so the guard that reviews these handlers could not see it. Read-only
  accounts could also fill an instance-wide limit.

### Smaller

- The web terminal's helper process did not check the scheme of its own base
  address, while its three sibling processes all do. Anything but http or https
  is refused at startup now.
- Three alert actions raised their own "not found" and "already resolved"
  responses inside a block that rewrote any exception as a server error, so a
  clear answer arrived as a 500.

## Two safety inputs that were counting zero

Not vulnerabilities, but both are inputs to a decision about whether it is safe
to act, so they belong here.

Autonomous remediation weighs a **blast radius** before acting and refuses when
it is over your limit. Two of its four components read the wrong place, so
containers and watched services counted zero on every host — a machine running
thirty containers scored the same as an empty one. The pre-flight an operator can
open before a reboot reported zero containers as fact.

Separately, **config drift** was collected and stored correctly and read from the
wrong place by ten different features, so a drifted file raised no check, scored
no risk, and reached no alert.

## What the tests were and were not proving

The most useful finding of this pass is not a vulnerability. Two gates were
reporting success while measuring nothing, and one class of test defect had
quietly made a set of tenant-isolation tests meaningless.

- **The SQLite suite stopped testing SQLite about a quarter of the way in.** One
  test clears the backend setting to check a default and did not restore it, and
  the suite runs in one process. Roughly nine thousand of twelve thousand results
  ran against the wrong backend.
- **The JavaScript undefined-name check had never parsed anything.** It pointed
  the linter at a file the linter considered out of scope, and the "file ignored"
  notice did not match the filter looking for real problems. Once it could see,
  it found a live one.
- **Twenty-eight test modules pointed a storage key at a filename they invented.**
  On the file backend a path is a path. On SQLite and PostgreSQL the backend
  chooses its table from that name, so the data went somewhere else and every
  lookup came back empty. One of those modules exists to prove one tenant cannot
  approve another tenant's emergency-access request — and its "sees nothing"
  assertions were being satisfied by a fixture that returned nothing to anybody.

All three are fixed, and each now has a check that fails when the measurement
stops happening rather than when it finds something.

Five other guards were found to be enforcing a correct rule over a fraction of
the code they name — in one case 66 of 856 handlers, which is why a handler that
links one host's power supply to another's could sit outside a cross-tenant check
without being exempt from it. Each population is now derived rather than listed,
and each carries a check that fails if the derivation ever comes back empty.

## What the scans found

Re-run against the finished branch, not the one the first pass measured.

- **CodeQL**, with the same query suites and configuration the production scan
  uses: **no results**, Python and JavaScript.
- **bandit** across the server and all three agents, against the reviewed
  baseline: **no new findings**, and none at High.
- **gitleaks**: no leaks, in the working tree or across 2,064 commits of history.
- **ruff**, undefined-name checking over every Python file including the agents:
  clean. Its coverage grew this release — it had been skipping `packaging/`, the
  web terminal, and three programs with no `.py` extension, because the linter
  only picks up `*.py` when handed a directory.
- **semgrep**, Python and JavaScript security rule sets: 14 findings, all
  triaged to false positives, each checked against the code rather than
  dismissed by rule name:
  - Five "insecure file permissions". Four are a mode of `0700`, which is the
    restrictive one; the rule flags any change. The fifth really is world-
    writable, on an inner directory nested under a `0700` parent so no local
    user can traverse to it — it exists because a containerised scanner runs
    under a different user and has to write its report out.
  - Three "credential disclosure" in logging. All three log a file path and an
    error, not a secret. One matched on the word "credentials" in the message.
  - Three "tainted subprocess arguments". The value is a container runtime name
    that comes from the service definition, is allow-listed to two literals at
    every call site, and is passed as an argument list rather than through a
    shell. Anyone able to set it can already run commands.
  - One encryption mode without authentication. It is the mode the SNMPv3
    standard specifies; changing it would break the protocol.
  - Two cross-site scripting. One escapes every value it interpolates. The other
    was worth chasing, because it puts a value into an attribute unescaped and
    that value derives from a log line, which a monitored host controls — the
    function returns one of four fixed literals, so nothing flows through.

### Two defects found by the JavaScript rule set

Neither is a security issue; both are reported because they had been shipping.

**Nineteen alerts opened the wrong page.** The activity feed routes a click by
event, grouping events that share a destination. Two entries added four releases
ago were appended to the end of a group and took its destination with them, so
every event above them — temperature, power, clock, memory, network, disk
prediction — opened an unrelated page. Every comment in that block described the
intended destination correctly.

**Fifty-two translations were being discarded.** A repeated key in an object
means the later one wins, silently. Some had been overwritten since the day they
were written, including eighteen where the two texts differed, so a correction to
the first never took effect.

## Testing

The full suite runs on all three storage backends, and every fix in this
document has a test that was demonstrated to fail before the fix and pass after
it — including the guards, which were each reverted in turn to confirm they
detect what they claim to.

That discipline is why the second pass spent as much time on the tests as on the
code. Seven guards were found to be measuring less than they appeared to:

- **The accessibility sweep had never run.** An optional dependency was absent,
  and the class-level skip fired before the flag designed to catch exactly that
  could be consulted. It now audits every page and dialog on a populated
  instance — where it immediately found three controls with no accessible name,
  which are fixed here. On an empty instance those controls do not exist, which
  is why years of runs could not have found them.
- **The SQLite suite was not testing SQLite** for roughly three quarters of each
  run. One test cleared a setting and did not restore it.
- **The JavaScript undefined-name check had never parsed anything**, and was
  hiding a real defect: an operation that succeeded reported failure to the
  operator.
- **Twenty-eight test modules wrote to storage keys under invented filenames.**
  On the file backend that is harmless. On the database backends the filename
  chooses the table, so the data went nowhere — including in a module whose
  purpose is proving one tenant cannot approve another's emergency access.
- **Four guards enforced a correct rule over a fraction of the code they name**,
  in one case 66 of 856 handlers.

Each of those now derives its population rather than listing it, and carries a
check that fails when the measurement stops happening rather than only when it
finds something. That second half is the point: a gate that can return an empty
result for the wrong reason is indistinguishable from a clean run.

The demo instance the rendered checks measure was also seeded with signals in
shapes no agent produces, and with 23 of 56 signals missing entirely — so those
checks were partly measuring something the product never emits. A contract test
now compares every seeded store against its real producer or consumer.

## Reporting

Found something? See [SECURITY.md](../SECURITY.md). Reports are read and
answered.
