# Security review — v7.0.2 "Prec3dentMatters"

Every release gets a review before it ships. This one found **fifteen** issues
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

## What the scans found

- **CodeQL**, run with the same query suites and configuration as the production
  scan: no results, Python and JavaScript.
- **semgrep**, Python and JavaScript security rule sets: 24 findings, all
  triaged to false positives — a container runtime name restricted to two
  values, an encryption mode that is what the SNMPv3 standard specifies, and
  three "credential disclosure" sites that log a file path, a truncated hash and
  an exception respectively.
- **bandit**: one new finding against the baseline, a per-row error skip that is
  the fix rather than the flaw; annotated with that reason.
- **gitleaks**: no leaks, in the working tree or the history.
- **Strict type checking**: clean.
- **JavaScript correctness rules**: two real defects, described below.
- **Property-based testing** over the release's new safety helpers: one real
  defect, described above.

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

The full suite runs on all three storage backends: 12,658 tests on the default
backend, 12,606 on SQLite, and the PostgreSQL suite complete with no skips. Every
fix in this document has a test that was demonstrated to fail before the fix and
pass after it — including the guards, which were each reverted in turn to confirm
they detect what they claim to.

Two of those guards were found to be blind and were repaired:

- The accessibility sweep had been reporting success while running nothing,
  because an optional dependency was absent and the class-level skip fired before
  the flag designed to prevent exactly that could be consulted. It now audits
  74 pages and every dialog, with no violations.
- The demo instance — which the rendered checks measure — was seeded with eight
  signals in shapes no agent produces, so those checks were measuring something
  the product never emits. A new check pushes every seeded signal through the
  real ingest path and fails if any is dropped or altered.

## Reporting

Found something? See [SECURITY.md](../SECURITY.md). Reports are read and
answered.
