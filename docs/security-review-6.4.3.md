# Security review — v6.4.3 "Gu4rdMatters"

Every release gets a review before it ships. This one ran in two passes and
found **eight** issues worth reporting, all of them **caught before release**
and all fixed in the release they are described in.

Most were long-standing rather than new, which is the more useful thing to say
about them: they had been present through several prior versions and no scan,
test or review had surfaced them. The first pass went looking specifically at
fleet-wide read endpoints. The second went looking at the **write** side —
which account-creation and credential paths check tenancy, and which do not —
and found more, including the most serious issue in the release.

The bar this project holds itself to is that nothing Critical, High or Medium
ships. That bar is met.

## What was reviewed

- The full v6.4.2 → v6.4.3 diff, read adversarially rather than for correctness.
- **Second pass:** every path that CREATES an account or reads a stored
  credential, checked against "may this caller act on this tenant?" — the write
  side of the same question the first pass asked of reads.
- The endpoints that return **fleet-wide** data, checked one at a time against
  the question "which devices may this specific caller see?"
- The recurring weakness classes this codebase keeps a written list of —
  role-gate shape, read-only roles reaching write paths, tenant isolation,
  outbound-request validation, XML parsing, error-path handling.
- Static analysis (Bandit, gitleaks, undefined-name checks) across the server,
  all three agents and the sidecar daemons.
- Both storage backends, and the accessibility and interface suites, since a
  fix that breaks the product is not a fix.

## What was found and fixed

### Fleet-wide read endpoints ignored who was asking

Three endpoints authenticated the caller correctly and then answered as though
every caller were an unrestricted administrator.

- **The metrics endpoint** returned per-device telemetry — hostnames, memory
  use, last-seen times — for *every* device on the instance to *any* signed-in
  user. On a multi-tenant install, one tenant's lowest-privilege read-only
  account could see another tenant's host names and load.
- **The calendar feed** returned every tenant's scheduled jobs and maintenance
  windows, including device names and, for device-scoped windows, the device
  identifier itself.
- **The rack elevation view** returned the identifiers and hostnames of devices
  belonging to other tenants that happened to share a rack.

None of these permitted any *change* — they are read paths, and no credential,
secret or command channel was exposed. The impact is disclosure of inventory
and telemetry across a boundary that is supposed to hold.

The cause in each case was the same, and it is worth naming because it is easy
to reproduce by accident: these endpoints sit outside the URL prefix that
carries automatic per-device permission checks, so they need to apply the
filter themselves, and they did not. The metrics endpoint additionally serves
two very different callers — a machine scrape with a long-lived token, which
*should* see everything, and a logged-in operator, who should not. Its code
reasoned correctly about the scrape and never revisited the assumption for the
session. A neighbouring endpoint had already drawn the distinction properly;
all three now match it.

Fixed by filtering the device set through the same permission helper the rest
of the product uses, which folds in both role scope and tenant, and which does
nothing at all on a single-tenant install with unrestricted administrators —
the common case is unchanged. The machine-scrape path deliberately keeps its
instance-wide view, and there is a test asserting it, because quietly narrowing
that would break fleet monitoring rather than protect anything.

### A safety gate could be bypassed by editing instead of creating

File-backup jobs run a Linux-specific command, and creating one against a
Windows or macOS host is refused. *Editing* an existing job to point at one was
not. The scheduled sweep would then dispatch that command to a host that cannot
run it, indefinitely, while reporting the job as configured normally. Fixed by
applying the same check on the edit path, and by reporting the skipped hosts
the same way the create path does.

### An audit record with no author

New in this release: the audit entry written when an operator silences a
temperature sensor recorded the action but not who performed it, because the
arguments were supplied in the wrong order and the mistake was invisible at
runtime. Silencing a sensor suppresses a critical alert for that host, so the
record needs to name someone. Fixed, and the entry now also lists which sensors
were silenced.

### A tenant administrator could become a platform operator

**This is the most serious issue in the release**, and it affects only
deployments running **multi-tenancy**, which is off by default. On a
single-organisation install every administrator is already unrestricted, so
there is no boundary to cross and no impact.

Creating a user did not record which tenant the account belonged to. An account
with no tenant is treated as belonging to the built-in default one — and an
administrator in the default tenant is the platform operator, who can see every
tenant. So an administrator confined to one customer could create an account
that outranked their own, sign in as it, and use it to move themselves into the
default tenant permanently.

The same blind spot ran through the neighbouring endpoints: a tenant
administrator could promote an account in another tenant, delete the platform
operator's account, and list every tenant's user roster — that last one
readable by *any* signed-in role, including read-only ones.

A new account now inherits its creator's tenant, and account management is
scoped to it. The identical protection was added to API keys in v6.1.1; it
simply had never been applied to user accounts, which meant a tenant
administrator could not mint a cross-tenant API key but could mint a
cross-tenant login.

Two statements in our own documentation were wrong as a result — one in the
scaling guide and one in the threat model, both asserting that a tenant
administrator could not escalate. Both are corrected in this release. We would
rather publish that than quietly fix it.

### Stored credentials could be read across tenants

The endpoints that reveal, add, change and delete stored device credentials
checked that the caller was an administrator and nothing else. On a
multi-tenant install a tenant administrator could therefore read another
tenant's saved passwords in plaintext. The same applied to scope-based
credentials, which are filtered by role scope — and a tenant administrator has
no role scope, so every credential matched.

The shared credential vault is not a defence here and should not be mistaken
for one: it is a single passphrase for the whole instance, so anyone entitled
to unlock it for their own credentials could unlock everyone's. It protects
data at rest, not between tenants.

Both are now scoped, and a new check fails the build if a future credential
endpoint is added without one.

This was found by following up something that looked like the *opposite* of a
problem: an internal readiness report told operators the asset database was
"not tenant-partitioned at any layer". That was inaccurate — most of it was
partitioned — and auditing why the report understated its own coverage is what
exposed the handlers that genuinely were not.

### Rotating the credential-vault passphrase destroyed most of the vault

Four separate stores are encrypted with the vault passphrase. Rotation
re-encrypted one of them, and because it also replaces the salt, the old key
stopped existing — so every ordinary, entirely **successful** rotation
permanently orphaned the other three while reporting success.

The quietest of the four was the key server's own certificate authority: losing
it produces no immediate error, and surfaces later as appliances being unable
to fetch their keys and encrypted volumes failing to mount after a reboot.

A secret that would not decrypt was also treated as corrupt and deleted — so
the natural response to an interrupted rotation, retrying it, destroyed every
secret it could not read.

Rotation now covers every store, aborts and changes nothing if any secret will
not decrypt, writes the new passphrase only after the re-encrypted secrets are
safely stored, and keeps the previous salt so an interrupted rotation stays
recoverable. A dry-run reports what a rotation would touch before you commit to
it. The documentation for this feature described the opposite of the actual
behaviour in two places and is corrected.

We are being precise about what this is not: several stores cannot be written
in a single transaction, so an interruption *between* them can still leave a
split state. What changed is that the split is now recoverable and far less
likely, and the documentation says so plainly rather than claiming atomicity.

### Two surfaces reported protection that was not there

Neither is exploitable; both are recorded because a security control that
reports its own status incorrectly is a security problem of a different kind.

The Security-posture row *"Backups mirrored off-host"* graded whether a
destination was **configured**, not whether the last mirror **worked** — so it
turned green when a path was set and stayed green through every subsequent
failure, in the one place an operator checks before trusting disaster recovery.

The scheduled restore drill verified only the local archive, never the off-host
copy — so a passing drill meant the backup on the machine you had just lost was
intact, while the copy that exists for exactly that scenario had never been
tested. Our compliance mapping claimed test-restore verification of the
off-host copy; that claim is now true, and the mapping records that it
previously was not.

## What was checked and found sound

- No credential, token or secret is exposed by any of the issues above, and
  none of them permitted a state change.
- The recurring weakness classes were re-checked against current code rather
  than assumed still-fixed: role checks, write paths reachable by read-only
  roles, outbound-request validation, XML parsing, and error handling.
- The new notification-encoding path introduced in this release was reviewed
  for header injection; the sending library rejects the malformed values that
  would be required, and the encoding change itself does not create a path.
- The continuous-integration database added this release uses a throwaway
  container with no credential, cannot be reached from a production install,
  and introduces nothing into a release artifact.
- Static analysis reports no new findings across the server, all three agents
  and the sidecar daemons.

## Verification

Each issue was reproduced against a running instance before it was fixed, and
the same reproduction was re-run afterwards. The disclosure issues were checked
with a two-tenant instance from the lowest-privilege account available, not
from an administrator — an issue only reachable with elevated rights would rate
very differently, and these were not.

Regression tests ship with the release. They assert both directions: that a
restricted caller no longer sees other tenants' data, **and** that unrestricted
callers and the machine scrape still see everything they are supposed to. A
test that only checks the first half would pass just as well against an
endpoint that had been broken outright.

One of those tests also removes a device's display name before asserting its
identifier is absent. That looks pedantic and is not: the exporter falls back to
printing the identifier when a name is missing, so a fix that filtered only the
name lookup would have left the identifiers leaking while every naive test
passed.

The second pass held to the same rule and added one. Every finding was
**reproduced first** — the escalation by driving the real account-creation path
and then recomputing the caller's privilege the way the product computes it,
the credential reads by retrieving another tenant's password in plaintext, the
vault rotation by rotating a fully-populated vault and then attempting to
decrypt each store afterwards. Nothing was reported on the strength of reading
the code.

The addition is that each fix was then **removed again** to confirm its tests
fail without it. A test that has never been observed failing is
indistinguishable from one that cannot fail, and this release is largely about
that distinction. Every fix above reds between three and seven tests when
reverted.

Every finding also carries a test for the case that must keep working — a
tenant administrator managing its *own* users and credentials, a
single-organisation install behaving exactly as before. A tenancy fix that
refused everything would satisfy the security assertions and break the
product, and would look identical in a report.

## Scope

This review covers the server, the three agents and the sidecar receivers. It
does not constitute a penetration test of any particular deployment: network
exposure, TLS termination, reverse-proxy configuration and operating-system
hardening remain the operator's responsibility, and the hardening guide covers
them.

**Who the tenancy findings affect.** Four of the eight require multi-tenancy to
be turned on, which is opt-in and off by default. On a single-organisation
install — the usual case — every administrator is already unrestricted, so
there is no boundary to cross and those four have no impact. We are saying that
plainly rather than leaving it implied, in both directions: if you *do* run
multi-tenancy with more than one administrator, the first two are worth reading
carefully.

**What upgrading changes for you.** Nothing needs configuring. The one visible
behaviour change is on multi-tenant installs: an account created by a tenant
administrator now belongs to that administrator's tenant rather than silently
becoming unrestricted. Existing accounts are not modified — if this release is
the first you are hearing of the issue, it is worth reviewing who currently
holds an administrator account in the default tenant.

Please report security issues privately — see [SECURITY.md](../SECURITY.md).
