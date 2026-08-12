# Security review — v6.4.3 "Gu4rdMatters"

Every release gets a review before it ships. This one ran in two passes and
found **fifteen** issues worth reporting, all of them **caught before release**
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

### The control plane was the one host never graded on encryption at rest

Every managed machine was scored on disk encryption. The machine doing the
scoring was not — the one holding every device token, the credential vault, the
API-key hashes and the disaster-recovery backups, where a disk that leaves the
building hands over the whole fleet at once. An operator could have obtained the
answer by enrolling the server as a managed device, but the installer does not
do that and no document suggested it, so having the answer depended on somebody
thinking of the question.

It is now a graded item on the security-posture page, and deliberately
three-valued. Inside a container the mount table describes the container and the
host's disks are not visible; reporting "unencrypted" there would manufacture a
finding out of a blind spot, so it reports that it cannot tell and says to check
the host. The installer prints the same verdict at the point it is cheapest to
act on, and only when the answer is a definite no.

### Container images were the unsigned half of a signed release

Release tarballs have been checksummed and GPG-signed since v4.6.0, with the
packaging verifying that signature at build time. The container image — which is
how most people actually run this — carried build provenance and no signature.

Both images are now signed at publication. The signing is keyless, and that is
the point rather than a convenience: the reason the GPG key is generated and
used on a workstation is that continuous integration must not hold a signing
key, so putting one there for the images would have reintroduced exactly what
that rule exists to prevent. Signatures are made against the image digest, not a
tag, because a tag is a mutable pointer and signing one attests to whatever it
points at next.

The published verification command carries both the identity and the issuer
constraints. Omitting either accepts a signature from any identity, which
demonstrates that an image was signed without establishing by whom — a check
that reads as one while being none, and worse than publishing nothing.

### A sixth copy of the outbound-request classifier

Earlier in this release five hand-written copies of the "is this address one an
attacker would aim at" check were consolidated into a single module, after one
of the two copies that no guard covered was found to have silently lost an
ordering decision. A sixth copy was outside that consolidation and outside the
guard: the certificate monitor.

Its *policy* is deliberately different and stays local — it allows loopback and
private addresses, because inspecting an internal or same-host certificate is
the feature and the probe reads certificate metadata only. What it should never
have owned is the policy-free half: the encodings that smuggle an IPv4 address
past an IPv6 check, and the list of cloud metadata endpoints. Those are facts
about the internet rather than choices, they are the part an attacker probes,
and a second copy is a second thing to update when a new encoding appears.

The shared module now supplies both. Behaviour was captured across twenty-eight
addresses before the change — loopback, private, unique-local, link-local,
unspecified, multicast, public, all three wrapped forms of the metadata address,
all three wrapped forms of loopback, and unparseable input — and is identical
after. The drift guard now covers it, and the two modules that legitimately
classify under a different policy are recorded with the reason each differs: an
undocumented exemption is indistinguishable from an oversight, which is what
this one had become.

### Reporting an action as taken when the target cannot take it

A backup job spanning a mixed fleet ran on the hosts that support it, returned a
success count, and never mentioned the ones it had skipped. The refusal existed
and was reported only in the case where *every* target was unsupported, so a
partial run was indistinguishable from a complete one. This is the same class as
the platform refusals fixed earlier in the release, one layer further out, and
it is now reported on the success path as well.

### The sidecars asserted a safety property nothing enforced

Three sidecar daemons and the certificate-expiry cron each post to a base URL
taken from a service-unit environment value, and every call site carried a note
saying the base is a fixed loopback address and that no unusual URL scheme could
reach it. That was true by convention and by nothing else: the HTTP library
honours `file://`, so a base set to one would turn an internal POST into a local
file read while the comment sat above it saying that could not happen.

All four now refuse a non-HTTP base — the daemons exit at startup naming the
variable, the cron skips delivery. Verified by running each with a `file://`
base and requiring refusal, and again with ordinary `http://` and `https://`
bases and with no variable set at all, because a guard that refuses everything
would satisfy the first check and break every deployment.

Worth stating plainly: the cron was the one a scanner singled out, and the only
difference between it and the three daemons was that they carried a suppression
comment and it did not. The scanner was measuring annotations, not safety.

### Four responses were served with no security headers at all

nginx does not merge `add_header`: a location that sets any header of its own
discards every header inherited from the enclosing server block. The shipped
configuration knows this — it says so in a comment above the root location, and
the static-asset location re-emits the entire security set for exactly that
reason. Four other locations set a caching or content-type header and never
re-emitted it, so they were served with no content-security policy, no
`nosniff`, no frame protection and no referrer policy.

The one that matters is the **service worker**. A service worker takes its
execution policy from the headers on its own script response, so serving it
without a policy runs a persistent, origin-scoped, network-intercepting context
under no policy at all — of everything this server returns, the worst response
to send unrestricted. The others were the web app manifest and, in the container
configuration, the agent-installer path.

None of this is exploitable on its own; the document policy still governs the
page that registers the worker, and the manifest carries an explicit content
type. It is defence-in-depth that was believed to be in place and was not.

What made it worth a gate rather than a patch is that the mistake is invisible
in review: each location reads as correct on its own, and the headers are lost
in nginx's merge rules rather than in anything written in the file. The check is
therefore structural — any location that emits a header must emit the full set —
and it found four, where reading the file by eye had found two.

### A flow receiver wrote part of a live credential into its log

The network-flow receiver logs a warning when it cannot deliver a batch to the
application, and identified which exporter had failed by printing the last six
characters of that exporter's ingest token. The need is real — with several
exporters enrolled, a failure message that names none of them is not much use —
but the answer put a fragment of a working credential into a file that is
rotated, shipped to log collectors, and read by people who are not entitled to
the token itself.

It now logs a truncated digest of the token instead: the same ability to tell
two exporters apart in a log, with nothing that can be replayed. Its sibling
receiver logged no token at all, so this was also the odd one out rather than a
house style.

Severity is genuinely low — six hexadecimal characters do not meaningfully
narrow a search for the rest, and the endpoint is rate-limited — but "low" is
not a reason to keep credential material in a log when the alternative is a
one-line change.

### A vendored dependency was three patch releases behind on an advisory

The API-reference page bundles Swagger UI, which bundles DOMPurify. The pinned
build carried a version affected by three published advisories. Exposure was
low — the page renders this product's own generated specification, requires an
administrator session, and runs under a content-security policy with no inline
script, so the class those advisories describe was already strongly mitigated —
but the fix costs nothing and the advisory is real.

Updated and verified in a browser rather than by file comparison. That mattered:
the page pins integrity hashes for the bundle, so replacing the file without
recomputing them made the browser refuse the resource outright and the page
rendered blank — a failure a file-level diff shows as perfect. Every integrity
pin in every served page is now checked against the file it pins.

## What was checked and found sound

- A broader pattern-based scan was run across the server, all three agents and
  every sidecar, in addition to the tools that gate the build. It raised 38
  findings; one was real (the credential fragment in a log, above) and the rest
  were reviewed individually against the code and found not to apply:
  - **Query construction (20).** All of them are schema statements whose only
    interpolated values come from a fixed tuple of table names written in the
    source, plus one database setting chosen between two literals. No request
    data reaches any of them, and a table name cannot be sent as a bound
    parameter in any case — placeholders stand where a *value* goes, never
    where an identifier does.
  - **File permissions (11).** Every one sets `0700` or tighter, except two:
    the agent's own executable, which is deliberately world-readable like any
    other program in a system binary directory and holds no secret, and a
    scanner working directory that is already documented and annotated, whose
    parent is `0700` and therefore not traversable by other local users.
  - **Log content (2).** Both are the scanner matching the *word* "token" or
    "credentials" in a message; neither statement logs any secret. One of them
    is the line fixed above, which now emits a digest.
  - **Unencrypted transport (2).** The agent selects a plaintext socket only
    when the operator has explicitly configured a plaintext server address —
    the relay-satellite-on-a-trusted-segment case — and uses TLS in every other
    configuration. It cannot downgrade a TLS deployment.
  - **Cipher selection (3).** Three outbound clients accept the language
    runtime's default cipher list rather than pinning one. The default excludes
    everything currently considered weak and tracks upstream, which pinning
    would stop it doing.
  These are recorded here rather than annotated away in the source, so the next
  run of the same scan re-raises them and they get re-read against the code as
  it is then, instead of inheriting a judgement made today.
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
  and the sidecar daemons. Re-run after the third pass: the code-scanning suite
  reports nothing in either language; the secret scanner reports nothing across
  the full history; and the Python analyser reports nothing new against its
  baseline, with no high-severity finding anywhere in it.
- The nine analyser findings that appeared during the third pass were all one
  pattern in one file, and all of it pre-existing code that had been *moved*
  during a refactor — the baseline records line numbers, so relocating a
  function reports it as new. Each was confirmed to be the deliberate
  "recording an event must never fail the request" shape, with the success
  response correctly outside the guarded block. The baseline was regenerated
  only after that check, not before it.
- Credential ciphertext was traced across every read path rather than assumed
  contained. Unlocking the vault returns a key derived from the operator's
  passphrase, and that endpoint admits any authenticated role — so the question
  is whether a low-privilege caller can also obtain ciphertext to use it on.
  Every list and detail path strips the encrypted fields, revealing plaintext is
  separately role- and scope-checked and audited in both directions, and the one
  place outside the module that reads the store takes a port number. The key
  alone is not usable through the API.

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
