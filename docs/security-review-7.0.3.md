# Security review — v7.0.3 "C4useMatters"

Every release gets a review before it ships. This one found **fourteen** issues
worth reporting, all **caught before release** and all fixed in the release they
are described in. None came from the field.

Most are older than this release, several by years. That is the more useful
thing to say about them: they were present through prior versions, and the
scans, tests and reviews that ran on each of those did not surface them.

The bar this project holds itself to is that nothing Critical, High or Medium
ships. That bar is met.

## What was reviewed

- **The whole project, not the release's diff.** The diff is the wrong unit —
  every finding below except one predates the changes in this release.
- Two adversarial passes with disjoint territory: one over the server and its
  request handling, one over the three agents, the sidecar daemons, the
  installers, the container images and the web-server configuration.
- The recurring weakness classes this project keeps a written list of, each
  re-checked by enumerating every call site and printing the ratio rather than
  asking whether a rule "looks applied".
- Static analysis: CodeQL with the same query suites and configuration the
  production scan uses, semgrep's security and secrets rule sets across Python
  and JavaScript, bandit against a triaged baseline, gitleaks over the full
  history, an undefined-name check on every Python and JavaScript file, and a
  JavaScript correctness rule set.
- The full test suite on every storage backend, plus the browser-driven
  accessibility, dialog and rendering sweeps against a populated instance.

## The pattern worth naming

It is the same shape as last time, which is why it is worth naming again: **a
rule already written down and applied in most places, missed in one or two.**

Every outbound client that carries a credential refuses redirects — except one.
Every channel that can change a host honours read-only mode — except two. Every
surface that reports a host's security posture reads all three operating
systems — except three. Every token comparison is constant-time — except one.
Every installer writes a secret under a tight umask — except one.

A half-applied rule is harder to see than a missing one, because every correct
site makes the file read as though the rule is enforced. Reading for "is this
rule followed?" returns yes. Enumerating every site and counting is what works,
and several of the counts below came out as a surprise to the people who had
written the rule.

## Three ways one tenant could reach another

Multi-tenancy is opt-in and off by default. On an install that has it enabled,
these three were real.

**An identity-provider group could mint a platform operator.** A previous
release added a check that refuses to promote a single-sign-on user to admin in
the default tenant, because an admin there sees every tenant. The check asked
about the wrong account: it looked at the tenant a *newly created* user would
land in, while the branch it guarded acts on an account that already exists and
carries its own tenant. Point the "SSO users belong here" setting at a real
tenant and the check compared against a tenant nobody in that branch belonged
to, never fired, and an existing viewer signing in with the right group became a
platform operator. An account with no tenant recorded at all — the ordinary
shape for anyone created before tenancy was enabled — resolved the same way.

Fixed by asking the question about the account being promoted. A refusal is now
recorded in the audit log by name, because silence there reads as "the group
mapping is broken".

**Generating a runbook sent the whole fleet to the model provider.** The runbook
generator attaches a fleet snapshot to its prompt, naming every host and its
state, and it read the unfiltered device store. A tenant admin generating a
runbook for a host they legitimately own named every other tenant's hosts to
whatever model provider is configured, which may be a third party. There are
exactly two places that build such a prompt, and the other one has filtered its
roster since v3.13.0.

**The accepted-risk list for vulnerabilities had no tenant dimension.** Marking
a CVE as accepted risk stores a record keyed by the vulnerability id alone, and
every handler was gated on "is this an admin" — which a tenant admin is. So a
tenant admin could accept a risk on another tenant's host, could write a
fleet-wide record that silenced that CVE on every tenant's hosts and overwrote
whatever record another tenant held under the same key, and could read and
delete other tenants' records.

Records now carry the tenant that wrote them, and the thirteen places that
decided whether a record applies became one shared function. Records written
before this release carry no tenant and keep their old meaning: an upgrade that
silently un-suppressed findings an operator had already accepted would be a
worse bug than the one being fixed.

## The web terminal sent your SSH password to an unverified host

The browser terminal connected with SSH host-key checking disabled and then
authenticated with the operator's password. Password authentication happens
after the key exchange, so anything able to answer on that address and port
received the password on the first connect — an address-resolution or DHCP spoof
on the management network, a stale DNS record, a re-provisioned IP, a
compromised jump host. There was no setting to turn checking on, and every
session on every install was affected.

The comment in the code argued that the operator "typed in this hostname; they
know what they're connecting to", which is the thing host keys exist to refute:
knowing the intended destination is not knowing you reached it. It also called a
managed known-hosts file more theatre than security. That was the part worth
checking, and it was wrong — the product has collected each host's SSH key
fingerprints with every heartbeat since v6.1.2, stores them, and raises an alert
when they change. The evidence was already there and nothing consulted it.

The session now validates the presented key against those fingerprints during
the key exchange, before any authentication. A key that does not match refuses
the connection and explains why. A device with nothing on file — an agentless
host, or an agent that has not reported yet — still connects, and the session
audit records it as unverified along with the fingerprint that was presented,
rather than implying it was checked.

**The first version of that fix could not fire.** It installed the validation
callback and left the library's host-key argument at "no checking", and the
library only consults the callback when its trusted-key set exists. Driving a
real SSH server on loopback showed the callback running zero times. The
published fix passes an empty trusted set instead, and the same harness shows a
mismatched key refused with no authentication attempt reaching the server at
all — which is the assertion that makes this a test about the password rather
than about connectivity.

## The agents

**Two channels that run commands as root ignored read-only mode.** Setting
`audit-mode` on a host means the agent reports and changes nothing, and the
agent's source carries a numbered list of the channels that honour it, ending
with a note that any new channel belongs on the list. Backup verification and
restore drills were not on it. Both run a backup tool as root against a
repository path the server supplies, and the second also creates and deletes a
directory tree. An operator who set read-only mode believing the agent would run
nothing was wrong about both.

The repository path had no validation either, so a value shaped like a
command-line option reached the tool's arguments as one. It is now required to
be an absolute path or one of the remote repository URLs those tools understand;
remote repositories are common and are not blocked.

The list is derived rather than maintained now. A check walks the heartbeat,
follows every value that came from the server, and requires each function
receiving one to honour read-only mode or be listed as unable to change the host,
with the reason.

**A stale Windows installer shipped in the release archive.** It predates the
current one, installs the Linux agent as a Windows service — so the service
never starts — and downloads a service wrapper over the network and runs it as
SYSTEM with no signature or hash check. The current installer verifies both. The
stale file is deleted.

## Credentials that could ride a redirect

Every outbound client in the product refuses HTTP redirects, because these
clients carry a device token, an API token or a shared secret, and a redirect
would replay it to wherever it points. A comment in one of them said the class
was closed.

It was not. The Model Context Protocol client sent the RemotePower API token in
two headers through the default opener, which follows redirects — reproduced
with two loopback servers, where the redirect target received both headers in
full. Four sidecar clients were on the default opener as well; those reach a
fixed loopback address, so they are defence in depth rather than a live hole,
but the fix is one line each.

All five refuse redirects now. The population is derived from the directories
where clients live rather than listed, because the list is what went stale.

## The API reference returned 403 on every install

The web-server configuration blocks requests for files ending in `.json`, so a
data directory accidentally placed inside the web root is never served. That
rule is written as a regular-expression location, and in nginx a regular
expression outranks every ordinary prefix location — only an exact match or an
explicitly marked prefix beats it. The API prefix is an ordinary one, so the
block won: `/api/openapi.json` returned 403 on every install, which is what the
API reference page fetches. In the container image it also blocked the web-app
manifest and every JSON asset.

Reproduced against a real nginx with both shipped configurations included
unchanged, then re-run after the fix: all the real paths served, and a planted
stray file in the document root still refused.

## Four smaller ones

- **A one-time check-in URL compared its token with `==`.** The token is the
  credential for that endpoint, and string comparison stops at the first
  differing byte. Remote timing over HTTP is noisy, so this is hygiene rather
  than a live hole — but it was the only token comparison in the file that was
  not constant-time.
- **Running a playbook did its work before authenticating.** The permission
  check needs the resolved target list, so it sits at the end; an
  unauthenticated caller reached the playbook store, the device store and target
  resolution first, and could tell an existing playbook from a missing one by
  the status code. A coarse check now runs first, and the per-device check stays
  exactly where it was.
- **A credential's "applies to N hosts" count spanned tenants.** The rows beside
  it were filtered and the count was not, so the number told a tenant admin how
  many of another tenant's hosts a credential would match.
- **The web terminal installer exposed its shared secret twice** — once as a
  world-readable file for the moment between writing it and tightening the
  permissions, and once on a command line, where it is readable by any local
  user for the life of the process. The main installer had already fixed the
  first of those for a different secret, with a comment explaining why.

## Something the metadata advertised did not exist

Not a vulnerability, but it belongs here because it breaks a security feature:
the SAML metadata the product tells you to hand your identity provider
advertised an endpoint that is not routed. Anyone who set up single sign-on by
following the documentation had their assertions posted into a 404. Three
surfaces named that endpoint and the two that agreed with each other were both
right; the one that was wrong is the one the identity provider actually reads.

## What the scans found

Nothing. Every tool reports clean on the released tree:

| Tool | Result |
|---|---|
| CodeQL (production configuration) | 0 results, Python and JavaScript |
| semgrep (security-audit, secrets) | 0 findings across 109 files |
| bandit (against the triaged baseline) | 0 new, 0 high |
| gitleaks (full history and working tree) | no leaks |
| undefined-name check (Python) | 0, server and all three agents |
| undefined-name check (JavaScript) | 0 across the bundle |
| JavaScript correctness rules | 0 |

That table is worth reading with the rest of this document beside it. Every
issue above was present while those tools reported clean, and most were present
for several releases. Scanners find the classes they encode; they do not find a
rule this project invented and then applied to nine sites out of ten. That is
what the enumeration passes are for, and it is why "the scans are green" is
reported here as a fact rather than as reassurance.

Each of the scanners was given a control before its result was believed: semgrep
was run against a file written to be unsafe and reported it, the JavaScript rule
set carries a file containing one of each defect it looks for, and the
undefined-name checks fail if a planted undefined call is not reported.

## What the tests were and were not proving

Three test-suite defects were found and fixed. None is a product vulnerability;
all three made a green result mean less than it appeared to.

- A helper that isolates the Needs-Attention tests from each other derived its
  list of stores from one function body, and the digest reaches six more through
  helpers it calls. Those six stayed pointed at a shared directory.
- A test module that seeds a fixture directory left it as the ambient data
  directory for every module imported after it, so those modules wrote into the
  fixture its own assertions read back.
- The accessibility sweep audited pages mid-animation and reported colour
  contrast failures that were an artefact of the fade, not the palette.

## Reporting

If you find something, please report it privately — see
[SECURITY.md](../SECURITY.md) for how. Reports are answered.
