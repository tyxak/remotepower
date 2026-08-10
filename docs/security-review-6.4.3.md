# Security review — v6.4.3 "Gu4rdMatters"

Every release gets a review before it ships. This one found four issues worth
reporting, all of them **caught before release** and all fixed in the release
they are described in. Three were long-standing rather than new, which is the
more useful thing to say about them: they had been present through several
prior versions and no scan, test or review had surfaced them until this one
went looking specifically at fleet-wide read endpoints.

The bar this project holds itself to is that nothing Critical, High or Medium
ships. That bar is met.

## What was reviewed

- The full v6.4.2 → v6.4.3 diff, read adversarially rather than for correctness.
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

## Scope

This review covers the server, the three agents and the sidecar receivers. It
does not constitute a penetration test of any particular deployment: network
exposure, TLS termination, reverse-proxy configuration and operating-system
hardening remain the operator's responsibility, and the hardening guide covers
them.

Please report security issues privately — see [SECURITY.md](../SECURITY.md).
