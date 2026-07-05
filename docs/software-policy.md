# Software policy

**Security → Software policy** evaluates rules against **every host's
installed-package inventory** — so you can enforce what may and may not be
installed across the fleet.

## Rule types

- **Banned** — a package that **must not** be installed (e.g. `telnet`,
  `teamviewer`). A match is a violation.
- **Required** — a package that **must** be present (e.g. `auditd`, an EDR
  agent). A host missing it is a violation.
- **Minimum version** — a package must be installed **at or above** a version.
  A host below it is a violation.

Each rule can optionally be **scoped to device tags**, so a rule applies only to
the hosts it's relevant for (e.g. require a package only on `prod` servers).

## How it works

- Rules are evaluated against the package inventory the agents already report —
  no extra scan.
- Violations are listed per rule and per host, so you can see exactly which
  hosts breach which policy.

## Related

- Package **vulnerabilities** (CVEs) are the [CVE Findings](cve.md) page;
  software policy is about *presence and version*, not CVEs.
- To *remediate*, install or remove packages from the [Patch Report](patches.md),
  or push a fix with [Rollouts](rollouts.md).
- SSH key hygiene is covered by the [SSH key audit](security.md).

## Permissions

Creating and editing software-policy rules is admin-only; the evaluation results
are visible to any operator who can see the affected devices.
