# Software Policy

**Security → Software Policy** checks rules against **every host's installed-package
list**, so you can state what may and may not be installed across the fleet and see
who breaks the rules.

## Rule types

Add a rule at the bottom of the **Policy rules** card: pick a type, enter the package
name, and click **Add rule**.

- **banned** is a package that **must not** be installed (for example `telnet` or
  `teamviewer`). A match is a violation.
- **required** is a package that **must** be present (for example `auditd`, or an EDR
  agent). A host without it is a violation.
- **min_version** is a package that must be installed **at or above** a version you
  enter. A host with an older version is a violation. A host that does not have the
  package at all is not a violation of this rule type, so pair it with a
  **required** rule if the package must exist.

Package names are matched exactly, as the host's package manager spells them (`httpd`
on Red Hat family hosts, `apache2` on Debian family hosts, so write one rule for each).

Each rule can be **scoped to host tags** (comma-separated). A rule with tags applies
only to hosts that carry at least one of them, for example to require a package only on
`prod` servers. A rule with no tags applies to every host.

## How it works

- Rules are checked against the package list that agents already report, so no extra
  scan runs. A host is checked each time it sends a fresh package list, which happens
  every few hundred heartbeats and whenever you click **Scan packages** for it.
- When you save the rules, every host with a known package list is checked again
  straight away, so the **Current violations** table reflects the new rules at once.
- **Current violations** shows Host, Rule, Package, Expected and Found, and you can
  filter by host or package.
- You can keep up to 500 rules.

## Alerts

When a host starts breaking a rule, RemotePower raises `software_policy_violation`
(medium severity) once for that rule on that host. When the host stops breaking it,
`policy_compliant` closes the alert, so a fix clears itself. Turn either one off under
**Settings → Notifications → Per-event toggles**.

## Permissions

Everyone who is signed in can read the rules and see the violations on hosts they may
see. Creating, editing and removing rules is admin-only and is written to the audit log.

## API

| Method | Path | Notes |
|---|---|---|
| GET | `/api/software-policy` | The rule list. |
| POST | `/api/software-policy` | Admin. Replaces the whole list: `{"rules": [{"type", "package", "version"?, "tags"?, "note"?}]}`. Returns how many violations the new rules produce. |
| GET | `/api/software-policy/violations` | Current violations, limited to the hosts you may see. |

## Related

- Package **vulnerabilities** are on the [CVE Findings](cve.md) page. Software policy is
  about *presence and version*, not CVEs.
- To fix a violation, install or remove packages from the [Patch Report](patches.md), or
  push the change with [Rollouts](rollouts.md).
- SSH key hygiene is covered by the [SSH key audit](security.md).

## With multi-tenancy

There is one software policy, judged against the hosts of every tenant. With tenant isolation on, a tenant reads the policy and the violations on its own hosts, and only the platform operator can change the policy.
