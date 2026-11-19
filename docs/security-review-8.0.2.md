# Security review — v8.0.2

8.0.2 adds a lot to pages that already existed: enrolment tokens for many hosts, password rules, Windows and macOS software lists, the Windows build, shares, TPM,
registry checks, persistence and event log rules, a Linux host's refresh of its package lists and its list of what its agent can see, a CVE scan that says what it checked, and
per-host kernel findings. This review asked two questions. The first was what each of those can be made to do that it should not. The second was where a rule the code
already had, and applied in most places, was missed in one or two. Six reviewers each took one area (the API surface, the pages, Threat Intel, the agents, the vulnerability
pages and the stores) and ran every claim against a seeded copy of the product, never against an installation anyone uses. Their reproductions were then run again on the
final tree, and that second run found nine more things the first had not reached.

Most of what it found is **not new in this release. It is in 8.0.0**, which is the version in production, and in most cases in 7.5.0 too. Each finding was run against the
8.0.0 code, and the ones that only exist in code new in this release are marked below. That is why the Security section of the release notes is long, and why
[v8.0.2.md](v8.0.2.md) says what to do after you update.

It found **fourteen High issues, twenty-three Medium issues and twelve Low issues in the first run, and seven Medium and two Low issues more in the second. Every one of
them is fixed.** Nothing rated Medium or higher is open. The tests written for this review fail on the code without its fix. The list of things that are not attacks and stay as
they are is at the end.

## What changed that a reviewer should look at

| Where | What | Who may use it |
|---|---|---|
| `POST /api/users/passwd`, SCIM, single sign-on, LDAP | ask for a fresh sign-in | a person; an API key answers 403 |
| `POST /api/enrollment-tokens` | `max_uses` | an administrator |
| `POST /api/devices/<id>/refresh-package-lists` | queues a refresh of the package lists on a Linux host | a role with the command permission, for hosts it may see |
| `GET /api/ip-intel` and its clear and ban routes | the operator's view needs the whole fleet in scope | the platform operator without a host scope |
| `GET /api/export` | every store is masked, three are left out | an administrator; with tenants, the platform operator |
| `signin_sources.json` | a store of where people signed in from | none: it is read by Threat Intel only |

## How it was done

- **Six reviewers, one area each, then fixers.** Each reviewer wrote a reproduction for every finding (a script that drives the real handlers on a scratch data directory
  and prints a verdict) and a fix hint. Each fixer worked from the reproduction, wrote the test, and watched the test fail on the old code.
- **The reproductions were run again on the final tree**, and on the 8.0.0 tree for the comparison. Where a script could not run on 8.0.0 because the feature it exercises
  is new, the finding is new in 8.0.2. Where a script answered "not reproduced" on the final tree and reproduced on 8.0.0, it is closed.
- **Lists made by script, with the ratio printed.** The rule most often missed was one the code already had: every writer of a store that several requests write takes the
  store's lock. The writers of the session store were 9 locked and 3 not, of the command queue 27 and 3, of the settings document 81 and 1, and one more of the backup state
  that held its path in a variable. `tests/test_v802_store_write_locks.py` lists them by syntax tree for the four stores and fails when a writer is added without the lock.
- **A marker in every place that holds a secret.** Markers were put where the product keeps a credential (an SSH password, a private key, a community, a login, three
  tokens, a pre-shared key, an audit key, a destination address, a header value), and the export, the delivery log, the audit trail, the settings versions and
  the failed-delivery queue were read for them. Seven of seven markers of the first matrix were in the export of 8.0.0, and none is in it now.
- **Controls.** Each reproduction has a control that fails when it measures nothing: the same request as a caller who is allowed, the same text without the forged part, the
  store before the damage. A fix that makes a control fail is a fix that closed the wrong thing.

## What was found

| Area | Findings (high / medium / low) | Closed |
|---|---|---|
| API surface | 2 / 0 / 0 | the password reset and the scope of a key (below) |
| Pages | 1 / 2 / 3 | Threat Intel evidence across tenants and the operator's settings, a failing destination's alert, hidden characters |
| Threat Intel | 5 / 4 / 1 | the sensor reads, sign-in sources, tenants, report shares, the edge list, capability links |
| Agents | 1 / 4 / 1 | the nginx error log; the rest are in code new in this release |
| Vulnerability pages | 1 / 7 / 4 | accepted risks, scans, totals, campaigns, costs, a false clear, a host that came back |
| Stores | 4 / 6 / 3 | the export, the master key, sessions, queues, the purge, the shapes |
| The second run | 0 / 7 / 2 | the never-block rules (the mapped spelling, the ban route, the reason a tenant reads), sign-in sources, a scoped key on the Threat Intel page, the delivery log, a pre-shared key, an advisory with no name |

### High

- **An API key could set an administrator's password, and could lift its own scope.** A key cannot sign in again, so a route that asks for a fresh sign-in has to refuse
  it, and `POST /api/users/passwd` did not ask: a key with the administrator role set the password of another administrator and signed in as them. A key with a host scope
  could mint an administrator key with no scope and read what the first was kept from. The password route, SCIM, single sign-on and LDAP ask for a fresh sign-in now, and a scoped
  key creates keys, roles and accounts inside its scope only. In 8.0.0.
- **The export carried credentials of every kind.** The SSH passwords and private keys of agentless hosts, SNMP communities, RouterOS and OPNsense logins and the keys that sign
  the audit trail were in the file the guides call safe to share. With the audit keys one can rewrite an entry, re-chain the log, and the server's verifier says the log is
  whole. The settings history, each version with every credential in it, and the whole failed-delivery queue were in it too. Every store is masked and three are left out.
  In 8.0.0.
- **A revoked session came back.** A request that had read the session store before a revocation saved its copy back when it stamped its own last-seen time. In 8.0.0.
- **A request could name the address the sensor reports.** nginx writes the decoded request path before its own client field, so a request holding `, client: <address>,`
  made the sensor credit and report the address of someone else; a request body could write a whole transaction into ModSecurity's audit log. The agent takes the address
  only from a line that names its client once, whole and before the cut nginx makes at 2,047 bytes, and reads an audit record to its own end. In 8.0.0.
- **A page of another site could get a visitor reported.** One bait hit of the honeypot is a decision that reports the visitor, and a page the visitor was sent to could
  make their browser hit it. The Worker records how the request was made (the Fetch Metadata words a browser sends) and a hit that a page caused is not a decision. In 8.0.0.
- **With tenants, a tenant read the evidence another tenant's hosts collected.** The ledger of an address was one for the installation, returned whole. Each host's part is
  kept, and a caller is given the parts of the hosts they see. A tenant's host can no longer put an address in the operator's Cloudflare list. In 8.0.0.
- **The accepted risks of every organisation were listed to any signed-in user.** Each organisation keeps its own records now. In 8.0.0.

### Medium

- **Sealing at rest covered one field of seven.** With `RP_CONFIG_KEY` set, the addresses and header values of destinations and the SIEM, audit-forward, OTLP and health-check
  addresses were in plain text, and every settings version kept the document unsealed. One list of those fields serves the sealing and the exports. In 8.0.0.
- **Three queues and the settings lost writes.** The command queue by four writers, the settings document by a host's heartbeat, the backup state by one more. In 8.0.0.
- **Threat Intel could be made to leak or to be wrong.** Sign-ins by passkey, SAML and OIDC did not protect their address, the protection of a password sign-in was read from the
  500 lines of the audit log that Threat Intel fills itself, the IPv4-mapped spelling of a protected address was not protected, a tenant read which addresses are protected,
  a tenant administrator read the operator's settings, one host could spend the day's reports on invented addresses, and one request with a superscript digit stopped the
  sensor of a host. In 8.0.0.
- **A scoped key or role passed as the platform operator on the Threat Intel page.** It cleared the whole table and read every host's Request log. In 8.0.0.
- **The vulnerability pages crossed tenants and could be made expensive.** Scans and counts across tenants, campaigns used up by one tenant, the SBOM at 18 seconds of CPU, a
  scan that took memory and requests from one host's list, a scan that checked nothing and announced the findings cleared, bursts that started several scans. In 8.0.0.
- **A host could write unlimited documents into the data directory.** Infrastructure-as-code answers, under names the host picked, inside the heartbeat's lock. In 8.0.0.
- **A deleted host left data behind**, and three routes served it to another tenant's administrator who held the id. In 8.0.0.
- **A destination that answers every delivery with a redirect was never marked as failing**, and one destination's recovery closed another's alert. New in the 8.0.1 pre-release.
- **Windows and macOS: secret redaction in cubic time, a walk of application folders with no budget, startup folders followed through links.** In code new in 8.0.2.
- **Delivery log and pre-shared key.** The delivery log kept the whole address of every delivery and went into the export; a WireGuard client's pre-shared key and the sealed KMIP keys
  were not masked. In 8.0.0.

### Low

- A path segment that is a capability link reached the page and, with examples on, a public report. A settings document sealed by another installation was stored as ciphertext. The
  ban route answered "on the never-block list" before it asked for the permission. Wrong-typed values in fields the shape registry did not list answered 500. The Detections
  sweep forgot every finding when the host store could not be read. Names and notes could hold characters that reorder text. An advisory with no name read as nothing found. The
  software list cut at 5,000 rows said nothing. In 8.0.0 except the last two.

## Open

Nothing that is an attack. The remainders are in the next sections.

## Known and unchanged

- **Whether an address was reported or blocked is shown to the users of the hosts that saw it.** The reason an address was held back for being protected is the operator's
  to read, but the outcome (a block exists, a report was sent) is the product's answer to the evidence those users' hosts sent, and a tenant could learn only that, which is
  what the page is for. Advice: nothing to do.
- **The log lines a host sends through its heartbeat have no hourly allowance of their own.** The queue they feed holds 500 entries, takes the hosts in turn, and a host has a
  share of the day's lookups and reports, so one host cannot spend what the others need. A host can still keep its own share used up.
- **Windows hosts: what starts by itself is the host's own word.** The persistence inventory reports what the host says; nothing in it is run by the server.

## Not found

No SQL injection, command injection or path traversal was found in the routes added in this release. No new outbound connection was added without the address rule. The
agents' new readers were fed hostile registry values, task XML, event text, plists and folder layouts; the findings above are all they produced.

## Not run for this review

- The shipped nginx snippets were checked as text and against a model of nginx's location rules, not on a running nginx: there is none on the machine the review ran on.
- The full release gate was not run on this tree. The modules of the areas above, the guards that cover the whole product (the ratchets, the shape registry, the host purge,
  the translations, the JavaScript budget) and the reproductions were.
- The agents were exercised against stand-ins for the registry, the event log, `wevtutil`, plists and Homebrew, not against a Windows or macOS machine.
