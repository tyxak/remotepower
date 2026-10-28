# Security review — v7.4.3

7.4.3 answers seven requests (#46 to #52): a Prometheus integration, how busy each disk is,
CPU and memory lines for containers, a maintenance window that raises no alerts, and more
choices on the HTTP monitors. This review covers everything that changed since 7.4.2, the
last reviewed release: 29 server, agent and page files with about 2,300 lines added, and the
tests and documents that go with them. The scans ran over the whole project, and the reading
went to what changed and to the places where a rule the product already follows might have
been missed.

It found **four** issues worth reporting. All four were caught before 7.4.3 is released, and
all four are fixed in it. One is new in this release (an audit entry that did not say enough),
one was made larger by it (the integration list), and two are older (the Test buttons, which
date from 3.2.1 to 5.3.0, and the figures a host reports, where one place is the new disk
figures). None came from the field. Every fix has a test, and each test was run against the
code with its fix taken out.

## What changed that a reviewer should look at

- **The Linux agent.** It reads the kernel's disk counters (`/proc/diskstats`), asks
  `/sys/block` which names are whole disks, and reports a row for each. The Windows and
  macOS agents changed only in their version.
- **The heartbeat.** It takes the disk figures a host sends and keeps at most 32 rows of
  them, and the container figures keep up to 6,400% for CPU instead of 100%.
- **New routes.** `PUT /api/devices/<id>/disk-names`, and `GET` and `PUT` on
  `/api/devices/<id>/container-thresholds`.
- **Maintenance windows.** A setting that keeps what a window covers out of the Alerts inbox.
- **Integrations.** Two connectors that fetch a page or ask a query at an address an
  administrator gives, with a login if the target has one. The list and the save send back
  and take more fields.
- **HTTP monitors.** The request method, an expected status that decides alone, and a switch
  for the certificate check.
- **The page.** Cards and forms for all of it. They put names and text from hosts and
  operators into the page: drive names, container names, integration labels, the error text
  of a remote service and a window's reason.

## How it was done

| Method | Scope | Result |
|---|---|---|
| Read against the threat model | Everything above, then each place a rule is meant to apply: who may press a Test button, who may read the integration list, what a host can make the server do by what it reports, and what an audit entry says | 4 findings, below |
| Undefined names and other pyflakes errors (`ruff F`, `E9`) | Server, agents, sidecars, tools and tests | 0, once five unused imports in the new tests were removed |
| bandit | 131,966 lines of server and agent Python | 0 High, 25 Medium and 926 Low. Against the committed baseline nothing is new. Compared by file, test and code there are three Low: two `except Exception: continue` where the maintenance windows are read, and a false positive on the constant that names the password kind of form field, whose neighbour line changed. The baseline is regenerated |
| semgrep | The Python, JavaScript and security-audit rule sets over the 27 server, agent and page files changed since 7.4.2 | 25 results on 21 distinct lines (the agent's extensionless file is a copy of the `.py`). None is on a line that changed since 7.4.2, and every one is a reviewed false positive (below). Three rule and file pairs timed out on `api.py` |
| gitleaks | Every commit (2,442) | No leaks |
| Dependency audit (`pip-audit`) | The 16 packages the server and agents import: Flask 3.1.3, Werkzeug 3.1.9, pydantic 2.14.1, cryptography 50.0.2, psycopg 3.3.6, Jinja2 3.1.6, requests 2.34.2, asyncssh 2.24.1, psutil 7.2.2, reportlab 5.0.0, gunicorn 26.2.0, bcrypt 5.0.0, dnspython 2.9.0, webauthn 3.0.1, pysaml2 7.5.5 and websockets 10.4 | No advisory |
| CodeQL | The repository's own configuration, as the production workflow runs it, for Python and JavaScript | 0 results |
| nuclei | 6,553 templates (exposure, misconfiguration, tokens, default logins, XSS, SQL injection, file inclusion, redirects, CORS, SSRF and traversal) against a seeded server | 15 informational results, none about the release: the file server of the test setup sends none of the security headers that nginx sends, technology fingerprints, and an upload form |
| The new connectors, attacked from the server's network position | 26 spellings of an address, saved and tested through both connectors; redirects; paths with a full address, `//`, `@`, `..`, a fragment, a query and a line break; slow, hanging and endless targets; a login page where a metrics page should be | No request reached a listener kept on the loopback address for the purpose, and none read a value. See *Not found* |
| Who may do what | The new and changed routes as eight callers: the platform operator, the administrators of two tenants, a viewer of one tenant, a viewer of the default tenant, and a finance, an on-call and a patch role | Each route refuses the callers it should. The exceptions are findings 1 and 2 |
| A write from another origin | `POST /api/config` with a foreign `Origin` header | 403 |
| Hostile input to every route | All 958 operations of the OpenAPI document (753 paths) on a seeded server with tenancy on: 913 requests with no session (45 operations that sign out, change a password, restore, update, restart and the like are left out), 1,152 reads as the platform operator, as a viewer and as a tenant administrator, and 3,456 writes, eight bad bodies for each of 432 operations, as the platform operator | No 500. Seventeen requests answered 503, all on the three SAML routes, because the SAML library is not installed here. The same fifteen operations answer 200 or 204 without a session as in 7.4.2 (the sign-in, the installer scripts and agent versions, the portal's magic-link request, alert action links, the start of a passkey sign-in, the two report beacons for CSP and client errors, the customer satisfaction link, the health check and the public information) |
| Hostile heartbeats | The report of a host through the real handler: 2,500 reports built from the reports of 14 seeded hosts, with a hostile value placed anywhere in them (an integer too large for a float, NaN, an infinity, a string, a list, a dictionary, 3,000 characters, a NUL byte, markup) | Before the fix 827 and 799 of 2,500 answered 500 in two runs, about a third. After it, 2,500 of 2,500 answer 200 |
| Planted text in a real browser | A drive name, a container match, an integration label, the error text of a remote service, a disk name sent by a host and a window's reason, each holding an image tag with an `onerror`, then 14 pages and panes opened (Home, the Alerts inbox, Predictive Health, Containers, Tuning, Maintenance, Integrations, two Settings panes, the host's drawer and four of its sections) | No script ran, no element appeared, no dialog opened, no page error was raised. Where the text is shown it is shown as text |
| Mutation checks | Each new test run against the code with its fix taken out: 27 changes | 26 caught. The one that survived is a second line of defence (below) |

The nginx scanners (nmap, nikto and wapiti against the shipped configuration) were not run
this time. 7.4.3 did not change the web server configuration: no file under `server/conf`
or `docker` differs from 7.4.2.

**The one change the tests did not catch:** the fan speed. A fan reading goes through a guard
that drops every value `int()` could fail on, and then through `_hb_int`. Taking `_hb_int`
out of the second step changes nothing a test can see, because the guard in front of it has
already refused the value. The guard itself is covered (the change that removes it is caught).
It is a belt behind braces and was left in.

**Reviewed false positives in semgrep:** 25 results on 21 lines, every one in code that was
already in 7.4.2. Thirteen are `chmod` calls that set a mode on the agents' and the server's
own directories and binaries. Four are SHA-1 uses, all of them `usedforsecurity=False`: two
signatures of log lines, the prefix of a breached-password lookup that the service's protocol
requires, and the demo-data seeder. A fifth result is that lookup's `urlopen`, which goes to a
fixed https host and is annotated. Two are `xml.etree` imports that write XML for exports. One
is a `shell=True` for a command an operator sets in the environment, annotated. Two are
`os.execv`, the agent's restart after new credentials (counted twice, as the agent's
extensionless file is a copy). One is a logger message that names an error, not a secret. One
is the painter of long tables, whose template escapes every field.

## Summary

| # | Finding | Before the fix | Where |
|---|---|---|---|
| 1 | Six Test buttons that take an address or a recipient from the request were open to a tenant administrator | Medium on an install with tenancy on, nothing otherwise. The integration Test button (since 4.7.0) was reproduced over HTTP: a tenant administrator pointed it at a service on a private address and was handed the numbers it holds, which the Prometheus connectors make much more useful than before. The mail test sent a message to any recipient as the platform (3.2.1), the directory test connected to any directory address (3.2.1), the directory sign-in test was a password oracle for the platform's directory (3.2.1), the ticket mailbox test connected to any host and port with no address guard (5.3.0), and the Proxmox test connected to a host named in the request (3.2.1). The saves beside them were already the platform operator's; the buttons were not | Server |
| 2 | The integration list showed a tenant administrator more than a viewer sees, and other tenants' integrations | Medium on an install with tenancy on, nothing otherwise. Every integration came back with its raw address, and from 7.4.3 with a probe's path, which can carry a token, and a Prometheus instance's lines. Integrations bound to another tenant's hosts were listed with their state and numbers. The stored secret was never returned | Server |
| 3 | A host's report could make its own heartbeat fail | Low: nine places converted a figure in the report with a bare `float()` or `int()`, and the check for the new disk figures raised on an integer too large for a float. An integer that large, NaN, an infinity, a string or a list answered 500 and the report was lost, so the host showed no new data until it sent a plain one. A host can only do this to itself | Server |
| 4 | The audit trail did not say that a window raises no alerts | Low: a window that keeps events out of the Alerts inbox hides more than one that holds notifications, and the entry for adding or editing a window said only the scope, the target and the reason | Server |

The first is fixed with the rule the product already follows for the saves: the platform
operator's gate comes first in a handler that takes a destination or a recipient from the
request. Of the 22 handlers whose name says they are a test, 7 do that and 1 of the 7 (the
Cloudflare feed test, from 7.3.0) had the gate. All 7 have it now. A test derives the 22 from
the source, requires each to be listed with the reason it is safe or the gate it carries,
checks that the 15 that are listed as safe read no destination from the request, and fails
on a new handler that is in neither list. The second changes who is asked: under tenancy a
tenant administrator reads the list as a viewer does, with no address, no path and no lines,
and rows bound to hosts outside the caller's tenant are left out for every caller who is not
the platform operator. The third replaces the nine places with two helpers, `_hb_float` and
`_hb_int`, which return a default for anything that is not a usable number, and makes the
number check for the disk figures safe for an integer of any size. The fourth adds
`suppress=alerts` or `suppress=notifications` to the entry. Each has a test, and the commit
that fixed it says whether the test was run against the old code.

## Not found

- **The new connectors cannot be pointed at the server itself.** 26 spellings of an address
  were saved and tested through both connectors: loopback as a name, in decimal, octal and
  hex, as an IPv4-mapped IPv6 address, in capitals, with a trailing dot, with user
  information and with a backslash, the cloud metadata address, a link-local IPv6 address,
  the `file`, `gopher` and `ftp` schemes, and forms without a scheme. 23 are refused when
  saved. The other three are accepted because the address check cannot classify them: a host
  whose name is the private address (what comes before an `@` is a user name), a name this
  server cannot resolve, and an IPv4 address with a trailing dot, which no resolver reads.
  The check lets a name it cannot resolve through, since the connection is what is guarded,
  and the connection check refuses a loopback or link-local answer. None of the 52 tests read
  a value or reached the listener.
- **Redirects and paths.** A redirect is not followed; the test says "HTTP 302". A path that
  is a full address, begins with `//` or `@`, climbs with `..`, or carries a fragment or a
  query is appended to the address that was saved and never changes the host that is called.
  A carriage return and a line feed in the path are refused by the HTTP client, and the same
  two bytes percent-encoded arrive as text in the request line, not as a header.
- **Slow, hanging and endless targets** (an administrator's Test button, so a worker is held
  and not a stranger's request). Twelve slow queries took 21 seconds in all: a poll asks for
  its values for 20 seconds at most and the rest wait for the next poll, and the detail names
  them. A response that hangs ends after 8 seconds. A body that never ends is cut at 2 MB and
  refused. A login page where the metrics should be is refused as holding no samples.
- **The stored secret.** No caller of the integration list received it, with the new fields
  returned to administrators, and the Test button falls back to the stored secret only for an
  administrator of the platform.
- **Who may write.** Drive names, container lines, windows and monitor settings are refused
  to a viewer and to the read-only roles with 403. A tenant administrator can write them for
  their own tenant's hosts and not for another's. A window written by a tenant administrator
  reaches that tenant's hosts only, a global one included, and a window that raises no alerts
  is asked through the same function as every other window (new tests pin both).
- **The agent's new reads.** `/proc/diskstats` and `/sys/block` are kernel files. A local
  user cannot replace either with a FIFO or a file of their own, so the plain read that the
  7.4.2 fix guards against does not apply to them. The figures go through the heartbeat
  sanitizer as numbers: at most 32 rows, a name of at most 32 characters, every figure finite
  and in range.
- **The monitors' new settings.** A hostile method or certificate-check value sent through
  `POST /api/config` left 20 stored monitors with no unusual method, and the check was turned
  off only where the input was a real `false`; a string or a number that reads as "off" did
  not switch a security check off. The protocol floor and the address guard stay on.

## Known and unchanged

- Settings are one store for the whole install, and every signed-in role can read its
  non-secret keys (listed in the 7.4.2 review). The container lines, the disk lines and the
  monitor settings are in it, so with tenancy on the users of one tenant can read them. This
  is how the store was built; a settings view per tenant would be a design change and is
  listed for the maintainers.
- An integration that is not bound to a host is listed to every signed-in role with its
  label, type and state, whatever the tenant. Only the platform operator can change one.
- A host is believed about itself. A compromised agent can raise alerts and report disk and
  container figures for its own host and for no other.
- The unit that the quick-install script writes has less hardening than the one
  `install-client.sh` installs, and the Windows installer still builds its CA address with the
  port cut off. Neither was touched in 7.4.3; both are described in the 7.4.2 review.

## Left for the release gate

The suite on both storage backends, and the checks that need the release commit (the tarball
scan and the signature), run on the commit before the header flip. The release commit adds
their numbers here.

Not run for this release: a live probe of the maintainer's own instance (it needs a one-time
token), the nginx scanners (above), the SAML routes (the library is not installed here, so
all three answer 503), the PostgreSQL suite and the run with Python 3.14 and the CI
dependency list (both belong to `make pre-release`, which cannot finish on a dated header
while the AUR packages trail it), and a native read of the new translations.
