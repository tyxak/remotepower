# Security review — v7.4.9

7.4.9 is the release in which the whole project was reviewed, not only what changed since the last one. Seven reviews ran side by
side: an authorization matrix over every route, a hostile-input sweep of the server, a review of the three agents and their
installers, a review of the web client and the web server headers, a rendered audit of the interface, a documentation cross-check
and a map of what the agents send against where it is used. Scanners ran beside them. Everything below was found, reproduced and
fixed on a seeded copy of the product, not on anyone's installation.

It found **five High issues, seventeen Medium ones and ten Low or hardening items. Every one of them is fixed.** Nothing rated
Medium or higher is open. "Open" lists what is left, and none of it is a way to attack an installation. Each fix has tests, and
each test was run against the code with its fix taken out.

The agents have to be updated for the agent fixes (the agent version is 7.4.9). The server fixes need no action except where a note
below says so.

## What changed that a reviewer should look at

**Added after the review, in two batches.** Six features were built once the sweep was done and the gates had run, and eight more after
them. None loosens a permission, and each was checked with the same instruments. The matrix, run on the tree after the first batch, found
one defect in them, fixed before release (S32). It ran again on the finished tree: 1,088 routed operations (the thirteen new routes of the
two batches included), 85,302 requests in 60 runs, and no answer to a tenant user held another tenant's id, name or object. The 60 operations
that answered some caller with a marker it should not hold fall in the same groups as before: 13 answered tenant users (the caller's own
input stored and read back, the content of a cloned host, the shared knowledge base, or a host token's own scripts), 44 answered only
roles or keys scoped to groups or tags, 2 answered the finance role, and one was a planted row that the product itself had already
rewritten into an alert about the installation's own service. The 44 are two more than before: `GET /api/alerts` and `GET /api/problems`
for a scoped key, which carry the installation's monitor alerts (a scoped role is shown the same rows; see "Known and unchanged"). The 697
answers that were not a refusal are the same as in the earlier run (251 were 400 and 446 were 405), and so are the eight requests that
answered 5xx or not at all.

New routes of the first batch: `POST /api/alerts/{id}/assign` (it asks for the right to acknowledge an alert, refuses an alert the
caller cannot reach, and refuses an assignee who could not open the alert: another tenant's account, a role scoped to other hosts, a
disabled account), and `/api/business-services` with its `{id}` and `impact` routes (the organisation that runs the installation's, so
they sit in the second table below and a tenant's users never reach them; creating, changing and deleting ask for an administrator, and
a service that holds a host a user cannot see is hidden from that user). `allowed_cidrs` on `POST /api/enrollment-tokens` narrows what a
token allows and can only refuse more. The handler ratchet (`tests/test_v749_handler_tenant_ratchet.py`) and the store-shape registry cover
the new handlers and stores. Two review notes: the Nagios-plugin reading of a custom script runs no new code on a host (the server reads
the exit code the agent already sends), and a container's health-check output is shown to whoever can read the container's alert, so a
check should not print a secret.

New routes of the second batch: `GET` and `POST /api/devices/{id}/patch-preview` (anyone who may patch the host; a host outside the
caller's tenant or scope is refused first), `PUT /api/devices/{id}/container-audit` (an administrator, for a host the caller can reach; audited), `GET /api/containers/audit`
and `GET /api/repositories` (within the tenant and role scope of every fleet listing) and `POST /api/backup/s3-test` (the platform operator
only: the address comes from the request and the server connects to it; in the matrix every caller except the platform operator's
administrators was refused). The other features use routes that exist: the settings document (`time_periods`, `backup.s3` and the CPU time
lines, saved by the platform operator only under tenant isolation), `POST /api/maintenance` (takes a `period`), the monitors (`via_host`)
and the heartbeat (the server sends a host the checks assigned to it and takes their results back, for that host's own checks only). Review
notes: the agent's collectors for repositories, ZFS and container run options only read; the checks a host runs for the server use the
agent's own vetting of addresses (the host's loopback allowed, link-local and cloud metadata refused when the check is saved and again when
the agent connects, no redirect followed); the secret key of the S3 copy is read from the server's environment and is in no store, archive
or answer.

**Caught while building the second batch.** The test suite stopped three things before they shipped. A host in audit mode (read-only)
would have run the checks the server assigned to it, which open connections and run `ping` to addresses the server names: the agent
refuses them now, a check cannot be assigned to such a host and the row says why. The read of the settings would have given every reader
the access key id of the S3 copy, which names the account that owns the bucket: readers who are not administrators get an indicator
that one is set. The S3 connection test asked for an administrator in its handler and relied on the route table to keep a tenant's users
out: the handler asks for the platform operator itself. They are not in the counts above, which are the review's.

- **Routes.** One route is new: `POST /api/logout`. Two others are new for one feature: `POST /api/scap/{id}/report-ticket`, and
  the SCAP report route now also accepts a one-minute link. No permission was loosened. A permission check was added to one
  endpoint (`services/config`) and a tenant check to the ticket handlers and to many others. The table of what only the platform
  operator (an administrator of the default tenant) may do holds 55 entries, 29 more than in 7.4.8. A second table, new in this
  release, holds the 59 route prefixes that belong to the organisation running the installation (monitors, links, calendar,
  billing, integrations, DNS, the audit trail's archive and others): with tenant isolation on they answer only users of the
  default tenant.
- **Credentials.** Every comparison of a secret in the server goes through one helper (`secure_eq.py`) that never raises. A DNS
  provider token is removed from command output before it is stored.
- **Stored data.** The shape of 134 stores and of the settings document is stated once, in `store_shapes.py`, and checked where
  a store is read. A row of the wrong kind is left out of what a page reads; on the JSON storage the file is kept as it was in `quarantine/`.
- **Containers.** The Docker image starts its app server and daemons as `www-data`, not root.
- **Supply chain.** The GitHub Actions in the three workflows are pinned to commits, and Dependabot waits seven days before it
  proposes a release.
- **Size.** Since 7.4.8, counted by git with the documents left out: 244 files, +33,621 −1,035 lines. Server 55 files (+7,760 −475), web client 26 (+2,176 −161), agents and installers 7 (+2,338 −122), tests 135 (+20,660 −241), packaging, Docker and tools 21 (+687 −36).
- **Not changed.** No dependency was added or removed in the server (Swagger UI moved from 5.34.0 to 5.34.1, a bug-fix release with
  no advisory). The agent version is 7.4.9 in all three agents.

## How it was done

**Scanners, on the whole tree.**

| Scanner | What it covered | Result |
|---|---|---|
| CodeQL 2.27.3 (the version the pinned workflow action uses), Python and JavaScript, the repository's own configuration | the whole tree | no result, on the tree before the last fixes and again on the final tree (see "The release gate") |
| bandit (against its baseline), ruff (undefined names, errors), mypy (32 modules), the JavaScript correctness gate, vulture | server, agents, tools, tests | no new finding; vulture's two reports are unused parameters |
| semgrep (registry rule sets, with a known-bad file as a control) | the whole tree | 92 results; all triaged, see below |
| gitleaks (tree and the commits of this release, with planted keys as a control) | the whole tree | no leak found; the control found both planted keys |
| shellcheck | every shell script | five warnings in four scripts, fixed |
| nuclei 3.3.7 with 10,575 templates (a stub exposing a git configuration was found, as a control) | a seeded stack behind the shipped web server configuration | 12 findings, all informational (missing HSTS and Cross-Origin-Embedder-Policy headers, technology fingerprints, security.txt present) |
| wapiti 3.3.0, signed in, 15 modules (a page with a known reflected XSS was found, as a control) | the same stack, 148 pages | no finding |
| pip-audit | the server's Python dependencies | no known vulnerability |

The 92 semgrep results: 21 were mutable GitHub Action tags (fixed by pinning), 27 and 4 were notes on the web server's use of the
`Host` header and `proxy_pass` (reviewed, by design: a script served from the Host header is sent `no-store`, and links that leave
the server use the configured public address), 13 were file modes of `0700` directories, 6 were log lines that name a file and not
a secret, 7 were an `Upgrade` header forwarded to WebSocket-only daemons (hardened, see S11), 3 were Dependabot cooldowns (fixed),
one was the container running as root (fixed, see S1). The remaining ten are an AES-CFB mode that SNMPv3 requires, a SHA-1 in the
demo seeder, two web client sinks covered by the web client review, a URL fetch in a demo tool, and five subprocess calls in the
scanner and the agent that the agent review read.

**Seven reviews, with their populations.**

- *Authorization matrix.* 1,075 routed operations taken from the real route tables, 84,240 requests, 60 runs as 26 kinds of caller:
  no credential, a bad token, an administrator, a viewer, a custom role, a role with no permission, an auditor, a finance user,
  roles scoped to a group or a tag, administrators, viewers and an operator of two tenants, eight API keys and three host tokens.
  Controls: the administrator was answered 2xx by 498 to 554 operations in each run and the anonymous caller by 16; on the 391
  operations that take an id, a tenant administrator's own objects worked in 112 and the same call on another tenant's object was
  refused (403 or 404) in 107 of them (the rest are the shared knowledge base, a token or a random request id in the path, an
  idempotent delete of an id that does not exist, and one answer of 409); the scope check refused every host-path operation outside
  the role's scope (88 of 88 for a group role, 84 of 84 for a tag role, 11 of 11 for a scoped key); a leak scanner found the other
  tenants' planted markers in the platform operator's answer and none in a tenant administrator's. The matrix ran three times, each
  time on the tree with the earlier findings fixed. The last run was on the tree at the end of the tenancy work (the later commits
  add three prefixes to the operator table, move the image ignore list's add to the platform table and give a user's avatar a tenant
  check; the unit tests of those rows run every prefix of both tables). It found no answer to a tenant user that holds another
  tenant's id, name or object. 58 operations still answered some caller with a marker it should not hold: 13 of them answered tenant
  users, and each of the 13 is the caller's own input stored and read back, the content of a cloned host, the shared knowledge
  base, or a host token's own scripts; 43 answered only roles scoped to groups or tags (see "Known and unchanged"); 2 answered the
  finance role, which reads the operator's time entries. Compared with the run before, 2,152 requests of tenant users that were
  answered 2xx are refused, none became 2xx on another tenant's object, and the 21 that went from a refusal to 2xx are on the
  caller's own objects (an expired confirmation, an alert already resolved). No request answered 2xx where the handler's own declared
  gate refuses: of 697 answers that were not a refusal, 251 were 400 and 446 were 405.
- *Handler enumeration.* The matrix can only find what the seeded data holds, so a second instrument asks the code. A syntax tree
  over the server lists every routed handler outside the two tenant tables whose own body names no tenant or scope helper. Before
  the last pass that was 171 of 546 handlers (82 writes and 89 reads). On the final tree it is 90 of 453 (49 writes and 41 reads).
  The 81 that left the list joined one of the two tables or were fixed in the handler. Each of the 90 that remain was read or called
  as a tenant administrator on the seeded stack: the test sits in a helper the handler calls, the route takes a machine token or
  the caller's own session, or it serves a library every tenant may read. It found S30 and S31, the audit trail's archive, the
  restart and update of the service, and the migration of the data store. A test (`tests/test_v749_handler_tenant_ratchet.py`)
  keeps the list from growing: it finds the routes the application registers, takes out the two tables and the handlers that name a
  tenant helper, and fails when a route is left that is not on a reviewed list of 86 (the tool reads routes that the router matches
  by hand-written conditions, which the test cannot).
- *Hostile input.* About 41,650 requests over 975 routes, 4,252 body keys and 239 query keys, with 19 wrong types for each key
  (including NaN, Infinity, 400-digit integers, a lone surrogate, a 1 MiB string), 931 sparse hostile heartbeats, 19 hosts made of
  nothing but wrong-typed leaves, 139 stores mutated one row at a time, and the 76 periodic sweeps run on those rows. Every round
  had a non-zero count of successful answers. After the fixes, the 3,809 stored rows that had answered 500 all answer below 500 when replayed one at a time, and the 76 periodic
  sweeps, which had raised on 1,810 mutations when the first run had reached 72 of the 96 stores they read, raise on none of the
  4,032 mutations of all 96.
- *Agents.* The three agents, the six installers and the agent container, with real GNU tar and real PowerShell where the finding
  needed them. Nothing was run as root, on real Windows or macOS, or against real package managers.
- *Web client and headers.* 1,320 places where the page writes to the document and 7,070 operands of the HTML it builds were parsed
  with a real JavaScript parser; 11,522 hostile strings were planted in the stores and 130 host strings sent through the real
  heartbeat; every response of both shipped web server configurations was measured for its headers. The test the review had
  generated and not run, every number of every store replaced by markup (143,010 of them), was run at the end: see S29.
- *Interface.* 85 pages, 14 settings panes, 141 dialogs and the host drawer at desktop and phone width, 255 views in the six
  languages, with a known-good and a known-bad fixture for each check.
- *Documents and signals.* 139 of the 140 guides were read against the code; 98 signals the agents send were followed to 11 places
  that could use them, through the real heartbeat, and none of the 185 keys the Linux agent sends was dropped.

**The Docker change was run, not read.** The real entrypoint, the web server, the app server, the daemons and the real agent ran
in a user namespace that has a real uid 33. With the old entrypoint the five long-running processes were root. With the new one,
all of them are 33:33 with no capabilities and no root group, only the web server's master process is root, and every file in the
data volume belongs to `www-data` (52 checks pass; the old entrypoint fails the five that ask who runs what; putting the hand-over
back where it was gives 9 failures).

## Summary

Severity follows the project's own scale. Anything a stranger or a lower-privileged caller can exploit is at least Medium.

| id | severity | where | what |
|---|---|---|---|
| S1 | Low (hardening) | Docker image | the app server and daemons ran as root; they run as `www-data` now |
| S2 | **High** | `services/config` | a viewer, auditor, finance user or read-only key could rewrite a host's watched services and log-watch rules by changing the verb |
| S3 | **High** | Linux agent | one 107-byte web request target kept the log sensor busy for 1.3 s, 123 bytes for 17 s |
| S4 | **High** | Linux agent | host config and SSH key collection followed links in a user's `~/.ssh` as root |
| S5 | High with signed commands, Medium without | Linux agent | the restore drill's sample path could run a command through `tar` |
| S6 | Medium | server | a DNS provider token was readable in the command history by every signed-in role |
| S7 | Medium | server | a maintenance window written with a day name (the dialog's own example) never opened and could hold commands for ever |
| S8 | Medium | server | four AI features sent logs and command output to the provider unredacted |
| S9 | **High** | server, tenancy | instance-wide operations reachable by a tenant administrator: a full backup of every tenant's data and its restore, the audit chain's key, a restart of the service, a migration of the data store, the server's certificate, the operator's hypervisors and DNS zones, and others |
| S10 | Medium | server, tenancy | session revocation, schedules, rollouts, host links, the command history, image updates and the webhook log crossed tenants |
| S11 | Info (hardening) | web server | any `Upgrade` value was forwarded to the WebSocket daemons |
| S12 | Medium | server | hostile input answered 500 on routes a stranger or a host can reach: a non-ASCII token, a lone surrogate, Infinity, an unhashable value |
| S13 | Medium | web client | Sign out never ended the session on the server |
| S14 | Medium | web client | a host's SCAP report opened in the dashboard's origin and lost its sandbox |
| S15 | Medium | Windows agent | PowerShell's typographic quotes ended a quoted service name and ran a command as SYSTEM |
| S16 | Medium | installers | a CA pin checked the first certificate and trusted the whole file |
| S17 | Medium | Linux agent | a container's Update recreated it without its user, capabilities, read-only flag, limits and entrypoint arguments |
| S18 | Medium | Linux agent | account key files were read through links, pipes and `/dev/zero` as root |
| S19 | Medium | relay satellite | any `Content-Length` was read, with no timeout |
| S20 | Low | server | a Proxmox credential outside ASCII answered 500; Infinity reached `int()` in four coercers; a list where a string was expected |
| S21 | Low | Linux agent | the quarantine changed a file's mode through a planted link |
| S22 | Hardening | CI | the GitHub Actions followed mutable tags |
| S23 | Medium | server, tenancy | about twenty listings, and the operator's own data, showed a tenant user another tenant's host names or the operator's settings: tickets, hours, invoices, quotes, sites, contacts, monitors, links, calendar, the knowledge base's linked hosts and more |
| S24 | Medium | server | one stored row of the wrong shape answered 500 on the home, problems, alert and risk pages for everyone, stopped periodic sweeps, or dropped a host's report |
| S25 | Low | server | sessions and the CSP-report throttle recorded the proxy's address; two delete routes could not be reached; the public status page named every monitor |
| S26 | Low | web client | the click handlers called a function by a name from the page; a link signed a browser into someone else's session; the debug log opened a tab that cannot sign; Sign out left more per-person data; external links kept a handle to the page; the service worker cached token URLs; the portal escaped a name twice |
| S27 | Hardening | web server | the two configurations disagreed on headers, three responses carried a header twice and `/ca.crt` carried none |
| S28 | Low | agents, relay, installers | a link redirected a canary file; a pipe blocked the file manager; a directory walk had no budget; the downgrade guard trusted the server; three channels that run as root ignored `require-signed-commands`; the Windows installers skipped the checksum and the signature check; `docker` was found through `PATH` on Windows; an operator's regex had no time limit; the relay forwarded the whole API; the macOS update mode |
| S29 | Low (defense in depth) | web client, stored data | a number stored as text would be printed as markup by 731 template operands; no agent or API call can store one, and the loader now reads 34 kinds of field that way |
| S30 | **High** | server, tenancy | an ACME issue request handed the operator's central DNS credentials to a tenant's own host |
| S31 | Medium | server | a read-only role was shown the address that reports a dead-man job alive |
| S32 | Medium | server, tenancy | an event that names no host reached a tenant's users in the Home feed, in a personal notification and in a browser push, and a business service's alert named hosts to readers who cannot see them |

## Fixed in 7.4.9

- **S2.** The permission was asked for on POST only. Any other verb reached the write with a bare sign-in check. GET stays open to
  every signed-in role, POST needs the `services` permission, other verbs are refused.
- **S3 to S5, S15 to S19, S21.** See the CHANGELOG's agent entry. Each has a test that fails on the old agent file.
- **S6.** The command the agent echoes back carries the provider's credentials. They are removed before the command is stored, and
  before the length cap (a cap that cuts inside a value would have kept part of it); rows stored earlier are cleaned when read and
  when the host next reports. **If you used ACME with a saved DNS credential before 7.4.9, rotate that token.**
- **S7.** The matcher reads `SUN` to `SAT` and `JAN` to `DEC`, and a maintenance window with a field it cannot read is refused.
- **S8.** The helper behind the mitigate step, alert triage, the log-sweep analysis and the AI exec proposal now calls the same
  dispatcher as every other AI request, which redacts bearer tokens, access keys, long hex strings and (unless you allow them)
  addresses and host names. A test fails on a direct call of a provider adapter anywhere in the server.
- **S9, S10.** A tenant administrator passed each of these because the handler asks for an administrator and nothing more. They moved
  to the platform table: the audit chain's key and the export key, a full backup and its restore, the restore drill, the server's
  TLS material and the replacement of its certificate, the restart of the service and the update script, the migration of the data
  store to another backend, power and snapshots of the operator's hypervisors, the operator's DNS providers (reads too) and DNS
  blockers, the import from the operator's cloud accounts, GitOps, the test messages to the operator's AI provider, audit forwarder,
  OTLP, SIEM and posture digest, the replay of a past event of any tenant through the operator's channels, the fleet-wide image scan and
  the list of image updates to ignore, the single software policy that is judged against every tenant's hosts and the other instance-wide trackers. Session
  revocation is confined to the caller's tenant and takes the store's lock. A schedule job belongs to the tenant of its host, a rollout
  to the tenant that created it. A link between hosts may name only a host the caller can see, and the guard test that watches host
  ids in request bodies watches `depends_on` and `connected_to` too. A node on the network map is moved by someone who can see it.
- **S12.** One helper (`secure_eq.py`) replaced all 20 comparisons of a secret, and a test fails on a bare `compare_digest`. The
  request body is cleaned of lone surrogates where it is read. NaN, Infinity and 400-digit numbers are refused where a host sends
  them. A test feeds every request model every non-finite value for every field.
- **S13.** `POST /api/logout` removes the session. The page calls it after saving your preferences, and drops the hosts you opened
  recently, your favourites, your stats history, your drafts, the AI conversation and the infrastructure-as-code page's host and
  instructions from the browser.
- **S14.** The report opens from a link the server serves with its own sandbox policy. The page asks for the link first (signed in,
  host scope checked), and it works for one minute. A bad or expired link answers 403 with its own message.
- **S23.** A ticket has no tenant field, so it takes one from what it names: the tenant of its host while the host exists,
  otherwise the tenant of the account that opened it (a customer's reply by mail and an automation rule belong to the default
  tenant). The ticket list, a single ticket, update, delete, attachments, the e-mail thread, the open count and the hosts marked
  with a ticket show a tenant its own; a ticket cannot be moved onto another tenant's host. 59 route prefixes whose stores
  have no tenant column, or whose pages are the operator's, belong to the organisation running the installation (the monitors
  and the SLO figures, the links, the calendar and its feed, the mail round trip, Proxmox, the diagnostics bundle, configuration as
  code, billing, invoices, quotes, time entries and timesheets, sites, contacts, IPAM, racks, incidents, patch snapshots, the site
  report, the integrations and hypervisor platforms, the WAN address, the on-call roster, the customer portal's queue, report
  definitions and schedule, the security posture, diagnostics, self-test and setup pages, metrics push, client errors, DMARC, IP
  reputation, resolver health, the TLS monitors, the helpdesk mailbox, DNS, the audit trail's archive and chain check, the global
  log rules, the litigation hold, the AI parameters and prompts, the saved DNS credential list, dead-man jobs, the
  needs-attention suppression rules, the server's own status pages, the signing status and the AI index's status): with isolation on they answer only users of the default tenant, for reads and writes, so the
  operator's own viewers and operators keep their pages. What names no host (an alert about a monitor, a certificate watch or an
  integration, an activity item, a needs-attention item, the monitor families of the metrics scrape) is the installation's, and a
  tenant sees what names one of its hosts. The settings document comes back with its lists and addresses empty for a tenant, and the
  audit trail shows a tenant's administrator or auditor what the accounts of its own tenant did. Custom checks, drift profiles and
  policies, SLA targets, patch decisions, the suppression trail, gateway sessions, compliance evidence, alert mutes, batch jobs,
  tunnels, automation rules, accepted-risk records and the CMDB's function hints show or change only what reaches the caller's own
  hosts: a rule or an accepted risk with no tenant stamp belongs to the tenant of the account that wrote it, so a rule written before
  7.4.9 by a tenant account no longer fires on other tenants' hosts. The operator's own non-administrators read the operator's
  data, as before. The knowledge base is one library: only the platform
  operator writes it, and an article lists only the hosts the reader can see. The digest, discovery, a script's list and the script list of the results endpoint, the LLDP
  suggestions, the maintenance windows and automation rules, and the home page's links, calendar and on-call roster no longer
  name a host out of sight. The dashboard's "upcoming" card never showed a scheduled job (it read the schedule as a list, and the
  store is a map holding the list); it does now, and shows a tenant its own. Of the 32 handlers that read a host id from a request
  body under a key the guard test did not know, re-derived with a syntax tree and a seeded two-tenant run, two exposed anything (the
  LLDP and dependency listings); the others gate on a helper or never read the id back. `GET /api/tenancy/readiness` and the
  tenancy guide say what is isolated now.
- **S24.** The shapes are stated once and checked where a store is read (134 stores, 150 numeric settings and 6 text settings): a
  container of the wrong kind becomes an empty one, a row or list element that is not what the store holds is left out, a field
  of the wrong kind is read as the right one where that loses nothing (a number stored as text) and is otherwise removed, so the
  reader's own default applies, and a needed key of the wrong kind makes the row unusable. Two stores are repaired the other way
  because an empty value there would grant something: a damaged tenant stays a tenant (its users would otherwise move to the
  operator's tenant), and a smart group with damaged rules is dropped (an empty rule set matches every host). NaN, Infinity,
  an integer of 21 digits or more and a float that overflows are read as null. The repair is applied in memory; the next write
  saves the repaired copy; on the JSON storage the file as it was is kept in `quarantine/` (the last 20), on SQLite and PostgreSQL the
  row stays in the database until that write; one line on stderr says how many entries were left out. Replayed one at a time against the new code, the 3,809 stored rows that had answered 500 now all answer below 500.
  The 76 periodic sweeps, called with one wrong node at a time in each of the 96 stores they read, had raised on 1,810 mutations
  when the first run had reached 72 of them, and raise on none of the 4,032 now. Running the whole test suite with a report of every repair found two registry entries that disagreed with
  what the product itself writes (the remediation store and the webhook log), and two more after the second run (a saved query
  without a filter stores null, and one test fixture wrote a map where the CMDB writes a list); all four are corrected.
- **S25.** Sessions and the CSP-report throttle used `REMOTE_ADDR`, which is the proxy's own address behind nginx; five places use
  the client address now. `DELETE /api/devices/{id}/runbook` and `/drift` were matched by the host-delete row first; they are
  excluded from it. The public status answer counts the monitors and calls them `Monitor 1`, `Monitor 2` (name one by putting it
  in a component).
- **S26.** The delegated click handlers resolve a name through one function that accepts only what the application declares. The
  SSO buttons mark the tab, and `/#oidc_token=...` is taken only by a tab that started the sign-in (one use, fifteen minutes; the
  exception is IdP-initiated SAML, see "Known and unchanged"). The debug log is fetched through the API client. Sign out drops the
  AI conversation, the infrastructure-as-code page's host and instructions, the metric explorer's view and the activity feed's
  mark. `target="_blank"` links and the external sidebar links carry `rel="noopener noreferrer"`. The service worker does not
  cache a URL with a token in its query string. The portal no longer shows `&` as `&amp;`.
- **S27.** A location that sets its own `add_header` makes nginx drop the server-level headers, so each location now states the whole
  set, including the two cross-origin headers that were missing on the static files, the service worker and the manifest (and
  everywhere on Docker). `/sw.js`, `/manifest.json` and the Docker `/agent/` send each of `Cache-Control` and `Content-Type` once,
  and `/ca.crt` carries `nosniff`. Both configurations were measured through a real nginx.
- **S28.** The Linux agent resolves the directory of a canary decoy before it creates the file, reads the file manager's path
  without waiting on a FIFO, keeps the owner and mode of a file it writes, gives the directory baseline a time and entry budget,
  and refuses a signed release older than the running agent unless the host's own `allow-downgrade` file allows it; the macOS and
  Windows agents have the same downgrade check. Canary files, backup verification and the restore drill are refused when
  `require-signed-commands` is set. The Windows agent uses a `docker` only from Program Files or the Windows folder and refuses a
  log pattern that repeats a group inside a repeated group, and the macOS agent stops a log pattern that runs longer than ten
  seconds. The relay forwards only the paths an agent calls; a test reads every path out of the agents and installers and fails if
  one is not on its list. The Windows installers stop when they cannot read the agent's checksum and check that the Python
  installer they run elevated is signed by the Python Software Foundation. The macOS update mode is 0o755, like the Linux one.
- **S29.** The review had generated a test it did not run: every number of every store replaced by markup, 143,010 of them. It was
  run, and 262 planted values reached a page unescaped across 15 stores (host sysinfo and hardware, drift, secret findings, SCAP,
  package counts, speed tests, Compose, automation rules, webhooks, KMIP objects, schedules and snapshots). Two things bound the
  risk. First, the real Linux agent's own heartbeat (273 numbers and 6,332 strings from one poll, including SMART, GPU, kernel,
  antivirus, accounts and 43 sysinfo keys) was sent through the real handler with every number replaced by markup: none of the
  numbers was stored as text, because the ingest functions keep only numbers in these fields. A restore, an import or a hand edit
  can store one, an agent or an API call cannot. Second, the shipped Content-Security-Policy stops a planted handler from running,
  an external image from loading and a form from leaving the origin; what is left is an injected link or text. It is closed where
  it is measurable: the loader reads a field of the 34 kinds the crawl reached, and the numbers beside them, as absent when it
  holds text, and the same crawl on the changed tree finds none of the 262. The other 731 unescaped operands rely on the ingest
  and the policy, and are not escaped one by one. The 57 controls without an accessible name that the interface audit found
  (integration cards, the DNS pause, the webhook format) are named, and the same script finds no control without a name in 241 views.
- **S30.** `POST /api/acme/{host}/issue` builds an acme.sh command and puts the credentials of the operator's central DNS-provider
  store (Settings, ACME) in front of it, so nobody has to edit `account.conf` on each host. For a tenant's own host that handed the
  operator's token to the tenant's root account, where acme.sh keeps it, and with it the right to edit the operator's zones. The
  credentials go into commands for the operator's own hosts only. A tenant's host uses what acme.sh finds on it. **If you saved
  central DNS credentials and have tenants, rotate that token.**
- **S31.** The dead-man job list gave every signed-in role the address that reports a job alive, and whoever has it can report a
  missed job as on time. A read-only role is shown the job and not the address; an administrator gets both.
- **S32.** The events endpoint and the alert inbox kept an event that names no host (a monitor, an integration, a business service)
  for the organisation that runs the installation, and showed a tenant's users only the events of their own hosts. Three other
  readers did not. The Home feed showed a tenant's users the operator's monitors and integrations. A personal notification went to
  every subscriber, whichever tenant they belonged to. The browser push went to every subscription, so a tenant's user was told the
  title of every other tenant's high or critical host alert. All of them ask the same question now: a tenant's user is never shown
  or sent an event that names no host, and a host's event reaches the people who can see that host. The matrix also found the same gap in
  the Business Services feature before it shipped: the alert and the activity entry of a service list its parts by name, and only the
  page had hidden them from a reader who cannot see one of the hosts. A row about a service is shown to a reader only if every host
  it names is one they can see, and acknowledging, resolving or assigning such an alert refuses a reader who cannot see it.
  The hosts a row names are recorded with it, so changing a service later does not widen who can read an older row.
- **S1, S11, S22.** Described in the CHANGELOG.

## Open

Nothing rated Medium or higher is open. These are smaller, and none of them is a way to attack an installation.

- **Interface.** Chart text sized by the drawing's view box (14 to 16 px on a desktop, 4 to 5 px at phone width), table action buttons
  that wrap at phone width, the Provisioning name column at phone width, and a split of helper text between 11 and 12 pixels.
- **Signals.** Ten places that could use a signal the agents already send and do not: Fleet Query and the Data Explorer for
  encryption and security updates, alert events for the posture trio on Linux and macOS, a time-synchronisation compliance control,
  hardware and exposure sections in the fleet report, the macOS and Windows protections in the risk score, security updates, ECC
  errors and container crash loops in the risk score, `docker_df` sent on its own on a first poll, and DMI and memory-module data
  for the AI index.
  Three more (the Advisory's disk-encryption finding, the AI digest and the GPU line) are done.
- **Tenant-owned features.** The users of a tenant lost the pages of the organisation that runs the installation (monitors, links,
  calendar, integrations, dead-man jobs, needs-attention suppression rules and the rest of the list above). A tenant that needs its
  own copy of one has none. Each would keep its records stamped with the tenant, as tickets do: a feature to build, not a way to
  attack an installation.
- **Translations.** The strings added in 7.4.9 are owed a read by a native speaker in each of the six languages.

## Not found

- **Script injection from host or operator text.** None of the 11,522 planted strings and 130 host strings executed, injected an
  element or broke an attribute (79% of the planted strings never reached a screen, listed in the web client review).
- **Authorization gaps outside the ones above.** The administrator was refused nothing it should have been given, and no request
  answered 2xx where the handler's own declared gate refuses. Eight operations answered 5xx or timed out in the last run, and each
  has a reason that belongs to the harness: the SAML library is not installed (three routes, 503 with that message), the AI provider
  is off in the seed (two routes that say so in the answer, with 500 and 502 as the status), the two scans that reach out to the
  network were cut off by the network namespace, and key generation could not run gpg there.
- **Heartbeat ingest.** 931 sparse hostile heartbeats and 19 all-wrong-type hosts gave no 5xx and broke no page; the Linux agent's
  185 sysinfo keys all reached the server.
- **Public pages.** Framing of the status page and the dashboard is blocked, the status token is compared in constant time and an
  empty token is refused, the portal link is built from its configured address, and the portal cookie is `HttpOnly; Secure;
  SameSite=Strict`. No CORS headers are sent.

## Known and unchanged

- A fully compromised server is root on its agents, by design (see the threat model).
- **A role scoped to groups, tags or sites limits what a user can change, not what they can see.** The host list is filtered, and
  every operation on a single host outside the scope is refused (88 of 88 for a group role, 84 of 84 for a tag role and 11 of 11 for
  a scoped key in the matrix), but in the last run 54 operations answered a scoped caller with a marker of a host outside its scope.
  Most are lists that cover the whole fleet (alerts, problems, activity, checks, exposure, metrics and others); a few echo the
  caller's own input. The boundary for confidentiality is the tenant: give a person who must not see other hosts a tenant.
- **IdP-initiated SAML sign-in** (`saml_allow_unsolicited`, off by default) has no start in the browser tab, so the check of S26
  cannot apply to it. Leave it off unless you need it.
- Responses of a few administrator test endpoints carry the data directory's path, and the AI settings page shows the last four
  characters of a provider key to administrators (see the AI guide).
- The two nginx configurations send HSTS only when you turn it on, and no `Cross-Origin-Embedder-Policy` (the origin is already
  isolated by `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy` and a CSP with no external source).

## The release gate

The suites ran on the commits of this release. Where a line names a commit, the run is of that commit. After `c636d4b7` the tree changed in
documents and in one test (the redirect test of the S3 copy, which raced under load and is fixed). Rows that name an older commit were
not repeated, and the matrix ran on `a3e1ff9a`: the one commit after it (`c636d4b7`) only adds refusals (a host in audit mode runs no
checks, the S3 test asks for the platform operator in its handler, readers who are not administrators get no access key id).

| Check | Result |
|---|---|
| Test suite, JSON storage (`c636d4b7`) | 19,159 tests, 57 skipped. Red: the two subtests of the AUR check |
| Test suite, SQLite (`c636d4b7`) | 18,784 tests, 148 skipped. Red: the two AUR subtests, and the redirect test of the S3 copy, which failed when three suites ran at once (the server answered a 307 before the client had sent its upload and the client saw a broken pipe). The test reads the upload before it answers now, and passed eight runs at once |
| PostgreSQL tests (`c636d4b7`) | 28 tests, none skipped. The server was PostgreSQL 18.6 and CI runs 16 |
| `make ci-parity` (`c636d4b7`): Python 3.14, the workflow's dependency list resolved fresh, the workflow's runner | 18,858 tests, 371 skipped. Red: the two AUR subtests and the same redirect test |
| Authorization matrix (`a3e1ff9a`) | 1,088 operations, 85,302 requests, 60 runs; no answer to a tenant user held another tenant's id, name or object |
| `make dist` (`5ffc3dc6`): the tarball, its leak check and the suite on the staged tree | 18,305 tests, 88 skipped. Red: the two AUR subtests only. The tarball was built and passed its leak check. Not repeated after the later features |
| CodeQL 2.27.3, Python and JavaScript, the repository's own configuration (`c636d4b7`) | no result |
| bandit against its baseline, `make lint` (`c636d4b7`), gitleaks over the commits since the first batch (`a273939b`..`c636d4b7`) | no issue, clean, no leak |
| semgrep (python, javascript and security-audit rule sets) over the 18 files changed since the first batch (`c636d4b7`) | 5 findings, all in code older than this release (the permissions of files the agent creates, its restart call, one HTML format string); none new. A control file produced its 4 |
| `tools/release-prep.py verify` (`5ffc3dc6`) | 0 failures. Not repeated after the later features |

The two AUR subtests check that the Arch packages are on the last shipped release. They are on 7.4.0 and the last shipped release is
7.4.8, so they stay red until the packages are bumped. They were red in the gates of the earlier 7.4 releases too.

## Not run for this review

- A live probe of a running installation: none was available for this release, so every probe ran against a seeded copy.
- SQLite and PostgreSQL under the hostile-input sweep, and browsers other than Chromium (Safari and Firefox treat a `blob:`
  address's policy differently, which matters for S14).
- Real Windows and macOS hosts, real package managers, and a real container runtime for the agent's container update. The
  PowerShell installers were read, not run.
- The second batch against real services: the S3 copy ran against a store written for the tests that checks every signature, not against
  AWS, MinIO or Backblaze; the checks a host runs for the server ran against local servers and a stubbed `ping`, not on a real host; the
  CPU time shares were read from a real `/proc/stat` on the development machine and not from a Windows or macOS host.
- A latency benchmark of the product. One measurement was taken of the shape check, on a busy machine: it takes 10 ms for a
  1,000-host `devices.json` of 5.0 MB (parsing that file takes 34 ms) and 2 ms for 5,000 alerts. Nothing else is quoted.
