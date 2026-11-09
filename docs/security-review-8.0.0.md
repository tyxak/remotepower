# Security review — v8.0.0

8.0.0 adds a Traffic view, Detections (rules over behaviour), an app finder in the Linux agent, four handshake monitors, a read-only MCP endpoint, automatic container
image updates with a rollback, an Apprise destination and three connectors. This review asked two questions. The first was what each of those can be made to do
that it should not. The second was where a rule the code already had, written down and applied in most
places, was missed in one or two. The second question is the one that found most things, so it was answered with lists made by a script
(every writer of the command queue, every outbound connection, every place that turns text into a number) and with the ratio printed, not with a
reading of the places that looked likely. Every finding below was reproduced and fixed on a seeded copy of the product, not on anyone's
installation.

It found **one High issue, nine Medium issues, eight Low or hardening items and one informational item. Every one of them is fixed.** Nothing rated
Medium or higher is open. Each fix has tests, and each test was run against the code with its fix taken out.

Update the agents for the agent fixes (the agent version is 8.0.0). The server fixes need no action except where [v8.0.0.md](v8.0.0.md) says so.

## What changed that a reviewer should look at

Sixteen routes were added. The route table held 981 entries at 7.5.0 and holds 997 now.

| Route | Who may call it |
|---|---|
| `GET /api/devices/<id>/settings` | an administrator, and the host must be one the caller may see (the check that runs before every host route) |
| `GET /api/devices/<id>/apps`, `POST .../apps/monitor`, `POST .../apps/dismiss` | read: any signed-in role for a host the caller may see; the two writes: an administrator of the installation |
| `GET /api/app-discovery` | any signed-in role, over the hosts the caller may see |
| `GET /api/devices/<id>/traffic`, `GET /api/traffic/fleet`, `GET /api/traffic/config` | any signed-in role, over the hosts the caller may see; the module is off by default and the routes answer 404 until it is on |
| `POST /api/traffic/config` | the platform operator |
| `GET /api/detections` (and `?host=<id>`) | any signed-in role, over the hosts the caller may see; the module is off by default and the route answers 404 until it is on |
| `POST /api/detections/rules` | the platform operator |
| `GET /api/image-updates/auto` | any signed-in role, over the hosts the caller may see (S9) |
| `POST /api/image-updates/auto` | the platform operator, and a fresh sign-in to turn it on |
| `GET`, `POST` and `DELETE /api/mcp` | the MCP module, off by default; `POST` only, the other two answer 405 |

Six things changed what a host, a caller or an outside service can do:

- **The MCP endpoint reads through the same gates as the rest of the server.** A tool call is a request for one of the server's own read routes,
  made as the caller with the caller's own token, and it passes through every check the web server's front door makes. A test holds the list of
  those checks equal to the list in the request handler, so a check added there and not here fails the build. It can only read.
- **Four handshake monitors connect to the address they are given.** SMTP, IMAP, SSH banner and NTP run on the server, on a host's agent or on
  a satellite. The agent and the satellite carry a copy of the server's probe code that a script writes and a test keeps identical, and each
  passes its own address rule when it connects: link-local and cloud-metadata addresses are always refused, loopback only where allowed, and the
  address is checked when the name is resolved and again when the connection is made. Each handshake is tested against real local servers on all three.
- **The Linux agent reads its own connection table once a minute when Traffic is on.** It runs `ss`, adds up what each connection moved by remote
  address, port and program, and sends the 100 busiest rows. It captures no packets and reads no payload. Program names need root. Traffic is off
  until you switch it on.
- **Detections runs rules over data the server already holds and raises alerts.** A sweep every five minutes reads the Traffic records, the activity log and the Threat Intel
  store, writes one store (`detections.json`, a row for each host) and raises an alert for each new finding. It opens no connection and runs no command on a host. A finding is
  read through the caller's own host scope by the page, the host drawer, the Data Explorer, Fleet Query, the risk score, the fleet report and the AI context, and the rules are
  the platform operator's. A sweep raises at most 100 alerts for the whole fleet, the worst first, so one address that turns bad cannot flood an inbox. The module is off
  until you switch it on.
- **Automatic image updates put commands on a host through the gateway every other command uses.** Maintenance mode, quarantine, audit mode and
  four-eyes approval apply to them. The mode is off, shadow (records what it would do) or on; shadow queues nothing.
- **An Apprise destination is a webhook format.** Its key is part of the address, so it is stored, hidden and exported like every other destination
  address (S7).

## How it was done

**Scanners, on the final tree.**

| Scanner | What it covered | Result |
|---|---|---|
| CodeQL 2.27.4 (the version the pinned workflow action uses), Python and JavaScript, the repository's own configuration | the whole tree | no result in either language |
| bandit, against its baseline | 150 files of the server and the agents | no new result |
| semgrep (python, javascript and security-audit rule sets; a known-bad file as a control, which gave three results) | the Python, JavaScript and shell files changed since 7.5.0 (88 read), and then the four largest, `api.py`, the agent, the demo seeder and `app.js`, again with 900 seconds for each rule, because 11 rule runs had timed out on them | 7 results the first time: six on lines older than this release (three file modes and one log line in the macOS agent, a SHA-1 in the demo seeder, one JavaScript `innerHTML` call), and one on a line this release wrote, a SHA-1 that was already declared as not security-related and is SHA-256 now. The second run had no timeout and 17 results on those four files, none on a line written since 7.5.0 (file modes, SHA-1 of values that are not secrets, two XML parser uses, one `shell=True` on a fixed command, one dynamic `urlopen`, one `innerHTML`) |
| gitleaks (history and tree; three planted tokens as a control) | the whole repository | no leak; the control found all three |
| shellcheck | 29 shell scripts | one error and four warnings, all fixed (S17) |
| pip-audit | the 25 Python packages the server and its tests import, as installed | none in a package the product depends on; `mcp` 1.23.3, which only the test client uses, has ten (the product's MCP code is standard library) |
| nuclei 3.3.7 with 11,265 templates (the missing-headers template found 10 headers missing on a bare static server, as a control) | a seeded stack behind the shipped nginx configuration | 13 results, all informational: the server software, no HSTS on plain HTTP and no `Cross-Origin-Embedder-Policy` (both known, below), page text that names products the page integrates with, the `security.txt`, the demo addresses in the page |
| wapiti 3.3.0, all 18 modules in seven groups (CSP, security headers, cookie flags, CSRF, CRLF, redirect, XSS, stored XSS, SQL, blind SQL, SSRF, XXE, shellshock, backup files, dangerous files, htaccess, HTTP methods, command execution), twice: not signed in, and signed in as the demo's administrator from the 79 `GET` routes whose handler reads a query key (read from the list of handlers the matrix built), limited to `/api/` | the same stack | Not signed in: 150 addresses crawled, 30 answering 200, nine form fields, all on the sign-in form, no result; the command execution module did not finish. Signed in: 80 addresses attacked, no failed request in the final runs, and one result: an "SQL injection" in the `error_description` of the SSO callback. It is not one (the answer is the same redirect for every value, and it did not repeat in two of three quiet runs; the scanner read the server's rate limit, a 429, as a difference between its true and false probes) but reading the handler found S18. The methods module listed 33 addresses with interesting methods: `DELETE /api/alerts` and `POST /api/devices/<id>/patch-preview` answer 200 to an administrator, which they are meant to, and the rest answer 404, the router's answer to a method it has no route for. The command execution module finishes now: its rules for the output of `env` take four times as long for each doubling of a page, so the 450 KB index page cost minutes for every probe and the earlier run was not stuck, only slow; a scan limited to `/api/` has small answers |

**Measurements, each with a control that fails when it measures nothing.**

- **Generated tests.** 29 properties (Hypothesis) state a promise of a function over input it was never meant to read, and 23 examples keep
  the inputs it printed. They were run over the Traffic cleaners, the agent's reader of `ss`, the app catalog, the image update policy, the probe
  runner, the MCP endpoint and the Detections rules, and found S6, S11, S12, S14 and S19. Properties are skipped where Hypothesis is not installed (CI), and the examples are not.
- **Hostile requests to the new routes.** 1,904 requests (4 kinds of caller, 33 bodies, 5 query strings, with every module off and then on) to the
  14 routes added since 7.5.0, through the real request handler: no 500, no exception, no request left unanswered.
- **Lists made by script, with the ratio.** The command queue has 30 writers: 12 ask for approval or call a gateway that does, 18 are listed
  with a reason, none is neither, and no module added in 8.0.0 writes it. The outbound connections are 25 in 24 functions (23 in 22 at 7.5.0): 14 name
  an address rule, the other 11 are unchanged and each takes a target the operator names (SNMP, ICMP, WOL, the S3 endpoint, the mail relay) or is a
  constant, and the two new ones have the peer check. The connectors have no connection of their own; they go through one client that checks every
  request address twice and follows no redirect. All 1,744 names the 56 bound handler modules take from the server resolve. The text-to-number
  places are in S13. All eight settings kept by host id are cleared when a host is deleted (S15). The places that matched a row to a host by display name
  were found by syntax tree and by search, and two of them were wrong (S8, S9).
- **A marker in every place that holds a secret.** Seven markers (the Apprise key in a destination address, a header value, four connector keys, a
  basic-auth password in an address) and the operator's notes were put where 8.0.0 stores them, and every surface that sends settings out was read: the
  settings page as an administrator and as a viewer, the support bundle, the backup, the declarative export, the audit lines. One leak, S7. The settings
  page shows an administrator the destination and integration addresses on purpose, and a viewer sees none of them.
- **The authorization matrix.** 1,104 routed operations from the real route tables, 86,638 requests, 60 runs as 26 kinds of caller (the platform
  operator and five other roles, two roles scoped to a group or a tag, five roles of two organisations, eight API keys, three host tokens, a wrong
  token and no token), each against the objects of its own organisation, of the other one and of the default one, and every answer judged against
  the check the handler names. The run was made on a copy of the final server code (`5a414a55`; no file under `server/cgi-bin` has changed since).
  Controls: the platform administrator was answered 2xx by 504 to 567 operations in each run and the anonymous caller by 16; on the 403 operations
  that take an id, a tenant administrator's own objects worked in 118 to 120 and the same call on the other organisation's object was refused
  (403 or 404) in 114 to 115 of them; the scope check refused every host-path operation outside the role's scope (92 of 92 for a group role, 88 of
  88 for a tag role, 14 of 14 for a scoped key, which takes a host out of its own group part-way through the run, so only the calls before that
  were in scope). No request answered 2xx where the handler's own declared gate refuses: of 718 answers that were not a refusal, 251 were 400, 446
  were 405 and 21 were 404 from the MCP routes, which are off in the seed. 58 operations answered some caller with a marker it should not hold:
  12 answered tenant users and 1 a host token (its own scripts), which together are the 13 of 7.4.9 and 7.5.0, on routes that are not new (the
  caller's own input stored and read back, the content of a cloned host, the shared knowledge base); 42 answered only roles or keys scoped to
  groups or tags (see "Known and unchanged"), none of them a route added in 8.0.0; 2 answered the finance role (the operator's time entries);
  and 1, the Home page, answered 12 roles of the operator's organisation with one alert row that carries the matrix's tenant-B suffix. The matrix
  plants three rows for one business service, the service's next alert coalesces into the last of them, and that row then names the operator's
  own hosts (reproduced in process with the sweep: of three planted rows only the last was rewritten, to the service's hosts). No tenant caller
  holds a marker on the Home page any more. Fourteen
  operations answered 5xx or not at all: the three SAML routes (503: the library is not installed), key generation (500: gpg could not run in the
  namespace), two scans that reach out to the network (cut off by the network namespace), the monitor list, and seven operations that waited
  longer than the harness's 25 seconds in one run each (the export in three) while the machine was also running the browser suites; the SAML
  login route did the same once. In the other 46 to 59 runs each of those seven answered in under 3.5 seconds, the export in up to 22 and the
  bulk collect in up to 17. Asked alone on a seeded stack, the monitor list answers in 11 seconds the first time, which runs the sweeps that
  have fallen due, and in 0.2 seconds after that; it got no answer in 17 of the 47 runs that ask for it.
- **An upgrade.** A data directory written by 7.5.0 (146 files) was served by this version: sign-in worked, 296 `GET` routes that take no parameter
  answered 263 times 200, 13 times 400, 3 times 401, 3 times 403, 12 times 404 and twice 503 (the two SAML routes, which answer 503 when SAML is
  not set up), never 500. A heartbeat from a real 7.5.0 agent was accepted by this version's handler on that data.
- **Another browser.** Firefox 150.0.2 (the Playwright build) opened each of the 85 sidebar pages of the seeded stack, signed in, at 1440 and at 390 px, and Chromium did the same as the
  control. Firefox showed no console error, no uncaught page error, no failed request and no horizontal overflow, and every page drew its root. The only responses of 400 or more were three
  502s that the demo's integrations to services that do not exist give, the same in both browsers. Chromium also logs those as console errors and reports a poll that the app cancels when
  the page changes (`net::ERR_ABORTED`); Firefox does neither. WebKit was installed and does not start on this system: the Playwright build needs five libraries of Ubuntu's versions
  (ICU 74, libjxl 0.8, libxml2.so.2, flite and libbacktrace), so there is no result for Safari's engine.
- **Speed.** Start-up, the host list, Home, Needs attention, the fleet query and a heartbeat with a real 151 KB agent payload, at 500 hosts, on JSON
  and SQLite: within 2 percent of 7.5.0 on both.

## Fixed in 8.0.0

| # | Severity | Where | What was wrong | The fix | Held by |
|---|---|---|---|---|---|
| S1 | High | web page, host drawer | The settings form under Actions & settings read nine fields the host list never carries. Changing only a host's group posted them empty, and the save treats an empty list as a clear: the host lost its command allowlist, its watched units and files and its log rules, and an agentless host lost its SSH mode, user and port | the page asks `GET /api/devices/<id>/settings` and stays read-only, with a line that says why, when the answer does not come | test_v800_drawer_settings, test_v800_drawer_settings_e2e |
| S2 | Medium | server, command channels | Run command on an SSH host, the Ansible run and the web terminal ignored quarantine and maintenance mode, which the command queue and the SSH gateway honoured | all ask the one rule the queue asks, and a test lists the channels by syntax tree | test_v800_direct_exec_gates |
| S3 | Medium | server, AI executor | Three readers took the script library, a list inside a map, for a map of scripts: the executor could not propose a saved script, the re-check when an approved proposal runs could not find one, and an approval row named none | the three use the helpers the others use, which also limit the answer to the scripts the caller may see | test_v800_ai_exec_scripts |
| S4 | Medium | web page, CSV exports | The two CSV builders in the page did not quote a cell that starts with `=`, `+`, `-` or `@`, so a program or host name sent by a host ran as a formula when the file was opened | the rule the server's exports have; a test runs the real function with hostile cells | test_v800_csv_formula_guard |
| S5 | Medium | server, app finder | One damaged or hostile container report (`²` as a published port) made the Integrations list, the Data Explorer apps entity and the Fleet Query app criterion answer 500 for every user | digits are read as ASCII only | test_v800_ascii_digits |
| S6 | Medium | server, Traffic | A stored connection row that was not a row (a SQL backend gives a record back as it was written) made the host page, the fleet view, the Data Explorer and Fleet Query answer 500 for every user until it was deleted | the readers check the type of each field | test_v800_found_by_properties, test_v800_properties |
| S7 | Medium | server, declarative export | The export, whose note says it is safe to commit, held a webhook destination's header values (an `Authorization` or `X-API-Key` credential, likely on an Apprise destination) and its Pushover user in plain text. 6.4.2 hid them in the support bundle and the backup and missed this third surface | the names stay; the values are masked, or ciphertext that an import restores when a config key is set, and when the crypto library is missing the export falls back to masked (the destination address too) | test_v800_declarative_headers |
| S8 | Medium | server, compliance evidence | A fleet event counted as yours when its host id was yours or its name was one of yours, so another organisation's new port, SSH key or brute-force event for a host with the same name went into your evidence | by id; an event with no id is still matched by name | test_v800_name_collision_scope |
| S9 | Medium | server, image updates | The last run's held rows were matched to your hosts by display name, so another organisation's compose directory and image names showed on a host with the same name, and the count of updates made was the whole installation's | the run keeps host ids; you get the rows and the count of your own hosts | test_v800_image_autoupdate, test_v800_name_collision_scope |
| S10 | Medium | server, Home page | The Home page's summaries are built from stores that are not keyed by host. A tenant's administrator or viewer was answered with the whole installation's: every open alert by severity, the monitors, the VPN totals, the backup jobs and their stale checks, the fleet checks roll-up, and the list of integrations with their labels, versions and the addresses in their error texts (the routes that give a tenant these answer 403 since 7.4.9). The checks roll-up also filled the 15-second cache of every host with the first caller's own narrow view | the monitors, the VPN totals and the integrations are the operator's and are not built for anyone else; the alert, backup and checks figures count what the caller may see; the cache is filled from the whole fleet | test_v800_home_widgets_scope |
| S11 | Low | server, MCP endpoint | A tool that met an answer it did not expect raised out of the endpoint: HTTP 500 and no result | a failed tool call that names the exception | test_v800_found_by_properties |
| S12 | Low | server, app catalog | `describe()` of an id that was a list raised | answers none for anything that is not text | test_v800_found_by_properties |
| S13 | Low | server and agents, 17 places | Text checked with `isdigit()` and then given to `int()`, which refuses the superscript two: a 500 where a 400 was meant (a port of the watch list, a cidr, a query value, an object id, a cron field, a JSON path, a probe's status, the log length the server sends an agent) and "error" for "not SMTP" | ASCII only. 17 places in 14 functions (a function and its copy in an agent or the satellite count apart; S5 is the worst of them) were found by reading every `isdigit()`; 12 more places in 11 functions read the output of a tool and are listed with the reason | test_v800_ascii_digits |
| S14 | Low | Linux agent | The reader of `ss` took any text `isdigit()` accepted for a port, in the new reader and in the older reader of peer connections | ASCII digits from 0 to 65535 | test_v800_properties, test_v800_found_by_properties |
| S15 | Low | server, deleting a host | The purge cleared four of the eight settings kept by host id and left the patch alert flag, the disabled checks, the DNS result and the hidden apps | all eight; the list is read from the code | test_v800_purge_config_maps |
| S16 | Low | server, sign-in | Five places chose between http and https and no two read `X-Forwarded-Proto` alike; capitals or a list made the passkey origin one the browser never matches | one reading of the header's first entry | test_v800_request_scheme |
| S17 | Info | server, `rp doctor` | A test for a database file used a pattern that answers no when two files match; shellcheck found it and four warnings | fixed, and error level is held | test_v800_shellcheck |
| S18 | Low | server, SSO sign-in | The public OIDC callback wrote the `error` and `error_description` of its query string to the error log as they came, so a line break in either started a line of its own and anyone who could reach the server could add a `[remotepower] ...` entry. A scanner reported the route as an SQL injection (it is not); reading the handler found the log line | both go through the two log helpers the heartbeat already used: control characters and line separators become `?`, the code is cut to 80 characters and the description to 240 | test_v800_oidc_callback_log |
| S19 | Low | server, Detections | A record of a damaged or restored store could stop a rule for a host or break the page: a Threat Intel score of infinity or of 400 digits raised in the known-bad rule, `NaN` in a byte count made the answer invalid JSON for the browser, rows or events that were a number raised in every rule, and a port or an address that was not one was kept as it came. Generated records found them. Nothing a host sends reaches these fields unclean (the Traffic cleaners stop it), so it took a damaged store | a score that is not finite or is too large for a float reads as none, a port outside 0 to 65535 is left out, addresses and program names are cut at 64 characters, every fact kept with a finding is a finite number or text, and rows or events that are not lists read as empty | test_v800_detections_found_by_properties, test_v800_detections_properties |

## Open

Nothing rated Medium or higher is open. These are smaller, and none of them is a way to attack an installation.

- **Translations.** No native speaker has read the strings added in 8.0.0, in any of the six languages. German, French and Spanish were read in full by the assistant that wrote the release
  against the existing glossary, Chinese, Hindi and Arabic as a sample of 36 entries, and the read corrected 117 texts (informal forms, the Settings page named with a word the menu does
  not use, a few terms). Register (Sie, vous, usted) and the word for the Settings page are held by tests; wording is not. A sheet per language with every changed entry is ready for a reviewer.

## Not found

- **A way for a new route to reach another organisation's data.** The handlers were read by script (which check each one names) and driven as a
  tenant administrator, a viewer and the platform operator. The two places that matched by name are S8 and S9.
- **A secret in the repository or its history.** gitleaks found none; a planted token was found by the same command.
- **A new outbound connection without the address check.** See the list above.
- **A new writer of the command queue that does not ask for approval.** 30 writers, none neither asking nor listed.
- **A slower heartbeat, host list, Home or fleet query.** Within 4 percent of 7.5.0, measured again at 500 hosts on both backends after Detections (the heartbeat 432 to 441 ms on the file
  backend and 9.2 to 9.5 on SQLite).
- **A Detections route that answers a hostile body with a server error.** The rules route was driven with 24 bodies of the wrong kind (a list, a number, a boolean, a number with
  four hundred digits, a NaN, a key of 100,000 characters, nested lists) as three callers with three methods: 200, 400, 401, 403 and 405 only.

## Known and unchanged

- A fully compromised server is root on its agents, by design (see the threat model).
- **A deleted host's history stays.** Deleting a host removes the data kept for it, the schedules and mutes that name only it, and its place in groups, services and links
  (see [data-retention.md](data-retention.md)). Alerts, tickets, time entries, the audit trail, command history, receipts and gateway sessions keep its id, because they say what
  happened; 25 of the 149 stores of the demo instance still name a deleted host for that reason, and each is listed with its reason in `tests/test_v800_host_purge.py`. The audit
  trail is append-only on purpose. A ticket or a time entry can be deleted by hand.
- **The knowledge base is the operator's shared library.** Every signed-in user reads every article; the hosts an article points at are filtered to the
  ones the reader can see (7.4.9). A tenant that wants its own articles has none.
- **A role scoped to groups, tags or sites limits what a user can change, not what they can see.** Give a person who must not see other hosts a
  tenant (see the 7.4.9 review).
- **Traffic's watch list and sampling interval belong to the installation.** On an installation with tenants, everyone sees the matches on their own
  hosts, and the entries, their notes and the alert text that names them stay with the operator.
- **On the JSON file backend, Traffic rewrites its file for each report.** It costs about 80 milliseconds with 50 hosts and 340 with 200; SQLite and
  PostgreSQL write one row. The Traffic guide says so. It is off by default.
- The two web server configurations send HSTS only when you turn it on, and no `Cross-Origin-Embedder-Policy`.
- **A container image is pinned by tag, not by digest, in the Dockerfiles.** A release build takes the current patched `python:3.14-slim`.

## The release gate

The gate ran in two passes. The first was the steps of `make pre-release` run side by side on `6ac3a1d0`, the commit that carried the first version of
this review, from 00:29 to 03:11 on 2026-11-09, with the browser and PostgreSQL tests required. It found eleven problems in tests and two in the page,
listed below. The second pass ran on `cc33217b`, which fixed them, and the three small commits after it (`eb7a2047`, `2bdb7128`, `171e5d46`). It is a
set of runs and not one run of everything on one commit; the commits after `cc33217b` touch one line of the server, which binds a name, and tests.

Later commits changed more: a deleted host takes its own data with it (`host_purge.py`), the public SSO callback writes its query string as one log
line (S18), 117 translated texts were corrected, the demo's seed opens in Pilot and B612 for its own directory and has a Timesheet entry dated
today, and the Traffic view moved from the Network page to the Threat Intel page. Each was checked with the test files it touched and the modules
that read what it changed; for the Traffic move that was 434 modules without a browser (10,301 tests) and 22 browser modules (217 tests), and all
passed. The authorization matrix ran again for every caller on the last server code (see "The authorization matrix" above). The whole gate was not
run again on the last commit: the suites on JSON and SQLite, the browser modules, CodeQL, the CI-parity run and the suite on the staged tarball.
It has to run before this version is released.

| Step | Result |
|---|---|
| Test suite, JSON storage (`6ac3a1d0`) | 22,473 tests, 57 skipped; 27 failures and 9 errors in 12 modules, all listed below |
| Test suite, SQLite (`6ac3a1d0`) | 21,522 tests, 191 skipped; 29 failures and 10 errors in three test files |
| `make lint`: isort, black and mypy over 45 source files, ruff in two passes | no finding |
| PostgreSQL tests (the server was PostgreSQL 18.6; CI runs 16) | 28 tests, none skipped, all pass |
| `make dist`: the tarball, its leak check, and the suite on the staged tree | no forbidden path; the suite: 22,473 tests, 90 skipped, 45 failures and 9 errors (the JSON ones, and the shellcheck test, which listed no script in a staged copy) |
| `make ci-parity`: Python 3.14, the workflow's dependency list, the workflow's runner | 21,673 tests, 522 skipped, 1 failure (the seeder test) |
| bandit against its baseline | no issue outside the baseline, and none rated High |
| CodeQL 2.27.4, Python and JavaScript, the repository's configuration | no result in either language; the preview that also reads the tests lists the reviewed classes (1,332 Python results, 18 of them in tests, none in JavaScript) |
| Second pass: every module without a browser (1,119), on JSON and on SQLite | 21,399 and 21,352 tests; two failures in each, both of this round's making and both fixed: a source check that read a new name as a write through a shared object, and a clock taken when the module was imported |
| Second pass: every browser module (99), four at a time | 1,080 tests; 95 modules passed. Four failed under that load: the SMTP and the integration wizard passed alone on the next run, and the six-language title check of two wizards and the branding dialogs were hardened and passed three whole-module runs each |
| Third pass: the authorization matrix, every caller, on the last server code (`5a414a55`) | 60 runs, 86,638 requests (see "The authorization matrix" above) |
| Second pass: hostile requests to the 14 new routes, on the final code | 1,904 requests, no 500, no exception, nothing left unanswered |

The first pass found these, and none of them was a way in. In tests: two files wrote the stores as files, which a SQL backend never reads; a seeder
test compared the seed's clock with the time at the test, and a full run reaches it minutes after the seed was built; a browser test hard-coded the
server version; two wizard tests flagged a French word that is the English one; the shellcheck test listed no script in a staged copy; the page
sections walker read a tab that a lazy module fills at once; the Timesheet test fails on a Monday, because the demo's entries are dated 1 to 9 days
ago; the monitor table test assumed the two monitors probed by a host sit on the first page of 15, which four new monitors changed; and a branding
dialog test lost a click to a redraw. In the page: the top bar's breadcrumb, which the tablet fix let shrink below "Dashboard" at the 200% text size
(the narrow rules now apply below 1290 px), and the shared host list, which could hold an error answer, so the Cron, File manager and App Catalog
pickers threw when every request failed. The accessibility sweep failed 34 and 18 subtests under load and passed 10 of 10 alone on the same commit
and again after the fixes.

## Not run for this review

- The whole gate on the last commit (see "The release gate").
- A live probe of a running installation: none was available for this release, so every probe ran against a seeded copy.
- Real Windows and macOS hosts. Traffic, the app finder, the rollback and the Suricata readers are Linux only; the other agents were changed for
  one declared key.
- Real services behind the integrations: the UniFi, Tailscale, Headscale and Cloudflare connectors ran against stand-ins written from the vendors'
  published descriptions. An Apprise server was not run. The Suricata readers ran over captured log samples, not a live sensor.
- Safari's engine: WebKit does not start on the machine the checks ran on (see "Another browser"). Firefox and Chromium were run.
- A latency benchmark of the product beyond the speed comparison above.
