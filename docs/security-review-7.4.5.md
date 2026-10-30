# Security review — v7.4.5

7.4.5 was folded into 7.4.6 before it was released. This review covers the part of 7.4.6 that came from it.

7.4.5 answers one request (#55): an administrator can mark a host as internal, so a service that
listens on every address is graded as reachable from the local network instead of from the world.
That is a new way to quiet an alert for one host, so the review looked at who may set the switch,
what a host can make the server do by what it reports about its addresses and ports, what the pages
and the assistant print from those reports, and what a lowered grade does to the alerts that follow
it. This review covers everything that changed since 7.4.4, the last reviewed release: 23 server,
agent, page and packaging files with about 560 lines added, and the tests and documents that go with
them. The scans ran over the whole project, and the reading went to what changed and to the places
where a rule the product already follows might have been missed.

It found **two** issues worth reporting. Both are low, and both are fixed in 7.4.5. One came from the
new route and one was older than this release and came to light because the new tests read the pages
the release changed with stored values the code does not write. Neither came from the field. Each fix
has tests, and each test was run against the code with its fix taken out.

## What changed that a reviewer should look at

- **The Linux agent.** It sends the addresses the host holds, from `ip -j addr`, a call with a fixed
  argument list and no shell that it already makes for the interface list. It reads no new file. The
  Windows and macOS agents changed only in their version, and send no addresses.
- **The report.** The server keeps the addresses only as a list of at most 64 entries, each written
  back from a parsed address, and drops the whole list when anything in it is not an address. After
  the fields an agent leaves out as unchanged are merged back, and before the record is stored and
  handed to the port audit, it grades the host's listening sockets by one rule. A host never reports
  the grade or the switch: the mark that says a socket was graded by the switch is derived there and
  dropped from anything a host sends.
- **Routes.** `GET` and `PUT` on `/api/devices/<id>/exposure-internal` are new. The Exposure page's
  answer carries `assumed` on each socket, a count of them and a map of the hosts that are marked,
  with why a mark does not hold. The Checks row for world-exposed ports says how many services it is
  not warning about.
- **Alerts.** The port audit reads the graded sockets. Marking a host closes its open world-exposed
  alerts at its next report, and a marked host that gains a public address raises them again. A new
  listener is reported as before.
- **The assistant.** A host's summary in the knowledge the assistant searches now carries its
  addresses and whether it is marked internal. At chat time the assistant sees an address only when
  the install sends addresses.
- **The page.** The Exposure page and the Ports card of a host print the host's strings in new
  places: a reason line, the arguments of the buttons, the scope label, and the text of a
  confirmation.
- **Not changed.** No file under `.github`, `server/conf` or `docker`, no installer, no package
  recipe and no list of dependencies differs from 7.4.4. The one packaging file that changed is the
  demo data seeder.

## How it was done

| Method | Scope | Result |
|---|---|---|
| Read against the threat model | Everything above, then each place a rule is meant to apply: who may set the switch, who may read a host's addresses, what a host can make the server keep or do, what the audit trail says, what is printed where | Two findings (below), and the places listed under "Not found" |
| Lint (`make lint`: isort, black, mypy, ruff `F` and `E9`) | The type-checked modules, the agents, the sidecars, the tools, the tests and the packaging | Clean, once black had reformatted the new module and one line of the Checks row |
| bandit | 134,941 lines of server and agent Python, against the committed baseline | 0 High, 24 Medium and 920 Low. Nothing is new against the baseline. The two extra Low are the agent's new `ip -j addr` call (the same call, with a fixed argument list and no shell, that `get_network_info` has made for years), and the two new Python modules have no finding |
| semgrep | The Python, JavaScript and security-audit rule sets over the 12 server, agent, page and packaging files that changed, with the per-rule timeout raised to 120 seconds | 21 results, none on a line this release added or changed, and the same 3 timeouts on `api.py` as in 7.4.4 |
| gitleaks | Every commit (2,471) and the unpacked release tarball | No leaks |
| Dependency audit (`pip-audit`) | The 26 packages the server and agents import or pull in, at the versions installed here, among them Flask 3.1.3, Werkzeug 3.1.9, pydantic 2.14.1, cryptography 50.0.2, psycopg 3.3.6 and requests 2.34.2 | No known vulnerabilities. No dependency changed in 7.4.5 |
| CodeQL | The repository's own configuration, as the production workflow runs it, for Python and JavaScript | 0 results. The raw output holds 687 (686 in Python, 1 in JavaScript), all in the six rule classes the configuration scopes out as reviewed false positives, and none on a line this release added or changed |
| nuclei | 6,613 templates (exposure, misconfiguration, tokens, default logins, XSS, SQL injection, file inclusion, redirects, CORS, SSRF, traversal, technology detection and the generic checks; the denial-of-service, fuzzing and brute-force ones left out) against a seeded server | 17 informational results, the same as on 7.4.4 and none about the release: the file server of the test setup sends none of the security headers that nginx sends (10), technology fingerprints (4), an upload form, a `security.txt` and an address on a page. The control template for the headers matched 10 times, so the scan did look. The file server logs a traceback for a request with a NUL byte in its path; that is the test setup's server and not the product's |
| Who may do what | The new route as eight callers with tenancy on: the platform operator, the administrators of two tenants, a viewer, a role holding every action permission, an auditor, an MCP role and a finance role. Each call was followed by a look at which host's switch had changed | Only the platform operator and the administrator of the host's own tenant changed a switch, and only on hosts they may reach. The viewer, the all-permissions role, the auditor, the MCP role and the finance role got 403 on every write, and 403 on a read of a host outside their tenant. A `DELETE` on the route never reached the host |
| What each caller sees of the Exposure page | The answer for the same eight callers, with a marked host in each tenant | A tenant sees its own sockets, counts and marked hosts and no other tenant's, and the public address of one tenant's host is not in the other's answer |
| A write from another origin | The route with a foreign `Origin` header | 403, and 200 with the same origin |
| Hostile input to every route | The 869 `GET`, `POST`, `PUT` and `PATCH` operations of the OpenAPI document on a seeded server with tenancy on (867 on the 7.4.4 tree, the two new ones are the new route's `GET` and `PUT`). With no session: 821 requests (the 46 that sign out, change a password, restart, restore, import and the like were left out). Reads as the platform operator, a viewer and a finance user. Writes as the platform operator with eight bad bodies each (empty, a list, null, a string, a number, and every property of the schema set to a list, a dictionary or an integer too large for a float). 5,452 requests in all, against 5,439 on 7.4.4 | 17 answers of 5xx, the same 17 as on 7.4.4: the three SAML routes, which answer 503 because the library is not installed here. 1,606 answers of 2xx (1,601 on 7.4.4), so the sweep reached the routes. No route answers 5xx on this tree that did not on 7.4.4 |
| Hostile input to the new route | 18 host ids (path traversal, an encoded dot, 5,000 characters, a NUL byte, a right-to-left mark, an emoji, a second path) with each of 5 methods, and 17 bodies (empty, broken, null, a list, a string, deeply nested, 100 KB, other types of the one field) in 3 content types, 8,744 requests in all with the other sections of the run | No 5xx and no failed transfer. After the fix described below, 45 of the 51 bodies answered 400 and the 6 that said true or false answered 200 |
| Hostile heartbeats | A host's own token, 46 reports through the real handler over HTTP: 26 lists of addresses (markup, 100 KB, a NUL byte, a network written with a mask, an integer too large for a float, NaN, 65 entries, an address with a scope that holds markup, 6to4), 9 hostile rows, a report of 499 rows, 8 shapes of the field that lists what to merge back, a partial report and one that claims the switch. After each, the stored rows were checked | All answered 200. Stored rows kept their five keys and the mark, the scope was one of three words, no address was stored that did not parse and print as written, nothing over 64 addresses or 80 rows was kept, the mark appeared only on a socket the rule would have marked, and a report never changed the switch |
| A race | Three threads toggling the switch and three sending heartbeats on one host for 25 seconds: 5,529 toggles and 2,934 reports, then one more report. The committed test runs a shorter one | No 5xx and no refused write. The stored rows and the switch agreed afterwards |
| Stored values the code did not write | 432 combinations of a switch that is not a boolean, an address list that is not one, and sockets whose mark or scope is not what the ingest writes, read by the Exposure answer, the route, the Checks row, the risk score, the assistant's knowledge and the rule | No error from any reader of the new fields. Two older readers did raise, on a port list that is not a list or a row that is not a map (see finding 2) |
| Planted text in a real browser | A host's name (one that breaks out of an attribute), the process and bind address of its sockets, an entry of its address list that is no address and a scope that is no word, each holding an image tag with an `onerror` or an svg with an `onload`, then the Exposure page, the confirmation of the button and the Ports card of three hosts | Nothing ran, no element was made, and the text was on every page as text. Printing the text raw at each of 8 places made the browser tests fail at each |
| The assistant's view of the addresses | The knowledge text of a host holding two IPv4 and two IPv6 addresses through the redaction used at chat time | None of the four reaches the assistant when the install does not send addresses, and all four do when it does. Taking the IPv6 redaction out made the test fail |
| Mutation checks | Each new test run against the code with its guard taken out: 53 changes, among them the check on the body (3), the tenant filter, the admin check, the agent reporting the mark, the addresses stored raw, the list guard, a truthy switch, the IPv6 redaction, the order of the grade in the ingest (2), a heartbeat that drops its grade, the grade by the risk score and by the advisory (2) and the escaping at 8 places on the pages | All 53 were caught. One slipped at first and was closed: the first planted name held no quote, so the argument of the unmarked host's button looked safe without its escaping |
| PostgreSQL | The storage suite against a real PostgreSQL 18.6 started for the purpose | 28 tests pass. The switch lives in the host's record like the 7.4.3 container lines, and the new server tests also pass on SQLite |

The nginx scanners (nmap, nikto and wapiti against the shipped configuration) were not run this
time. 7.4.5 did not change the web server configuration: no file under `server/conf` or `docker`
differs from 7.4.4.

## Summary

| # | Finding | Before the fix | Where |
|---|---|---|---|
| 1 | A request to the new route that did not say what it wanted turned the switch off | Low. An empty body, a broken one, null or a list answered 200 and removed a host's mark. It fails closed, since off is the safe side, but a request that does not say what it wants must not change a host's grade, and a proxy that mangled a body would have raised a world-exposure alert for every wildcard socket of the host | `exposure_scope_handlers.py` |
| 2 | The Exposure answer and the Checks row raised on a stored port list that is not a list of maps | Low, and older than 7.4.5. The agent's report can never produce one, so only a hand-edited or imported store reaches it, and it takes the page down for the whole fleet (the Exposure answer) or the host (the Checks row) | `api.py`, `checks.py` |

**Finding 1** is fixed by reading the body again and answering 400 ("The internal setting must be
true or false", in the six languages) unless `internal` is the JSON value true or false. A body that
is no object is still refused by the shared check. A refused request changes nothing and writes
nothing to the audit trail. The tests hold the refusals for 12 bodies and a 200 for true and for
false, and they were run with the check taken out, with only false refused and with any truthy value
accepted.

**Finding 2** is fixed by skipping what cannot be read: a port list that is not a list, a row that
is not a map and a scope that is not a word. The other readers of a host's ports (the AI flags, the
fleet query and the advisory) have the same gap and were not changed; see below.

## Not found

- **The switch cannot be set across tenants.** With tenancy on, a tenant administrator sets and reads
  the switch of the tenant's own hosts and is refused for another tenant's before the handler runs.
  A viewer, an auditor, the MCP role and the finance role cannot set it, and neither can a role that
  holds every action permission, because the route is for an administrator only, the way a host mute
  is. A host's own token reaches nothing of another host.
- **A host cannot set its own grade.** The switch is read from the stored host and never from the
  report. The mark on a socket is derived, so a report that carries it is not believed, and a socket
  that the agent itself graded as local or LAN never gets one.
- **A report cannot make the heartbeat fail or the server keep more than a bounded amount.** A
  hostile list of addresses or rows answers 200. At most 64 addresses and 80 sockets are kept, and a
  list with an entry that is not an address, or with more than 64, is dropped whole and read as
  "the agent did not say", which keeps the sockets as the agent graded them.
- **An address cannot carry markup.** What is stored is written back from the parsed address, so a
  string that is not one is not kept, and the page prints what it does show as text.
- **The grade does not go stale.** It is applied after the fields an agent leaves out are merged
  back, so a host that leaves its ports out still has them graded by its current switch and
  addresses, and a public address in a report ends the grade at once. The order is pinned by a test
  that reads the ingest, and by two tests that drive it, and moving the grade fails all three.
- **A mark does not outlive its reason.** A public address, an agent that stops reporting addresses,
  or taking the switch off puts the sockets back to what the agent said, the page names the cause,
  and the port audit raises the alerts it would have raised for a newly opened port.
- **The pages print the host's text as text.** The Exposure page, the confirmation of the button and
  the Ports card show planted markup as text. Taking the escaping out at the 8 places that print a
  host's string made the browser tests fail at each.
- **The assistant does not see the addresses unless the install sends them.** The redaction used at
  chat time masks IPv6 addresses as well as IPv4 ones.
- **The audit trail names the change and not the addresses.** A change writes one entry with the
  host, the new state and whether the mark holds; a request that changes nothing, and a refused one,
  write none.
- **The race is safe.** The route and the heartbeat both change the host under its lock, and the
  grade is applied inside it by both.

## Known and unchanged

- A host is believed about itself. A compromised agent can report only private addresses to keep a
  grade an administrator gave its host, as it can already leave a port out or report a socket as
  local. It cannot do that for another host.
- The switch lowers a host's grade, and an administrator, or the administrator of a tenant for its
  own hosts, can use it to quiet a host. That is the purpose of the switch, the same as a host mute.
  It is audited, and marking a host closes its open world-exposed alerts at its next report.
- The other readers of a host's listening ports (the AI flags, the fleet query and the advisory)
  still raise on a stored port list that is not a list. Only a hand-edited or imported store holds
  one.
- The Windows and macOS agents send no addresses, so marking such a host changes nothing, and the
  page says so.
- A containerized agent reports the addresses of the network it runs in. The shipped compose file
  runs it on the host's network, so they are the host's.
- The agent runs `ip` by name, as it already did for the interface list, and bandit reports it as a
  Low.
- Settings are one store for the whole install, and every signed-in role can read its non-secret
  keys. With tenancy on, that includes the host identifiers behind the exposure mutes, the labels and
  bound hosts of integration instances, and the container exclude list. Secrets are withheld. The
  switch of this release is a field of the host and not a setting, and it is read through the host's
  own routes, which a tenant reaches for its own hosts only. A settings view per tenant would be a
  design change and is listed for the maintainers.
- The unit that the quick-install script writes gives the agent no private `/tmp` and no read-only
  view of the kernel tunables and the control groups, which the unit that `install-client.sh`
  installs does. The Windows installer still builds its CA address from the host with the port cut
  off. Neither was touched in 7.4.5.

## Left for the release gate

Run on a copy of the tree at 49f88946, which holds all the server, agent and page code of the
release. The commits after it add this document with its pins, the changelog entry, the release
notes, the card and the date. The suite on JSON, 16,978 tests, and on SQLite, 16,731 tests. Both
pass except `test_v643_aur_tracks_release` (two subtests), which compares the AUR packages with the
newest dated release in the changelog. It goes red the moment the header carries a date and stays
red until the AUR packages are bumped, and that bump needs the checksum of a published tarball, so
for a release that is not published it is red by design. The suite ran once before, on 4f5b514d,
which lacks the 400 on the new route and the guards of the two older readers: SQLite 16,717 tests,
the same two failures; its JSON run was stopped part-way when this one started. The PostgreSQL suite
(`tests.test_pg`, 28 tests) ran against a real server and passes; it was PostgreSQL 18.6 here, and
CI runs 16. `make lint` (isort, black, mypy and ruff) and `make bandit` are clean, and
`tools/release-prep.py verify` reports 0 failures.

Not run for this release: a live probe of the maintainer's own instance (it needs a one-time
token), the nginx scanners (above), the SAML routes (the library is not installed here, so all
three answer 503), the run with Python 3.14 and the CI dependency list (it belongs to
`make pre-release`, which cannot finish on a dated header while the AUR packages trail it), and a
native read of the new translations.
