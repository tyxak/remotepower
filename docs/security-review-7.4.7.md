# Security review — v7.4.7

7.4.7 answers two reports (#56 and #57) and carries the Thermal, Disk and Host metrics work that was built after 7.4.6. The
new part is one list of problems that joins Alerts, Needs Attention and Checks, with a history and the actions that apply
to each problem; a switch that decides which CVE findings the numbers count; and the pages that show them. This review
covers everything that changed since 7.4.6: 29 server, page and packaging files with about 2,400 lines added, and 35
files of tests and documents. The agents, the web server configuration, the container and package files and the installers
did not change.

It found **one** issue worth reporting. It is low, it is fixed in 7.4.7, and it sits in five readers: one in the new code and
four older. Each fix has tests, and each test was run against the code with its fix taken out.

## What changed that a reviewer should look at

- **Two new routes.** `GET /api/problems` returns the list, with a state for each problem, and `GET /api/problems/history`
  returns what happened to one problem. Both only read. Every action on a row (resolve, mute, snooze, ignore, switch a
  check off, fix) calls a route that already existed, with the permission that route already asked for.
- **The state on the older pages.** `GET /api/alerts` always adds `problem_state` to the alerts it lists. `GET /api/attention`
  and `GET /api/checks` add `problem` only when the request says `?problems=1`.
- **The CVE count option.** `cve_count_fixable_only` is a new setting, off by default, that decides which findings the sidebar
  badge, the severity tiles, Needs Attention, the risk score, Checks, the scheduled digest and the Fleet query count. The badge,
  Needs Attention and the digest count monitored hosts only.
- **Thermal, Disk and Host metrics.** The heartbeat keeps a temperature history for every sensor a host reports, not only the
  hottest, and notes when a host last reported its cpu, memory and disk figures. The Disk views fold mounts that are one
  filesystem into one entry.
- **The pages.** A new Problems page, a bar that links Alerts, Needs Attention, Checks and Problems, a tag beside an item or a
  check whose alert someone resolved, and a sidebar that no longer covers the left edge of a page while alerts are open.
- **Not changed.** No file under `client`, `server/conf`, `docker` or `.github`, no installer and no package recipe differs
  from 7.4.6. The Makefile gained two module names in its lint lists.

## How it was done

| Method | Scope | Result |
|---|---|---|
| Read against the threat model | Everything above, then each place a rule is meant to apply: who may see a host, what a host may leave on itself, what a stored row may do to a reader, what a name or a path may do to a page | The finding below |
| Lint (`make lint`: isort, black, mypy, ruff `F` and `E9`) | The type-checked modules, the agents, the sidecars, the tools, the tests and the packaging | Clean |
| bandit | 136,519 lines of server and agent Python, against the committed baseline | 0 High, 24 Medium and 923 Low, the same counts as 7.4.6. Nothing is new against the baseline |
| semgrep | The Python, JavaScript and security-audit rule sets over the 21 server, page and packaging files that changed, with the per-rule timeout raised to 120 seconds | 13 results in 3 files: SHA-1 where `usedforsecurity=False` is set or the protocol needs it (4), `chmod` on directories the service owns (4), the import of an XML writer (2), a fixed HTTPS host (1), `shell=True` on a fixed command (1) and the table renderer's `insertAdjacentHTML` (1). Each was annotated or reviewed in an earlier release, and none is on a line changed since 7.4.6 |
| gitleaks | All 2,479 commits and the tree | No leaks |
| Dependency audit (`pip-audit`) | The 11 pinned requirements of the server, with their dependencies | No known vulnerabilities |
| CodeQL | The repository's own configuration, as the production workflow runs it, for Python and JavaScript | 0 results in Python and 0 in JavaScript |
| Who sees what, over HTTP | A seeded instance with 18 hosts. With tenancy off: an administrator, a viewer, a user whose role is scoped to one group and one scoped to one tag. With tenancy on: the platform administrator, a tenant administrator, a tenant viewer and a viewer of the default tenant, with three hosts in the tenant. For each user, `/api/problems`, the history of each of the 117 problems, the inbox, Needs Attention, Checks and the Fleet query, and a call of the badge | Every user got their own hosts and no others. The history of a host outside a user's reach was empty. Six interleaved rounds of the plain and the `?problems=1` calls, as administrator and as the narrowest user, never gave one caller another's rows, and the plain calls never carried the new field |
| Hostile parameters to the new routes | 9 parameters (`state`, `source`, `device_id`, `q`, `days`, `limit`, `offset`, `family`, `detail`) with 29 values each (NUL, a path, markup, SQL, a template, a log lookup, 5,000 characters, a negative number, `1e999`, `NaN`, 40 digits, full-width digits, a right-to-left mark, a bad percent escape) and 8 repeated or array forms, on both routes, as the administrator and as the narrowest user | 520 answers of 200 and 18 of 400 on each route in each of two runs. No server error. Nothing is reflected into the page: the history route repeats `device_id` and `family` in its JSON body, which is not markup |
| Methods and sessions | Every verb on both routes, no session, a wrong token, an empty token and a token with a NUL | 401 without a valid session, 404, 405 or 501 for a verb that is not GET, and the NUL refused before the application |
| Markup in a browser | A seeded instance whose alerts, host names, groups, tags, failed units, mount paths, sensor labels, SMART model and serial, and CVE package, version and fix hold markup that would run a script or add an element. Chromium, signed in as an administrator, opened the Problems page in every state and every view, the history dialog and the row menu of the problems, and Needs Attention, Checks, Alerts, Thermal, Host metrics and CVE | No script ran, no element was added, no element had a handler, no dialog opened and no page error was thrown. The markup showed as text, on the pages that list it |
| Stored rows the code did not write | 25 alerts of shapes `_record_alert` cannot write, through the Problems list and its history, the inbox, the dashboard, the resolution stats, the summary, the badge counts and the autonomy sweep; then rows of the thermal, roll-up, host-metrics and disk stores | Finding 1. After the fix every route answers 200 on all 25 |
| Hostile input to every GET route | The OpenAPI operations on a seeded server, on the 7.4.6 tree and on this one, with and without a session, each with the 25 alerts stored | 381 operations here and 379 there. Two server errors here (the two SAML routes answering 503 because the library is not installed here) and five there (the same two, the inbox, the dashboard and the resolution stats) |
| What a host can make the server do | A host with a valid token sent 17 heartbeats (11 of system information, 4 of hardware and the whole set together three times) with mounts, failed units, ports, packages, processes, sensors, SMART rows and GPUs of the wrong shape, huge numbers, markup and 300 sensors. After each, 19 read routes were asked for as the administrator | Every heartbeat answered 200 and no read route changed its answer. No store grew by more than a few hundred bytes (the host's row by 30 bytes against the 7.4.6 tree, the thermal history by 149). So a host cannot store a row that stops a page for everyone; only a hand edit or an import can |
| Mutation checks | Each new test run against the code with its guard taken out: 14 changes in this pass (the three readers' skip of a bad row, each of its three conditions, the fix hint, the autonomy filter and five reads of a stored time) | All caught. One was not at first: the sort of acknowledged alerts, because one bad row passes a sort and two of different kinds do not. A test with two now holds it |

The nginx scanners (nmap, nikto and wapiti against the shipped configuration) and nuclei were not run this time. 7.4.7 did not
change the web server configuration: no file under `server/conf` or `docker` differs from 7.4.6.

## Summary

| # | Finding | Before the fix | Where |
|---|---|---|---|
| 1 | A stored alert of the wrong shape answered 500 to every caller, on the new Problems list and on four older readers | Low. A payload that is a string, an event or a host id that is a list, a `ts` or `resolved_at` that is not a number. Only a hand edit or an import can store such a row, because `_record_alert` writes nothing else and a host's report is cleaned at ingest. The effect lasted as long as the row stayed: `GET /api/problems` (new), `GET /api/alerts`, `GET /api/home` (the dashboard), `GET /api/alerts/resolution-stats`, and the autonomy sweep, which raised on every pass, logged a traceback for each request (1,528 in one probe) and took no action | `_fix_of_alert`, `handle_alerts_list`, `_dashboard_tickets`, `_alert_resolution_stats`, `_ladder_for` |

**Finding 1** is fixed by reading what cannot be read as absent. The inbox and the Problems list skip an alert whose event or
host id is not a string or whose payload is not a map (`_readable_alerts`); the Fix hint of a row can no longer fail a list; a
stored time that is not a number reads as 0 on the dashboard and in the resolution stats; and the autonomy filter skips an
event that is not a string. Only the two read paths skip rows. Clear all and the bulk operations still see every row, so a bad
one can be removed, and a test holds that. The tests run each of the 25 shapes alone and all together, for an unscoped caller
and a scoped one (the visibility filter looks a host up by its id, so an id that is a list raised for a scoped caller and never
for an administrator).

One more thing came out of the probe and is not a product defect. The browser test harness started gunicorn with its error
output on a pipe that nothing read. A pipe holds 64 KB, and after that the next log line of a worker blocks it while it holds the
logging lock, so the whole stack stops answering. The probe reached that after a few hundred log lines. The harness now writes the
output to a file, and a test logs 117 KB and then asks for a page.

## Not found

- **A caller cannot see a host outside their reach.** Role scope and tenancy both hold on every new and changed read route, and
  the history of a host outside them is empty, the same as for a host that has no alerts, so the answer does not say whether it
  exists.
- **The new field cannot leak through a cache.** The Checks rows and the Needs Attention digest are cached for a few seconds and
  shared; the code that adds `problem` builds new objects and writes into neither. The probe asked for the tagged and the plain
  answer in turn as two different callers and saw each one's own.
- **Nothing a person or a host types becomes markup.** Every text the new pages print goes through the page's escaping, the row
  key that travels in an attribute always holds a `|` so it can never read as a number, and the history route's JSON repeats only
  its two identifiers.
- **The new routes do not change anything.** Both are GET. The actions on a row use the routes the other pages call, so the
  permission a role needs for a mute or an ignore is the one it always needed, and the page hides a button as a courtesy while
  the server asks again.
- **The new routes are safe to compress.** `/api/problems` and its history are on the list of answers that are compressed.
  The session token travels in a header, not a cookie, so a page on another site cannot make the browser send an
  authenticated request, which is what a compression attack needs.
- **A host cannot grow the new history without limit.** At most 24 series per host, a label of at most 128 characters, a point
  about every 14 minutes and a fixed number of points in each. A report of 301 sensors, one of them with a label of 500
  characters, leaves 24 series and none of that length, in the module's own tests and in a direct call.

## Known and unchanged

- Some readers of the stores that hold a host's record and its metrics still raise on a stored row that is not shaped like what the code writes
  (Needs Attention, Checks, the forecast pages, the fleet anomalies and thermal views, the host's change list, the reports).
  They did the same on the 7.4.6 tree, and the Problems list reads Needs Attention and Checks, so it fails with them. A host's
  report cannot produce such a row, as the 17 heartbeats above show, so only a hand-edited or imported store reaches them.
- An alert for a host that no longer exists is visible to a caller who is not scoped, as it was.
- `GET /api/alerts/act`, `GET /api/tickets/csat`, the agent install and version routes and the SAML login answer without a
  session. They are the links and public downloads they were in 7.4.6, and none was changed.
- The Problems list costs what Needs Attention and Checks cost on a cold cache, once in each cache window, and a few
  milliseconds after that. On the seeded instance the first call took 4 seconds with the machine busy and the next ones 40
  milliseconds.
- A signed-in user may resolve an alert unless the install says otherwise, as before. That request still makes the host report
  once in 120 seconds at most.

## Not run for this review

A live probe of the maintainer's own instance (it needs a one-time token), the nginx scanners and nuclei (above), the SAML routes
(the library is not installed here, so both answer 503) and the check of the version comparison with the real `dpkg` (this
machine has none).
