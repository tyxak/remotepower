# Security review — v7.4.6

7.4.6 answers four requests (#55, #56, #57 and #58) and a follow-up on a fifth (#54). The first, a
switch that marks a host as internal, was reviewed on its own while it was still going to be released
as 7.4.5; that review is [security-review-7.4.5.md](security-review-7.4.5.md) and is not repeated here.
This review covers everything that changed after that candidate: 24 server, agent, page and packaging
files with about 800 lines added, and 55 files with the tests and documents that go with them. The
scans ran over the whole project, and the reading went to what changed: who may ask a host to report,
what a host can make the server do through the connections and listening ports it reports, what an OSV
record can put into the cache, the findings and the page, the setting that keeps CVE alerts quiet, and
the stored values the new code reads that the code itself did not write.

It found **two** issues worth reporting. Both are low, and both are fixed in 7.4.6. One was in the new
code and one was older than this release and came to light because the new tests fed the readers
stored rows the code does not write. Neither came from the field. Each fix has tests, and each test
was run against the code with its fix taken out.

## What changed that a reviewer should look at

- **The Linux agent.** It reads the host's sockets with psutil, or with `ss -tln` and `ss -tn state
  established` (fixed argument lists, no shell, no new file), leaves out the connections the host
  accepted, and sends an empty list when nothing is left. It reads one new key of the heartbeat
  answer, `force_sysinfo`. The Windows and macOS agents changed only to read that key.
- **The heartbeat.** The answer carries `force_sysinfo` once to a host that was asked and clears it. A
  host's report is parsed as before, and a report that carries the key or its timestamp leaves
  nothing on the host.
- **Alerts.** Resolving an alert by hand, one at a time or in bulk, leaves that request on the
  alert's host after the alert lock is released. Both handlers keep the permission and visibility
  checks they had, and the request is made only for an alert the caller could resolve.
- **Suggested dependencies.** A pure module drops a suggestion when the far end of a connection is a
  port from 32768 up that the other host does not list among the ports it listens on, when that host
  reports a whole, readable list.
- **CVE findings.** The scanner keeps the per-release fixes of an OSV record in its details cache,
  with bounds on what one record may add, and a finding carries a fix status, the fixed version of the
  host's own release and where a newer release has the fix. `cve_alert_fixable_only` is a new setting
  that decides which findings raise `cve_found`, in the scan and in Re-alert backlog.
- **The Thermal page and the risk score.** A drive is held to its own temperature lines when it has
  some. Every other sensor is judged as before.
- **The pages.** The CVE page prints the status, the version to install and the name of a newer
  release; the Settings page has the new switch; the sensor table colours a drive by its state.
- **Not changed.** No file under `.github`, `server/conf` or `docker`, no installer, no package
  recipe and no list of dependencies differs from the 7.4.5 candidate. The Makefile gained two module
  names in its lint lists.

## How it was done

| Method | Scope | Result |
|---|---|---|
| Read against the threat model | Everything above, then each place a rule is meant to apply: who may make a host report, what a host may leave on itself, what a public feed's record may add, what a switch that quiets alerts accepts | The two findings below, and the bounds on an OSV record |
| Lint (`make lint`: isort, black, mypy, ruff `F` and `E9`) | The type-checked modules, the agents, the sidecars, the tools, the tests and the packaging | Clean |
| bandit | 135,345 lines of server and agent Python, against the committed baseline | 0 High, 24 Medium and 923 Low. Nothing is new against the baseline |
| semgrep | The Python, JavaScript and security-audit rule sets over the 16 server, agent, page and packaging files that changed, with the per-rule timeout raised to 120 seconds | 21 results (10 on file permissions, 4 on SHA-1, 2 on an XML parser and 5 others), none on a line changed since the 7.4.5 candidate. Three rules timed out on `api.py` and did not finish: two taint rules for subprocess and system calls, and a hard-coded-token rule |
| gitleaks | Every commit (2,480) | No leaks. No tarball was built for this review |
| Dependency audit (`pip-audit`) | The 18 pinned requirements of the server and agents, with their dependencies | No known vulnerabilities |
| CodeQL | The repository's own configuration, as the production workflow runs it, for Python and JavaScript | 0 results in Python and 0 in JavaScript |
| Hostile input to what is new | 19 tests through the real functions: a viewer resolving and reopening 20 times, a scoped caller and a tenant caller asking for a host they cannot see, a host's own heartbeat carrying the request, 14 values for the switch, a stored finding of 11 shapes, a Thermal page and a score over 8 shapes of a host's lines and drive entries, and peer rows of 6 shapes | The two findings below. Everything else held |
| A version or a release name as markup | The page's own functions, run under node, over a fixed version and a release name that hold an image tag with `onerror` and a script element | Both come out as text |
| Hostile input to every route | The OpenAPI operations on a seeded server, on the 7.4.4 tree and on this one, with and without a session | 869 operations here and 867 on the 7.4.4 tree (the two more are the 7.4.5 route's `GET` and `PUT`). 17 server errors on both, all of them the three SAML routes answering 503 because the library is not installed here. Nothing is new |
| A scan against the live OSV | 6 packages of a Debian 12 host, no part stubbed | 177 findings: 117 fixed in the host's release, 33 fixed only in a newer one, 27 with no fix. Every record was kept per release, and a second scan fetched none |
| The agent's sockets | A real listener and a real client on this machine's private address, read by both branches of the collector | The connection the host opened is reported and the one it accepted is not, on both |
| Mutation checks | Each new test run against the code with its guard taken out: 62 changes in the release, 8 of them in this pass (the strict switch, the cool-down, five readers and the page's escaping) | All caught. The first cool-down test was not caught until it let the host report between the cycles |
| PostgreSQL | The storage suite against a real PostgreSQL 18.6 started for the purpose | 28 tests pass |

The nginx scanners (nmap, nikto and wapiti against the shipped configuration) and nuclei were not run
this time. 7.4.6 did not change the web server configuration: no file under `server/conf` or `docker`
differs from the 7.4.5 candidate.

## Summary

| # | Finding | Before the fix | Where |
|---|---|---|---|
| 1 | The setting that keeps CVE alerts quiet turned on for the string "false" | Low. `cve_alert_fixable_only` took the truthiness of whatever arrived, so a client that sent the string `"false"` (or `"0"`) switched it on and `cve_found` stopped for every finding no update can clear. It needs an administrator's request and it fails quiet | `handle_config_save` |
| 2 | Five readers raised on a stored row that is not a whole map | Low, and older than 7.4.6. The suggested dependencies (a port that is not a number, a row that is not a map), the CVE report's counts and the host view, the scan's alert path and the Thermal page (a drive or GPU entry that is not a map) failed the whole page or scan for one bad row. The agent's report can never produce such a row, so only a hand-edited or imported store reaches them | `_dependency_suggestions`, `cve_scanner.summarize_findings` and `apply_ignore_list`, `_detect_new_cve_and_fire_webhook`, `handle_fleet_thermal` |

**Finding 1** is fixed by answering 400 ("cve_alert_fixable_only must be true or false", in the six
languages) unless the value is the JSON true or false, and by leaving the stored value unchanged. The
dashboard has always sent a real boolean. The tests hold 14 refusals with the option on and with it
off, and they were run with the check taken out.

**Finding 2** is fixed by skipping what cannot be read. The other settings in the same handler still
take the truthiness of their value, as they always did; only the one that quiets alerts was made strict.

## Not found

- **A host cannot leave the request on itself.** `force_sysinfo` and its timestamp are written by the
  alert handlers only. A heartbeat that carries them neither gets the key back nor stores them.
- **A caller cannot ask a host they cannot see.** With a role scoped to one group, or with tenancy on,
  resolving the alert of a host outside the caller's reach answers 404 and leaves nothing on the host,
  and bulk resolve is for an administrator.
- **Asking cannot be turned into load.** A viewer may resolve alerts unless the install says
  otherwise, so a host is asked at most once in 120 seconds, whatever is resolved and reopened in
  between: 20 cycles with a report between each left one request.
- **An OSV record cannot grow the cache or the page without limit.** A fixed version over 128
  characters, a package name over 200 and an entry past the 1,024th are left out, and a finding that
  loses its entry reads "unknown", the older behaviour, and never "no fix exists". What is kept is
  printed through the page's escaping.
- **The switch cannot be read the wrong way round on the server.** Only a stored `true` turns it on,
  and a stored string, number or list reads as off.
- **A drive is not judged by a list that may be cut.** The suggestion rule trusts a host's listening
  ports only when the list has fewer than 80 rows and every row is readable. The agent reports at most
  80, lowest port first, so a list that long may have lost exactly the ports the rule asks about.
- **The Thermal page does not change for an install that sets no drive line.** The 591 tests that
  already read the page and the score pass, and the first new tests hold the same flags and values.

## Known and unchanged

- A host is believed about itself. A compromised agent can report a short list of listening ports so
  that suggestions pointing at it are dropped, or a long one so that they are kept. It can only change
  what is suggested about itself, and a suggestion is only ever a question the operator can dismiss.
- Any signed-in user may resolve an alert unless `viewers_can_ack_alerts` is off, and so may make a
  host send one fresh report in 120 seconds. That is the cost of the request, and it is bounded.
- Needs attention and the risk score still count every CVE finding, fixable or not. The new setting
  changes what raises `cve_found` and nothing else.
- The assistant's notes on the observed network (`connects out to`) read the same peer report as the
  suggestions, and for a host with an agent older than 7.4.6 they still list its clients until it is
  updated.
- An OSV record is a public feed's word for the severity and the fix, as it always was. Nothing here
  makes the scanner more or less willing to believe it, apart from the bounds above.
- The other settings of the save handler take the truthiness of their value, so the string `"false"`
  turns them on. They were left alone because changing them is a breaking change for any client that
  sends strings, and the one that quiets alerts was the only one where a mistake fails quiet.

## Left for the release gate

The full suite and the checks that belong to a release are listed with the release, once it is cut.
Run so far, each on a copy of the tree. At 66220e27, JSON 17,124 tests and SQLite 16,863, red only in
`test_v643_aur_tracks_release` (two subtests, which compare the AUR packages with the newest dated
release and are red by design until a release is published) and in the eager JavaScript budget, which
the next commit moved with its reason. At 5c9a746b, which holds all the code of this review, JSON
17,176 tests and SQLite 16,912: the same two AUR subtests, and six tests of this release that were wrong
and not the code (an older test module left a stand-in for the role lookup in place, so a viewer passed
the administrator check in the new test, and a fixture held an integer key that the SQLite store cannot
sort). Two test-only commits fixed them, and the SQLite suite ran again on the final tree at 74786743:
16,912 tests, red only in the two AUR subtests. The JSON suite was not run again after those two
test-only commits; the three modules involved were run under their top-level names, the way discover
loads them, on both backends.

Not run for this review: a live probe of the maintainer's own instance (it needs a one-time token),
the nginx scanners and nuclei (above), the SAML routes (the library is not installed here, so all
three answer 503), the run with Python 3.14 and the CI dependency list (`make ci-parity`), and the
check of the version comparison with the real `dpkg` (this machine has none; the tests stand in a
comparison for it, and the scanner keeps a finding when it cannot compare).
