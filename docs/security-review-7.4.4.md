# Security review — v7.4.4

7.4.4 answers one request (#54): a warning line and a critical line for the temperature of a
drive, for each type of drive, for a host and for the whole fleet. That is a new way to quiet
or raise an alert for one drive, so the review looked at who may set a line, what a host can
make the server do by what it reports about its drives, and what the pages and messages print
from those reports. This review covers everything that changed since 7.4.3, the last reviewed
release: 20 server, agent, page and packaging files with about 850 lines added, and the tests
and documents that go with them. The scans ran over the whole project, and the reading went
to what changed and to the places where a rule the product already follows might have been
missed.

It found **one** issue worth reporting. It is fixed in 7.4.4. The gap is older than this
release (it dates from the per-host thresholds in 1.11.10) and the drive lines made it matter
more. It did not come from the field. The fix has tests, and each test was run against the
code with its fix taken out.

## What changed that a reviewer should look at

- **The Linux agent.** It reads the type of a drive from the output of the `smartctl` call it
  already makes (the rotation rate, and a path under `/dev/nvme` for NVMe) and adds it to each SMART
  row. It makes no new call and reads no new file. The Windows and macOS agents changed only
  in their version.
- **The report.** The server accepts the drive type only as `hdd`, `ssd` or `nvme`, judges each
  drive against its lines in the hardware step, and keeps a small state for each drive that
  is over a line. The heartbeat now hands that step the host's thresholds and its ignored
  sensors, which it had been leaving out.
- **Routes.** `PATCH` and `DELETE` on `/api/devices/<id>/metric-thresholds` take eight more
  keys and a map of lines for single drives. `GET /api/devices/<id>/hardware` returns the
  lines each drive is held to. The settings save and read carry eight more keys. The Needs
  attention list gets a row for a drive over a line.
- **Alerts.** A drive over a line raises a metric alert of a new kind. Its title and message
  name the drive by the name an operator gave it or by its serial number.
- **The page.** A pane in Settings, a block in the host's thresholds box, two boxes beside
  each drive on the Hardware tab and a colour on the SMART temperature. They print the paths,
  serial numbers and models that hosts report.
- **The release workflow.** Dependabot's update of the Docker login action from 4.6.0 to
  4.7.0. The workflow names the action by its version tag, as before. The tag is the one the
  upstream project published, and its notes list routine changes that do not touch a sign-in
  to ghcr.io with the workflow token.

## How it was done

| Method | Scope | Result |
|---|---|---|
| Read against the threat model | Everything above, then each place a rule is meant to apply: who may set a line, who may read what a drive reports, what a host can make the server keep or do, what the audit trail says, and what the pages and messages print | 1 finding, below |
| Undefined names and other pyflakes errors (`ruff F`, `E9`) | Server, agents, sidecars, tools and tests | 0, once an unused import in the new tests was removed |
| bandit | 132,430 lines of server and agent Python | 0 High, 25 Medium and 926 Low, the same counts as 7.4.3. Nothing is new against the committed baseline, and the new module has no finding |
| semgrep | The Python, JavaScript and security-audit rule sets over the 11 server, agent, page and packaging files changed since 7.4.3 | 21 results on 17 distinct lines (the agent's extensionless file is a copy of the `.py`). None is on a line that changed since 7.4.3, and every one is of a kind reviewed in 7.4.3: `chmod` calls on the agents' and the server's own files, SHA-1 uses that are not for security, `xml.etree` where exports are written, one fixed-host `urlopen`, one `shell=True` for a command an operator sets, the agent's `execv` restart and the painter of long tables. Three rule and file pairs timed out on `api.py`, with 120 seconds each |
| gitleaks | Every commit (2,458) and the unpacked release tarball | No leaks |
| Dependency audit (`pip-audit`) | The 16 packages the server and agents import, at the versions of 7.4.3: Flask 3.1.3, Werkzeug 3.1.9, pydantic 2.14.1, cryptography 50.0.2, psycopg 3.3.6, Jinja2 3.1.6, requests 2.34.2, asyncssh 2.24.1, psutil 7.2.2, reportlab 5.0.0, gunicorn 26.2.0, bcrypt 5.0.0, dnspython 2.9.0, webauthn 3.0.1, pysaml2 7.5.5 and websockets 10.4 | No advisory. 7.4.4 added no dependency |
| CodeQL | The repository's own configuration, as the production workflow runs it, for Python and JavaScript | 0 results. The raw output holds 687, all in the six rule classes the configuration scopes out as reviewed false positives (hashed or encrypted values that are stored or logged, the legacy protocols a certificate probe offers, an HMAC chain and a log fingerprint, the browser's same-origin API helper, and the syslog receiver's bind address). None of the 687 is on a line that changed since 7.4.3 |
| nuclei | 6,613 templates (exposure, misconfiguration, tokens, default logins, XSS, SQL injection, file inclusion, redirects, CORS, SSRF, traversal, technology detection and the generic checks; the denial-of-service, fuzzing and brute-force ones left out) against a seeded server | 17 informational results, none about the release: the file server of the test setup sends none of the security headers that nginx sends (10), technology fingerprints (4), an upload form, a `security.txt` and an address on a page. The control template for the headers matched 10 times. A first run at higher concurrency found nothing at all, because that file server timed out under the load; the control showed it, and the run counted here is the one at lower concurrency |
| Who may do what | The changed routes as six callers with tenancy on: the platform operator, the administrators of two tenants, a viewer of one tenant, an auditor and an MCP role | A tenant administrator reads and sets the lines of the tenant's own hosts and is refused (403) for another tenant's. A viewer, an auditor and the MCP role are refused every write and the thresholds read. The fleet's lines are the platform operator's. Needs attention and the hardware answer hold only the caller's own tenant's drives. Every caller can read the settings (known, below) |
| A write from another origin | The three routes that save lines (the fleet's, a host's and a drive's name) with a foreign `Origin` header | 403 each, and 200 with the same origin |
| Hostile input to every route | The 867 `GET`, `POST`, `PUT` and `PATCH` operations of the OpenAPI document on a seeded server with tenancy on. With no session: 821 requests (the 46 that sign out, change a password, restore, update, restart and the like are left out). The 390 reads, as the platform operator, as a viewer and as a finance user: 1,170 requests. The 431 writes, as the platform operator, with eight bad bodies each: 3,448 requests | No 500, and 1,601 answers in the 200s, so the sweep reached real handlers. Seventeen requests answered 503, all on the three SAML routes, because the SAML library is not installed here; the same seventeen as in 7.4.3. The `DELETE` operations were not swept (the one this release changed is covered by the tests above) |
| Hostile input to the changed routes | Each of the eight line keys with 26 values (an integer too large for a float, NaN, an infinity, a number written as a string, 5,000 characters, a NUL byte, markup, lists, dictionaries, 0, -1 and 151) on the host route and on the settings route; the map of single drives in 78 shapes; eight malformed or oversized bodies, among them one 500 levels deep and one with 5,000 drives | 502 requests as the platform operator: 116 answered 200, 386 answered 400, none 5xx. More than 128 drives with lines of their own are refused |
| Hostile heartbeats | The report of a host through the real handler: a hostile value in each of the eight fields of a drive's entry (136 reports in the tests), and 111 more over HTTP with the host's own token, among them a SMART value that is not a list and a list of 3,000 empty entries | Every one answered 200. A host's token on another host's report or thresholds route: 403 |
| Stored values the code did not write | The thresholds of a host set to 12 shapes no handler writes (a string, a number, a list, a map of lines holding strings, lists, dictionaries or an integer too large for a float), then the heartbeat, the hardware answer and the Needs attention list | All three answer without an error |
| Planted text in a real browser | A drive's path, serial number, model and chosen name, each holding an image tag with an `onerror` or an svg with an `onload`, then Needs attention, the Alerts inbox, Predictive Health and the host's Hardware tab opened | No script ran, no element appeared, no dialog opened, no page error was raised. The planted text was on the pages, as text, 3, 4, 4 and 12 times. The Thermal page shows none of these strings |
| Mutation checks | Each new test run against the code with its fix taken out: 28 changes (the audit entry 9, the properties of the server 5, the three guards of the tenant tests 3, the escaping at 11 places on the pages) | 27 caught. The one that survived is an equivalent change (below) |

The nginx scanners (nmap, nikto and wapiti against the shipped configuration) were not run
this time. 7.4.4 did not change the web server configuration: no file under `server/conf`
or `docker` differs from 7.4.3.

**The one change the tests did not catch:** the tooltip of a Needs attention item on the home
page. It is the fixed text "Click for details" unless the item comes from a log alert, so no
host string can reach it, and taking the escaping out of that attribute changes nothing a
person or a test can see. Two other changes survived at first and were closed with tests. The
hardware answer checks that a host's saved thresholds are a map before it reads them, and the
first test of that only used maps that held odd values, never a value that was not a map. And
the mail subject: an alert's subject always holds a dash or a degree sign, so the email package
encodes it whatever the notifier does, and a test that used it could not see the notifier's own
line go. A test with an ASCII subject now pins that line.

## Summary

| # | Finding | Before the fix | Where |
|---|---|---|---|
| 1 | Saving or resetting a host's thresholds left nothing on the audit trail | Low. Only a change to the ignored sensors was recorded. The fleet's save, the container lines and the disk names were all recorded. A critical line of 150 never fires, so a save that raises a line quietly stops one kind of alert for that host, and nothing showed who did it or when. The drive lines added a new kind of alert that can be stopped this way. Only an administrator can make the change (a tenant administrator for the hosts of the tenant), so this is a gap in accountability and not a way in | Server |

It is fixed with the rule the product already follows for the other saves. `PATCH` and
`DELETE` on a host's thresholds now write one `device_metric_thresholds` entry: the lines that
were set with their numbers, the ones that were taken away, and how many drives and mounts
have lines of their own, as a count and not as their serial numbers or paths. A save that
changes nothing writes nothing, and a refused save writes nothing. The tests cover each of
those cases, the ignored sensors that were recorded before, and a change long enough to be
cut (it keeps its start and its length). The commit that fixed it says the tests were run
against the old code.

## Not found

- **A line cannot be used across tenants.** With tenancy on, a tenant administrator sets the
  lines of the tenant's own hosts and is refused for another tenant's, on the host route, the
  hardware route and the route for drive names, before the handler runs. A viewer, an auditor
  and the MCP role are refused every write. The lines of the whole fleet are saved by the
  platform operator only. A drive over its line is a row in Needs attention for its host, and
  the digest keeps an item that has no host; a test with two tenants and a drive over its line
  on each host shows a tenant sees its own drive and never the other tenant's.
- **A report cannot make the heartbeat fail or the server keep more than a bounded amount.**
  A hostile value in any of the eight fields, a SMART value that is not a list, and a list of
  3,000 empty entries all answer 200. At most 32 drives of a report are kept, the state for a
  drive is dropped three reports after the drive leaves, and a host that invents 80 new
  serial numbers in each of 12 reports never holds more than 96 state entries. The check that
  compares a reading with a line cannot raise on an integer of any size: the first version of
  it did, on `10**400`, and a test written for it found that before the code was committed.
- **A line break in a drive's name stays out of a header.** A name holding a carriage return,
  a line feed and the text of another header is flattened to spaces in the subject of a mail
  by the notifier, and the push and webhook senders send no line break in a header. The mail
  test also guards against the earlier version of itself: it first passed with the notifier's
  line taken out (see above).
- **A line is a number or nothing.** A value outside 1 to 150, a warning line that is not
  below its critical line, a string, a list, a dictionary, NaN, an infinity and an integer too
  large for a float are all refused with 400, and a refused save changes nothing. An empty or
  null value removes a line.
- **Drive names are text on every page that prints them.** Needs attention, the Alerts inbox,
  Predictive Health and the Hardware tab (the rows, the boxes beside them and their labels)
  show a planted image tag or svg as text. Taking the escaping out at 11 places made the
  browser test fail at 10 of them; the 11th is the equivalent change above.
- **The agent's new read is the output of a command it already runs.** The rotation rate and
  the drive's path are read from `smartctl`'s output, and the server keeps the type only as
  one of three words.
- **Alerts keep their identity when a drive is renamed.** The name of a drive travels in a
  field that is not part of an alert's identity, so renaming a drive cannot leave an alert
  open that nothing will close.

## Known and unchanged

- Settings are one store for the whole install, and every signed-in role can read its
  non-secret keys (listed in the 7.4.2 review). The eight fleet lines for drive temperature
  are plain numbers in it. A settings view per tenant would be a design change and is listed
  for the maintainers.
- A host is believed about itself. A compromised agent can report any temperature and drive
  type for its own drives, and so raise or avoid its own drive alert. It cannot do that for
  another host (the token of one host is refused on another host's routes).
- The risk score and the Thermal page still judge every sensor, drives included, against the
  fleet's hot and critical pair. The drive lines drive the alert, Needs attention and the
  colour of the SMART temperature. The documentation says so.
- An administrator can raise a line until it never fires. That is allowed; the audit entry
  from this release is what records it.
- The unit that the quick-install script writes has less hardening than the one
  `install-client.sh` installs, and the Windows installer still builds its CA address with the
  port cut off. Neither was touched in 7.4.4; both are described in the 7.4.2 review.

## Left for the release gate

Run on a copy of the tree at a41566ce, which holds all the server, agent and page code of the
release. The commits after it add three tests of the tenant boundary, the credit for the
reporter, this document with its pins, and one paragraph of the What's new card. The suite on
JSON, 16,816 tests, and on SQLite, 16,589 tests. Both pass except `test_v643_aur_tracks_release` (two
subtests), which compares the AUR packages with the newest dated release in the changelog. It
goes red the moment the header carries a date and stays red until the AUR packages are bumped,
and that bump needs the checksum of a published tarball, so for a release that is not
published it is red by design. The JSON run has one more error, in the browser test of the
Prometheus card from 7.4.3 (`test_saving_what_the_form_was_given_changes_nothing`). It fails the
same way on the 7.4.3 commit on this machine: the test points an integration at an address in
the range reserved for documentation, and this network now lets the connection hang for the
whole timeout where it used to refuse it at once. It says nothing about 7.4.4. The PostgreSQL
suite (`tests.test_pg`, 28 tests) ran against a real server and passes; it was PostgreSQL 18.6
here, and CI runs 16. `make lint` (isort, black, mypy and ruff) and `make bandit` are clean, and
`tools/release-prep.py verify` reports 0 failures.

Not run for this release: a live probe of the maintainer's own instance (it needs a one-time
token), the nginx scanners (above), the SAML routes (the library is not installed here, so all
three answer 503), the run with Python 3.14 and the CI dependency list (it belongs to
`make pre-release`, which cannot finish on a dated header while the AUR packages trail it),
and a native read of the new translations.
