# Security review — v7.4.8

7.4.8 corrects three screens that said something untrue: a Problems row that read "never" under Updated, a sensor limit of
65261.8 °C on the Thermal page, and a host that read "Fully Patched" with a kernel update waiting. It adds no page and no
route. This review covers everything that changed since 7.4.7: five files of code (the API, the drive-line module, the
Prometheus export, the Linux agent and the script of the Problems page) with 161 lines added and 24 removed, 57 new tests, and
the documents. The Windows and macOS agents changed in their version number only. The web server configuration, the container
and package files and the installers did not change, and no file that lists a dependency differs from 7.4.7.

It found **one** issue worth reporting. It is low, it is fixed in 7.4.8, and it sits in three readers of a stored number.
Each fix has tests, and each test was run against the code with its fix taken out.

## What changed that a reviewer should look at

- **The agent runs two commands it did not run before.** When `apt-get upgrade` keeps a package back, the agent reads
  `apt-mark showhold` and runs one `apt-get --simulate --quiet --with-new-pkgs upgrade`. Both are argument lists with no shell,
  with a time limit of 15 and 45 seconds, and neither runs when nothing is kept back. A name that apt prints is only compared
  with other names. It is never part of a command. In a container the two commands carry `-o Dir=` options built from the
  agent's own host-root setting. The patch command that installs packages is unchanged.
- **The server reads a sensor's limit and label in a new way.** A limit outside 1 to 150 °C is dropped on the way in and when a
  stored one is read. The chip name before the first `/` of a sensor's label picks the lines a drive's own sensors are held to.
- **A reader of a stored temperature changed.** The Thermal page, the risk score and the Prometheus export convert what they
  read to a float. This is where finding 1 is.
- **One table cell.** The Problems page prints a host's last report when a row has no alert.
- **Not changed.** No route, permission check, role or token: the diff of `server/cgi-bin` holds no line that adds or alters
  one. No dependency, no web server file, no installer. The `temp_high` alert and the reliability grade still judge a sensor by
  the fleet's settings.

## How it was done

| Method | Scope | Result |
|---|---|---|
| Read against the threat model | Everything above, then each place a rule is meant to apply: what a host may make the agent run, what a stored row may do to a reader, what a number or a name may do to a page | The finding below |
| Lint (`make lint`: isort, black, mypy, ruff `F` and `E9`) | The type-checked modules, the agents, the sidecars, the tools, the tests and the packaging | Clean |
| bandit | 136,650 lines of server and agent Python, against the committed baseline | 0 High, 24 Medium and 928 Low. Nothing is new against the baseline. Five Low are new since 7.4.7 (923), all in the agent: two for running `apt-mark` and `apt-get` as a list of arguments with no shell, two for naming them without a full path, and one for a `try` that passes in a function that must never raise |
| semgrep | The Python, JavaScript and security-audit rule sets over the five files of code that changed, with the per-rule timeout raised to 120 seconds. `api.py` has 77,821 lines, so it was scanned as the seven functions that hold a changed line (1,071 lines) | Four results, all in the agent and none on a line changed since 7.4.7: file permissions the agent sets on its own directories and update files (3) and the agent starting itself again with its own arguments (1). Nothing in the other files. A control, the same seven functions with an `eval` and a `shell=True` added, was flagged for both |
| gitleaks | All 2,514 commits on every ref, and the 1,650 tracked files as `git archive` writes them | No leaks |
| Dependency audit (`pip-audit`) | The 11 pinned requirements of the server | No known vulnerabilities. No requirement changed since 7.4.7 |
| Hostile values through the real functions | 20 sensor limits (NaN, infinity, 1e308, 0, 0.5, 150.0001, integers of 400 digits, strings, booleans, lists, maps), 14 labels (not a string, empty, 100,000 characters, a chip name in capitals or with a space in front, a NUL, a right-to-left mark, a path, markup) and 10 readings, through the ingest, then the Thermal page and the risk score; and the same values written as stored rows, with the readings also in a drive's and a GPU's | Finding 1. After the fix every case answers, the page is strict JSON, and nothing outside 1 to 150 °C is stored or shown as a limit |
| Hostile text from apt | Output of 5 MB on one line, one of 200,000 names, the heading 10,000 times, Windows line endings, a NUL, and 10 names that are shell words or options (`$(…)`, `;id`, a backtick, `--force-yes`, `-o`, a path, a NUL, a right-to-left mark, 4,000 characters) | Read in well under a second. No name was part of a command, no call used a shell, every `apt-get` call had `--simulate`, and the list of names stopped at 300 while the count stayed whole |
| The Updated cell | 13 rows, 11 of them with a value of the wrong kind (markup in a string, a map, a list, 1e21, 400 digits, infinity, NaN, a boolean), through the page's own `timeAgoHtml`, run in Node | Each came out as a dash or as a `<time>` element holding a time. None carried its input |
| The Prometheus export | A stored reading of 400 digits in a sensor, a drive and a GPU, through the temperature family | Finding 1. After the fix the good reading is written and the three bad ones are not |
| Mutation checks | Each new test run against the code with its guard taken out: 10 changes in this pass (the size check of a stored temperature, the two `float()` comparisons of the suspect check, the ingest rule, the stored limit, the label type, a name in a command, a shell, the cap on names, the exporter's check and the cell), 17 in the sensor and kept-back changes before it, and 2 in the Problems cell | All 29 caught |

CodeQL, the nginx scanners (nmap, nikto and wapiti against the shipped configuration) and nuclei were not run this time. 7.4.8
adds no route and did not change the web server configuration: no file under `server/conf` or `docker` differs from 7.4.7.

## Summary

| # | Finding | Before the fix | Where |
|---|---|---|---|
| 1 | A stored reading or limit too big for a float made the Thermal page and the Prometheus export fail | Low. A sensor, drive or GPU reading, or a sensor limit, that is an integer of more than 308 digits cannot be converted by `float()`. The server never writes such a row: the ingest keeps only measurements, and from this release limits from 1 to 150 °C. Only a hand edit or an import can store one. The effect lasted as long as the row stayed: the Thermal page raised for every host, and the export raised on the temperature family | `handle_fleet_thermal` (the sensor, drive and GPU loops), `_temp_suspect`, `_device_risk`, `prometheus_export._num` |

**Finding 1** is fixed by reading what cannot be converted as absent. `_temp_number` is the one test of "float() can take
this", and the four places that accepted a stored temperature with `isinstance` use it. `_temp_suspect` compares the values as
they are. The exporter's `_num` already turned a NaN or an infinity into no sample, because one bad sample makes a whole scrape
invalid, and now does the same for a number too big for a float. `_num` has 15 call sites, so the other 14 readers of a stored
number in the exporter are covered too. The tests run the stored values for a sensor, a drive and a GPU, for the page and for
the score. A page that raised was measured by calling the handler: the server turns an uncaught error into a 500.

## Not found

- **A host cannot make the agent run what apt prints.** The names go into sets and are compared with the `Inst` lines. They are
  never part of an argument list, and no call goes through a shell.
- **The second simulation cannot install anything.** Every `apt-get` call the agent makes for this has `--simulate`, and a
  test fails if one does not.
- **A host cannot make the agent do more work by what it prints.** The simulation runs only when something is kept back, with a
  time limit, and the list sent to the server is capped at 300 names as before.
- **A sensor's label cannot choose a line it should not.** Only the chip name before the first `/` of a label stored at 64
  characters is read, a board sensor is never held to a drive line, and a line kept against a serial number never applies to a
  sensor, since a sensor has none.
- **A limit or a time cannot become markup.** A limit is a float between 1 and 150 or nothing, and the cell prints a time or a
  dash.

## Known and unchanged

- The same failure exists in other readers of a stored number, and a host's report cannot reach them. The exporter's SLO block
  has eight more `float()` of a stored value, and the readers listed in the 7.4.7 review (Needs Attention, Checks, the forecast
  pages and the others) still raise on a stored row that is not shaped like what the code writes. Only a hand edit or an import
  stores such a row. This pass enumerated the readers of a stored temperature, not of every stored number.
- The `temp_high` alert and the reliability grade judge a drive's own sensors by the fleet's settings. The Thermal page and the
  risk score follow the drive lines.
- A held package is left out of the pending count by reading `apt-mark showhold`. When the holds cannot be read the agent counts
  no kept-back package at all, so a host never counts a held package for ever.

## Left for the release gate

The full suite and the checks that belong to a release are listed with the release, once it is cut. Run so far, each on a copy
of the tree. At 903d1bd4, which holds the code of the Problems, Thermal and Patching changes: JSON 17,660 tests and SQLite
17,352, both red only in the two AUR subtests of `test_v643_aur_tracks_release`, which compare the AUR packages with the newest
dated release and are red by design until a release is published. The release commit carries the two fixes of this review, and
its numbers are written here when its run finishes.

## Not run for this review

A live probe of the maintainer's own instance (it needs a one-time token), CodeQL, the nginx scanners and nuclei (above), the SAML
routes (the library is not installed here), and `apt` itself: this machine has none, so the agent was driven with stand-in
`apt-get` and `apt-mark` programs and with mocks, and the hostile values went through the ingest and the pages in process, not as
requests over HTTP.
