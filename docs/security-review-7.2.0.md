# Security review — v7.2.0

The earlier reviews covered the whole project. This one does not, and says so.
It covers the one new thing in this release that changes who can influence what:
**an agent that reads logs an attacker can write to, and a server that turns
what it reads into public reports.**

It found **eight** issues worth reporting. All were **caught before release**, by
the tests written for the feature, and all are fixed in this release. None came
from the field. The bar this project holds itself to — nothing Critical, High or
Medium ships — is met for what was reviewed.

## What was reviewed

- **The log sensor in the Linux agent**: file discovery, the readers and parsers
  for each log, the request classifier, the aggregator, the submission and the
  thread that runs it.
- **The intake**: `POST /api/threat-events`, its validation, its limits and how
  it authenticates.
- **The path from evidence to a public report**: the vocabulary, the category
  mapping, the comment, the sweep's qualification rules, ledger and rationing.
- **The Threat intel page**, for what it prints from that data.
- **Static analysis on the changed files**: bandit against the project's triaged
  baseline (one High, below, fixed), semgrep's default ruleset (no findings),
  gitleaks over the changes (none) and an undefined-name check on every Python
  and JavaScript file.
- **Each guard was run against a mutation** that removes the behaviour it
  protects, and has to fail: log text reaching the payload, offsets committed
  before the server accepts them, a half-written audit transaction consumed, a
  path outside `/var/log` accepted, a report per host instead of per address,
  and the evidence ledger cleared after one service took a report, among others.
- **The whole path over real HTTP**: the agent's own sensor thread, reading real
  files, against a real gunicorn stack, with the result read back the way the page
  reads it (`tests/test_v720_threat_sensor_wire.py`). Authentication by device token,
  the gates in front of the handlers and the setting that reaches the agent in a
  heartbeat are only visible from there. It found no defect. It did show one blind
  spot in its own checks, which a direct post of a Cloudflare address now covers.
- **A real browser** against the seeded stack at desktop and phone width: no
  console, page or network errors, no page overflow, the new table capped.

## Summary

| # | Finding | Before the fix | Where |
|---|---|---|---|
| 1 | The first SQL-injection pattern matched an ordinary search | Medium: a report about a visitor | Agent |
| 2 | A request containing raw spaces was cut at its first word | Low: the payload was never looked at | Agent |
| 3 | A vocabulary check accepted a token with a trailing newline | Low | Server |
| 4 | A short word inside a longer one misclassified a jail (`rdp` in `wordpress`) | Low | Server |
| 5 | A Windows agent would have been offered the sensor | Low | Server |
| 6 | The evidence ledger was cleared when one service took a report | Low: the other service lost it | Server |
| 7 | A refusal on a later WAF line was not counted; an unreadable log read as quiet; impossible times were accepted | Low | Agent |
| 8 | The agent fingerprinted its source list with SHA-1 | Low: change detection, but bandit rates it High | Agent |

An older issue turned up on the way: two hosts that saw the same attacker in
the same sweep filed two reports to each service. It is fixed here too.

## The trust boundary

**Logs are attacker-written.** Every byte of a request line, a User-Agent and a
referrer is chosen by whoever sent the request, and the same holds for what the
WAF copies into its audit log. So nothing in the sensor builds a command, a
path or a pattern from a log. Lines are matched against fixed patterns and
dropped. The sensor runs no shell and evaluates no text; the only program it
starts is `cscli alerts list` with fixed arguments, and its only network call is
the POST of its summary. Tests pin all three. Long lines are cut before any
pattern sees them, the patterns are bounded, and a throughput test over 60,000
lines is there to notice one that backtracks.

**What leaves the host is a vocabulary.** The agent sends counts and tokens of a
few fixed shapes. The server rebuilds each address's summary from those and
drops everything else, including a token with a stray newline (finding 3). A
fuzz test fills every string field with attacker text, some shaped like valid
tokens, and asserts that none of it reaches a report's words; it was also run
against a leaky version of the code and fails there.

**The report is public.** It is filed under the operator's account on two
services, so what it says is built only from the vocabulary's own phrases and
numbers. A CVE id the logs named is allowed because it is a public identifier
the logs matched with a strict pattern.

**A report about the wrong address is the worst outcome.** The classifier is
conservative on purpose and a long list of ordinary requests must not match it
(finding 1 is the case that did). Things a real site serves, such as an admin
tool or `/cgi-bin/`, count only when the server refused them. The addresses that
are never blocked are never reported either, now including Cloudflare's. Only
scenarios that fired on this host count as CrowdSec evidence, never community
lists or decisions made by hand.

**The agent is root on a host an attacker may already be on.** So the intake
treats what it sends as data to check. A host can add at most 3,000 addresses an
hour and 300 in one post, and the intake accepts public, non-proxy addresses
only. A compromised host can still cause reports about arbitrary public
addresses up to those limits and the daily report budget. That is the same
power the brute-force counter always gave it, now bounded, and is accepted: root
on a host already allows far more.

**The one path that comes from the network.** The operator's extra log files
reach the agent from the server. Each must be a regular file that really lives
under `/var/log` once symlinks are resolved, at most 20, and are checked on the
server and again on the agent. Paths outside it, a symlink out of it, a
directory and `..` are all refused, and the logs are only ever opened for
reading.

**Authentication and exposure.** The intake authenticates with the device token
in the body, like `/api/logs`; a logged-in user's session proves nothing there.
It is exempt from the UI IP allowlist for the same reason as the other agent
endpoints, with a test that the allowlist still covers everything around it. The
page shows sensors and evidence only for hosts the caller can see.

## 1. A search for "select a color from the list" looked like SQL injection

The first pattern for SQL injection looked for `select … from`. An ordinary
search query contains both words, and enough of them in one minute is what makes
an address reportable. It is gone. What remains needs something no sentence
contains: `union select` followed by a column list, `select *`, `information_schema`,
`or 1=1`, `sleep(5)` and the like. The test that caught it keeps a list of about
fifty ordinary requests that must never match, and the rule for things a real site
serves.

## 2. A request with raw spaces was cut at its first word

`GET /?id=1 union select … HTTP/1.1`, with the spaces unencoded, was split on its
first space, so the classifier saw `/?id=1` and the attack went unnoticed. The
target is now everything between the method and a trailing `HTTP/x.y`.

## 3. A trailing newline passed a vocabulary check

Python's `$` also matches before a trailing newline, so `req:sqli` followed by a
newline passed a `^req:sqli$` check. Every vocabulary check uses a full match now.

## 4. `rdp` is inside `wordpress`

Jail and scenario names were matched by substring, and a jail called
`wordpress-hard` was classed as an RDP brute-forcer. Short tokens match as whole
words now, and a test names the pairs.

## 5. A Windows agent would have been offered a Linux-only feature

The heartbeat hands the response builder a snapshot of the device that carried no
operating system, and the OS check defaults to Linux. The new key reached every
host. `os` joins the heartbeat contract table and is read explicitly, and the
parity table declares the key as Linux only.

## 6. One service's success discarded the other's evidence

After a report, the evidence ledger starts over. If one service accepted it and
the other was busy, the busy one was left with nothing to go on until a whole
new threshold's worth of attempts piled up. The ledger is kept until every
service has been told.

## 7. Three smaller reading faults

A WAF transaction whose refusal appeared on a later line than its first was not
counted as refused. A log the agent could not read was reported as quiet when
nothing new had been written. A time such as `99:00:00` was carried into the next
day instead of refused.

## 8. SHA-1 for change detection

The agent summarised its list of sources with SHA-1 to decide whether to report
their health. Nothing depends on it for security, but bandit rates the call
High, so it uses the agent's existing SHA-256 helper.

## What this review did not cover

- **The rest of the project, and the usual release gate.** This release was cut
  without the pre-release gate: no CodeQL scan, no CI run, no dynamic scans
  (nmap, nikto, nuclei, wapiti against the shipped web-server configuration) and
  no run of the test suite inside the packaged tarball. All of that is still owed
  before `main` is promoted. The full test suite passed on both storage backends
  on an earlier commit of this release (14,145 tests on JSON, 14,084 on SQLite).
  The last changes, SniffCat's repeat reply, the wording of the standard report
  text and the documentation, were checked with the tests around them instead.
- **A production host's real logs.** Each parser was built from the documented
  format of its tool and exercised with realistic fixtures for every layout,
  including the odd ones. It has not yet read a live host's logs. The Log sources
  card exists so a layout it misreads shows as **Not understood** instead of
  looking like a quiet night.
- **Windows and macOS.** The sensor is Linux only; those agents never receive the
  setting.
