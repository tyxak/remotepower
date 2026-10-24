# Security review — v7.4.0

7.4.0 is a polish release. The review started with what changed (112 server, agent
and client files since 7.3.0) and then covered the whole project: every route sent
hostile input, the scanners ran against the shipped nginx configuration, and the
suite runs on each storage backend at the release gate.

It found **eleven** issues worth reporting. All were **caught before release**, by
the work that touched the code or by the tests written for it, and all are fixed in
this release. None came from the field.

## What is new that a reviewer should look at

- **A reader for firewall syslog** (OPNsense, pfSense, MikroTik): UDP from outside the
  fleet is parsed into evidence and can end up in a public report.
- **Three agent additions:** a carry file for slow scanners, a read of fail2ban's
  configuration, and clearer messages for the Windows and macOS command lines.
- **Two server changes to who sees what:** the ignore list, and a new alert for
  reported addresses.
- **Status codes that decide whether the dashboard signs you out.** A wrong password
  in a re-authentication prompt used to answer 401, which the dashboard reads as "your
  session is gone".

## How it was done

| Method | Scope | Result |
|---|---|---|
| Read against the threat model | The new code above, then each place a rule is meant to apply: who may read a host's data, which store is shared across tenants, what a sender of syslog can make the server spend | 9 findings, below |
| Undefined names (`ruff F821`) | Server, agents, sidecars, tools and tests | 0 |
| bandit | 129,286 lines of server and agent Python, against the committed baseline | 0 High, 25 Medium (unchanged), 924 Low (2 more than the baseline: the agents' command-line handling and the fail2ban reader, both `try`/`except` or a fixed argument list). The baseline is regenerated |
| semgrep | The Python, JavaScript and security-audit rulesets over the 112 changed files | 12 results on the changed files and 27 over the whole project, every one a reviewed false positive (below) |
| gitleaks | Every commit (2,336) and the working tree | No leaks |
| Dependency audit (`pip-audit`) | The packages the server and agents import: Flask 3.1.3, Werkzeug 3.1.9, pydantic 2.14.1, cryptography 50.0.2, psycopg 3.3.6, Jinja2 3.1.6, requests 2.34.2, asyncssh 2.24.1, psutil 7.2.2, reportlab 5.0.0 | No advisory. The audit of the whole dev environment lists others (anyio, h2, mcp, msgpack, PyJWT, tornado and more); nothing in the server, the agents or the sidecars imports them |
| eslint correctness rules and undefined names | Every client file; both are tests | Pass |
| Rendered browser gates | Every page on a seeded fleet: console errors, failed requests, accessibility, box overflow, contrast in 13 themes, keyboard, print, a phone's width in six languages, and every request answered 500 | No console error, no failed request except the two demo integrations that point at addresses that do not exist |
| Hostile input to every route | All 954 operations in the OpenAPI document on a seeded server, with no token, a wrong token, a valid session and malformed or oversized bodies: 25,522 requests | No 500. Nine routes answer 200 to a caller without a session; each is meant to (installer scripts, agent version, magic-link request, alert action links, client-error beacon). Calls that reach out to the network (DMARC and TLS scans) take up to 15 seconds when DNS is unreachable, and need an admin |
| nuclei and wapiti | The shipped nginx configuration in front of a seeded server; wapiti signed in, with SQL, XSS, SSRF, file, redirect, XXE, shellshock, upload, header and cookie modules | nuclei: information-level only (technology detection). wapiti: 0 vulnerabilities, 0 anomalies |
| CodeQL | The repository's own configuration, as the production workflow runs it | 0 results |
| Timing | All 243 GET routes on the seeded fleet, three runs each | Slowest is the full export at 258 ms; every other route is under 70 ms |
| Mutation checks | New tests run against the old code or against a version with the fix removed | Most of the gates were shown failing this way; each commit message says which |

**Reviewed false positives in semgrep:** four `chmod` calls set a mode of 0700 on
the agent's own directories and a provisioning working directory; three log lines
name an error or a file and not a secret; one `innerHTML` insertion is fed by a
template that escapes every field; one is a ticket body cut to 80 characters and
escaped; one is a SHA-1 in the demo-data seeder, which is not a security use.

## Summary

| # | Finding | Before the fix | Where |
|---|---|---|---|
| 1 | The ignore list was one list for the whole install | Medium: any signed-in user could read the names of every tenant's hidden hosts, and a tenant admin could hide another tenant's host from its Containers page and Needs attention | Server |
| 2 | A single crafted Suricata line took 165 ms to read, and a post of them 33 seconds | Medium: a sender of syslog could keep the server busy. A lazy match before a run of spaces backtracks quadratically; the line is read from its two ends now | Server |
| 3 | The "classes of attack" classifier filed "brute force" and "external source" as remote code execution | Low: a wrong word in a public report. `rce` matched the end of "force" and "source" | Server |
| 4 | A wrong password in a re-authentication prompt answered 401 | Low: the dashboard signed the user out and said nothing. It answers 403 now, as the other prompts already did | Server |
| 5 | A heartbeat that reported attackers rewrote Threat Intel's whole table | Low: 132 to 334 ms per heartbeat at 5,000 recorded addresses, under a lock the sweep and the page wait on. The queue now has its own document: 0.1 to 0.2 ms | Server |
| 6 | The Ignore button accepted an address that is not public | Low: an entry that could never match anything, and a way to hide a private host from the page | Server |
| 7 | Thirteen test classes removed the data directory setting when they finished | Low, development only: a later test could run the server's start-up against `/var/lib/remotepower`, which on a machine with a real install means writing to it | Tests |
| 8 | The new `ip_reported` alert has no host, and an alert with no host is visible to every tenant | Medium, caught before release: it names addresses that may have attacked another tenant's hosts. It is not sent when tenancy is on | Server |
| 9 | The carry file of the log sensor is read back from disk | Low, caught before release: the first version raised on a damaged entry. Every carried number is coerced now and an entry that does not read is skipped | Agent |
| 10 | The assistant's list of attacking addresses called firewall events "failed logins" and did not say what an address did | Low: a wrong word in an answer. It now says "events seen by the firewall sensor", the attack class and up to three CVE ids | Server |
| 11 | A mail-path placeholder, a hint and the demo data carried the maintainer's own account name | Low: information in a public file. Replaced with neutral examples | Web UI |

Each has a test. The commit that fixed it says whether the test was run against the old
code.

## Not found

- Nothing in the new firewall reader builds a command, a path or a pattern from a
  line it reads, and its output is fixed phrases and counts.
- The agent's read of fail2ban's configuration is a read of three named locations,
  capped at 60 files and 200 KB each. Nothing is sent but the names of two services.
- The copy-on-click for table cells writes to the clipboard text that is already on
  the page. It does not read anything the user cannot see.

## Left for the release gate

Run on the commit before the header flip (701261f6): the suite on JSON, 15,544 tests, all
passing; on SQLite, 15,481, all passing; on PostgreSQL 18, all 28 tests, none skipped; with
Python 3.14 and the CI dependency list, 15,497, all passing; bandit with no new finding and no
High; CodeQL, as the production workflow runs it, 0 results. The suite run against the unpacked
release tarball failed one test, a keyboard check of the host drawer that races the drawer
filling in under load. It passed on its own six times and the test now waits for the drawer to
settle; the tarball suite is run again on the tagged commit.
