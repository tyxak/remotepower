# Security review — v7.4.2

7.4.2 is a patch release for four reports. 7.4.1 went out as a pre-release without a
review of its own, so this one covers both: everything that changed since 7.4.0, the
last reviewed release (50 server, agent, installer, container and tooling files, about
2,700 lines added). The scans ran over the whole project, and the reading went to what
changed and to the places where a rule the product already follows might have been
missed.

It found **three** issues worth reporting. All three were caught before 7.4.2 is
released, and all three are fixed in it. Two came in with 7.4.1; the third is much
older. None came from the field.

## What changed that a reviewer should look at

- **The agents (7.4.1).** Watching folders and patterns for drift, so the agent, which
  runs as root, expands a pattern the server sends into the files it hashes. A restart
  of the agent when its credentials change on disk.
- **The installers (7.4.1).** The CA of a self-signed server is fetched from the
  server's own address, port included, and trusted only if its fingerprint matches.
- **The container image and the web server configuration (7.4.1).** A web terminal
  location, the `Host` header forwarded with its port, and an HTTP to HTTPS redirect
  that names the published port.
- **The server (7.4.1).** A poll interval per host, separate thresholds for NIC errors
  and drops, drift lists that add to or take away from the default, and a setting that
  tells a thinking model not to think.
- **The server and the page (7.4.2).** A read-only route that lists the integrations
  bound to a host, a list of containers kept out of alerts that can be edited in the
  browser, memory arithmetic for SNMP hosts, hourly averages kept in the integrations
  state file, and recovery notices that a maintenance window now holds.

## How it was done

| Method | Scope | Result |
|---|---|---|
| Read against the threat model | Everything above, then each place a rule is meant to apply: who may read a host's data, what a local user can leave where the root agent will look, what the installers trust, what the server believes about a request | 3 findings, below |
| Undefined names (`ruff F821`) | Server, agents, sidecars, tools and tests | 0 |
| bandit | 130,649 lines of server and agent Python, against the committed baseline | 0 High, 25 Medium and 924 Low, the same numbers as the baseline. The one finding that moved is the agent's restart after new credentials (`os.execv`, 7.4.1), which runs the agent again with its own arguments. The baseline is regenerated |
| semgrep | The Python, JavaScript and security-audit rule sets over the 44 files changed since 7.4.0 | 35 results on 29 distinct lines (the agent's extensionless file is a copy of the `.py`), every one a reviewed false positive (below), and 2 rule and file pairs that timed out on the largest files |
| gitleaks | Every commit (2,426) and the unpacked release tarball | No leaks |
| Dependency audit (`pip-audit`) | The packages the server and agents import: Flask 3.1.3, Werkzeug 3.1.9, pydantic 2.14.1, cryptography 50.0.2, psycopg 3.3.6, Jinja2 3.1.6, requests 2.34.2, asyncssh 2.24.1, psutil 7.2.2, reportlab 5.0.0 | No advisory. The audit of the whole development environment lists others (anyio, black, filelock, graphql-core, h2, mcp, msgpack, openapi-python-client, opentelemetry-api, PyJWT, tornado and uv); nothing the server, the agents or the sidecars import |
| Undefined names and correctness in the client | Every client file; it is a test | Pass |
| Rendered browser gates | Every page on a seeded fleet, the accessibility, box-overflow and icon-gap sweeps with the new card on the Tuning page: 28 tests | Pass |
| Hostile input to the new and changed routes | The host's integrations route with every kind of identifier, every method and every role; the container exclude list with bodies of the wrong type, 10,000 entries, entries of 5,000 characters, control characters and markup; a request from another origin | No 500. Nothing the route answers contains an address or a credential. The list keeps at most 200 entries of 128 characters, and a body that is not a list is refused |
| Hostile input to every route | All 955 operations of the OpenAPI document on a seeded server, with no token, a wrong token, a valid session and malformed or oversized bodies: about 6,200 requests | No 500. Fifteen operations answer 200 or 204 without a session and each is meant to (the sign-in, the installer scripts and agent versions, the portal's magic-link request, alert action links, the start of a passkey sign-in, the two report beacons for CSP and client errors, the customer satisfaction link, the health check and the public information). The SAML routes answer 503 on a server without the SAML library, a walk of an unreachable host answers 502, and one SNMP read of a host that does not exist outlasted the 60-second client timeout |
| Hostile heartbeats | The container report the release changed, through the real handler: 6,000 heartbeats with random container lists and exclude lists (wrong types, names of 5,000 characters, NUL and escape bytes, 500 exclude entries) | No exception. The list of names waiting for a recovery never passed 20 (its cap is 200) |
| A race, run for real | The agent's drift report against a second process that swaps a watched file between a FIFO and a regular file | 7.4.1: stopped inside `open()` after 353 rounds. 7.4.2: 2,879,518 rounds in 19 seconds |
| CodeQL | The repository's own configuration, as the production workflow runs it | 0 results |
| Mutation checks | Each new test run against the code with its fix taken out | 27 of 27 caught: every read going back to a plain open, the helper without the non-blocking flag, without the type check, without the owner check and without the mode check, a state reader going back to the unchecked open, and the installers fetching unchecked again or always skipping the check |

The nginx scanners (nmap, nikto, nuclei and wapiti against the shipped configuration) were
not run this time. 7.4.2 did not change the web server configuration, and the changes 7.4.1
made to it (the `Host` header forwarded with its port, a web terminal location, the
redirect) were read line by line instead; see *Not found*.

**Reviewed false positives in semgrep:** 35 results on 29 lines, and every line but one was in the code at 7.4.0. Thirteen are `chmod` calls that set a mode on the agents' and the server's own directories and binaries. Four are SHA-1 uses that all say `usedforsecurity=False`: two signatures of log lines, the prefix of a breached-password lookup that the service's protocol requires, and the demo-data seeder; the lookup's `urlopen` goes to a fixed https host and is annotated. Four are `xml.etree` imports: two write XML for exports and the agent reads the file oscap wrote for it (counted twice, as its extensionless file is a copy). Three are `shell=True`: a command an operator sets in the environment, annotated, and the agent's root command channel, which is its job. Two are `os.execv`, the agent's restart after new credentials (7.4.1, the one new line), which runs the agent again with its own arguments. Four are `proxy_pass` locations without `internal`, the installer routes, public by design. One is the AES mode that SNMPv3's user security model requires. Two are `insertAdjacentHTML` calls whose templates escape every field (the log viewer and the painter of long tables). One is a logger message that names an error, not a secret.

## Summary

| # | Finding | Before the fix | Where |
|---|---|---|---|
| 1 | The agent read its state files from `/tmp` when its own directory did not have them yet, and believed what it found | Medium for a host whose agent shares `/tmp` with its users: any local user could stop the root agent for good by leaving a FIFO under the name of one of its state files, or steer it with a file of their own: a poll interval of ten million seconds, a check baseline, a scan time, a command result sent to the server as the agent's. The unit `install-client.sh` installs gives the agent a private `/tmp`, so those hosts could not be reached this way; the unit the quick-install script writes does not, and neither does an agent started by hand. The fallback dates from 3.0.2 | Agent |
| 2 | The agent waited on files another user can turn into a FIFO | Medium: a plain open of a FIFO waits for a writer that never comes. A local user who could write a watched folder, or a tree the secret and PII scans, the loader check or the log sweep walk, could stop the agent by leaving a FIFO there, or by swapping a file for one between the agent's `stat` and `open`. Watching folders and patterns, new in 7.4.1, made the set of names larger | Agent |
| 3 | The installers fetched a CA address with the certificate check off even when no fingerprint was given | Low: `--ca https://...` alone became trust on first use of whatever answered, for an attacker on the path at install time. The installer printed a warning when it trusted a file this way. The line the dashboard prints and the script the server serves were already right | Installer |

The first two are fixed with one helper in each agent that opens a file without blocking
and asks the descriptor what it is, and a reader for state files that accepts only a regular
file, owned by the user the agent runs as, that nobody else can write. A test lists every
other binary read in the three agents with the reason nobody but root can reach it, so a new
plain read fails until it is one or the other. Each has a test, and the commit that fixed it
says whether the test was run against the old code.

## Not found

- The new route `GET /api/devices/<id>/integrations` checks the session first, sits under
  the pre-dispatch gate that refuses a host the caller may not see, answers 404 to an
  identifier that is not a host and to every method but `GET`, and sends no address, no
  credential and no username. Everything it prints on the page is escaped.
- The container exclude list matches with substring tests, not patterns, so there is
  nothing to make slow. It is cut to 200 entries of 128 characters, a value that is not a
  list is refused on save and read as empty from a file, and a row of the list of what is
  silenced is text, not markup.
- The SNMP memory arithmetic runs over integers the poll has already converted, and a
  value that cannot be divided is dropped before it is stored.
- The hourly averages are bounded (168 rows of 12 numbers for a bound instance), a damaged
  row in the file costs a point and not the answer, and an instance that is no longer bound
  loses what was kept.
- The change from `$host` to `$http_host` in the nginx locations forwards the `Host` header
  the client sent, port included. The application already builds its public addresses from
  that header after cutting it to a safe set of characters, and has settings for the
  addresses that are emailed (`public_base_url`, `portal_base_url`), so nothing new is
  trusted. The web terminal location only proxies to a daemon on the loopback address, which
  asks for a ticket; the container starts it only when asked, and writes its secret with
  mode 0600.
- The script the server serves for the quick-install line fetches the CA without checking the
  certificate only inside the branch that then compares its fingerprint, and refuses the file
  on a mismatch before it lands anywhere the agent would trust it.
- The drift watch expansion is bounded (200 listings and 4,000 candidates for a pattern),
  refuses a pattern that climbs out with `..`, and lists regular files only.

## Known and unchanged

- The unit that `install-client.sh` installs gives the agent a private `/tmp` and a
  read-only view of the kernel tunables and the control groups. The unit the quick-install
  script writes sets none of them. With the fix above the missing private `/tmp` no longer
  matters for finding 1, and the other two are hardening rather than a way in. Giving new
  quick-install hosts the same unit would change how commands run over the agent's exec
  channel, which needs its own look, so it was left alone and is listed for the maintainers.

- Settings are one store for the whole install, and every signed-in role can read its
  non-secret keys. With tenancy on, that includes the host identifiers behind the exposure
  mutes, the labels and bound hosts of integration instances, and the container exclude
  list. Secrets are withheld. This is how the store was built, not something this release
  added, and the new list of what is silenced shows no more than a read of the settings
  already did. A settings view per tenant would be a design change; it is listed for the
  maintainers.
- The Windows installer still builds its CA address from the host with the port cut off, which
  is port 80, and the script the server serves for Windows has no path for a self-signed
  server. It was not changed because it cannot be run on a real Windows host here, and a test
  lists it as open so the list can only shrink.

## Left for the release gate

Run on the commit before the header flip: the suite on each storage backend, bandit, CodeQL and gitleaks again. The release commit adds the numbers.
