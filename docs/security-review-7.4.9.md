# Security review — v7.4.9

7.4.9 is the release in which the whole project was reviewed, not only what changed since the last one. Seven reviews ran side by
side: an authorization matrix over every route, a hostile-input sweep of the server, a review of the three agents and their
installers, a review of the web client and the web server headers, a rendered audit of the interface, a documentation cross-check
and a map of what the agents send against where it is used. Scanners ran beside them. Everything below was found, reproduced and
fixed on a seeded copy of the product, not on anyone's installation.

It found **three High issues, sixteen Medium ones and five Low or hardening items. All of the High and Low ones and fourteen of
the Medium ones are fixed.** Two groups of Medium findings are not fixed in 7.4.9. "Open" describes them first, with their size,
and then lists smaller items that were found along the way and are not counted in the figures above. Each fix has tests, and
each test was run against the code with its fix taken out.

The agents have to be updated for the agent fixes (the agent version is 7.4.9). The server fixes need no action except where a note
below says so.

## What changed that a reviewer should look at

- **Routes.** One route is new: `POST /api/logout`. Two others are new for one feature: `POST /api/scap/{id}/report-ticket`, and
  the SCAP report route now also accepts a one-minute link. No permission was loosened. A permission check was added to one
  endpoint (`services/config`), a tenant check to twelve handlers, and twelve instance-wide operations (and the webhook log's
  reads) moved to the platform operator.
- **Credentials.** Every comparison of a secret in the server goes through one helper (`secure_eq.py`) that never raises. A DNS
  provider token is removed from command output before it is stored.
- **Containers.** The Docker image starts its app server and daemons as `www-data`, not root.
- **Supply chain.** The GitHub Actions in the three workflows are pinned to commits, and Dependabot waits seven days before it
  proposes a release.
- **Size.** 203 files changed since 7.4.8, 12,378 lines added and 4,818 removed: 569 and 191 of them in the server and the web
  client, 645 and 107 in the agents and installers, the rest tests, documents and workflows. There are 22 new test files.
- **Not changed.** No dependency was added or removed in the server (Swagger UI moved from 5.34.0 to 5.34.1, a bug-fix release with
  no advisory). The agent version is 7.4.9 in all three agents.

## How it was done

**Scanners, on the whole tree.**

| Scanner | What it covered | Result |
|---|---|---|
| CodeQL 2.27.3 (the version the pinned workflow action uses), Python and JavaScript, the repository's own configuration | the whole tree | see "Left for the release gate" |
| bandit (against its baseline), ruff (undefined names, errors), mypy (31 modules), the JavaScript correctness gate, vulture | server, agents, tools, tests | no new finding; vulture's two reports are unused parameters |
| semgrep (registry rule sets, with a known-bad file as a control) | the whole tree | 92 results; all triaged, see below |
| gitleaks (tree and the commits of this release, with planted keys as a control) | the whole tree | no leak found; the control found both planted keys |
| shellcheck | every shell script | five warnings in four scripts, fixed |
| nuclei 3.3.7 with 10,575 templates (a stub exposing a git configuration was found, as a control) | a seeded stack behind the shipped web server configuration | 12 findings, all informational (missing HSTS and Cross-Origin-Embedder-Policy headers, technology fingerprints, security.txt present) |
| wapiti, signed in, 15 modules | the same stack | see "Left for the release gate" |
| pip-audit | the server's Python dependencies | no known vulnerability |

The 92 semgrep results: 21 were mutable GitHub Action tags (fixed by pinning), 27 and 4 were notes on the web server's use of the
`Host` header and `proxy_pass` (reviewed, by design: a script served from the Host header is sent `no-store`, and links that leave
the server use the configured public address), 13 were file modes of `0700` directories, 6 were log lines that name a file and not
a secret, 7 were an `Upgrade` header forwarded to WebSocket-only daemons (hardened, see S11), 3 were Dependabot cooldowns (fixed),
one was the container running as root (fixed, see S1). The remaining ten are an AES-CFB mode that SNMPv3 requires, a SHA-1 in the
demo seeder, two web client sinks covered by the web client review, a URL fetch in a demo tool, and five subprocess calls in the
scanner and the agent that the agent review read.

**Seven reviews, with their populations.**

- *Authorization matrix.* 1,073 routed operations taken from the real route tables, 84,120 requests, 60 runs as 26 kinds of caller:
  no credential, a bad token, an administrator, a viewer, a custom role, a role with no permission, an auditor, a finance user,
  roles scoped to a group or a tag, administrators, viewers and an operator of two tenants, eight API keys and three host tokens.
  Controls: the administrator was answered 2xx by 502 to 555 operations in each run and the anonymous caller by 16; the tenant
  check refused 104 operations that worked on the caller's own objects; the scope check refused 86 of 86 host-path operations
  outside the role's scope; a leak scanner found a planted foreign marker where one existed and none where it did not.
- *Hostile input.* About 41,650 requests over 975 routes, 4,252 body keys and 239 query keys, with 19 wrong types for each key
  (including NaN, Infinity, 400-digit integers, a lone surrogate, a 1 MiB string), 931 sparse hostile heartbeats, 19 hosts made of
  nothing but wrong-typed leaves, 139 stores mutated one row at a time, and the 76 periodic sweeps run on those rows. Every round
  had a non-zero count of successful answers.
- *Agents.* The three agents, the six installers and the agent container, with real GNU tar and real PowerShell where the finding
  needed them. Nothing was run as root, on real Windows or macOS, or against real package managers.
- *Web client and headers.* 1,320 places where the page writes to the document and 7,070 operands of the HTML it builds were parsed
  with a real JavaScript parser; 11,522 hostile strings were planted in the stores and 130 host strings sent through the real
  heartbeat; every response of both shipped web server configurations was measured for its headers.
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
| S9 | Medium | server, tenancy | instance-wide operations reachable by a tenant administrator (audit key rotation, a full backup, TLS generation and others) |
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
- **S9, S10.** Twelve operations joined the platform table. Session revocation is confined to the caller's tenant and takes the
  store's lock. A schedule job belongs to the tenant of its host, a rollout to the tenant that created it. A link between hosts
  may name only a host the caller can see, and the guard test that watches host ids in request bodies watches `depends_on` and
  `connected_to` too.
- **S12.** One helper (`secure_eq.py`) replaced all 20 comparisons of a secret, and a test fails on a bare `compare_digest`. The
  request body is cleaned of lone surrogates where it is read. NaN, Infinity and 400-digit numbers are refused where a host sends
  them. A test feeds every request model every non-finite value for every field.
- **S13.** `POST /api/logout` removes the session. The page calls it after saving your preferences, and drops the hosts you opened
  recently, your favourites, your stats history and your drafts from the browser.
- **S14.** The report opens from a link the server serves with its own sandbox policy. The page asks for the link first (signed in,
  host scope checked), and it works for one minute.
- **S1, S11, S22.** Described in the CHANGELOG.

## Open

These are not fixed in 7.4.9. Each is listed with what it is and how big it is, so you can decide what to do.

- **Tenant isolation of about ten more listings (Medium, tenancy only).** Time entries, a knowledge-base article's linked hosts,
  the home aggregate's ticket hosts, tickets (documented as not isolated), and the platform operator's instance data behind the
  SLO, links, calendar, monitor export, mail flow, Proxmox, diagnostics and declarative configuration routes can show another
  tenant's host names or the operator's settings to a tenant user. Medium, about ten handlers, each with a reproduction in the
  authorization review. Also open: 32 handlers read a host id from a request body under a key the guard test does not know
  (`members`, `upstream_id`, `peer_id`, `scope_value`, `reach_scope_value`) and call no tenant helper.
- **Stored rows of the wrong shape (Medium, robustness).** One wrong-shaped row in `alerts.json`, `alert_mutes.json`,
  `hardware.json`, `fleet_events.json`, `apikeys.json` or the antivirus store makes the home page, the problems page, the alert
  summary or the risk page answer 500 for everyone. 109 stores had at least one such failure. Rows come from validated ingest and
  imports, so this is a corruption and import problem and not a remote one. The fix is a pair of row-reading helpers next to the
  existing list helper and a test that derives the population from the stores the pages load; it is large (202 endpoints) and
  mechanical. Periodic sweeps that raise on such a row stop silently, and one non-finite number inside a host's hardware or
  antivirus report drops that report.
- **Low items of the web client.** The page's delegated click handlers resolve a name from an attribute on `window`; the OIDC
  sign-in accepts a token and a user name from the address fragment with no state check; the debug log link opens in a tab that
  cannot send the token; sign-out leaves a few more browser keys. The two web server configurations disagree on a few headers and
  `/ca.crt` has none. Each has a proposed change in the web client review.
- **Agents, lower severity.** A canary path that a symlinked parent in a user-owned directory can redirect, a pipe at a file-manager
  path that blocks the agent, an unbounded walk in a directory baseline, a downgrade guard that trusts the advertised version, three
  code-running channels (canary, backup verify, restore drill) that are not behind signed commands, a Windows installer that runs
  the Python installer with no hash check, and `docker` found through `PATH` on Windows.
- **Interface.** Chart text sized by the drawing's view box, four strings with no translation entry, table action buttons that wrap
  at phone width, a split of helper text between 11 and 12 pixels.
- **Signals.** Seven places that could use a signal the agents already send and do not (Fleet Query and the Data Explorer for
  encryption and security updates, alert events for the posture trio on Linux and macOS, a time-synchronisation compliance control,
  hardware and exposure sections in the fleet report, container crash loops in the risk score, and `docker_df` sent on its own).

## Not found

- **Script injection from host or operator text.** None of the 11,522 planted strings and 130 host strings executed, injected an
  element or broke an attribute (79% of the planted strings never reached a screen, listed in the web client review).
- **Authorization gaps outside the ones above.** The administrator was refused nothing it should have been given, and no request
  answered 2xx where the handler's own declared gate refuses. No unexplained 5xx came out of the matrix.
- **Heartbeat ingest.** 931 sparse hostile heartbeats and 19 all-wrong-type hosts gave no 5xx and broke no page; the Linux agent's
  185 sysinfo keys all reached the server.
- **Public pages.** Framing of the status page and the dashboard is blocked, the status token is compared in constant time and an
  empty token is refused, the portal link is built from its configured address, and the portal cookie is `HttpOnly; Secure;
  SameSite=Strict`. No CORS headers are sent.

## Known and unchanged

- A fully compromised server is root on its agents, by design (see the threat model).
- Responses of a few administrator test endpoints carry the data directory's path.
- The two nginx configurations send HSTS only when you turn it on, and no `Cross-Origin-Embedder-Policy` (the origin is already
  isolated by `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy` and a CSP with no external source).

## Left for the release gate

- The full test suite on the JSON and SQLite backends, the PostgreSQL tests, `make ci-parity` (the dependencies resolved fresh, as
  CI does), `make dist`, the local CodeQL run on the final tree, bandit, gitleaks and the release preparation check. The numbers
  of that run are in the release page.
- wapiti's result for the signed-in crawl.

## Not run for this review

- A live probe of a running installation: none was available for this release, so every probe ran against a seeded copy.
- SQLite and PostgreSQL under the hostile-input sweep, and browsers other than Chromium (Safari and Firefox treat a `blob:`
  address's policy differently, which matters for S14).
- Real Windows and macOS hosts, real package managers, and a real container runtime for the agent's container update.
- A latency benchmark: the machine was busy with the reviews themselves, so no timing is quoted.
