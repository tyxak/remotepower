# Security review — v7.3.0

This is the whole-project review for 7.3.0. It has two parts.

**Part one is the new code.** It is what changes who can influence what: a
Cloudflare token the server stores and uses, two feeds the server reads from outside
(Cloudflare's firewall events and a honeypot Worker's log) and turns into public
reports, an agent reader for the host firewall's log, a second token that can edit
lists with a sync that writes a list in the operator's account, a button that bans an
address there and on hosts, and two automatic paths that carry a block from one place
to the other.

**Part two is the rest of the product**: the server, the three agents, the sidecars,
the installers and the containers. It combined a read of every place a rule is
applied, static analysis, a scanner run against the shipped nginx configuration, and
every route sent hostile input as several different users.

It found **twenty-three** issues worth reporting. All were **caught before release** by
the review and the tests written for it, and all are fixed in this release. None came
from the field. The bar this project holds itself to, that nothing Critical, High or
Medium ships, is met for everything reviewed. The scan tools report nothing open;
what each one said, and the reviewed false positives, are below.

## How it was done

| Method | Scope | Result |
|---|---|---|
| Read against the threat model | The new code (part one), then each place a rule is meant to apply: who may write a store, who may read a device, which routes check who you are before they say whether something exists | 23 findings, below |
| Undefined names (`ruff F821`) | Server, agents, sidecars, tools and tests; the server's route table is checked with a generated list of the names bound at runtime | 0 |
| bandit | 127,903 lines of server and agent Python, against the committed baseline | 0 new, 0 High. The baseline holds 25 Medium and 925 Low, each reviewed and marked on its line when it is by design |
| semgrep | The Python, JavaScript and security-audit rulesets over the server and the agents | 17 results, every one a reviewed false positive (see below) |
| CodeQL | Python and JavaScript, GitHub's default code-scanning suites, with the project's configuration, which is the one the production scan uses | 0 results |
| gitleaks | Every commit on every branch (2,270 at the time of writing) and the working tree | No leaks |
| eslint correctness rules | Every client file; now a test | 1 defect (a function declared twice, not a vulnerability) |
| Dependency audit (`pip-audit`) | The packages the server imports | Three advisories at the versions on the dev box (cryptography, pyasn1, werkzeug); each is fixed in a newer release, and a fresh install resolves the newer one. The suite's modules that touch them pass at the latest releases |
| nuclei 10.5.0 | All templates, low to critical, against nginx running the shipped configuration, anonymous and signed in | 0 results. A control run of the informational templates found nginx and the swagger page, so the templates were reaching the target |
| nmap 7.99 | The HTTP scripts (headers, methods, enum, CORS, cookies, trace, open redirect, shellshock, slowloris) against nginx and the loopback app server | nginx answers GET and HEAD only on the shell and sends the full header set. The slowloris check flags the app server on loopback, which nginx fronts with 10-second header and body timeouts |
| nikto 2.6.1 | nginx running the shipped configuration | 1 item: no HSTS on the plain-HTTP test listener (the TLS server block sends it) |
| wapiti 3.3 | An unauthenticated crawl and attack of the whole site, then 48 signed-in query routes with the injection, XSS, command, file, redirect, CRLF and SSRF modules | Crawl and passive checks, unauthenticated: the login form posts over the plain-HTTP test listener, `object-src` fell back to the default (fixed: `object-src 'none'` is in every shipped config), and 59 pages mention an install path that the public docs document. Attack modules, signed in: 0 vulnerabilities and 0 server errors |
| Every route, hostile input | The 952 operations in the OpenAPI document (44 skipped: sign-out, password change, restore, update, restart and the like), each sent bodies in which every key held one wrong type, numbers past the float range, a 20,000-deep nested array, NUL and bidirectional characters, and query strings of the same kind; as the operator, a viewer and with no token | About 49,000 requests over five rounds. The first rounds found 20 routes that answered 500 (finding 21). After the fixes, the viewer's round and the last operator's round found one route left, the Proxmox connection test for a host name with a label past 63 characters, which is fixed and has a test |
| Authorization matrix | The 908 operations that remain, each sent one benign request as five identities: no token, a viewer, a finance role, an operator role and an administrator | 835 refuse an anonymous caller with 401, 13 answer 400, 27 answer 404 and 20 answer 403. The 13 that answer an anonymous caller with 2xx are public on purpose (the agent install and version scripts, `health`, `public-info`, the signed alert-action and survey links, the portal sign-in request, and the two CSP report receivers). No route answered 5xx to any identity |
| Timing the writers | Every writer of the Threat intel store at 1,000 and at 5,000 recorded addresses, and one heartbeat in which forty sources cross the threshold, before and after the fix | 1 finding (23): ten seconds at the cap, 0.3 seconds after |
| Rendered browser gates | Every page on a seeded fleet: console errors, failed requests, accessibility, box overflow, spacing, typography | No CSP violation, no failed request except the two demo integrations that point at addresses that do not exist |
| The test suite, on every storage backend | The whole suite against JSON files (14,704 tests), SQLite (14,641) and a real PostgreSQL (28 integration tests), then the release tarball unpacked, then Python 3.14 with only the dependency list the CI workflow installs (14,676) | All pass, with the browser gates required to run rather than skip |

**Reviewed false positives in semgrep:** the SNMPv3 privacy layer uses AES in CFB
mode because RFC 3826 specifies it (authentication is the protocol's separate HMAC);
five `chmod` calls set a mode of 0700 or less and one sets 0777 on a scratch
directory inside a 0700 parent so a scanner container running as another user can
write its report, which the line says; two nginx locations (`/install`,
`/install.ps1`) are public because a fresh host runs them before it has a token;
four log lines name the secret **file** and not its contents; and one `innerHTML`
sink is fed by a template that escapes every field.

## Summary

| # | Finding | Before the fix | Where |
|---|---|---|---|
| 1 | One vocabulary and one reader: an agent could have claimed the honeypot's or Cloudflare's decision | Medium: a compromised host could make any address reportable at once | Server |
| 2 | A challenge would have been counted as a refusal | Medium: a report about a visitor the operator's own geo rule challenged | Server |
| 3 | A rule that also blocks an IP list, and IP access rules, would have been reported back | Low: circular reports, inflating the services' counts | Server |
| 4 | UDP and ICMP firewall records name the victim of a spoofed flood | Medium: a public report about the victim | Agent |
| 5 | The host name before a firewall record decided its verdict | Low: a machine called `blockhost` | Agent |
| 6 | A slow Cloudflare could hold the sweep up | Low: availability | Server |
| 7 | A missing list id could reach a URL as the text `None` | Low: a request to a path that does not exist | Server |
| 8 | A range typed under Always include was not checked against Cloudflare's ranges | Low: an entry covering Cloudflare's own addresses | Server |
| 9 | The shrink guard measured what was read, not what the list holds | Medium: a read that stopped early let a large list be replaced unasked | Server |
| 10 | A tenant's host could write to the account-wide edge list through the automatic ban | Low: a tenant's report could ban an address on the platform's edge | Server |
| 11 | A session's stored hash was a working session, and so was an enrolment token's | High: a leaked backup or database dump signed in as every user | Server |
| 12 | A correct password bought unlimited second-factor guesses | Medium: the lockout was never reached | Server |
| 13 | An unknown user name answered faster than a wrong password | Low: user names could be enumerated | Server |
| 14 | The "type your password to confirm" prompts could be guessed at without limit | Medium: a stolen session could brute-force the password | Server |
| 15 | An IPv6 zone id reached a root shell on the agents | High: text in a log field became a command | Server, agent |
| 16 | The customer portal's sign-in link fell back to the request's Host header | Medium: a forged Host mailed a live sign-in nonce to the attacker's address | Server |
| 17 | An unauthenticated caller could grow the rate-limit store for ever | Medium: login and enrolment slowed for everyone, then the disk | Server |
| 18 | A 6-digit enrolment PIN was limited per source address only | Low: guesses from many addresses were unmetered | Server |
| 19 | A 404 or 400 came before the 401 on several routes | Low: which ids, tags and groups exist was visible to anyone | Server |
| 20 | Smaller issues: log forging through a heartbeat's device id, an unthrottled monitor run, SNMP answers that raised the wrong exception, installers writing to fixed names in `/tmp` as root, Postgres sharing a network with the scanner | Low | Server, installers, compose |
| 21 | A body of the wrong type answered `500` on 20 routes, and the idioms behind them were everywhere | Low: a signed-in caller could provoke server errors on demand | Server |
| 22 | The suppressions list lost every maintenance window after the first recurring one | Low: an incomplete answer to "why am I not being paged?" | Server |
| 23 | A burst of attacking sources rewrote the whole Threat intel store once each | Medium: forty sources in one heartbeat held it for ten seconds at the cap, and slowed every other writer of the store | Server |

## The trust boundary

**The token.** It is a read-only Cloudflare token and the server stores it like
the AbuseIPDB and SniffCat keys: write-only on the page, never returned, scrubbed
from `GET /api/config`, masked in a backup and left out of a support bundle, and
encrypted at rest when config encryption is on (all by name, and a test pins each
of them for this key). The audit line names the change and not the value. The
connection test can use a token you typed, which is sent to `api.cloudflare.com`
and nowhere else and is not saved.

**Where it can go.** Every request goes to one fixed base, `api.cloudflare.com`,
through the SSRF-guarded opener with redirects refused. The only parts of a URL
that come from outside are a zone id and an account id, and both are checked to be
32 hex digits before they are used; a Worker name is checked against Cloudflare's
own naming rule. The GraphQL query takes no variables: the zone ids, the times
and the limit are validated and written into it, and a test feeds it a hostile id.

**The list token.** The second token can edit lists, so it is the one that can do
harm: a leaked copy could take an attacker off the blocklist or put visitors on
it. It is stored apart from the read token, write-only on the page, never
returned, scrubbed from `GET /api/config`, and removable from the page. The guide
tells the operator to give it one permission and an address restriction. The audit
line names the change and not the value.

**Where the sync writes.** Three requests change anything, all to
`/accounts/{id}/rules/lists` on `api.cloudflare.com`: create a list, set its
description, and replace its items. The account id and the list id are 32 hex
digits and the list name is checked against Cloudflare's own rule before they
are used. RemotePower never creates, edits or deletes a rule and never writes to
another list. A list it did not create is read and left alone until an
administrator asks it to take the list over, and the replace carries a marker in
the description so a later sync knows the list is its own.

**What goes in.** Entries come from the operator's own list, RemotePower's own
findings and two blacklists, and each passes the same checks: a public address, not
wider than /16 or /32, and not one of the fleet's, the allow-list's, recent
RemotePower logins', the never-block list's or Cloudflare's. A source that fails
holds the sync unless it has a copy under three days old, so a lapsed key cannot
silently turn the list into the smaller set the other sources make.

**What goes with it.** The sync sends the list's name, its entries and a comment on
each entry naming the source. The blacklists are downloaded with the operator's
own key, at most four times a day for each.

**A ban by hand.** `POST /api/ip-intel/ban` is two actions that already existed,
behind one button. The host half is the manual block for many hosts: it needs the
`command` permission on each target, the targets are only Linux agents inside the
caller's role scope and tenant (a list of ids is filtered, not trusted), the
never-block rules apply, and four-eyes approval parks each host as it parks a
block. The edge half adds the address to the list the sync keeps, so it is limited
to the platform operator and does nothing while the Edge blocklist is off. An
address the operator banned is stored with an end time and leaves the list when it
ends. The address is parsed as one address, never a range, and the same protected
networks that stop a block stop a ban, so a ban cannot be used to cut off the
fleet, the allow-list, a recent login or Cloudflare itself.

**A ban across many hosts.** The block record is written before the commands
are queued, and what was not queued is taken out afterwards, so a request that
dies half way leaves a record the expiry sweep lifts and never a rule on a host
nothing remembers. Hosts are queued twenty at a time and no new step starts after
25 seconds; the answer says how many were not reached, and a second Ban carries
on. Each host still passes the checks a single block does.

**An edge finding blocked on every host.** An address only the edge saw has no
host of its own. A separate switch, off by default, queues the same block command
on each Linux agent, with the same score, never-block and hourly limits, at most
100 hosts a sweep. It is skipped on a multi-tenant install, so one tenant's edge
data never blocks another tenant's hosts.

**A host's block banned at the edge.** When the Edge blocklist can write, an
automatic block is also stored as an edge ban for the same lifetime, behind the
same never-block check and at most 50 an hour. An address the host only claimed
still needs a reputation score above the block threshold from the lookups, which
an agent does not supply, so a compromised host can name addresses that already
score as hostile and no others. On a multi-tenant install only the edge's own
findings take this path (finding 10).

**What comes back is data.** Cloudflare's firewall events are asked for as groups
of address, action, source and rule, so no path, query string or user agent is
ever fetched. A Free plan is refused that dataset; its events are then read one
at a time, with the same four fields named in the query and no others, so the
response carries no path, query string, host or user agent there either. A test
pins the field list and that the filter never excludes something that counts.
From the Worker's log the server reads four fields: the trap kind,
the address, the Worker's decision and the time. Everything else in a line, which
includes text the visitor chose, is dropped before it is stored. What is kept is
mapped through fixed tables to a class, so the words of a report come from the
vocabulary and from numbers.

**Two senders, two sets of families.** An agent's summary is read with the agent
families and the edge feeds with the edge ones (finding 1). A family a sender may
not claim is dropped, not trusted.

**What a compromised Cloudflare account could do.** Someone who can write to the
Worker's log, or who holds a token for the account, could make RemotePower queue
addresses of their choosing. That is the same standing as any account that can
change your edge rules, and it is not new. The protections that apply to every
report still apply: addresses of your own fleet, your allow-list, recent
RemotePower logins and Cloudflare's own ranges are never reported, and reporting
can be switched off.

**The report is public.** As before, it is built only from the vocabulary's own
phrases and numbers.

## 1. One reader for every sender

The first version of the vocabulary had one reader. The honeypot's decision was a
field like any other, so a summary from a host that said "the honeypot banned
this" would have been believed, and an address reportable at once. An agent runs
as root on a machine an attacker may already be on, so the server reads its
summary with the agent families only. Edge evidence is read with the edge
families only. Both directions have a test, and the one that claims the edge from
an agent fails when the default is widened back.

## 2. A challenge is not a refusal

Cloudflare reports a challenge as an event. The operator's own rules challenge
visitors outside their country, and a person who solves it is a visitor. Counting
those would have filed reports about the operator's own readers. Only a block, or
a connection closed, counts.

## 3. Somebody else's decision

An IP access rule is a ban that fail2ban, CrowdSec or the honeypot already
decided, usually mirrored into Cloudflare by a sync. The requests it blocks are
the same address, already reported. A rule that also blocks an IP list refuses
addresses for being on a community blocklist, which is not an attack on you, and
reporting them back inflates the same lists. Both are set aside and counted on the
page, and a rule that names a list is recognised from its own expression. A switch
counts them anyway for an operator who wants that.

## 4. A forged source

A firewall record names the source address the packet claimed. UDP and ICMP are
what reflection attacks forge, so a report built on them would name the victim of
a flood. Only inbound TCP counts, and an address needs four ports or fifteen
packets within a minute, which a stray packet never reaches.

## 5. The host name was in the window

The first firewall reader took the sixty characters before `IN=` as the rule's
prefix. That window holds the host name, so a machine called `blockhost` made
every unlabelled record read as a refusal. The prefix is now what sits between
`kernel:` and `IN=`.

## 6. A slow answer

Reading a zone's rules costs one call per zone. With Cloudflare slow, twelve of
them could have held the sweep for minutes. A poll now spends at most twenty
seconds on rules and reads the rest on the next one.

## 7. A missing list id

A request builder took the list id from a parser and put it in the path. A parser
that found no id returned `None`, and `None` became the text `None` in the URL.
Cloudflare would have answered 404, but a value that is not 32 hex digits has no
business in a path. Every id is now validated where the request is built, and a
test builds a request with each id missing.

## 8. A range over Cloudflare

An address was checked against Cloudflare's ranges; a network was only checked
against the operator's own addresses and lists. A range typed under **Always
include** that covered Cloudflare's edge went through. A network that overlaps one
of Cloudflare's ranges is now left out whole, like one that overlaps your fleet.

## 9. The guard measured the wrong list

A sync that would empty or halve the list is held until the operator asks. It
measured the size of the list from the entries it had read, and the read stops
after a fixed number of pages. A list that Cloudflare paged more finely than
expected looked small, so a replacement that halved it would not have been held.
The guard now measures the larger of what was read and what Cloudflare says the
list holds, and a read that stopped early never skips a write.

## 10. One tenant's host, the whole account's list

The fan-out to hosts was skipped on a multi-tenant install, and the commit that
added it said why. The automatic edge ban, added after it, was not: a block queued
for a tenant's host also went into the ban list, and that list is the Cloudflare
account's, so it applies to every tenant's traffic through it. The address still
needed a high reputation score, which limits the harm to banning addresses that
are already bad, but the same rule was missing at the second site. The ban is now
taken only from the edge's own findings on a multi-tenant install. A test drives
a host finding through both settings and fails when the check is removed.

## 11. A stored hash was a working session

`tokens.json` is keyed by the SHA-256 of each bearer token so that a leaked copy (a
backup, a database dump, a support bundle) yields no usable session. A fallback for
sessions created before that change also looked the presented value up as a raw
key. The hash read from the file, sent as the token, signed the reader in as that
user. The enrolment-token store had the same fallback and let a stored hash enrol a
device. Both fallbacks now refuse a value shaped like a stored hash, and a test signs
in with each hash and requires a refusal.

## 12. A correct password bought unlimited second-factor guesses

The failure counter was cleared as soon as the password was right, before the code
from the authenticator was looked at. Every attempt started again from zero, so the
lockout was never reached and six-digit codes could be tried as fast as the server
answered. The counter now clears only once the whole sign-in has passed.

## 13. A name that does not exist answered faster

An unknown user name was checked against a stand-in that was not a real password
hash, so no hashing happened and the difference in response time told a caller which
user names exist. The stand-in is a real hash now, and a test compares the two paths.

## 14. The confirm-with-your-password prompts had no limit

Step-up, the web terminal, SSH-gateway keys, signing the agent release, turning off
signing enforcement, clearing the audit log, switching off 2FA, regenerating recovery
codes and changing a password are what stop a stolen session on its own, and each
could be tried as often as the caller liked. They share one lockout now (the sign-in
ladder, in a bucket of its own, so a locked prompt does not lock the sign-in).

## 15. A zone id in an address reached a root shell

`ipaddress` accepts anything after a `%`: `2606:4700::1%$(id)` parses, survives
`str()` and still counts as a public address. The threat-intel block command
interpolates the address into what the agent runs as root, and an address can come
from a log field (a forwarded-for header in a web log, for one). The checks in
threat intel, the edge list, WireGuard, the log sensor, the fail2ban action, scan
targets, the TLS host check and the CMDB and IPAM fields now refuse a `%`, and the
block command validates what it is given again at the point of use.

## 16. A portal link built from the Host header

On an install that enabled the customer portal without a **Portal public URL** (the
save-time check does not cover an older install, a restored backup or an imported
configuration), the sign-in link fell back to the request's Host header. A forged
Host mailed the real contact a live sign-in nonce pointing at the attacker's address.
With no URL set, no link is sent.

## 17. A limiter store anyone could grow

One document holds every limiter's state, nothing removed a quiet entry, and each
limited request rewrote the whole document. A fresh user name per failed login, or a
fresh address per request, slowed login and enrolment for everyone and filled the
disk. Entries that can no longer matter are dropped, a cap holds, and a lockout that
is still running is never the entry that is evicted.

## 18. A PIN limited by source address

A six-digit enrolment PIN was limited per source address, which means nothing to a
caller with a different address for each guess. Guesses now also share one
server-wide budget; enrolment tokens are not charged to it.

## 19. A 404 before the 401

The device SSH, SNMP, RouterOS and OPNsense routes, ticket hours, scan delete,
backup-job run and every route that takes a tag or a group answered 404 or 400 for
an id, tag or group that does not exist, before they checked who was asking, so an
anonymous caller could tell which exist. Authentication comes first. The
authorization matrix above is the check that this holds for every route.

## 20. Smaller things

A non-ASCII value in a signed alert-action link, a survey link, an inbound webhook
path, the billing secret or the SCIM token was a server error instead of a refusal.
The heartbeat's debug line wrote a device id and version straight from an
unauthenticated body, so a newline forged log lines. Any signed-in role could run
every monitor again as often as it liked. A malformed SNMP answer (an arc too large
to print, a truncated datagram) raised IndexError or ValueError where every caller
expects an SnmpError. The installers wrote their logs and the fetched CA to fixed
names in `/tmp` as root. In the compose file, Postgres with its published fallback
password shared a network with the scanner; it is on a private network that only the
app joins.

## 21. A body of the wrong type was a server error

Sending every route a body in which every key held the same wrong type (a number,
a list, an object, a number past the float range) found handlers that raised and
answered `500 Internal server error` on 20 routes: roles, the webhook test, Proxmox snapshots
and the Proxmox test, KB articles, CVE campaigns, monitoring profiles, KMIP config,
report definitions, SLA targets, drift ignore, time entries, the timeline window,
threshold preview, TLS self-signing and host-config collect. None is reachable
without signing in and none reads or changes data it should not, so this is a
robustness and noise finding and not an exposure: a signed-in caller could make the
server log a traceback and fill the error counters on demand.

The routes shared three idioms, and each is closed everywhere rather than at the
named handlers:

- `(body.get('k') or '').strip()` and `(x.get('k') or '')[:n]`, which raise for
  anything that is not text. `_read_valid` hands a handler the original body, not the
  model's coerced copy, so the pre-check cannot save it. 271 calls are wrapped in
  `str()`, and a test holds the pattern at zero.
- `(body.get('k') or [])` iterated or sliced, which raises for a number and takes a
  slice of an object as a key. The sites that iterate a field of the request body
  use `as_list`, which is an empty list for anything that is not one.
- `int()` and `float()` under an `except ValueError` that missed `TypeError` and
  `OverflowError`. 349 `except` clauses in the route handlers were widened.

Alongside, a host label past 63 characters raised out of the SSRF pre-flight that
every URL-taking handler shares, a role scope that was not an object raised, and
`/api/acme/<device>/renew` without a domain split the path into one name. Each of
the sites found has a test that fails without the change; a final round of the same
fuzz found nothing.

## 22. A list that stopped early

The suppressions page lists everything that stops you being paged. A recurring
maintenance window has no start or end, parsing the empty string raised, and the
loop over the windows ended there: every window after the first recurring one was
missing from the list, and an error was logged on every request. It is not an
exposure, but a list that says less than is true about what is silenced is the wrong
way round for a page that exists to answer "why am I not being paged".

## 23. A burst of sources was a write each

The Threat intel store is one document, and every writer rewrites all of it. That
costs 46 ms at 1,000 recorded addresses, 250 ms at the cap of 5,000 and 640 ms when
every address carries a day of evidence. When a source crossed the brute-force
threshold, the heartbeat took the store's lock for that one source, so a heartbeat
in which forty sources crossed held the request for ten seconds at the cap, and
every other writer of the store (the sensors' reports, the edge feeds, the sweep)
queued behind it. Nobody needed to sign in: the sources are addresses sending failed
logins to a monitored host.

The sources one heartbeat found are written under one lock now, so the same forty
cost 51 ms at 1,000 addresses and 283 ms at 5,000. The queue they join is trimmed
the way the sensor's is, keeping an address a ban engine decided on over the newest
arrivals; it used to keep the newest 500 whatever they were. What a burst still
costs is one alert in the inbox for each source, about 20 ms apiece.

## What this review did not cover

- **A third party.** This is the project's own review, run with the tools above.
  It is not an independent audit, and it says what was done so that you can judge it.
- **The live Cloudflare API.** The GraphQL fields and the Workers Observability
  response were written from Cloudflare's documentation and from the operator's
  own report scripts, and the parsers accept the shapes those scripts handle. The
  first live run showed a difference (a Free zone refuses the grouped dataset) and
  the event read was added. **Test connection** is there so a first run says
  what differs.
- **The live Lists API.** The list requests, the asynchronous replace and the
  bulk-operation status were run against an in-memory model of the API, and the
  paths, the request body and the response fields were read again against
  Cloudflare's reference on the day of this review. **Preview** is there so the
  first live run changes nothing.
- **A production host's real logs and rules.** The firewall reader was run over
  realistic UFW and kernel records, not a live host's.
- **Windows and macOS agents.** They were read and linted with the same tools, and
  the routes they call were part of the fuzz, but the agents themselves were not
  driven on those platforms in this review.
- **A deployment you configured.** The scans ran against the shipped nginx
  configuration on plain HTTP. TLS, an IP allow-list in front of `/api/`, your
  identity provider and your own rules are yours; [security.md](security.md) says what
  to check.
