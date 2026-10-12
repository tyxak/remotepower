# Security review — v7.3.0

Like the one before it, this review does not cover the whole project, and says
so. It covers what is new in this release and changes who can influence what:
**a Cloudflare token the server stores and uses, two feeds the server reads from
outside (Cloudflare's firewall events and a honeypot Worker's log) and turns into
public reports, an agent reader for the host firewall's log, a second token
that can edit lists, with a sync that writes a list in the operator's account, and
a button that bans an address there and on hosts, and two automatic paths
that carry a block from one place to another: an edge finding to every Linux
agent, and a host's block to the edge.**

It found **ten** issues worth reporting. All were **caught before release**, by
reading the design against the threat model and then by the tests written for the
feature, and all are fixed in this release. None came from the field. The bar this
project holds itself to, that nothing Critical, High or Medium ships, is met for
what was reviewed.

## What was reviewed

- **The new server modules**: `edge_evidence.py` (requests, parsers and the
  reduction to evidence) and `edge_intel_handlers.py` (the poll, the status and the
  connection test).
- **The vocabulary change**: two new families, the honeypot's decision field and
  three new classes in `threat_evidence.py`, and who may send which.
- **The token**: how it is stored, scrubbed, redacted in exports and used.
- **The blocklist**: `edge_blocklist.py` (requests, parsers and the choice of what
  goes in the list) and `edge_blocklist_handlers.py` (the sync, its endpoints, the
  ban and unban endpoints and what the page reads), and the second token that can
  edit lists.
- **The two automatic paths in the sweep** (`ip_intel_handlers.py`): an
  edge-found address blocked on every Linux agent, and a host's automatic block
  banned at the edge.
- **The firewall-log reader** in the Linux agent.
- **The Threat intel page**, for what it prints from Cloudflare's answers.
- **Static analysis on the changed files**: bandit (no issue in the two new
  modules; nine older Medium findings in the agent file, none in the new code),
  semgrep's Python ruleset (151 rules, no findings), gitleaks over the tree (no
  leaks) and an undefined-name check on every Python and JavaScript file.
- **Each guard was run against a mutation** that removes the behaviour it
  protects, and has to fail: a challenge counted as a refusal, a list-carrying
  rule trusted, a policy source kept, the default family set widened back to all
  families, the outbound check dropped from the firewall reader, and its
  thresholds removed, the tenancy check on both automatic paths, and the
  never-block check on the edge ban.

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

## What this review did not cover

- **The live Cloudflare API.** The GraphQL fields and the Workers Observability
  response were written from Cloudflare's documentation and from the operator's
  own report scripts, which already query that API, and the parsers accept the
  shapes those scripts handle. They were not run against a real account in this
  review. **Test connection** is there so the first run says what differs. The
  first live run did: a Free zone refused the grouped dataset, and the event read
  was added, with the query shape cf-sniffcat uses on the same zones.
- **A production host's real logs and rules.** The firewall reader was run over
  realistic UFW and kernel records, not a live host's.
- **The live Lists API.** The list requests, the asynchronous replace and the
  bulk-operation status were written from Cloudflare's documentation and run
  against an in-memory model of it. **Preview** is there so the first live run
  changes nothing.
- **The rest of the project.** The whole-project reviews are the earlier ones.
- **Windows and macOS.** The agents there do not carry the sensor.
