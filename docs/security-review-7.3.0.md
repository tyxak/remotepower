# Security review — v7.3.0

Like the one before it, this review does not cover the whole project, and says
so. It covers what is new in this release and changes who can influence what:
**a Cloudflare token the server stores and uses, two feeds the server reads from
outside (Cloudflare's firewall events and a honeypot Worker's log) and turns into
public reports, and an agent reader for the host firewall's log.**

It found **six** issues worth reporting. All were **caught before release**, by
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
  thresholds removed.

## Summary

| # | Finding | Before the fix | Where |
|---|---|---|---|
| 1 | One vocabulary and one reader: an agent could have claimed the honeypot's or Cloudflare's decision | Medium: a compromised host could make any address reportable at once | Server |
| 2 | A challenge would have been counted as a refusal | Medium: a report about a visitor the operator's own geo rule challenged | Server |
| 3 | A rule that also blocks an IP list, and IP access rules, would have been reported back | Low: circular reports, inflating the services' counts | Server |
| 4 | UDP and ICMP firewall records name the victim of a spoofed flood | Medium: a public report about the victim | Agent |
| 5 | The host name before a firewall record decided its verdict | Low: a machine called `blockhost` | Agent |
| 6 | A slow Cloudflare could hold the sweep up | Low: availability | Server |

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
- **The rest of the project.** The whole-project reviews are the earlier ones.
- **Windows and macOS.** The agents there do not carry the sensor.
