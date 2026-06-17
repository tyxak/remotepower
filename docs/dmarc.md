# Reputation/DMARC monitor

Track your mail-deliverability posture from the **Reputation/DMARC** page (under
Security in the sidebar). The page has three complementary halves:

- **IP reputation (DNSBL)** — add the IPv4 addresses you send mail from and
  RemotePower checks each against a set of **DNS blocklists** (DNSBLs such as
  Spamhaus, SpamCop, Barracuda). It shows which lists, if any, name each IP,
  re-scans periodically, and raises an **`ip_blacklisted`** alert when a
  monitored IP gets listed (auto-resolved when it clears).
- **DNS posture checks** — RemotePower reads each domain's published TXT records
  (`_dmarc`, SPF, optionally a DKIM selector) and grades them. Fast and
  synchronous; no mailbox required.
- **Aggregate reports via IMAP** *(optional)* — point RemotePower at the mailbox
  that receives your DMARC **RUA** aggregate reports. It polls that mailbox on a
  schedule (and on demand), parses the gzip/zip XML reports, and shows per-source
  SPF/DKIM pass/fail tallies plus a lightweight **mailbox health** view (message
  and unseen counts).

All three are read-only — RemotePower never sends mail or changes a DNS record.

## IP reputation (DNS blocklists)

Add an IPv4 address (your MX / smarthost / outbound mail IP) under **IP
reputation** and click **Check reputation now**, or let the periodic re-scan run.
For each IP the table shows whether it is **Clean** or **Listed on N** blocklists,
which lists, and when it was last checked. A newly-listed IP fires the
`ip_blacklisted` webhook/alert; clearing fires `ip_blacklist_cleared` and
auto-resolves the alert.

Endpoints: `GET /api/reputation/targets`, `POST /api/reputation/targets`,
`DELETE /api/reputation/targets/<id>`, `POST /api/reputation/scan`.

> **Resolver note:** some blocklists (Spamhaus in particular) refuse queries that
> arrive via large public DNS resolvers. For reliable results, the server should
> use its own or a private recursive resolver rather than a public one.

## What it checks

For each domain you add:

- **DMARC** — `_dmarc.<domain>`: the policy (`p=none` / `quarantine` / `reject`),
  `pct`, and whether an aggregate-report address (`rua=`) is set.
- **SPF** — `<domain>` TXT `v=spf1 …`: the `all` qualifier (`-all` hard-fail,
  `~all` soft-fail, `?all`/`+all` = effectively no protection).
- **DKIM** *(optional)* — `<selector>._domainkey.<domain>`: only checked when you
  give a selector (e.g. `google`, `default`, `s1`); confirms a public key is
  published.

## Grades

| Status | Meaning |
|--------|---------|
| **ok**   | Enforcing (`p=quarantine`/`reject`), `rua` set, SPF `-all`/`~all`. |
| **weak** | Enforcing, but with gaps (no `rua`, `pct<100`, soft SPF, missing DKIM). |
| **fail** | Not enforcing — no DMARC record, or `p=none`. The domain is spoofable. |

The page lists each domain with its grade and the specific findings. **Add
domain** prompts for the domain (and an optional DKIM selector); **Scan now**
re-checks every domain over DNS (fast, synchronous).

## Aggregate reports via IMAP

DMARC's value comes from the **aggregate (RUA) reports** that receiving mail
providers send back to the `rua=` address you publish. They're small XML
documents (gzip- or zip-compressed) summarising, per sending source IP, how many
messages passed or failed SPF and DKIM under your policy — the data that tells
you whether your legitimate senders are aligned and whether anyone is spoofing
your domain.

RemotePower can collect and parse those reports for you:

1. Create (or reuse) a mailbox that receives the RUA reports — i.e. the address
   in your `rua=mailto:` tag.
2. Configure its **IMAP** connection on the DMARC page (host, port, username,
   credential, folder).
3. RemotePower **polls that mailbox on a schedule and on demand**, downloads each
   report attachment, decompresses the gzip/zip payload, and parses the XML.

The page then shows **per-source pass/fail tallies** (which sending IPs are
passing or failing SPF/DKIM, and in what volume) alongside a **mailbox health**
summary (total message count and unseen/unread count) so you can confirm reports
are actually arriving. Parsed report state is stored in `dmarc_reports`.

## Endpoints

| Method | Path | Notes |
|--------|------|-------|
| GET    | `/api/dmarc/targets` | list domains + last result |
| POST   | `/api/dmarc/targets` | add a domain (admin) |
| DELETE | `/api/dmarc/targets/{id}` | remove a domain (admin) |
| POST   | `/api/dmarc/scan` | re-check all now over DNS (admin) |
| GET    | `/api/dmarc/reports` | parsed aggregate-report tallies |
| POST   | `/api/dmarc/fetch` | poll the IMAP mailbox now and ingest reports (admin) |
| GET    | `/api/dmarc/imap` | current IMAP mailbox config + health |
| POST   | `/api/dmarc/imap` | configure / update the IMAP mailbox (admin) |

DNS targets and results are stored in `dmarc_targets.json` / `dmarc_results.json`
in the data dir; parsed aggregate-report state lives in `dmarc_reports`.
