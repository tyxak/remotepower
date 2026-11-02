# Reputation/DMARC monitor

Track your mail-deliverability posture from the **Reputation/DMARC** page (under
**Compliance** in the sidebar). The page has three complementary parts:

- **IP reputation (DNS blocklists)**: add the IPv4 addresses you send mail from and
  RemotePower checks each one against a set of **DNS blocklists** (DNSBLs). It shows which
  lists, if any, name each IP, re-checks every six hours, and raises an **`ip_blacklisted`**
  alert when a monitored IP is listed. The alert resolves when the listing clears.
- **DMARC / SPF / DKIM posture**: RemotePower reads each domain's published TXT records
  (`_dmarc`, SPF, and a DKIM selector if you give one) and grades them. The check is fast and
  needs no mailbox.
- **Aggregate reports (RUA) via IMAP** *(optional)*: point RemotePower at the mailbox that
  receives your DMARC aggregate reports. It polls the mailbox on a schedule (and on demand),
  parses the gzip or zip XML reports, and shows pass/fail tallies for each sending source,
  plus a **mailbox health** line (message and unseen counts).

All three are read-only. RemotePower never sends mail and never changes a DNS record.
Admins add and remove entries and start scans; any signed-in user can read the results.

## IP reputation (DNS blocklists)

Click **+ Add IP**, enter an IPv4 address (your MX, smarthost or outbound mail IP) and an
optional label, and RemotePower checks it at once. **Check reputation now** re-checks all of them.
You can add up to 200 IPs.

RemotePower queries six lists by default: Spamhaus ZEN, SpamCop, Barracuda, SORBS, UCEPROTECT
level 1 and PSBL. The page names the lists it is checking.

For each IP the table shows a status:

- **Clean** (green): no list names the IP.
- **Clean — N unreachable** (amber): no list that answered names the IP, but N lists could not
  be queried. See the resolver note below.
- **Listed on N** (red): N lists name the IP. The **Blocklists** column gives each list with its
  return codes, and a hover shows the reason the list gives (often a delisting link).
- **not checked**: the first check has not run yet.

The table also shows the label and when each IP was last checked.

**When an alert fires.** An IP has to be listed on **two scans in a row** before `ip_blacklisted`
fires (**Settings → Alert parameters → Reachability → IP-reputation confirm scans**, default 2),
so one blip does not page you. `ip_blacklist_cleared` fires, and the alert resolves, only
after a scan where every list answered and none named the IP. A scan where some lists could not be
queried never fires an alert and never clears one. Automatic re-checks run every six hours per
IP, up to 20 IPs per run. A manual check skips an IP that was checked less than a minute ago.

Endpoints: `GET /api/reputation/targets`, `POST /api/reputation/targets`,
`DELETE /api/reputation/targets/<id>` and `POST /api/reputation/scan`.

> **Resolver note (important).** Most public DNSBLs — Spamhaus, Barracuda,
> SpamCop, SORBS, UCEPROTECT — **refuse free queries that arrive via large public
> or shared DNS resolvers** (a cloud VM's default resolver usually forwards to
> one). When that happens the row shows **Clean — N unreachable** with a reason
> like *"query via a public/open resolver"* (Spamhaus code `127.255.255.254`) or
> *"rate-limited / daily query volume exceeded"* (`127.255.255.255`) — these mean
> the **query** was rejected, not that the IP is dirty.
>
> Two things matter, and both are about the **host that runs the scan** (the
> RemotePower server itself):
>
> 1. **It must use a resolver it can actually reach.** A LAN resolver (e.g. an
>    AdGuard/Pi-hole box at a private `10.x`/`192.168.x` address) is unreachable
>    from a cloud server unless you route to it over a VPN/tunnel.
> 2. **That resolver must do its own recursion, not forward to a public resolver.**
>    A *forwarding* resolver — which is what AdGuard Home and Pi-hole are by default
>    (they forward to Cloudflare / Quad9 / Google) — doesn't help: the DNSBL still
>    sees the query arrive from that public upstream and rejects it. DNSSEC doesn't
>    change this; it authenticates answers, it doesn't change who the query comes
>    from.
>
> The reliable fix is a **recursive resolver that talks straight to the
> authoritative nameservers** — e.g. run `unbound` (in recursive mode, *not*
> forwarding) on the RemotePower server and point its `/etc/resolv.conf` /
> systemd-resolved at `127.0.0.1`. You can also point AdGuard at a recursive
> upstream, but the simplest is unbound on the scanning host itself. For Spamhaus
> specifically, the free **Data Query Service (DQS)** works through any resolver:
> sign up for a key and query the `*.dq.spamhaus.net` zones. With recursion in
> place the lists answer normally and rows resolve to Clean / Listed.

### Setting up `unbound` for DNSBL lookups

Run `unbound` as a **recursive, validating** resolver (not a forwarder) and make
the host that runs RemotePower resolve through it. On Debian/Ubuntu
`apt install unbound`, on Arch `pacman -S unbound expat` (then fetch the root
hints / trust anchor as below).

`/etc/unbound/unbound.conf` — minimal recursive + DNSSEC config:

```
server:
    interface: 127.0.0.1
    access-control: 127.0.0.0/8 allow
    # DNSSEC validation (unbound-anchor seeds /var/lib/unbound/root.key)
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    harden-dnssec-stripped: yes
    prefetch: yes
    hide-identity: yes
    hide-version: yes
    # NOTE: do NOT add a `forward-zone:` — forwarding to a public resolver is
    # exactly what the DNSBLs reject. Unbound must recurse to the roots itself.
```

Enable it and point the host's resolver at it:

```
unbound-anchor -a /var/lib/unbound/root.key   # one-time DNSSEC anchor (ok if it warns)
systemctl enable --now unbound

# If systemd-resolved manages /etc/resolv.conf, stop it forwarding: in
# /etc/systemd/resolved.conf set  DNS=127.0.0.1  and  DNSStubListener=no ,
# then  systemctl restart systemd-resolved
# Otherwise just point resolv.conf straight at unbound:
printf 'nameserver 127.0.0.1\n' > /etc/resolv.conf
```

Verify recursion actually works (Spamhaus publishes a permanent test entry at
`127.0.0.2`, so the reversed query must return a `127.0.0.x` answer):

```
dig +short 2.0.0.127.zen.spamhaus.org @127.0.0.1   # -> 127.0.0.2 (and friends)
```

If it returns an answer, RemotePower's next scan will resolve the rows to
**Clean** or **Listed** instead of *Clean — N unreachable*.

**Already have unbound on another box** (e.g. a LAN resolver)? Point the scanning
host at *that* IP instead of `127.0.0.1` — but the scanning host must be able to
reach it (same LAN, or a VPN/tunnel for a cloud server), and that unbound must
listen on the shared interface and allow the scanner's network:

```
server:
    interface: 0.0.0.0                 # or the specific LAN/tunnel IP
    access-control: 10.0.0.0/24 allow  # the network the scanner is on
```

## What it checks

Click **+ Add domain** and enter the domain, and a DKIM selector if you want one checked. You
can watch up to 200 domains. For each domain RemotePower checks:

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

The table lists each domain with its grade, the DMARC, SPF and DKIM results, the specific
findings and when it was checked. **Scan now** re-checks every domain over DNS and answers at
once. RemotePower does not re-check domains on a schedule, so click **Scan now** after you change a
record. The grades raise no alert of their own, but they feed the email-authentication control on
the [Compliance](compliance.md) page: it fails for a domain that does not enforce DMARC or enforces
it with gaps, and reads *Not assessed* until a domain has been checked.

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
2. Click **IMAP settings** in the *Aggregate reports (RUA)* card and fill in the host, port
   (993 by default), username, password and folder (`INBOX` by default). Tick **Enabled**. The
   dialog also has **Use SSL/TLS**, **Verify TLS certificate** (untick it for an internal server
   with a self-signed certificate) and **Poll interval** (900 seconds by default, 300 at least).
3. RemotePower **polls that mailbox on the interval you set, and when you click
   Fetch reports now**. It downloads each report attachment, decompresses the gzip or zip
   payload, and parses the XML.

The page then shows a **Reporter / Domain / Policy / Window / Messages / Pass / Fail** table of
the reports, a **Sending sources** table (which IPs are passing or failing SPF and DKIM, and
in what volume, with the domains they send as and when they were last seen) and a **mailbox
health** line (total messages and unread count), so you can confirm reports are arriving.
**Clear reports** empties the reports, the sources and the mailbox status. Your IMAP settings
stay, and the next fetch reads the mailbox again from the start. RemotePower keeps the latest 300
reports, and the page lists the newest 100.

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
| DELETE | `/api/dmarc/reports` | clear the ingested reports and sources (admin) |

The IMAP password is never returned. `GET /api/dmarc/imap` only says whether one is set.

## Troubleshooting

| Problem | What to check |
| --- | --- |
| Every IP shows **Clean — N unreachable** | The server's resolver is a public or forwarding one. See the resolver note above. |
| An IP is listed on one scan but no alert came | It has to be listed on two scans in a row (see *When an alert fires*). |
| **Fetch reports now** ingests nothing | Read the mailbox line on the page for the IMAP error. Check the host, port, folder, and whether the certificate verifies. Reports arrive as `.gz`, `.zip` or `.xml` attachments. |
| The sender list is empty | Reports usually arrive once a day from each provider, so it takes a day or more after you publish a `rua=` address. |
| A domain shows **fail** though DMARC is published | `p=none` is monitoring only. Move to `quarantine` or `reject` once the reports show your own mail passing. |

## With multi-tenancy

The DMARC domains and their reports belong to the organisation that runs the installation. With tenant isolation on, only users of the default tenant can read them, and only the platform operator can change them.

## See also

[ip-intel.md](ip-intel.md) (reputation of addresses that attack you), [tls-monitor.md](tls-monitor.md)
(certificate and domain expiry), [dns.md](dns.md), [compliance.md](compliance.md).
