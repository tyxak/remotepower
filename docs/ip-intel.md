# Threat Intel: AbuseIPDB and SniffCat

RemotePower already notices when an address hammers a host with failed SSH
or web logins. Threat Intel builds on that. It can:

- **look up** the address with [AbuseIPDB](https://www.abuseipdb.com) and
  [SniffCat](https://sniffcat.com), so you can see whether it's a known
  scanner;
- **report** it back to both services, so other people benefit from what your
  hosts saw;
- **block** it for a while on the host it attacked.

All three are off until you turn them on. You'll find everything under
**Security → Threat Intel**.

The page has four tabs: **Attackers**, **Active blocks**, **Log sources** and
**Settings**. A fifth, **Traffic**, sits before **Settings** once you turn on the
[Traffic module](traffic.md); it shows which addresses your Linux hosts talk to and
marks the ones Threat Intel has a score for. A strip of counts above them shows the attackers, how many were
reported, how many are waiting for a lookup and the active blocks. An admin who
has turned on edge sources also sees **Feeds with a problem**. Click a count to
open the matching tab. The provider keys, the log sensor, firewalls and routers,
edge sources and the edge blocklist are all cards on **Settings**, and only
admins see them. **Check an address**, for a manual lookup, sits on the
**Attackers** tab and is for admins too.

If you also run a web server, a WAF, fail2ban or CrowdSec, the
[log sensor](#the-log-sensor) lets RemotePower read what those logs say about
each address, so a report says what the address actually did. If you run
Cloudflare or a honeypot, [edge sources](#edge-sources) bring in what they saw
too, and a firewall or router that sends its syslog to RemotePower can be read
as [firewall sources](#firewalls-and-routers).

## How it works

1. A host's sshd or web server logs failed logins. The brute-force detector
   counts them per source address. When an address crosses the threshold
   (**Settings → Alerting → Brute-force detection**, 20 attempts in 5 minutes
   by default), RemotePower raises an alert and queues the address for threat
   intel. The host's check-in only adds the address to the queue.
2. Once a minute, RemotePower works through the queue in the background.
   Private and reserved addresses are skipped. No lookup or report happens
   during a host's check-in, so a slow provider can't hold up your fleet.
3. **Lookup.** Both services are asked for the address's confidence score
   (0–100). The higher of the two is used, along with the report count,
   country and network owner. Answers are reused for 24 hours.
4. **Report.** If reporting is on and the address made at least the number of
   attempts you set (default 10), it's reported to each service at most once a
   day. The categories used are SSH and brute-force for sshd, and web attack
   and brute-force for web logins. An address that is never blocked (see
   [Blocking](#blocking)) is never reported either.
5. **Block.** If blocking is on and the score reaches your threshold (default
   90), the host it attacked gets a firewall rule that drops its traffic. The
   rule is removed again after the hours you set (default 24). With **Also block
   addresses that fail2ban, CrowdSec or a honeypot has already banned** ticked, an
   address one of them has banned is blocked without waiting for a score. See
   [Block what a ban engine already banned](#block-what-a-ban-engine-already-banned).

## The log sensor

Out of the box RemotePower learns about an attacker from failed SSH logins and
a few web patterns. The log sensor reads more. Switch it on under
**Security → Threat Intel**, on the **Settings** tab in the **Log sensor** card, and the agent on each Linux
host reads these, read-only, once a minute:

| Log | What it tells RemotePower |
|---|---|
| Web server access logs (nginx, Apache) | Requests that look like SQL injection, path traversal, code execution, a scan for exposed files, or login brute force, and whether the server answered them |
| Web server error logs | ModSecurity messages, rate-limit trips, failed basic-auth logins, requests the server refused, and the lines CrowdSec's nginx bouncer writes when it refuses a request on AppSec's verdict |
| ModSecurity audit log (native or JSON) | Which rules fired, and whether the WAF blocked the request |
| fail2ban's log | Which addresses it saw failing, which it banned, and in which jail |
| CrowdSec | The alerts its own scenarios raised on this host, including AppSec |
| Firewall log (UFW, kernel `LOG` records) | Addresses the firewall refused on several ports, or many times, within a minute |
| Suricata (`eve.json`, `fast.log`) | The alerts of an intrusion detection system on this host that name an attack |

The agent finds the files from the web server's own configuration (nginx
`access_log` and `error_log`, Apache `CustomLog` and `ErrorLog`, ModSecurity's
`SecAuditLog`), and reads each one in the layout its `log_format` declares, so
a custom format works without setup. A host with no configuration is covered by
the standard paths. Add anything else under **Extra log files**: up to 20,
each a file under `/var/log`.

### The firewall log

The agent reads `/var/log/ufw.log`, or `/var/log/kern.log` when there is no
UFW log, for records the firewall wrote when it refused a packet. One refused
packet means nothing on a public address, so an address only counts as a scan
when, within one minute, it tried **four different ports** or had **fifteen
packets** refused. Only inbound TCP refusals count. Allowed and audited records,
outbound packets, private source addresses, and UDP and ICMP are ignored. The
source address of an unsolicited packet is whatever the sender wrote, and UDP
and ICMP are what a flood forges, so a report built on them could name its
victim.

The firewall has to log for this to see anything. With UFW that is `ufw logging
low`. A host whose firewall is off, or does not log, shows its log as quiet on
the **Log sources** card, which is true.

### Suricata on the host

If Suricata runs on the host, the agent reads the logs it writes, `eve.json` and
`fast.log` in its log directory (`/var/log/suricata`, or the `default-log-dir` in
`/etc/suricata/suricata.yaml`). Either file is enough and both can be read: an alert
that is in both is counted once. Add a file of another name under **Extra log files**
(a name that starts with `eve` and ends in `.json`, or starts with `fast` and ends in
`.log`).

An alert counts when its signature or classification names an attack, in the same
classes and by the same rules as the alerts of a firewall's Suricata (see
[Firewall sources](firewall-sources.md#suricata)): remote code execution, SQL
injection, a scan and so on. The reputation lists, the policy and information rules,
the malware rules and anything outbound name no attack and are read and dropped. The
other events in `eve.json` (flows, DNS, TLS, statistics) are read and not used. A
record that is longer than the agent keeps is read from its start, where the address,
the signature and the category are.

An address is sent once it has three alerts, counted across minutes, and is reported
when the count reaches **Report after attempts**, like a web address. Private and
reserved addresses, and Cloudflare's, are dropped. The agent has to be able to read the
files, which Suricata usually makes readable by root only. On the **Log sources**
card the host shows `Intrusion detection alerts` with the path, and `No permission`
when the agent cannot read it.

The sensor is off by default and works on Linux agents only. It does nothing
to the logs it reads and runs in its own thread, so a slow or broken log can
never delay a heartbeat.

### What is sent

Per address: counts and a short list of fixed labels, such as `SQL injection`,
a WAF rule number, a CVE id the logs named, the name of a fail2ban jail, or the
name of the CrowdSec scenario or AppSec rule that decided on it.

With **Send up to three request samples with each address** ticked (on the
**Settings** tab of Threat Intel, in the **Log sensor** card; it is ticked by
default), up to three samples go with it. A sample is one request the address
made: the method, the path, the status and which log it came from. The path has
no query string, because that is where a request keeps what it carries. It ends
at a path parameter (`;name=value`), at a URL inside the path and at any
character other than letters, digits and `. _ ~ / % + -`, and it is at most 80
characters, so a session id or a host name does not reach RemotePower in one.
Headers, host names, user names and log lines never leave the host. Untick the
box and hosts send counts and fixed labels only, as they did before 8.0.1.

RemotePower does not trust the agent. It rebuilds every sample from parts it
checks itself (the method from a list of ten, the path through the same cut, the
status as a number) and drops what does not fit. A host is root on a machine an
attacker may be on, and the text of a request is whatever its sender typed, so
nothing is kept as it arrived and the page escapes what it shows. The AI
features never read samples.

The same box covers the [edge sources](edge-sources.md). With it ticked,
RemotePower keeps the method and the path of up to three requests per address
that Cloudflare refused or your honeypot Worker answered, cut the same way. It
never asks Cloudflare for a query string, a host name or a user agent.

Samples are there for you to read. They sit in the details of each address on
the **Attackers** tab, next to the CrowdSec scenarios and the rules that named
it, and they change nothing about what is reported or blocked. A request that
was refused but that nothing called an attack is kept in the agent's memory for
15 minutes and sent only if fail2ban, CrowdSec or the WAF then decides on the
address: it is what the ban was for. A report carries them only if you tick
**Add a few example requests to reports**, see
[Examples at the end of a report](#examples-at-the-end-of-a-report).

### When an address is reported

An address is reported when **any** of these is true:

- fail2ban banned it;
- one of CrowdSec's own scenarios raised a ban on this host (a community
  blocklist entry or a decision someone made by hand does not count);
- the WAF on a host refused its requests as many times as **Report after WAF
  refusals** says (1 by default). A request CrowdSec's nginx bouncer refused on
  AppSec's verdict counts as a WAF refusal;
- Cloudflare refused its requests as many times as **Report after Cloudflare
  refusals** says (1 by default, see [Edge sources](#edge-sources));
- it made as many hostile requests as **Report after attempts** says (10 by
  default).

What it does adds up for a day, so a slow attacker still counts. The page says
why an address has not been reported yet and names the nearest of these routes,
for example `4 / 10 attempts so far` or `2 / 3 WAF refusals so far` (when you
have raised the WAF number). An address
with no attack category for what the logs showed is never reported. The page
names the CrowdSec scenario or the fail2ban jail that has none, so you can see
what it was.

### What a report says

The categories follow what was seen:

| Seen | AbuseIPDB | SniffCat |
|---|---|---|
| SSH brute force | 18, 22 | 17, 18 |
| Login brute force (web) | 18, 21 | 17, 21 |
| SQL injection | 16, 21 | 12, 21 |
| Path traversal | 21 | 16, 21 |
| Code execution attempts | 15, 21 | 13, 21 |
| Probing for configuration files, keys and backups | 15, 21 | 11, 21 |
| Downloading files from a decoy backup or repository | 15, 21 | 11, 21 |
| Any other kind of probing | 21 | 21 |
| Attack tools and scanners | 19, 21 | 5, 21 |
| RDP brute force | 18 | 17, 22 |
| SMB brute force | 18 | 17, 24 |
| Telnet brute force | 18 | 17, 23 |

Probing has kinds, and a report names the kind when the source can tell it:

| Kind | What the address asked for |
|---|---|
| Probing for configuration files, keys and backups | `.env`, `.git`, a key file, a database dump, a backup archive |
| Probing for admin, login and debug pages | phpMyAdmin, `server-status`, a login page your site does not have |
| WordPress probing | The installer, a plugin's readme, the debug log, the uploads directory |
| User enumeration | The list of a site's users |
| Open proxy probing | A request that asks your server to fetch another site |
| Probing private host names | A host name you keep for yourself, or a decoy one |
| Probing with unusual HTTP methods | `TRACE`, `PROPFIND` and others a browser never sends |
| Downloading files from a decoy backup or repository | A file from the honeypot's fake backup directory or fake git repository |

A source that can only say an address was probing still says `probing for
exposed files and admin pages`. Until 8.0.1 every kind was reported with that one
sentence. A service's login has kinds too: RDP, SMB, Telnet and database logins
are named, and anything else is `service login brute force`.

Mail, FTP, request flooding and port scans have their own
categories too. The standard message is the same for every report and names the
attack and where it was seen, for example `SQL injection and path traversal: 41
attempts within 10 minutes, seen by web server log and WAF (reported by
RemotePower)`, so it says "brute force" only when that is what happened. You can
write your own (see [The report message](#the-report-message)). For a report
built from the logs, AbuseIPDB also gets the time the attack happened.

Each sweep that reports addresses raises one **Addresses Reported** alert
(`ip_reported`) that names up to five of them and counts the rest, so a busy hour
is one line and not one message per address. It is news, not a fault: it goes to the
inbox and the activity feed, and to Needs Attention and webhooks only if you turn
those on for the **Threat Intel reports** kind under **Settings → Alerting → Channel
routing**. It is not sent when tenant isolation is on.

An address is reported once per service per sweep, however many hosts or logs
saw it. If a service answers that it was reported moments ago, RemotePower
counts it as reported instead of retrying. **Evidence → Details** on the
Attackers table shows exactly what was sent to each service.

On a multi-tenant install, an address that the hosts of two tenants both saw has
one row. Each tenant reads the evidence its own hosts collected (the request
paths, the jail names, the CVE ids, the counts) and none of the other tenant's.
The platform operator reads the sum. A report is made from the evidence of every
host that saw the address, so when it includes a host you cannot see, you are told
that the address was reported and what the service answered, but not the text that
was sent. The reason an address was not reported yet, such as `7 of 10 attempts so
far`, is held back the same way.

### Examples at the end of a report

A report is public on both services, and what other people want to see in it is
the request. Tick **Add a few example requests to reports** (on the **Settings**
tab of Threat Intel, in the **Limits and report message** card) and a report
about a web attack ends with up to three of the requests the logs showed, for
example `Examples: GET /wp-login.php (404), POST /xmlrpc.php (403)`. It is off
until you turn it on, and it is narrow:

- It is only for an address whose every attack class is a web one. A request
  line says nothing about an SSH brute force, so a report about SSH, mail or
  another login carries none, and neither does one about an address seen doing
  both.
- Each example is rebuilt from the stored sample when the message is made: a
  method from a fixed list, a path of letters, digits and `. _ ~ / % + -` with
  no query string, and a status. No host name, user name or query string is in
  one. The message is plain ASCII, and an example that would not fit in the
  1,000 characters a report may have is left out whole.

Look at the requests on the **Attackers** tab first. An address that your own
software banned by mistake would put a path from your site on a public page.

### If fail2ban reports too

fail2ban's own AbuseIPDB and SniffCat actions report each ban on its own. An
address that several jails ban is reported several times, and the services
refuse a second report of the same address within 15 minutes (AbuseIPDB) or 20
minutes (SniffCat). If you let RemotePower do the reporting, turn those actions
off. If you leave them on, nothing breaks: a report the service calls a repeat
is treated as already done.

The log sensor checks for this. It reads `jail.local`, `jail.d` and `fail2ban.local` on each
host, and when an uncommented line names AbuseIPDB or SniffCat it adds a note under the Log
sources table naming the host and the services.

### Behind Cloudflare or another proxy

If your web server logs the proxy's address instead of the visitor's, every
request seems to come from the proxy. RemotePower ignores Cloudflare's
published addresses and says so on the **Log sources** card, with how many it
ignored.

This holds for every source, not only the web log: the WAF, fail2ban,
CrowdSec, a firewall's refused packets, intrusion detection alerts, the edge
feeds and a host's own brute-force counter. A Cloudflare address is dropped where
each source is read and again at the intake they all share, so it is never
looked up, reported, blocked or banned. If one still reaches the last step, the
row says `not reported: a Cloudflare edge address`. You do not need to add
Cloudflare's ranges to **Never report these addresses**. The list is the one
Cloudflare publishes (15 IPv4 and 7 IPv6 ranges, compared with
`cloudflare.com/ips-v4` and `/ips-v6` on 2026-11-07). Restore the visitor's address (nginx `real_ip_header`, Apache
`mod_remoteip`) and the real addresses are counted. A web attack that arrives
through a proxy is never blocked on the host, because a firewall rule on the
host would not match it.

### Limits

- An agent sends at most 300 addresses at a time, and a host can add at most
  3,000 an hour, so one host cannot use up your day's reports.
- Each pass reads at most 8 MB of a log. A log seen for the first time is read
  from its last 2 MB, and nothing older than six hours counts.
- A plain web address is sent after 3 hostile requests in a pass, or at once if
  fail2ban, CrowdSec or the WAF flagged it.
  A slow scanner is still caught: the agent keeps what it saw of an address
  under 3 (up to 2,000 addresses, for six hours) and adds it to the next pass.
- Network work is limited to 25 addresses a sweep, strongest first, so a short
  daily allowance goes to the addresses that earned it.

## Firewalls and routers

A firewall or router has no agent, but it can send its syslog to RemotePower, and
the server can read that for the same evidence a host's sensor sends: addresses
that scanned it, connected to a decoy port, tripped Suricata or CrowdSec, or
failed to sign in. Switch it on under **Security → Threat Intel**, on the **Settings** tab
in the **Firewalls and routers** card. It reads and reports; it blocks nothing on the firewall
or router. Off until you turn it on.

| Source | What counts |
|---|---|
| Refused packets (OPNsense, pfSense, MikroTik RouterOS) | 10 different ports, or 25 refused packets, within 30 minutes |
| A decoy port (MikroTik RouterOS) | Two connection attempts; reported at once |
| Suricata alerts (OPNsense) | An alert whose signature names an attack |
| CrowdSec alerts (OPNsense) | One of its own scenarios raised the alert |
| Failed sign-ins (RouterOS, OPNsense) | The brute-force threshold |

The setup for each, the formats it reads and what to check when nothing shows
are in [Firewall sources: OPNsense and MikroTik](firewall-sources.md).

## Edge sources

Your hosts are not the only place an attack shows up. Cloudflare refuses
requests before they reach your server, and a honeypot catches scanners that no
host log ever sees. RemotePower can read both and report what they show, the same
way it reports what your hosts' logs show.

Reading does not block anything: banning stays with whatever you already use,
such as ModSecurity, CrowdSec, fail2ban or Cloudflare's own rules. Off until you
turn it on, under **Security → Threat Intel**, on the **Settings** tab in the **Edge sources** card. The
[edge blocklist](#the-edge-blocklist) below is a separate card, with its own
switch and its own token.

| Source | What you get |
|---|---|
| Cloudflare firewall events | The requests Cloudflare refused, by address, with the mechanism that refused them |
| Honeypot Worker log | The traps a visitor tripped, and whether your Worker banned the address |

RemotePower asks Cloudflare for counts grouped by address, mechanism and rule.
The grouped view holds no request, so nothing a visitor typed is fetched.

A Free plan has no grouped view. Cloudflare refuses it with `zone '…' does not
have access to the path`, and RemotePower then reads that zone's events one at a
time and groups them itself. It asks for four fields (address, action, source and
rule). With **Send up to three request samples with each address** ticked it also
asks for the path, the method and the time of each refused request, and keeps up
to three per address as samples; see [What is sent](#what-is-sent). The query
string, the host name and the user agent are never asked for. A path reaches a
report only when you tick **Add a few example requests to reports**. Each zone is
asked on its own: a zone Cloudflare refuses is named on the **Edge feeds** card
and does not hold back the others.

### What counts

Only a **refusal** by a mechanism that means "this looked like an attack":

| Counts | Does not count |
|---|---|
| Managed rules, your own custom rules (action block), rate limiting rules, HTTP DDoS protection, Bot Fight Mode, Bot Management, Browser Integrity Check, user-agent block rules | Challenges and log-only actions, country and ASN rules, the security level, IP access rules, and rules that also block an IP list |

The last two are left out for a reason. An IP access rule is a ban that
fail2ban, CrowdSec or your honeypot already decided on, so counting the requests
it blocks would report the same address again. A rule that also blocks an IP
list refuses addresses for being on a community blocklist, which is not
something they did to you. The **Test connection** button lists your custom
rules and marks the ones that name an IP list. If you want them counted anyway,
tick **Count refusals by a rule that also blocks an IP list**.

An address is reported after **Report after Cloudflare refusals** refusals by
Cloudflare, which is 1 unless you change it: the refusal is a block your own
rules or Cloudflare's already made. A host's WAF works the same way with **Report
after WAF refusals**, also 1 by default. A weaker mechanism
(Bot Fight Mode, Browser Integrity Check, a user-agent rule) only counts towards
**Report after attempts**. The reason an address has not been reported yet names
the nearest route, for example `1 / 3 Cloudflare refusals so far`. When you
lower the number, addresses counted in the last day are reported on the next
sweep.

### The honeypot

The honeypot Worker logs every trap hit with its own decision. RemotePower reads
those lines and files each trap under an attack class:

| Trap | Filed as |
|---|---|
| Loot and exploit paths, and opening the fake backup directory | Probing for configuration files, keys and backups |
| Fake admin and login pages | Probing for admin, login and debug pages |
| WordPress files on a site that is not WordPress | WordPress probing |
| The WordPress user list | User enumeration |
| Private host names and decoy host names | Probing private host names |
| Walking the fake backup directory, taking a file from it, or dumping the fake git repository | Downloading files from a decoy backup or repository |
| A path only `robots.txt` names | Unwanted web crawling (a bot that ignores `robots.txt`) |
| A crawler claiming to be a search engine from the wrong network | Unwanted web crawling (user-agent spoofing) |
| A credential the honeypot handed out being used | Using a credential planted in a decoy file |
| Signing in to a decoy service | Signing in to a decoy service |

A report from the honeypot reads, for example, `using a credential planted in a
decoy file: 1 attempt within 1 minute, seen by edge honeypot (reported by
RemotePower)`. One built from Cloudflare's events reads `WordPress probing: 8
attempts within 10 minutes, seen by Cloudflare WAF (reported by RemotePower)`.

For a custom rule of yours, RemotePower picks the kind from the words of the
rule's description, so say in it what the rule blocks: "sensitive files",
"WordPress", "admin panels", "user enumeration", "unusual methods", "private
hosts", "SQL injection". **Test connection** on the Edge sources card lists
your rules. A rule whose description names no kind is reported as `requests
blocked by a web application firewall`.

The Worker's own ban counts as a decision, like fail2ban's. An address it banned
is reported at once. Hits it only counted wait for **Report after attempts**, with
two exceptions you control on the Edge sources card: one hit on a bait path decides
by default (**Count one hit on a bait path as decided**), and a planted credential or
a decoy sign-in decides once you tick **Count a planted credential or decoy sign-in
as decided** ([the settings](edge-sources.md#step-3-enter-it-in-remotepower)).
Addresses the Worker never bans (yours, Cloudflare's shared ones, countries you
exempt) are not reported on its word alone. Lines it logs only to be read, such
as a self-test, are not evidence.

If you do not run a honeypot yet, [Run a honeypot Worker on Cloudflare](honeypot-worker.md) builds a small one.

### Set up the edge feeds

[Edge sources: Cloudflare](edge-sources.md) is the step-by-step guide: the token
and its permissions, the account id, Test connection, what each card shows and
what to do when Cloudflare refuses a read. In short: create a read-only token
(Zone: Zone, Analytics and Zone WAF; Account: Workers Observability, for the
honeypot's log), paste it with your account id on the **Settings** tab of **Security → Threat Intel**,
in the **Edge sources** card, press **Test connection**, and tick the switch.

RemotePower reads every ten minutes (every five at the fastest). A read never
goes back further than six hours, as with the host logs, so a pause longer than
that loses what it held. An unticked feed shows as off.

### The edge blocklist

Edge sources reads. The edge blocklist writes one thing: a Cloudflare IP list. It
builds the list from the sources you pick (your own entries, the addresses
RemotePower found, AbuseIPDB's blacklist and SniffCat's blacklist) and keeps it
up to date, so a rule of yours that says `ip.src in $your_list` keeps blocking
what they report. RemotePower never creates or edits a rule.

It is off until you turn it on, and it needs a second token that can edit lists
(Account Filter Lists: Edit). A list it did not create is left alone until you
tell it to take the list over. Its guards, the sources' settings and what to do
when it holds a sync are in
[Edge sources: Cloudflare](edge-sources.md#edge-blocklist).

### If other scripts report the same things

Scripts that report Cloudflare events or UFW blocks to AbuseIPDB or SniffCat
report on their own, usually every hour or two. The services refuse a second
report of the same address within 15 and 20 minutes, and RemotePower counts that
as already reported, so nothing breaks. When the feeds here work, stop those
scripts, so each address is one report with all the evidence. Keep whatever bans.

## Set it up

1. Create API keys:
   - AbuseIPDB: sign in, then **Account → API**. The free plan allows 1,000
     lookups and 1,000 reports a day.
   - SniffCat: sign in, then **API**.

   You can use one service or both.
2. **Security → Threat Intel**, **Settings** tab, **Providers** card: paste the keys and tick
   what you want (**Look up attacking addresses**, **Report attackers back to
   both services**, **Block high-scoring attackers on the host they attacked**).
   Keys are write-only. The page shows that a key is saved, never the key
   itself.
3. Save.

### Limits on API use

Each service has its own daily limits, and you set them on the same page:

| Setting | Default | What it does |
|---|---|---|
| **Lookups per day (each service)** | 900 | Stops asking a service once it has been asked this many times today. |
| **Reports per day (each service)** | 900 | Stops reporting to a service once it has been sent this many reports today. A report the service did not answer (a network failure or an HTTP 5xx error) does not count. |
| **Lookups, reports and blacklist downloads per day, for one service** | blank | A service's own number replaces the general one for that service. A blank box uses the number above, and downloads use 4 a day. Use it when a plan allows more than the free one: AbuseIPDB's free plan is about 1,000 lookups and reports and 5 downloads a day, and another plan or service can allow far more. |
| **Reuse a lookup for (hours)** | 24 | How long an answer is kept before the same address is asked about again. |
| **Report after attempts** | 10 | How many failed attempts an address needs before it is reported. |
| **Report listed addresses after blocks** | 3 | How many times a firewall must block an address that is on a reputation list (Spamhaus, Dshield, CINS) before it is reported as port scanning. 0 keeps those hits as context only. See [Firewall sources](firewall-sources.md). |
| **Report after WAF refusals** | 1 | How many requests the WAF on a host must have refused before an address is reported. Raise it if a single refusal is too little for you. |

The defaults stay under AbuseIPDB's free plan of 1,000 a day. Days run in UTC.
When a limit is reached, RemotePower stops until the next day and says so in the
address's row. Use `0` to switch lookups or reports off for that service. The
page shows how many have been used today.

Each host has a share of every daily limit: the limit divided by the number of
Linux agents (and by one for each edge feed that is switched on), and never less
than 5. A host whose evidence has used its share is not looked up or reported
for until tomorrow, and the limit that is left stays for the hosts that have not
used theirs, so a host that sends made-up addresses cannot spend the allowance
of the others. The address's row says `not reported: this host has used its
share of the day's report limit`. With one host the share is the whole limit.
When one host is busy and the others are quiet, raise **Lookups per day** and
**Reports per day**; the shares grow with them.

### Check an address by hand

Type a public address into **Check an address** on the Attackers tab and press
**Look up**. RemotePower asks both services at once, ignores the saved answer
and counts the lookups against today's limit. It needs at least one saved key,
and it is for admins. The private and reserved ranges are refused.

### See what was sent

The **Request log**, on the **Log sources** tab, lists the last 150 lines of two kinds. Only the platform operator sees it.

- **What RemotePower sent** to AbuseIPDB and SniffCat: the time, the service, whether it was a lookup, a report or a blacklist download, the address, the answer (the HTTP status and what it came to), how long it took and the service's own sentence.
- **What your hosts sent** (a **Sensor report**): the time, the host, the first address of the pass and how many were queued, held back by the hour's limit or set aside, with the addresses.

Keys, headers and the text of a report are never shown. RemotePower keeps the last 300 requests and the last 200 passes of the hosts, and deleting a host removes the passes it sent.

When a service fails, its line says so, for example `500 Server error` with the service's message, or `No answer`. A service that fails three times in a row in one pass is left alone for the rest of that pass, and the address waits ten minutes before that service is asked about it again. None of this counts against your daily limits.

If an address you expected is missing, look for it here. A sensor report with the address means the server received it. Lookup and report lines for it mean it was handled. The Linux agent also writes a line to its own log each time its log sensor sends addresses (`threat sensor: 2 addresses sent (ok): …`) and a warning when a send or a pass fails, so the host's side of the trail can be read too.

### The report message

Every report carries the standard text unless you write your own in **Report
message** on the same page. The standard text is the same for all of them and
names what was seen:

`{attack}: {count} attempts within {minutes} minutes, seen by {seen_by} (reported by RemotePower)`

A report built from the logs reads `SQL injection and path traversal: 41
attempts within 10 minutes, seen by web server log and WAF (reported by
RemotePower)`. One from the SSH counter reads `SSH brute force: 42 attempts
within 10 minutes, seen by system log (reported by RemotePower)`. One from the
web counter, which counts WordPress login posts and any 401 or 403, reads `web
login attempts and refused requests: 25 attempts within 5 minutes, seen by web
server log (reported by RemotePower)`.

Your own text can use five placeholders:

| Placeholder | Becomes |
|---|---|
| `{attack}` | what was seen, in fixed words: `SQL injection`, `path traversal`, `SSH brute force` |
| `{seen_by}` | which logs saw it: `web server log and WAF` |
| `{count}` | the number of attempts |
| `{minutes}` | the time window, in minutes |
| `{what}` | a short noun, for example `SSH`, `web login`, `web`, `mail login`, `RDP`, `port` or `login` |

For example, `{attack}, {count} attempts in {minutes} minutes` is sent as `SQL
injection, 41 attempts in 10 minutes`. It needs at least 10 characters, because
SniffCat refuses anything shorter, and at most 300. There is no placeholder for
a host name, so one can't end up in a public report by accident. Don't type
one. Clear the box to go back to the standard text.

## Ignore what you do not want reported

Some addresses are yours to ignore: a partner's scanner, a monitoring service, a
customer's office. Some kinds of attack are not worth a public report. Two lists
under **Limits and report message** and a button on each attacker say so.

| Setting | What it does |
|---|---|
| **Never report these addresses** | One address or network per line, up to 500, none wider than a /8 (IPv4) or /16 (IPv6). An address on it is never reported to AbuseIPDB or SniffCat. |
| **Never report an address when all it did was** | Tick the kinds of attack. An address is held back when everything it did is a kind you ticked. If it did anything else as well, it is reported as usual. Probing and a service's login each have finer kinds, listed under them. Ticking the general kind covers its finer kinds, so a list that ignored probing before 8.0.1 ignores the same addresses now. |
| **Ignore** on an attacker's row | Adds that one address to the first list, after asking. It is not shown on an address the list already covers. |

Ignoring only ever does less in public. An ignored address is still recorded and
looked up, and it is blocked when auto-block is on. **Never block or report**,
above, stops that too. The evidence is kept, so taking an address off the list
reports it on its next sighting if it qualifies. A report that was already made
is not taken back.

The status column says `on the ignore list` for an address on the first list and
`not reported: only attacks you ignore` when the second list held it back. The
[edge blocklist](#the-edge-blocklist) still takes high-scoring addresses from the
table, ignored or not: the ignore lists change reporting and nothing else. On a
multi-tenant install only the platform operator can change them.

## What leaves your network

| Action | What is sent |
|---|---|
| Edge read | A request to `api.cloudflare.com` with your read-only token, once every few minutes. Nothing about your hosts. |
| Blocklist sync | Requests to `api.cloudflare.com` with your list token: the list's name, its entries, and a comment on each entry saying which source it came from. Nothing about your hosts. |
| Blacklist download | A request to AbuseIPDB and to SniffCat with your key, at most four a day for each. Nothing about your hosts. |
| Lookup | The attacking address. |
| Report | The attacking address, the attack categories, a one-line comment, and, for a report built from the logs, the time of the attack (AbuseIPDB only). The standard text reads "SQL injection and path traversal: 41 attempts within 10 minutes, seen by web server log and WAF (reported by RemotePower)"; you can change it (see [The report message](#the-report-message)). With **Add a few example requests to reports** ticked, a report about a web attack also ends with up to three requests: the method, the path without its query string and the status. |

Hostnames, user names, log lines and your own addresses are never sent. The one
thing in a report that an attacker typed is the path of an example request, and
only when you turn examples on.

The address is the one sshd logged the connection from, not anything the
client typed. sshd writes the user name a client asks for into the same log
line, before the real address, so a login as `x from 203.0.113.9` puts a
second address in the line. RemotePower reads the last address, the one
followed by `port`.

## Blocking

Blocks run through the normal command queue, so everything that applies to a
person's command applies here too. Nothing is sent to a host in maintenance
mode, quarantine or audit mode, and with four-eyes approval on, a block waits
for a second admin.

The thresholds are on the **Providers** card of the Settings tab: **Block at
score** (90), **Block for (hours)** (24) and **Blocks per host per hour** (20).

On the host, the block uses whichever firewall is active: `ufw`, then
`firewalld`, then plain `iptables` / `ip6tables`. A `ufw` or `iptables` rule
carries the comment `rp-ipintel`, so you can find it with `ufw status` or
`iptables -S`. A `firewalld` rule is a rich rule on the address and has no
comment.

These addresses are **never** blocked:

- private, loopback, link-local and other non-public ranges;
- every address your hosts report as their own;
- the addresses on your UI IP allow-list (Settings → Security);
- anything on the **Never block** list on the Threat Intel page;
- addresses people signed in to RemotePower from in the last 30 days, whether
  with a password (LDAP too), a passkey, SAML or OIDC, and addresses
  SSH-gateway sessions came from in that time.

Two limits stop a runaway. A host gets at most 20 automatic blocks an hour,
which you can change with **Blocks per host per hour**. An address one of the
services lists as legitimate (its whitelist) is never blocked.

Blocking needs a Linux agent. You can also block or unblock by hand from the
page, which needs the **command** permission on that host.

With the [edge blocklist](#the-edge-blocklist) on, an address that automatic
blocking blocks is also banned at the edge for the same time, so a visitor who
arrives through Cloudflare is stopped as well (at most 50 automatic edge bans
an hour). **Also block addresses found at the edge on every Linux agent** goes
the other way: an address that only Cloudflare or the honeypot saw gets the
block on every Linux agent that is online, up to 100 hosts a sweep. A host that is off is left out, so nothing piles up in its queue. It needs automatic
blocking and stays off on a multi-tenant install. The details are in
[Edge sources: Cloudflare](edge-sources.md#the-attackers-list).

### Block what a ban engine already banned

A new scanner has no reputation yet: AbuseIPDB and SniffCat score an address 0 until others have reported it. So by default an address that fail2ban banned in three jails is
not blocked by RemotePower, because its score is below the threshold. The ban is on the host that made it, and RemotePower adds nothing to it.

Tick **Also block addresses that fail2ban, CrowdSec or a honeypot has already banned, whatever their score** (on the **Settings** tab of Threat Intel, in the **Providers** card; it needs automatic blocking on)
and an address one of these banned is treated like a high-scoring one:

- **fail2ban**: a `Ban` line in its log. A `Found` line is a failure, not a ban.
- **CrowdSec**: a scenario of its own decided on the address.
- **The edge honeypot** and **a decoy port**: the address used a planted credential or a decoy, which no ordinary visitor does.

It is blocked on the host that saw it and, with the [edge blocklist](#the-edge-blocklist) on, banned at the edge for the same hours. For a site behind Cloudflare the edge ban is the one that
stops the visitor, because a rule on the host does not match a proxied visitor. The row in **Active blocks** says `automatic · fail2ban` (or `CrowdSec`) so you can tell it from a block made
by score, and the audit line ends in `confirmed=`.

Everything that protects an address still applies: your own hosts, your allow-list, recent logins, the never-block list, Cloudflare's addresses, an address a provider lists as
legitimate, the hourly limit per host and the cap on automatic edge bans. Know what you are trusting. The decision is made by the software on your hosts, so a host you do not trust can
get an address banned at the edge this way, up to the hourly cap. Leave the box unticked if one of your hosts is not under your control.

### Ban by hand

**Ban** on a row opens a dialog that bans the address in the two places
RemotePower can act: at the edge (the Cloudflare list the
[edge blocklist](#the-edge-blocklist) keeps) and on hosts (the same firewall rule a
block queues, to the hosts that saw it or to every Linux host). They are separate
choices because they stop different traffic: a visitor proxied by Cloudflare
arrives from Cloudflare's addresses, so a rule on a host only stops connections
that reach it directly, and the edge ban is what stops the visitors behind the
proxy. The edge half needs the edge blocklist on with a token and is for the
platform operator; the host half needs the **command** permission on each host and
is skipped for a host that is not a Linux agent you can reach.

Nothing here lifts the protections above: your own hosts, your allow-list, recent
logins, the never-block list, Cloudflare's addresses and private addresses are
refused. A ban lasts 1 hour to 90 days. **Unban** lifts the edge ban and every host
block RemotePower made for that address. The status column says
`in the edge blocklist` for an address the last sync put in your list and
`banned at the edge` for one you banned by hand.

## How much it keeps

Threat Intel remembers up to 5,000 addresses. An address that nobody has seen for
90 days is forgotten, so the table does not fill with the past. When there are more
than 5,000, the ones seen longest ago go first. If you set the Edge blocklist to
look back further than 90 days, an address it still wants stays. The page is sent the 1,000 most recent and says how many there
are in all when that is more. The filter above the table works on what the page
has, so **Load all** asks for everything that is kept, and the filter can then find
an older address.

Each table draws its first 200 rows and says how many there are. **Show more** adds
200 and **Show all** goes to 1,000, the most the page draws at once. Past that,
filter the list. A filter always starts again from the first 200.

Up to 500 addresses wait to be looked up at a time. When more arrive, an address
that fail2ban, CrowdSec or the honeypot already decided on stays, and the newest of
the rest follow it.

A burst of attacking sources costs one write of the store however large it is, so a
botnet trying your SSH port from thousands of addresses does not hold up the
host's heartbeats.

### Clear the list

**Clear**, above the attackers table, forgets the addresses Threat Intel has
recorded and the ones waiting to be looked up. It asks first, and it is for
administrators. On a multi-tenant install a tenant's administrator clears what
their own hosts saw, and the edge's addresses are the platform operator's.

The answer says how many addresses went and how many of each of these it kept:

| Kept | Why |
|---|---|
| Blocks on hosts and bans at the edge | Each expires by itself and has its own **Unblock** or **Unban**. The sweep still lifts what runs out. |
| What the [edge blocklist](#the-edge-blocklist) reads of the addresses it takes from the table | These addresses leave the table like the rest. The list is kept equal to its sources, so the blocklist keeps each one's last sighting, score and reports, and your Cloudflare list does not shrink at the next sync. An address drops out of the list when the list would have dropped it anyway. Turn off **Found by RemotePower** under **Edge blocklist** and clear again if you want them out of the list too. |
| The date an address was last reported, for a day | Without it, the next time the address attacks it would be reported again. |
| Settings and keys, the day's counts, where the feeds had read to, each host's sensor status, and the scans a firewall has only half counted | They are not addresses. The half-counted scans expire within 30 minutes. |

An address that attacks again after a clear is recorded again from the start.

## Who can see what

| Role | Sees |
|---|---|
| Admin | Everything, including the provider settings, manual lookups and **Clear**. |
| Anyone else | Attackers and blocks for the hosts their role can see, and the evidence those hosts collected. |

Under multi-tenancy, only the platform operator sees or changes the provider
settings (the never-block and ignore lists, the Cloudflare account and list, the
extra log paths), sees the day's counts and the length of the whole queue, or runs a
manual lookup, which spends the install's daily quota. A tenant's administrator
sees the attackers and blocks of their own hosts, how many addresses are waiting
from them, the evidence those hosts collected, and the **Clear** button for them.
The same goes for a role that is limited to some hosts, or an API key that is: they
read the evidence of the hosts in their scope.

## Troubleshooting

| You see | Meaning |
|---|---|
| No attackers appear | Brute-force detection is off, the threshold is never reached, or the host's sshd/web logs aren't being watched. |
| `API key rejected` | The key is wrong or was revoked. Paste it again. |
| `refused by the provider (HTTP 403)` | The service or its firewall refused the request. This is not a verdict on your key; a wrong key shows as `API key rejected`. Try again later, and check the service's status page if it keeps happening. |
| `rate limited` | The service's daily or per-minute limit was hit. RemotePower tries again on the next attack. |
| `already reported a moment ago` | The service had the same address from you minutes earlier, often from fail2ban. Nothing is wrong. |
| `rate limited or already reported` | SniffCat uses one status for its own limit and for a repeat, and only a repeat says so in words (that case shows as `already reported a moment ago`). When the message does not say, RemotePower cannot tell which it was, and waits a little over 20 minutes before asking again. |
| `not reported: 4 / 10 attempts so far` | The logs show the address, but not enough yet. See [When an address is reported](#when-an-address-is-reported). |
| `not reported: 2 / 3 WAF refusals so far` or `... Cloudflare refusals so far` | The same, counted on the nearest route: the WAF needs the number in **Report after WAF refusals**, and Cloudflare needs the number in **Report after Cloudflare refusals**. |
| `not reported: the service is not answering` | The service failed or gave no answer to three requests in a row, so RemotePower stopped asking it for the rest of that pass and asks about this address again in ten minutes. Open the **Request log** to see what it said. Nothing was counted against your daily limit. |
| `not reported: this host has used its share of the day's report limit` | The host that saw the address has used its share of today's reports (see [Limits on API use](#limits-on-api-use)). The address keeps its evidence for the day it was gathered over, and is reported once the limit starts again if that evidence is still there. The limit that is left is for the hosts that have not used theirs. |
| `not reported: the daily report limit is used up` | The service has been sent as many reports today as its limit allows. The count is RemotePower's own and covers only reports the service answered, so compare it with the usage on the service's own page, and raise **Reports per day**, or set the limit of that service alone, if your plan allows more. It starts again at midnight UTC. The first time 8.0.1 runs it drops the day's report counts that older versions kept, because they also counted reports a service never answered. |
| `not reported: no attack category for the CrowdSec scenario crowdsecurity/...` | CrowdSec banned the address for a scenario or AppSec rule that RemotePower has no category for, so there is no honest category to report it under. The page shows the name, and the details of the address list what it asked for. |
| `not reported: no attack category for the fail2ban jail recidive` | The same for a fail2ban jail such as `recidive`, which bans repeat offenders and says nothing about what they did. |
| `not reported: nothing recognisable in the logs` | A ban engine decided on the address and named nothing RemotePower can read. |
| Log sources: `Quiet` | The agent looked at the log and nothing new had been written. It looks about once a minute and reads only what was added since the last look, so a log that is written to now and then shows `Quiet` between writes. |
| Log sources: `Reading` | New lines arrived since the last look. The numbers beside it are for that look, not totals. |
| Log sources: `File missing` | The configuration names a log that does not exist yet. |
| Log sources: `No permission` | The agent cannot read the file. It runs as root normally, so check how it was started. |
| Log sources: `Not understood` | Most lines did not match the log's format. Check the `log_format` and that it prints the address, the request and the status. |
| Log sources: `Cannot be read` | fail2ban logs to syslog or the journal, or ModSecurity writes one file per transaction. Log to a single file. |
| Log sources: a firewall or router, `Not understood` | Its syslog lines arrived and none could be read. See [Troubleshooting](firewall-sources.md#troubleshooting) in the firewall guide. |
| Log sources: a firewall, `No alerts sent` | Suricata is running and sends only its own messages. Tick **Enable syslog alerts** on the firewall. See [Suricata](firewall-sources.md#suricata). |
| Log sources: a firewall, `Quiet` with an old time | No line of that kind has arrived for a day. The row says what it last saw, and when. |
| Log sources: a host's `Intrusion detection alerts`, `No permission` | The agent cannot read Suricata's `eve.json` or `fast.log`, which Suricata usually makes readable by root only. See [Suricata on the host](#suricata-on-the-host). |
| Edge feeds: `Refused by Cloudflare` | Cloudflare refused the firewall events for a zone, grouped and one by one. The line names the zone. Check that the token has **Zone → Analytics → Read** and that its zone list includes that zone. |
| Edge feeds: `Reading`, with a note that the events are read one at a time | Expected on a Free plan. The grouped view is refused, so each event is read and grouped here. A read carries up to 2,500 events per zone. |
| Edge feeds: `No permission` | The token cannot read that. **Test connection** shows which check failed; add the permission listed under [Set up the edge feeds](#set-up-the-edge-feeds). |
| Edge feeds: `Needs an account id` | The honeypot's log is read through the account. Paste the account id. |
| Edge feeds: `No zones found` | The token sees no zone. Check it is for all zones of the account, or list the zones you want. |
| Edge feeds: events set aside as `a rule that also blocks an IP list` | Expected: those rules are not evidence. See [What counts](#what-counts). |
| `not blocked: seen at the edge only, so there is no host to block it on` | The address was seen by Cloudflare or the honeypot and by none of your hosts, so there is no host where a block could go. Whatever bans it (Cloudflare, CrowdSec, fail2ban) does it, and the [edge blocklist](#the-edge-blocklist) can hand it to a Cloudflare rule. An address that a host also saw shows that host's reason instead. |
| `not blocked: score 40 is below 90` | The address isn't bad enough for your threshold. |
| `not blocked: on the never-block list` | The address is one of yours, on an allow-list, or someone recently signed in from it. |

## See also

- [Firewall sources: OPNsense and MikroTik](firewall-sources.md): read a firewall's syslog.
- [Edge sources: Cloudflare](edge-sources.md): the Cloudflare feeds, the edge blocklist and bans by hand.
- [Run a honeypot Worker on Cloudflare](honeypot-worker.md) and [More traps for your honeypot Worker](honeypot-traps.md).
- [Security](security.md): brute-force detection and the other hardening settings.
