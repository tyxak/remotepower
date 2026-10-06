# Threat intel: AbuseIPDB and SniffCat

RemotePower already notices when an address hammers a host with failed SSH
or web logins. Threat intel builds on that. It can:

- **look up** the address with [AbuseIPDB](https://www.abuseipdb.com) and
  [SniffCat](https://sniffcat.com), so you can see whether it's a known
  scanner;
- **report** it back to both services, so other people benefit from what your
  hosts saw;
- **block** it for a while on the host it attacked.

All three are off until you turn them on. You'll find everything under
**Security → Threat intel**.

If you also run a web server, a WAF, fail2ban or CrowdSec, the
[log sensor](#the-log-sensor) lets RemotePower read what those logs say about
each address, so a report says what the address actually did.

## How it works

1. A host's sshd or web server logs failed logins. The brute-force detector
   counts them per source address. When an address crosses the threshold
   (Settings → Alert parameters), RemotePower raises an alert and queues the
   address for threat intel.
2. Once a minute, RemotePower handles the queue. Private and reserved
   addresses are skipped. It never calls out while an agent is reporting, so a
   slow provider can't hold up your fleet.
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
   rule is removed again after the hours you set (default 24).

## The log sensor

Out of the box RemotePower learns about an attacker from failed SSH logins and
a few web patterns. The log sensor reads more. Switch it on under
**Security → Threat intel → Log sensor** and the agent on each Linux host
reads these, read-only, once a minute:

| Log | What it tells RemotePower |
|---|---|
| Web server access logs (nginx, Apache) | Requests that look like SQL injection, path traversal, code execution, a scan for exposed files, or login brute force, and whether the server answered them |
| Web server error logs | ModSecurity messages, rate-limit trips, failed basic-auth logins, requests the server refused |
| ModSecurity audit log (native or JSON) | Which rules fired, and whether the WAF blocked the request |
| fail2ban's log | Which addresses it saw failing, which it banned, and in which jail |
| CrowdSec | The alerts its own scenarios raised on this host, including AppSec |

The agent finds the files from the web server's own configuration (nginx
`access_log` and `error_log`, Apache `CustomLog` and `ErrorLog`, ModSecurity's
`SecAuditLog`), and reads each one in the layout its `log_format` declares, so
a custom format works without setup. A host with no configuration is covered by
the standard paths. Add anything else under **Extra log files**: up to 20,
each a file under `/var/log`.

The sensor is off by default and works on Linux agents only. It does nothing
to the logs it reads and runs in its own thread, so a slow or broken log can
never delay a heartbeat.

### What is sent

Per address: counts and a short list of fixed labels, such as `SQL injection`,
a WAF rule number, a CVE id the logs named, or the name of a fail2ban jail.
**Log lines, request paths, host names and user names never leave the host.**
The server only keeps what is on its fixed list and drops the rest, so nothing
an attacker typed can reach a report or the page.

### When an address is reported

An address is reported when **any** of these is true:

- fail2ban banned it;
- one of CrowdSec's own scenarios raised a ban on this host (a community
  blocklist entry or a decision someone made by hand does not count);
- the WAF refused its requests three times;
- it made as many hostile requests as **Report after attempts** says (10 by
  default).

What it does adds up for a day, so a slow attacker still counts. The page says
why an address has not been reported yet, for example `4 / 10 attempts so far`.
An address with nothing recognisable in the logs is never reported.

### What a report says

The categories follow what was seen:

| Seen | AbuseIPDB | SniffCat |
|---|---|---|
| SSH brute force | 18, 22 | 17, 18 |
| Login brute force (web) | 18, 21 | 17, 21 |
| SQL injection | 16, 21 | 12, 21 |
| Path traversal | 21 | 16, 21 |
| Code execution attempts | 15, 21 | 13, 21 |
| Probing for exposed files | 21 | 21 |
| Attack tools and scanners | 19, 21 | 5, 21 |

Mail, FTP, other services, request flooding and port scans have their own
categories too. The default message names the attack and where it was seen,
for example `SQL injection and path traversal: 41 attempts within 10 minutes,
seen by web server log and WAF (reported by RemotePower)`. You can write your
own; besides `{what}`, `{count}` and `{minutes}` it can use `{attack}` and
`{seen_by}`. For a report built from the logs, AbuseIPDB also gets the time the
attack happened.

An address is reported once per service per sweep, however many hosts or logs
saw it. If a service answers that it was reported moments ago, RemotePower
counts it as reported instead of retrying. **Evidence → Details** on the
Attackers table shows exactly what was sent to each service.

### If fail2ban reports too

fail2ban's own AbuseIPDB and SniffCat actions report each ban on its own. An
address that several jails ban is reported several times, and the services
refuse a second report of the same address within 15 minutes (AbuseIPDB) or 20
minutes (SniffCat). If you let RemotePower do the reporting, turn those actions
off. If you leave them on, nothing breaks: a report the service calls a repeat
is treated as already done.

### Behind Cloudflare or another proxy

If your web server logs the proxy's address instead of the visitor's, every
request seems to come from the proxy. RemotePower ignores Cloudflare's
published addresses and says so on the **Log sources** card, with how many it
ignored. Restore the visitor's address (nginx `real_ip_header`, Apache
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
- Network work is limited to 25 addresses a sweep, strongest first, so a short
  daily allowance goes to the addresses that earned it.

## Set it up

1. Create API keys:
   - AbuseIPDB: sign in, then **Account → API**. The free plan allows 1,000
     lookups and 1,000 reports a day.
   - SniffCat: sign in, then **API**.

   You can use one service or both.
2. **Security → Threat intel → Providers**: paste the keys and tick what you
   want. Keys are write-only. The page shows that a key is saved, never the
   key itself.
3. Save.

### Limits on API use

Each service has its own daily limits, and you set them on the same page:

| Setting | Default | What it does |
|---|---|---|
| **Lookups per day (each service)** | 900 | Stops asking a service once it has been asked this many times today. |
| **Reports per day (each service)** | 900 | Stops reporting to a service once it has been sent this many reports today. |
| **Reuse a lookup for (hours)** | 24 | How long an answer is kept before the same address is asked about again. |
| **Report after attempts** | 10 | How many failed attempts an address needs before it is reported. |

The defaults stay under AbuseIPDB's free plan of 1,000 a day. Days run in UTC.
When a limit is reached, RemotePower stops until the next day and says so in the
address's row. Use `0` to switch lookups or reports off for that service. The
page shows how many have been used today.

### The report message

The comment in each report is yours to write: **Report message** on the same
page. It can use three placeholders:

| Placeholder | Becomes |
|---|---|
| `{what}` | `SSH` or `web login` |
| `{count}` | the number of failed attempts |
| `{minutes}` | the time window, in minutes |

For example, `{what} brute force: {count} attempts in {minutes} minutes` is sent
as `SSH brute force: 42 attempts in 10 minutes`. It needs at least 10
characters, because SniffCat refuses anything shorter, and at most 300. There
is no placeholder for a host name, so one can't end up in a public report by
accident. Don't type one. Clear the box to go back to the default.

## What leaves your network

| Action | What is sent |
|---|---|
| Lookup | The attacking address. |
| Report | The attacking address, the attack categories, a one-line comment, and, for a report built from the logs, the time of the attack (AbuseIPDB only). The default reads "SSH brute force: 42 failed attempts within 10 minutes (reported by RemotePower)"; you can change it (see [The report message](#the-report-message)). |

Hostnames, user names, log lines and your own addresses are never sent.

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

On the host, the block uses whichever firewall is active: `ufw`, then
`firewalld`, then plain `iptables` / `ip6tables`. Each rule is tagged
`rp-ipintel`, so you can find it with `ufw status` or `iptables -S`.

These addresses are **never** blocked:

- private, loopback, link-local and other non-public ranges;
- every address your devices report as their own;
- the addresses on your UI IP allow-list (Settings → Security);
- anything on the **Never block** list on the Threat intel page;
- addresses people signed in to RemotePower from in the last 30 days, and
  addresses SSH-gateway sessions came from in that time.

Two limits stop a runaway. A host gets at most 20 automatic blocks an hour,
which you can change. An address one of the services lists as legitimate (its
whitelist) is never blocked.

Blocking needs a Linux agent. You can also block or unblock by hand from the
page, which needs the **command** permission on that host.

## Who can see what

| Role | Sees |
|---|---|
| Admin | Everything, including the provider settings and manual lookups. |
| Anyone else | Attackers and blocks for the hosts their role can see. |

Under multi-tenancy, only the platform operator can change the provider
settings or run a manual lookup, which spends the install's daily quota.

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
| `not reported: nothing recognisable in the logs` | Only a jail such as `recidive` named it, so there is no honest category to report it under. |
| Log sources: `File missing` | The configuration names a log that does not exist yet. |
| Log sources: `No permission` | The agent cannot read the file. It runs as root normally, so check how it was started. |
| Log sources: `Not understood` | Most lines did not match the log's format. Check the `log_format` and that it prints the address, the request and the status. |
| Log sources: `Cannot be read` | fail2ban logs to syslog or the journal, or ModSecurity writes one file per transaction. Log to a single file. |
| `not blocked: score 40 is below 90` | The address isn't bad enough for your threshold. |
| `not blocked: on the never-block list` | The address is one of yours, on an allow-list, or someone recently signed in from it. |
