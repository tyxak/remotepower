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
| Report | The attacking address, the attack categories, and a one-line comment. The default reads "SSH brute force: 42 failed attempts within 10 minutes (reported by RemotePower)"; you can change it (see [The report message](#the-report-message)). |

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
| `not blocked: score 40 is below 90` | The address isn't bad enough for your threshold. |
| `not blocked: on the never-block list` | The address is one of yours, on an allow-list, or someone recently signed in from it. |
