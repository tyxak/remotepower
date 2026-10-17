# Firewall sources: OPNsense and MikroTik

A firewall or router sees attacks that never reach a host: port scans, probes of a port nobody should know about, sign-in attempts on its own web interface. It has no agent, but it already sends its logs to RemotePower. Firewall sources lets RemotePower read those logs and report the addresses behind them to AbuseIPDB and SniffCat, the same way it reports what your hosts' logs show.

Reading is all it does. RemotePower does not change the firewall or the router, and it blocks nothing on either. It stays off until you turn it on.

On this page: [Before you start](#before-you-start) · [What it reads](#what-it-reads) · [How it works](#how-it-works) · [Turn it on](#turn-it-on) · [OPNsense](#opnsense) · [MikroTik RouterOS](#mikrotik-routeros) · [Failed sign-ins](#failed-sign-ins) · [When an address is reported](#when-an-address-is-reported) · [What a report says](#what-a-report-says) · [Check that it works](#check-that-it-works) · [Limits](#limits) · [Security](#security) · [What it does not do](#what-it-does-not-do) · [Troubleshooting](#troubleshooting) · [Turn it off](#turn-it-off)

## Before you start

You need:

- RemotePower 7.4.0 or later, and an administrator account. The card is hidden
  from everyone else.
- AbuseIPDB or SniffCat keys saved under **Security → Threat intel → Providers**,
  with **Report attackers back to both services** ticked (see
  [Set it up](ip-intel.md#set-it-up)). Without them RemotePower still reads the
  logs and shows what it found, but it reports nothing.
- The firewall's syslog arriving at RemotePower. That takes a host record whose
  IP is the address the firewall sends from, a Syslog token pinned to that
  host, and the UDP receiver on the RemotePower server.
  [OPNsense](opnsense.md#send-the-firewalls-logs) and
  [MikroTik RouterOS](syslog.md#mikrotik-routeros) have the steps. It works when
  the firewall's lines appear on the host's **Logs** tab.

CrowdSec is the one source that skips the UDP receiver; see
[CrowdSec](#crowdsec).

## What it reads

| Source | Comes from | Counts when |
|---|---|---|
| Refused packets | `filterlog` lines from OPNsense and pfSense; RouterOS firewall log lines | An address tries 10 different ports, or is refused 25 times, within 30 minutes |
| Decoy port | A RouterOS rule you add | An address connects to the port twice |
| Intrusion detection | Suricata alerts from OPNsense | The signature names an attack |
| CrowdSec | CrowdSec alerts from OPNsense | One of its own scenarios raised the alert |
| Failed sign-ins | RouterOS, the OPNsense web interface, and SSH on either | The brute-force threshold is crossed (20 failures in 5 minutes unless you changed it) |

The refused-packet reader follows pf's `filterlog` layout, which pfSense also
writes. It has been run against a real OPNsense and not against a pfSense. The
RouterOS, Suricata and CrowdSec readers follow those products' documented
formats and have not yet read a live firewall or router. [Check that it works](#check-that-it-works)
shows how you would notice a mismatch.

Lines from any other program stay on the Logs tab as before and are not read
further.

## How it works

1. A batch of lines arrives and is stored on the host's **Logs** tab, as it
   always was.
2. With the switch on, RemotePower reads the batch for the five things above.
   Most lines are none of them and are skipped after a quick check.
3. Refused packets and decoy-port hits are counted per address, in a small store
   of their own. Writing them into the Threat intel table would rewrite the
   whole table on every batch of a busy firewall. Intrusion detection and
   CrowdSec alerts settle within their batch.
4. An address that qualifies joins the queue your hosts' sensors feed. From
   there it is looked up and, if it qualifies, reported, as described in
   [Threat intel](ip-intel.md#how-it-works).

### Refused packets

A packet counts when all of these are true:

- the firewall refused it, and it is inbound TCP;
- it carries only SYN, only FIN, or FIN, PSH and URG together (the "Xmas"
  probe). The ECN bits that a modern stack sets on its SYN do not matter;
- its source is a public address.

UDP and ICMP never count. The source address of an unsolicited UDP or ICMP
packet is whatever the sender wrote, and floods forge them, so a report built on
those could name the flood's victim. A packet with ACK or RST set is a reply.
One that reaches your firewall unasked answers a packet somebody forged with
your address, so blaming its sender would name a victim.

An address is a scanner when, within 30 minutes of its first refused packet, it
tried **10 different ports** or was refused **25 times**. It is queued once when
it crosses the line. An address that stays quiet for 30 minutes is forgotten.
One that carries on is counted again from a fresh window, so a persistent
scanner is queued again, and reported at most once a day to each service.

The window is long because scanners are slow. Seventeen minutes of one
internet-facing OPNsense log held 431 refused SYN packets from 216 addresses.
Most sent a single packet, and the persistent scanners were slow: 19 ports in 16
minutes. The one-minute window that the check on a Linux host's firewall uses
(see [The firewall log](ip-intel.md#the-firewall-log)) would have caught almost
none of them.

## Turn it on

Open **Security → Threat intel** and scroll to the **Firewalls and routers**
card.

1. Tick **Read the syslog of firewalls and routers**.
2. Press **Save**.

The switch covers every host whose syslog reaches RemotePower. A host whose
lines match none of the formats above is not affected. Lines already on the Logs
tab are not read; reading starts with the next batch.

## OPNsense

Start with [Send the firewall's logs](opnsense.md#send-the-firewalls-logs). In
the log target, leave **Applications** empty, or list `filterlog` and `suricata`.
Failed sign-ins come from other programs, so an empty list is the simpler
choice.

OPNsense menu paths here use OPNsense's own arrow, ‣. Names differ a little
between releases.

### The firewall log

There is nothing to set in RemotePower beyond the switch. The firewall writes a
log line only for a rule that has logging on, and that includes the default block
rule. Tick **Log** on the rules whose refusals you want counted. The OPNsense
manual says where the default block rule's logging is set in your release.

On the Logs tab a refused packet looks like this:

```
1 2026-10-17T09:42:22+02:00 OPNsense01.example.org filterlog 66335 - [meta sequenceId="1"] 8,,,02f4bab031b57d1e30553ce08e0ec131,vtnet0,match,block,in,4,0x0,,64,16955,0,DF,6,tcp,52,203.0.113.9,192.0.2.1,51234,22,0,S,2909759651,,64240,,mss;nop;nop;sackOK;nop;wscale
```

The fields RemotePower uses are the action (`block`), the direction (`in`), the
protocol (`tcp`), the source address, the destination port (`22`) and the TCP
flags (`S`).

### Suricata

Intrusion detection has to be running first: **Services ‣ Intrusion Detection ‣
Administration**, with **Enabled** ticked and at least one rule set switched on.
On the **Settings** tab, tick **Enable syslog alerts**. Each alert then goes to
syslog as one line:

```
[1:2001219:20] ET SCAN Potential SSH Scan [Classification: Attempted Information Leak] [Priority: 2] {TCP} 203.0.113.9:40222 -> 192.0.2.1:22
```

Prefer this to **Enable eve syslog output**. The syslog intake keeps 2,048
characters of a line, and an EVE record with a payload is longer, so it arrives
cut off and shows as not understood on the Log sources card.

RemotePower keeps an alert when its signature or classification names an attack,
and files it under the class the words point to. The first row that matches
wins:

| The signature or classification mentions | Reported as |
|---|---|
| log4j, Struts, Shellshock, "remote code", "command injection", "code exec", a webshell, a CVE id | remote code execution attempts |
| SQL injection | SQL injection |
| XSS, cross-site scripting | cross-site scripting |
| traversal, LFI, RFI, `/etc/passwd` | path traversal |
| DoS, denial of service, flood | request flooding |
| nmap, nikto, sqlmap, masscan, zmap, Nessus, OpenVAS, WPScan, Nuclei and other scanner names | vulnerability scanning |
| FTP with brute, login or auth | FTP brute force |
| SMTP, IMAP or POP3 with brute, login or auth | mail login brute force |
| Telnet, RDP, VNC, MSSQL, MySQL or PostgreSQL with brute, login or auth | service login brute force |
| a scan: "ET SCAN", a network scan, a port scan | port scanning |
| "attempted information leak" | probing for exposed files and admin pages |

An alert that names no attack is read and dropped. That covers Suricata's own
engine events, the reputation lists (ET DROP, Dshield, CINS, compromised hosts,
Tor), the policy and informational rules (ET INFO, POLICY, CHAT, GAMES, P2P,
DNS), the malware and command-and-control rules, which fire on traffic from your
own network, and anything marked outbound. A reputation hit means an address is
on somebody's list. It says nothing about what the address did to you, so
reporting it would repeat someone else's opinion.

### CrowdSec

CrowdSec on OPNsense does not use syslog for this. It posts its alerts over HTTP,
and the token goes into its configuration file.

1. In RemotePower, create a **Syslog** token pinned to the firewall under
   **Settings → Integrations → Inbound webhooks**, and copy its URL from the
   dialog. The dialog says not to enter the token on the host; that holds for
   the UDP path, and CrowdSec is the exception. A token is shown once, so make a
   new one if you did not keep the first. Two syslog tokens on one host do no
   harm to the UDP receiver.
2. On the firewall, create the notification file. On OPNsense CrowdSec's
   configuration is in `/usr/local/etc/crowdsec/`, and the file goes in its
   `notifications` directory as `http_remotepower.yaml`:

   ```yaml
   type: http
   name: http_remotepower
   log_level: info
   format: |
     {{.|toJson}}
   url: https://remotepower.example.com/api/syslog/in/<token>
   method: POST
   headers:
     Content-Type: application/json
   ```

   Use the address you open RemotePower at. The certificate has to be one the
   firewall trusts. Without the `Content-Type` header the post is read as plain
   text and its alerts are not recognised.
3. In `profiles.yaml`, add `http_remotepower` to the `notifications` list of the
   profile that bans addresses (the default one is `default_ip_remediation`).
4. Restart CrowdSec.
5. Run `cscli notifications test http_remotepower` if your CrowdSec has that
   command. The token's **Hits** on the Inbound webhooks page goes up by one.

RemotePower turns each alert into one line on the Logs tab, in a fixed shape:

```
crowdsec alert scenario=crowdsecurity/ssh-bf src=203.0.113.9 events=6 decision=ban
```

It keeps four things: the scenario name, the address, the number of events and
what was decided. Nothing an attacker typed is copied; a scenario name that is
not a plain name is dropped. The scenario's name decides the kind of attack, as
it does for CrowdSec on a host (see [The log sensor](ip-intel.md#the-log-sensor)),
and a scenario whose name points to no kind is read and dropped.

A ban from one of the firewall's own scenarios counts as a decision, and the
address is reported at once. A decision from CrowdSec's community blocklist does
not count, and neither does a ban added by hand with `cscli`. Both are somebody
else's finding. Simulated alerts are dropped.

## MikroTik RouterOS

### Send the log

[Syslog ingestion](syslog.md#mikrotik-routeros) covers the host record, the
Syslog token and the UDP receiver. Then tell RouterOS what to send, with the
source address that is on the host record:

```
/system logging action add name=remotepower target=remote remote=<server-ip> remote-port=5514 src-address=<router-ip>
/system logging add topics=firewall action=remotepower
/system logging add topics=system,error,critical action=remotepower
```

The second line sends the firewall log. The third sends failed sign-ins, which
RouterOS logs under the topics `system`, `error` and `critical`. RemotePower
reads both of RouterOS's formats, the plain one and the BSD one that
`bsd-syslog=yes` switches on.

### Count refused packets

RouterOS logs a packet only for a rule with `log=yes`. Give each rule that drops
traffic from the internet a log prefix that says so:

```
/ip firewall filter print
/ip firewall filter set <number> log=yes log-prefix=drop-in
```

A prefix that contains `drop`, `deny`, `denied`, `block`, `reject` or `refus`
marks the rule as a refusal, whatever the capitals. A rule that logs with any
other prefix is read as a log line and not as a refusal, and nothing it logs is
counted. Do this for the rules in the `input` chain (traffic to the router) and
the `forward` chain (traffic through it) that face the internet. Logging every
drop is work for a small router; the `input` chain alone covers scans of the
router itself.

A refused packet looks like this:

```
firewall,info drop-in input: in:ether1 out:(unknown 0), src-mac 00:11:22:33:44:55, proto TCP (SYN), 203.0.113.9:51234->192.0.2.1:23, len 60
```

### A decoy port

A decoy port is one that nothing legitimate connects to, so a connection to it
is a scan. Two connections are enough. RemotePower reports the address at once,
without waiting for the count in **Report after attempts**.

RemotePower does not run anything on the port. The rule logs the packet and drops
it, so the router answers nothing and a scanner sees a filtered port. Add one
rule above the rules that accept traffic. Its log prefix must contain `rp-trap`:

```
/ip firewall filter add chain=input action=drop protocol=tcp dst-port=2222 in-interface-list=WAN log=yes log-prefix=rp-trap place-before=0 comment="RemotePower decoy port"
```

Pick a port that none of your services uses; the example uses 2222. If you have
no interface list called `WAN`, name the interface with `in-interface=` instead.
Only a plain SYN counts, so a stray ACK to the port does not, and only from a
public address. The logged packet looks like this:

```
firewall,info rp-trap input: in:ether1 out:(unknown 0), src-mac 00:11:22:33:44:55, proto TCP (SYN), 203.0.113.9:51234->192.0.2.1:2222, len 60
```

## Failed sign-ins

Both products log a failed sign-in with the address it came from:

| Product | Line |
|---|---|
| RouterOS, any service | `login failure for user admin from 203.0.113.9 via ssh`, and `via winbox`, `web`, `telnet`, `ftp`, `api` |
| OPNsense, web interface | `Web GUI authentication error for 'root' from 203.0.113.9` |
| OPNsense, SSH | `Failed password for root from 203.0.113.9 port 51234 ssh2` |

These go through the same brute-force counter as failed SSH logins on your hosts.
It counts failures per address, raises an alert when the threshold is crossed
(**Settings → Alert parameters**, 20 failures in 5 minutes by default), and
queues the address for Threat intel. A failed SSH login keeps its SSH category;
the others are reported as failed logins.

A host that has an agent is left out of this. The agent already counts its
logins from the journal, and counting the same failures again from forwarded
syslog would halve your threshold.

## When an address is reported

Reporting follows [the rules for hosts](ip-intel.md#when-an-address-is-reported).
This is what each kind of evidence needs:

| Evidence | Reported |
|---|---|
| A scan | When the packets it was refused reach **Report after attempts** (10 by default). What an address does adds up for a day. |
| A hit on the decoy port | At once, whatever **Report after attempts** says |
| Intrusion detection alerts | When the alerts reach **Report after attempts** |
| A CrowdSec ban from the firewall's own scenarios | At once |
| CrowdSec alerts without such a ban | When the events reach **Report after attempts** |
| Failed sign-ins | When the brute-force threshold is crossed and the count reaches **Report after attempts** |

An address that is never blocked is never reported either: private and reserved
addresses, your hosts' own addresses, your UI allow-list, the **Never block or
report** list, and addresses people signed in from in the last 30 days.
Cloudflare's published ranges are set aside and counted on the Log sources card.

## What a report says

The text is built from fixed phrases and numbers, like every Threat intel
report:

```
port scanning: 38 attempts within 16 minutes, seen by firewall log (reported by RemotePower)
connecting to a decoy port: 2 attempts within 1 minute, seen by decoy port (reported by RemotePower)
vulnerability scanning: 12 attempts within 1 minute, seen by intrusion detection (reported by RemotePower)
```

A port scan and a decoy-port hit are filed under AbuseIPDB category 14 and
SniffCat category 4. An intrusion detection alert and a CrowdSec alert use the
categories of the class they were filed under; the table is in
[What a report says](ip-intel.md#what-a-report-says). A failed SSH login is
18 and 22 at AbuseIPDB and 17 and 18 at SniffCat. Any other failed sign-in is 18
at AbuseIPDB and 17 at SniffCat. On the Attackers table, **Evidence → Details**
shows what was sent to each service.

## Check that it works

Open **Security → Threat intel → Log sources**. Each kind of line that RemotePower
read from a firewall's syslog has a row under the firewall's name, with the log
shown as `syslog`:

| Source | Counts |
|---|---|
| Firewall log | `filterlog` and RouterOS firewall lines |
| Intrusion detection alerts | Suricata alerts |
| CrowdSec alerts | The lines made from CrowdSec's posts |

For a firewall the three numbers are the day's totals since midnight UTC. **Lines
read** counts every line of that kind, **Understood** those the reader could
parse, and **Hostile** the scans, decoy hits and alerts it found. **Reading**
means lines were understood. **Not understood** means lines of that kind arrived
and none could be read, which is the sign of a format the reader does not know.

To test each source:

- **Refused packets.** Wait. An internet-facing firewall is scanned within
  minutes, and **Lines read** rises with it.
- **Decoy port.** From a machine outside your network, connect to the port twice.
  The `rp-trap` lines appear on the router's Logs tab at once, and the address
  appears on the Attackers table about a minute later. If you test from your own
  address, put it on **Never block or report** first, or it is reported like any
  other.
- **CrowdSec.** Run the test command in [CrowdSec](#crowdsec) and watch the
  token's **Hits**.

## Limits

| Limit | Value |
|---|---|
| Addresses counted per firewall at once | 2,000, the oldest dropped first |
| Ports remembered per address | 16, which is more than the 10 a scan needs |
| Time an address is counted over | 30 minutes from its first refused packet |
| Lines in one post | 200 |
| Line length kept by the intake | 2,048 characters |
| Addresses queued from one host in an hour | 3,000, the rest counted as skipped |
| Counts on the Log sources card | The UTC day |

## Security

**Forged packets.** A firewall that drops a SYN never completes the handshake, so
it cannot prove who sent it. Anyone who can forge source addresses can make your
firewall log refused packets "from" an address that never sent them. A forged
scan needs 10 ports or 25 packets inside 30 minutes, which is cheap. The decoy
port needs two packets and is reported at once, so it is cheaper still. If you
would rather not report from refused packets alone, tick **port
scanning** and **connecting to a decoy port** under **Never report an address
when all it did was**. The evidence is still recorded and shown, and the address
is looked up but never reported.

**Forged syslog.** UDP source addresses can be forged by anything on the path,
and RemotePower now acts on what the lines say, so a forged datagram from the
firewall's address could name an address of its choosing. Let only the firewall's
address reach the receiver's port, as described in
[Inbound tokens](inbound-tokens.md#security).

**The CrowdSec token.** It sits in a file on the firewall. A syslog token writes
lines for the one host it is pinned to and nothing else, so the worst a leak
allows is false lines for that host. To rotate it, revoke it and create
another.

**What leaves your network.** The address, the attack categories, one line of
text and, for AbuseIPDB, the time of the attack. Log lines, ports, interface
names, rule names and signature text stay on your server. A CVE id that a
signature names can appear in the text.

## What it does not do

- **It does not block.** With auto-block on, an address found on a firewall that
  scores high enough shows `not blocked: host is not a Linux agent`, because a
  block is a rule on a Linux host. If you use the
  [edge blocklist](ip-intel.md#the-edge-blocklist), these addresses are
  candidates for it like any other the server found.
- **It does not raise an alert for a scan or a decoy hit.** They are reported and
  shown on the Threat intel page. Failed sign-ins do raise the brute-force alert.
- **It does not read other formats.** A firewall whose lines are not pf
  `filterlog`, RouterOS, Suricata or CrowdSec lines is stored on the Logs tab and
  not read further.
- **It does not start from the past.** Lines already stored are not read when you
  turn it on.

## Troubleshooting

| You see | Meaning |
|---|---|
| No **Firewalls and routers** card | The card is for administrators. |
| The firewall is missing from **Log sources** | The switch is off, or no line of a kind in this guide has arrived since you turned it on. Check first that lines reach the host's Logs tab: [Reading the symptoms](inbound-tokens.md#reading-the-symptoms). |
| Firewall log: **Not understood** | Lines arrived from `filterlog` or a RouterOS firewall rule and none could be read. Compare one with the examples above. |
| Firewall log: **Reading**, but no attackers | Normal on a quiet network. A scan needs 10 ports or 25 refused packets within 30 minutes. |
| Nothing from a RouterOS rule | The rule needs `log=yes`, a prefix with a refusing word or `rp-trap`, and a place above the rule that accepts the traffic. |
| No refused packets from OPNsense | The rule that refused the packet does not have **Log** ticked. |
| Intrusion detection: **Not understood** | The alerts are EVE records cut at 2,048 characters, or not alert lines. Use **Enable syslog alerts**. |
| No CrowdSec row | The notification is not arriving. The test command should raise the token's **Hits** by one. If it does not, check the URL, the `Content-Type` header and that the firewall trusts RemotePower's certificate. |
| `not blocked: host is not a Linux agent` | Expected. RemotePower does not block on a firewall or router. |
| The same address again the next day | A persistent scanner is queued for each 30-minute window and reported at most once a day to each service. |
| An address of yours was reported | Add it to **Never block or report**. Taking it off the list reports it again on its next sighting if it qualifies. |

## Turn it off

Untick **Read the syslog of firewalls and routers** and press **Save**. Reading
stops with the next batch. Addresses already queued are still looked up and
reported, and what was reported stays reported. The counts a firewall had half
finished expire by themselves within 30 minutes.
