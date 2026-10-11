# Edge sources: Cloudflare

Cloudflare refuses many attacks before they reach your server, so your host logs never see them. Edge sources lets RemotePower read those refusals from the Cloudflare API and report the addresses behind them to AbuseIPDB and SniffCat, the same way it reports what your hosts' logs show.

It only reads, with a read-only token. Nothing here blocks anything: banning stays with whatever you already use, such as ModSecurity, CrowdSec, fail2ban or Cloudflare's own rules. It stays off until you turn it on.

On this page: [Before you start](#before-you-start) · [How it works](#how-it-works) · [Step 1: Create the API token](#step-1-create-the-api-token) · [Step 2: Find your account id](#step-2-find-your-account-id) · [Step 3: Enter it in RemotePower](#step-3-enter-it-in-remotepower) · [Step 4: Test the connection](#step-4-test-the-connection) · [Step 5: Switch it on](#step-5-switch-it-on) · [What you see](#what-you-see) · [Free plans](#free-plans) · [Rules that also block an IP list](#rules-that-also-block-an-ip-list) · [Reporting](#reporting) · [Limits](#limits) · [Security](#security) · [Troubleshooting](#troubleshooting) · [The honeypot Worker log](#the-honeypot-worker-log) · [Turn it off](#turn-it-off)

## Before you start

You need:

- RemotePower 7.3.0 or later, and an administrator account. The card is hidden
  from everyone else.
- A Cloudflare account that holds your domains, and the right to create API
  tokens in it.
- AbuseIPDB or SniffCat keys saved under **Security → Threat intel → Providers**,
  with **Report attackers back to both services** ticked (see
  [Set it up](ip-intel.md#set-it-up)). Without them RemotePower still reads and
  shows what Cloudflare refused, but it reports nothing.

Every Cloudflare plan works, including Free. A Free zone is refused the grouped view of the events, so RemotePower reads them one at a time; see [Free plans](#free-plans).

## How it works

Every ten minutes the RemotePower server calls `api.cloudflare.com` with your token. Your browser and your hosts are not involved. A read does four things:

1. Lists the zones the token can see, and keeps the list for six hours.
2. Reads each zone's custom rules once an hour, to find the rules that also block
   an IP list.
3. Reads the firewall events since the last read, one zone at a time.
4. Reads your honeypot Worker's log, if you tick that feed
   ([The honeypot Worker log](#the-honeypot-worker-log)).

What it finds is queued as evidence on the Threat intel page, in the same list as the addresses your hosts' logs found. From there it takes the normal path: a look-up, then a report to AbuseIPDB and SniffCat.

For each event RemotePower asks Cloudflare for four facts: the address, the action, the mechanism that acted and the rule id. It never asks for the request path, the query string, the user agent or the host name. An attacker typed those, and a report is public.

## Step 1: Create the API token

The token only needs to read.

1. In the Cloudflare dashboard open **Manage Account → Account API Tokens**. A
   token owned by your user, under **My Profile → API Tokens**, works the same
   way; an account-owned one does not depend on one person's membership.
2. Click **Create Token**, then **Create Custom Token → Get started**.
3. Name it, for example `remotepower-edge-read`.
4. Under **Permissions**, add one row for each line of
   [the permission rows](#the-permission-rows) below. Every row has three
   drop-downs: scope, permission and access level. Pick **Read** each time.
5. Under **Account Resources** choose **Include**, then your account.
6. Under **Zone Resources** choose **Include → All zones from an account**, then
   your account. To limit the token to some zones, choose **Specific zone** and
   add each zone you want read.
7. Optional: under **Client IP Address Filtering** add the public address of your
   RemotePower server, so the token works from nowhere else. Under **TTL** you
   can set an end date; the token stops working that day.
8. Click **Continue to summary**, check the list, then click **Create Token**.
9. Copy the token now. Cloudflare shows it once.

### The permission rows

| Scope | Permission | Access | What RemotePower uses it for |
|---|---|---|---|
| Zone | Zone | Read | Lists your zones. |
| Zone | Analytics | Read | Reads the firewall events. |
| Zone | Zone WAF | Read | Reads your custom rules, to see which ones also block an IP list. |
| Account | Workers Observability | Read | Reads the honeypot Worker's log. Leave the row out if you do not run a honeypot Worker. |

### The Workers row

Cloudflare renamed its Workers permissions on 15 September 2026. The old name **Workers Observability Read** now corresponds to the role **Metadata Read-Only** at the Workers scope, and the old names still work. Choose whichever your page offers, and never an Edit, Write or Admin role.

Cloudflare's API reference lists only **Workers Observability Write** for the log query. A token with Read has been used successfully against it. If Test connection says the honeypot check is refused with Read, leave the honeypot feed unticked instead of granting Write. The firewall feed does not need that row.

### What the token can do

It can list your zones, read analytics and rules, and read Worker logs. It cannot change a zone, a rule, a DNS record or a Worker. Do not reuse your Global API Key, or a token that can edit rules.

## Step 2: Find your account id

The honeypot feed needs the account id. The firewall feed does not, but setting it limits the zone list to that account. Use any of these:

- **The address bar.** After you open your account, the 32 characters after
  `dash.cloudflare.com/` are the id.
- **A zone's Overview page.** The **API** box in the right-hand column shows
  **Account ID**, and the **Zone ID** you may need in step 3.
- **The account's home page.** Click the three dots next to the account name and
  choose **Copy account ID**.

The id is 32 hexadecimal digits (0 to 9, a to f). RemotePower refuses anything else.

## Step 3: Enter it in RemotePower

Open **Security → Threat intel** and scroll to the **Edge sources** card.

| Field | What to enter | Default |
|---|---|---|
| **Cloudflare API token (read-only)** | Paste the token. RemotePower stores it and never shows it again. Leave the field empty to keep the stored one. | empty |
| **Account id** | The 32 digits from step 2. | empty |
| **Firewall events** | Tick to read Cloudflare's firewall events. | ticked |
| **Honeypot Worker log** | Tick to read a honeypot Worker's log. Untick it if you do not run one. | ticked |
| **Count refusals by a rule that also blocks an IP list** | See [Rules that also block an IP list](#rules-that-also-block-an-ip-list). | unticked |
| **Zones** | One zone id per line. Leave it empty to read every zone the token can see. The Zone ID is on each zone's Overview page. | empty |
| **Worker names** | The Workers whose log to read, one per line, up to three. | `trap-sink` |
| **Read every (minutes)** | How often to read, from 5 to 1,440. | 10 |
| **Report after Cloudflare refusals** | How many refusals by an attack mechanism an address needs before it is reported, from 1 to 50. | 1 |
| The switch at the top, **Read Cloudflare's firewall events and the honeypot's log, and use them for reporting** | Tick it last, after Test connection works. | unticked |

Paste the token and the account id first and press **Save**. The switch can stay unticked while you test.

## Step 4: Test the connection

Press **Test connection**. It uses the token you typed, or the stored one, and it does not save anything. It runs four checks and says which one fails.

| Line | What it does | A good result |
|---|---|---|
| **Zones** | Lists the zones the token can see. | `Works`, with the number of zones and the first twelve names. Every zone you want read should be there. |
| **Firewall events** | Reads the last 15 minutes of events, one zone at a time, for the first twelve zones. | `Works`. On a Free zone the line adds that the events are read one at a time. |
| **Custom rules** | Reads the rules of the first zone and marks the ones that also block an IP list. | `Works`, with up to twelve rules. |
| **Honeypot log** | Reads your Worker's log. | `Works`, or `Skipped` when no account id is set. |

A result looks like this:

```
Works   Zones · 3 zones: example.com, example.net, example.org
Works   Firewall events · Cloudflare refused the grouped view, so the events are read one at a time.
Works   Custom rules
        0a1b2c3d  Block probes and disclosure
        4e5f6a7b  Block unusual HTTP methods — also blocks an IP list
Works   Honeypot log
```

Each line starts with one of these states:

| State | What it means | What to do |
|---|---|---|
| `Works` | Cloudflare answered. | Nothing. |
| `Skipped` | There was nothing to try: no zone was found, or no account id is set for the honeypot. | Fix the line above it, or add the account id. |
| `The token cannot read this` | Cloudflare refused the token itself: it is wrong, expired, deleted, or limited to another IP address. | Create a new token ([step 1](#step-1-create-the-api-token)) and paste it. |
| `Cloudflare refused this read` | Cloudflare refused one dataset for the zone it names. A missing Analytics permission and a plan without the dataset give the same sentence, so the page names neither. | Check **Zone → Analytics → Read** and the zone list on the token. See [Troubleshooting](#troubleshooting). |
| `Failed` | Cloudflare or the network failed: a timeout, a rate limit, an error from Cloudflare. | Press **Test connection** again. |

## Step 5: Switch it on

Tick the switch at the top of the card and press **Save**. The first read happens within one read interval. The **Edge feeds** card, further down, shows `Waiting for the first read` and then `Reading`.

## What you see

### The Edge feeds card

One row for each feed.

| Column | What it shows |
|---|---|
| **Feed** | Cloudflare firewall events or Edge honeypot. The Cloudflare row lists the zones it read. |
| **State** | `Reading`, `Refused by Cloudflare`, `No permission`, `Error`, `Needs an account id`, `No zones found`, `Off` or `Waiting for the first read`. A grey line under it carries Cloudflare's own sentence, or the note that a zone is read one event at a time. |
| **Last read** | When the last read ran. |
| **Events read** | For Cloudflare, how many address-and-rule groups came back. For the honeypot, how many log lines. |
| **Counted** | How many refusals qualified as evidence. |
| **Set aside** | What was left out, and why. |

These are the reasons a line is set aside:

| Label on the card | What it means |
|---|---|
| challenges and log-only actions | Cloudflare challenged the visitor or only logged the request. A person can solve a challenge, so it is not evidence of an attack. |
| country, network and security-level rules | A refusal by a country rule, an ASN rule, the security level or an IP access rule. These are your own policy, or a ban somebody else already decided. |
| a rule that also blocks an IP list | See [Rules that also block an IP list](#rules-that-also-block-an-ip-list). |
| private or invalid addresses | The address is not a public one. |
| Cloudflare's own addresses | The address belongs to Cloudflare's network. |
| your own or shared addresses | Honeypot only: the Worker marked the address as allow-listed or as a shared exit. |
| lines the honeypot logs only to be read | Honeypot only: a kind of line that is not an attack, such as a self-test. |

### The attackers list

An address found at the edge appears in the same table as the addresses your hosts found, under the name **Cloudflare edge** or **Edge honeypot**. **Details** shows where it was seen, which rules fired and exactly what was sent to each service.

An edge address has no **Block** button. An edge source has no host to block it on, and the row says `not blocked: edge sources are only reported`.

## Free plans

Asked for the grouped view of the firewall events, a Free zone answers `zone '…' does not have access to the path`. RemotePower does not need to know your plan. It asks for the grouped view, and when Cloudflare refuses it, it asks the same zone for its events one at a time and groups them itself.

What changes for you:

- Under `Reading`, the card shows the note
  `Cloudflare refused the grouped view, so the events are read one at a time.`
- A read carries up to 2,500 events for each zone. The card says when a zone came
  back full; a shorter read interval makes each read smaller.
- Each zone is asked on its own, so a zone Cloudflare refuses is named on the
  card and does not hold back the others.
- Every six hours RemotePower asks for the grouped view again, in case the plan
  changed.

What stays the same: the four facts it asks for, what counts, and the report path.

## Rules that also block an IP list

Some custom rules add `or (ip.src in $some_list)` to their expression, to block addresses from a community blocklist or from a list a tool keeps up to date. Cloudflare says which rule refused a request, not which half of its expression matched. A refusal by such a rule may be the pattern, or only the address being on the list.

RemotePower sets those refusals aside, for two reasons. An address blocked for being on a list did nothing to you. And counting them would let a list feed its own reports back: an address you reported lands on a blocklist, the blocklist blocks it, and the block counts as new evidence for the next report.

A rule is marked when its expression names any Cloudflare list (`$name`). Test connection lists your rules and marks them, and the Edge feeds card counts the refusals under `a rule that also blocks an IP list`.

To count them anyway, tick **Count refusals by a rule that also blocks an IP list**. That suits a short list of your own. It does not suit a community blocklist.

A Free plan allows five custom rules for each zone, which is why a list is often added to an existing rule and not given a rule of its own. A list in a rule of its own leaves the pattern rules countable.

## Reporting

Edge evidence takes the same report path as your hosts' logs.

- An address is reported after **Report after Cloudflare refusals** refusals by
  Cloudflare, which is 1 unless you change it. The refusal is a block your own
  rules or Cloudflare's already made. A host's WAF needs three.
- Bot Fight Mode, Browser Integrity Check and user-agent rules are weaker
  signals. They only count towards **Report after attempts**, which is 10 unless
  you changed it.
- An address your honeypot Worker banned, or that fail2ban or CrowdSec decided
  on, is reported at once.
- An address that has not qualified yet shows the nearest route in its status,
  for example `not reported: 1 of 3 Cloudflare refusals so far`. When you lower
  the number, addresses counted in the last day are reported on the next sweep.
- The daily limits and the wording of the report are the ones on the Providers
  card: see [Limits on API use](ip-intel.md#limits-on-api-use) and
  [The report message](ip-intel.md#the-report-message).

A report built from Cloudflare's events reads:

`probing for exposed files and admin pages: 8 attempts within 10 minutes, seen by Cloudflare WAF (reported by RemotePower)`

If a script of yours already reports Cloudflare events to AbuseIPDB or SniffCat, stop it once RemotePower works, so each address is one report with all the evidence. The services refuse a second report of the same address within 15 and 20 minutes, and RemotePower counts that as already reported, so nothing breaks while both run. Keep whatever bans.

## Limits

| What | Limit |
|---|---|
| How often it reads | Every 10 minutes by default. You can set 5 to 1,440. |
| How far back one read goes | Six hours. After a longer pause, what happened before that is not read. |
| Delay | Each read stops 90 seconds short of the present, because events take a moment to show up in Cloudflare's analytics. |
| Zones | Up to 50. |
| Single events (Free plans) | 2,500 for each zone in a read. |
| Custom rules | Read once an hour, for the first 12 zones and up to 60 rules in each. A zone beyond the twelfth is counted, but its list rules cannot be told apart. |
| Honeypot log | Up to 3 Workers and 1,000 lines for each Worker in a read. Cloudflare keeps the log for about three days. |
| Accounts | One account id for each RemotePower. With an id set, only that account's zones are read. |

## Security

- **The token** is stored with RemotePower's other secrets, and it is never sent
  back to the browser. Only an administrator can set it. The audit log records
  that it changed, not its value.
- **What it can do** is read your zone list, analytics, custom rules and Worker
  logs. A leaked token cannot change anything in your account, but it can read
  those, so treat it like a password.
- **Restrict it** with Client IP Address Filtering (step 1, point 7), and keep the
  scope to the rows above.
- **Rotate it** by creating a new token in Cloudflare, pasting it into the token
  field and pressing **Save**, then deleting the old token in Cloudflare.
- **What RemotePower sends to Cloudflare** is the token, zone ids, an account id
  and time windows. Nothing about your hosts.
- **What reaches AbuseIPDB and SniffCat** is on the
  [What leaves your network](ip-intel.md#what-leaves-your-network) table.

## Troubleshooting

| What you see | Why | What to do |
|---|---|---|
| State `Waiting for the first read` for longer than two read intervals | The sweep has not run. | Check that RemotePower's scheduler is running. |
| `Reading`, **Counted** is 0, **Set aside** shows `challenges and log-only actions` | Your zones challenge visitors and do not block them. A challenge is not counted, because a person can solve one. | Nothing to fix. **Counted** rises when a managed rule, a custom rule, rate limiting or DDoS protection blocks a request. |
| `Reading`, **Events read** is 0 | Cloudflare had no events for those zones in the window. | Normal for a quiet zone. |
| `Refused by Cloudflare`, with `zone '…' does not have access to the path` | Cloudflare refused the firewall events for that zone, grouped and one at a time. | Check the token has **Zone → Analytics → Read** and that its Zone Resources include the zone. Then press **Test connection**. |
| `No permission` | Cloudflare refused the token: wrong, expired, deleted, or limited to another IP address. | Create a new token ([step 1](#step-1-create-the-api-token)) and paste it. |
| `No zones found` | The token sees no zone. | Add **Zone → Zone → Read** and include the zones under Zone Resources, or list the zone ids under **Zones**. |
| `Needs an account id` | The honeypot feed is ticked and no account id is set. | Add the account id, or untick **Honeypot Worker log**. |
| `Error` with `rate limited by Cloudflare`, `unreachable` or `HTTP 5xx` | Cloudflare or the network failed. | Nothing. The window is read at the next read, for up to six hours back. |
| `Error` with `too many zones to read in one pass` | Reading all the zones took longer than a read may. | List the zones you care about under **Zones**. |
| The note `Rules could not be read, so a rule that also blocks an IP list cannot be told apart.` | The token lacks **Zone → Zone WAF → Read**, or Cloudflare did not answer. | Add the row. Events are still read, but list rules count like any other rule. |
| The note `More events than one read can hold; some were not counted.` | A zone came back with as many events as a read carries. | Set a shorter **Read every (minutes)**, so each read is smaller. |
| Evidence is there but nothing is reported | The reporting side is not set up or has hit its limit. | Check the keys and **Report attackers back to both services**, then the address's **Details** row, which says why a report was not sent. |

## The honeypot Worker log

This feed is for operators who run a honeypot Worker, a Cloudflare Worker that answers decoy paths and logs who asked. If you do not run one, untick **Honeypot Worker log** and leave the Workers row out of the token.

RemotePower reads the Worker's log through Workers Observability. The Worker has to keep Workers Logs on and print one JSON object for each hit, with these fields:

```json
{"msg": "trap hit", "kind": "bait", "ip": "203.0.113.7", "action": "banned", "at": "2026-10-11T09:30:00.000Z"}
```

| Field | What RemotePower reads |
|---|---|
| `msg` | Only lines whose `msg` is `trap hit` are read. |
| `kind` | The trap that was hit. These are known: `bait`, `robots`, `login`, `private`, `impostor`, `wpprobe`, `wpenum`, `mazeentry`, `maze`, `mazeloot`, `gitdump`, `canary_use`, `decoy` and `decoy_login`. Any other kind is set aside as not evidence. |
| `ip` | The visitor's address. |
| `action` | What the Worker decided. `banned`, `already-banned` and `already-blocked-elsewhere` count as the Worker's own decision, and the address is reported at once. `allowlisted` and `shared-egress` are set aside. Anything else counts as a hit that waits for **Report after attempts**. |
| `at` | When it happened. `timestamp` works too. |

The table of what each kind is filed as is under [The honeypot](ip-intel.md#the-honeypot).

## Turn it off

- **Stop reading.** Untick the switch at the top of the card and press **Save**.
  Nothing else changes, and the feeds show as `Off`. To stop one feed, untick
  **Firewall events** or **Honeypot Worker log**.
- **Revoke the access.** Delete the token in Cloudflare. That is the step that
  ends it.
- **Remove the stored copy.** The page has no button for it. An administrator can
  send `{"clear_edge_token": true}` to `POST /api/ip-intel/settings`.
