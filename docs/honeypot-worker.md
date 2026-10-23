# Run a honeypot Worker on Cloudflare

A honeypot Worker answers paths that no real visitor asks for, such as `/.env` or `/wp-login.php`, and writes down who asked. Scanners ask for these all day, and nobody who asks has a good reason.

RemotePower reads that log and reports the addresses that keep asking to AbuseIPDB and SniffCat. This page builds the Worker: one script and one config file, with no database and no credentials. It adds nothing to your host and leaves the rest of your site alone. Once it works, [More traps for your honeypot Worker](honeypot-traps.md) adds a `robots.txt` decoy, a fake backup directory, decoy host names and more.

On this page: [Before you start](#before-you-start) · [How it works](#how-it-works) · [Step 1: Create the two files](#step-1-create-the-two-files) · [Step 2: Add your own addresses](#step-2-add-your-own-addresses) · [Step 3: Deploy it](#step-3-deploy-it) · [Step 4: Check that it answers](#step-4-check-that-it-answers) · [Step 5: Connect RemotePower](#step-5-connect-remotepower) · [What RemotePower does with a hit](#what-remotepower-does-with-a-hit) · [Block what it finds](#block-what-it-finds) · [Rules that answer first](#rules-that-answer-first) · [Change the decoys](#change-the-decoys) · [Limits](#limits) · [Security](#security) · [Troubleshooting](#troubleshooting) · [Turn it off](#turn-it-off)

## Before you start

You need:

- A domain on Cloudflare, with the hostname proxied (the orange cloud). A Worker route only runs for traffic that goes through Cloudflare.
- A Cloudflare account that can create Workers. The Free plan is enough.
- The current LTS release of Node.js on the computer you deploy from. Wrangler, Cloudflare's command line tool, says so if yours is too old.
- RemotePower 7.3.0 or later, with [Edge sources](edge-sources.md) set up. You can build the Worker first and connect RemotePower afterwards.

Do not trap a path your site really serves. A WordPress site has a real `/wp-login.php`, and so does every visitor who logs in. [Change the decoys](#change-the-decoys) says how to drop one.

## How it works

1. A visitor asks your site for `/.env`.
2. Cloudflare has a route for that path, so it hands the request to the Worker. Every other request goes straight to your site and the Worker never sees it.
3. The Worker answers with a made-up file and writes one `trap hit` line to Workers Logs.
4. RemotePower reads those lines, counts the hits for each address and reports the ones that reach **Report after attempts**.

The Worker blocks nobody. It answers and writes things down. Blocking stays with whatever you already use. The [Edge blocklist](edge-sources.md#edge-blocklist) can hand the addresses RemotePower found to a Cloudflare rule of yours.

## Step 1: Create the two files

Make an empty folder and save these two files in it.

`worker.js`:

```js
// A honeypot Worker for RemotePower. It answers a short list of decoy paths and
// prints one `trap hit` line for each visit, which RemotePower reads from
// Workers Logs. It holds no credentials and calls no API. Every other path goes
// through to your site untouched.

// [kind, lower-case path prefix]. Each prefix needs a route in wrangler.toml.
// Delete a line, and its route, if your site really serves that path.
const TRAPS = [
  ["bait", "/.env"],
  ["bait", "/.git"],
  ["bait", "/.aws/"],
  ["bait", "/.ssh/"],
  ["bait", "/backup.sql"],
  ["bait", "/dump.sql"],
  ["bait", "/database.sql"],
  ["bait", "/actuator"],
  ["bait", "/vendor/phpunit/"],
  ["login", "/wp-login.php"],
  ["login", "/xmlrpc.php"],
  ["login", "/phpmyadmin"],
  ["login", "/administrator"],
];

// What a visitor gets back. All of it is made up and none of it is a secret.
const FAKE_ENV =
  "APP_ENV=production\nAPP_DEBUG=false\nDB_HOST=127.0.0.1\nDB_DATABASE=app\n" +
  "DB_USERNAME=app\nDB_PASSWORD=change-me\n";
const FAKE_GIT = {
  "/.git/head": "ref: refs/heads/main\n",
  "/.git/config": "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n",
};
const LOGIN_PAGE =
  '<!doctype html><title>Log in</title><form method="post">' +
  '<input name="log"><input name="pwd" type="password"><button>Log in</button></form>';

// A flood must not fill the log quota. Per address and trap, the first 20 visits
// in an hour are logged, then every 50th. Keep FIRST at or above RemotePower's
// "Report after attempts", which is 10 unless you changed it.
const FIRST = 20;
const THEN_EVERY = 50;
const WINDOW_MS = 3600000;
const MAX_KEYS = 5000;
const seen = new Map();

function shouldLog(key) {
  const now = Date.now();
  let s = seen.get(key);
  if (!s || now - s.since > WINDOW_MS) {
    if (seen.size >= MAX_KEYS) seen.clear();
    s = { since: now, n: 0 };
    seen.set(key, s);
  }
  s.n += 1;
  return s.n <= FIRST || s.n % THEN_EVERY === 0;
}

function decoy(kind, path) {
  const headers = { "cache-control": "no-store", "x-robots-tag": "noindex, nofollow" };
  if (kind === "login") {
    return new Response(LOGIN_PAGE, {
      headers: { ...headers, "content-type": "text/html; charset=utf-8" },
    });
  }
  const text = { ...headers, "content-type": "text/plain; charset=utf-8" };
  if (path.startsWith("/.env")) return new Response(FAKE_ENV, { headers: text });
  if (FAKE_GIT[path]) return new Response(FAKE_GIT[path], { headers: text });
  return new Response("Not found\n", { status: 404, headers: text });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.toLowerCase();
    const trap = TRAPS.find(([, prefix]) => path.startsWith(prefix));
    if (!trap) return fetch(request);

    const kind = trap[0];
    const ip = request.headers.get("cf-connecting-ip") || "";
    const own = String(env.ALLOW || "")
      .split(",")
      .map((a) => a.trim())
      .filter(Boolean)
      .includes(ip);

    if (ip && shouldLog(kind + " " + ip)) {
      console.log(
        JSON.stringify({
          msg: "trap hit",
          kind,
          ip,
          action: own ? "allowlisted" : "recorded",
          at: new Date().toISOString(),
          host: url.hostname,
          method: request.method,
          path: url.pathname.slice(0, 200),
          ua: (request.headers.get("user-agent") || "").slice(0, 160),
          country: (request.cf && request.cf.country) || "",
        }),
      );
    }
    return decoy(kind, path);
  },
};
```

`wrangler.toml`:

```toml
name = "trap-sink"
main = "worker.js"
compatibility_date = "2025-01-01"
workers_dev = false

# One route per decoy path. Replace example.com with your domain in every line.
# A leading * in the host covers the domain and every subdomain.
routes = [
  { pattern = "*example.com/.env*", zone_name = "example.com" },
  { pattern = "*example.com/.git*", zone_name = "example.com" },
  { pattern = "*example.com/.aws/*", zone_name = "example.com" },
  { pattern = "*example.com/.ssh/*", zone_name = "example.com" },
  { pattern = "*example.com/backup.sql*", zone_name = "example.com" },
  { pattern = "*example.com/dump.sql*", zone_name = "example.com" },
  { pattern = "*example.com/database.sql*", zone_name = "example.com" },
  { pattern = "*example.com/actuator*", zone_name = "example.com" },
  { pattern = "*example.com/vendor/phpunit/*", zone_name = "example.com" },
  { pattern = "*example.com/wp-login.php*", zone_name = "example.com" },
  { pattern = "*example.com/xmlrpc.php*", zone_name = "example.com" },
  { pattern = "*example.com/phpmyadmin*", zone_name = "example.com" },
  { pattern = "*example.com/administrator*", zone_name = "example.com" },
]

# Without this, Workers Logs is off and RemotePower has nothing to read.
[observability]
enabled = true

[vars]
# Your own addresses, comma separated. Visits from these are logged as
# "allowlisted" and RemotePower sets them aside.
ALLOW = ""
```

Replace `example.com` with your domain in every route line. Use find and replace in your editor so none is missed.

Leave the Worker's name as `trap-sink`. RemotePower reads a Worker with that name unless you change **Worker names** on the Edge sources card. If your account already has a Worker called `trap-sink`, deploying this one replaces it. Use another name in `wrangler.toml` and enter it under **Worker names**.

What each part does:

| Part | What it does |
|---|---|
| `TRAPS` | The decoy paths, and which kind of trap each one is. Matching ignores case. |
| `routes` | One route per decoy path. Only these paths reach the Worker. |
| `[observability]` | Turns on Workers Logs. Without it RemotePower has nothing to read. |
| `ALLOW` | Your own addresses. See the next step. |
| `FIRST` and `THEN_EVERY` | How many visits from one address are logged. See [Limits](#limits). |

## Step 2: Add your own addresses

Your own test visits are hits like anyone else's, and they add up. Put your public addresses in `ALLOW`, separated by commas, before you deploy.

Cloudflare tells you the address it sees. Run both lines, because a network with IPv6 uses it for sites that offer it:

```sh
curl -4 -s https://www.cloudflare.com/cdn-cgi/trace
curl -6 -s https://www.cloudflare.com/cdn-cgi/trace
```

The `ip=` line in each answer is the address. The second command fails on a network without IPv6, which is fine. Write an IPv6 address in its short, lower-case form, for example:

```toml
ALLOW = "203.0.113.7, 2001:db8::1"
```

A visit from an address on the list is still answered and logged, as `allowlisted`, so you can test. RemotePower sets those lines aside and never reports them.

## Step 3: Deploy it

In the folder with the two files:

```sh
npm install --save-dev wrangler
npx wrangler login
npx wrangler deploy
```

Wrangler opens your browser to sign in to Cloudflare, then uploads the Worker and attaches the routes. If it refuses a route, the domain is not on that Cloudflare account. If the routes attach and requests still do not reach the Worker, check that the hostname has a proxied DNS record.

## Step 4: Check that it answers

Ask for a decoy path, with your own domain in place of `example.com`:

```sh
curl -i https://example.com/.env
```

You should get `200 OK` and a few lines of made-up settings. If you get a Cloudflare block page or your own site's 404 instead, see [Rules that answer first](#rules-that-answer-first) and [Troubleshooting](#troubleshooting).

Then watch the log while you ask again:

```sh
npx wrangler tail trap-sink
```

Each visit prints one line:

```json
{"msg":"trap hit","kind":"bait","ip":"203.0.113.7","action":"recorded","at":"2026-10-14T09:30:00.000Z","host":"example.com","method":"GET","path":"/.env","ua":"curl/8.7.1","country":"DK"}
```

A visit from an address in `ALLOW` shows `"action":"allowlisted"`. You can also open the Worker in the Cloudflare dashboard (**Workers & Pages**, then your Worker, then **Observability**) and filter on `msg` equal to `trap hit`. If lines show there, the log has the `msg` field RemotePower asks for.

## Step 5: Connect RemotePower

The Edge sources guide has every click. For this Worker:

1. Create a read-only token with the **Workers Observability** row, as in [Step 1: Create the API token](edge-sources.md#step-1-create-the-api-token), and find your [account id](edge-sources.md#step-2-find-your-account-id).
2. Enter both under **Security → Threat Intel → Edge sources** ([Step 3](edge-sources.md#step-3-enter-it-in-remotepower)). Leave **Honeypot Worker log** ticked. **Worker names** already says `trap-sink`.
3. Press **Test connection** ([Step 4](edge-sources.md#step-4-test-the-connection)). The line `Honeypot log` should say `Works`.
4. Tick the switch at the top ([Step 5](edge-sources.md#step-5-switch-it-on)).

To see a hit the way RemotePower counts it, ask for a decoy path from an address that is not in `ALLOW`, such as a phone on mobile data. The address appears in the attackers list under **Edge honeypot** after the next read. To keep that test address out of reports, add it to the ignore list ([Ignore what you do not want reported](ip-intel.md#ignore-what-you-do-not-want-reported)).

## What RemotePower does with a hit

RemotePower reads the log every ten minutes unless you changed it, and files each line by its `kind`:

| `kind` | The visitor asked for | Filed as |
|---|---|---|
| `bait` | A file that should never be public: `.env`, `.git`, `.aws`, `.ssh`, SQL dumps, `actuator`, `phpunit` | Probing for exposed files and admin pages |
| `login` | A login or admin page your site does not have | Probing for exposed files and admin pages |

One hit on a `bait` path is enough to report an address, because nobody innocent asks for `.env` or a database dump ([Edge sources](edge-sources.md#step-3-enter-it-in-remotepower) has the setting). A hit on a `login` path counts as one attempt, and an address is reported when its hits reach **Report after attempts**, which is 10 unless you changed it ([Limits on API use](ip-intel.md#limits-on-api-use)). Until then the attackers list says how far it is, for example `not reported: 9 / 10 attempts so far`. A report reads:

```
probing for exposed files and admin pages: 12 attempts within 3 minutes, seen by edge honeypot (reported by RemotePower)
```

The report names counts and the kind of attack. The path, the user agent and the rest of the line stay in your log and are never sent. Lines marked `allowlisted` are set aside.

This Worker never bans, so it never writes the actions that make RemotePower report at once. If you add banning to it, log `banned`, `already-banned` or `already-blocked-elsewhere` for a ban. [The honeypot Worker log](edge-sources.md#the-honeypot-worker-log) lists what each action means.

## Block what it finds

The Worker blocks nobody, and RemotePower only reports. To stop an address at Cloudflare, let RemotePower keep a Cloudflare IP list and block that list with one rule of yours:

1. Turn on the [Edge blocklist](edge-sources.md#edge-blocklist), with a token that can edit lists. It builds the list from the sources you choose. **Found by RemotePower** is one of them: the addresses RemotePower reported, or that scored high.
2. Add one custom rule to your zone with the expression `(ip.src in $remotepower_blocklist)` and the action **Block**, using the name you gave the list ([Use the list in a rule](edge-sources.md#use-the-list-in-a-rule)).
3. To block one address now, press **Ban** on its row in the attackers table ([Ban an address by hand](edge-sources.md#ban-an-address-by-hand)).

An address goes into the list at the next sync after RemotePower reports it, which takes as many hits as **Report after attempts**, or after its score reaches **Found addresses: score of at least**. A report does not start a sync. The list is synced every six hours unless you changed **Update every (hours)**, so a reported address can wait that long, and **Sync now** on the card syncs at once. A Worker that bans on the first hit is faster, but it needs a token that can edit IP rules inside a Worker that faces the internet, and a job to expire the bans. Doing it from RemotePower keeps that token in one place.

## Rules that answer first

Cloudflare's WAF custom rules and managed rules run before a Worker, and bot protection can answer first too. A path that one of them blocks never reaches the Worker, so it leaves no `trap hit` line.

Those refusals are not lost. RemotePower reads them as Cloudflare firewall events and reports the addresses behind them ([Edge sources](edge-sources.md)). What you lose is the decoy answer and the line from the Worker.

To let the Worker answer a path, exclude that path from the rule that blocks it, or remove the rule. Cloudflare's own managed rules also block a few probe paths on every zone, for example any path that contains `wp-config.php`, and a Worker never sees those. Step 4 tells you which case you are in: a decoy answer means the path reaches the Worker, and a block page means something answered first.

## Change the decoys

- **Add one.** Add a line to `TRAPS` with a lower-case prefix, and a route in `wrangler.toml` whose path is that prefix followed by `*`. Run `npx wrangler deploy` again.
- **Drop one.** Delete its line and its route. Do this for any path your site really serves.
- **Kinds.** This script writes `bait` and `login`. RemotePower knows more kinds, listed in [The honeypot Worker log](edge-sources.md#the-honeypot-worker-log). The others need more than a path, such as a decoy host name, a `robots.txt` that names a path or a credential that is handed out. [More traps for your honeypot Worker](honeypot-traps.md) has a script that writes them. A kind that RemotePower does not know is set aside as not evidence.

Route paths are case sensitive, and a route cannot have a wildcard in the middle or a query string. A route for `/.env*` does not match `/.ENV`. Add a second route if you want both.

## Limits

- **Worker requests.** The Free plan allows 100,000 a day across every Worker on the account. Only the decoy paths are routed, so an ordinary site uses a small part of that. See [Cloudflare's limits](https://developers.cloudflare.com/workers/platform/limits/).
- **Log events.** The Free plan keeps 200,000 a day, for three days. A flood of requests could use all of that, so the script logs the first 20 visits from one address to one kind of trap in an hour, then every 50th. See [Workers Logs](https://developers.cloudflare.com/workers/observability/logs/workers-logs/).
- **Report after attempts.** Keep `FIRST` at or above it. With the default of 10, 20 leaves room. If you raise **Report after attempts** past 20, raise `FIRST` too, or an address needs far more visits than that before it is reported.
- **What RemotePower reads.** Up to 1,000 lines per Worker in a read, and never further back than six hours ([Limits](edge-sources.md#limits)).
- **Memory.** The counters live in the Worker's memory and start again when Cloudflare restarts it. That only means a few more lines are logged. Nothing is lost.

## Security

- The decoys hold made-up values. Never put a real key, password or address in one.
- The Worker never reads a request body, so a password sent to the fake login is not stored or logged.
- The Worker holds no token and calls no API, so a leaked copy of the files gives nobody access to your account.
- The script answers with fixed text and echoes nothing the visitor sent.
- The log holds the visitor's address, user agent, country and the path they asked for. Cloudflare keeps it for about three days. An address can be personal data where you live, so keep it in mind when you write your privacy notice.
- RemotePower reads the log with a read-only token ([The Workers row](edge-sources.md#the-workers-row)). Do not give it a token that can edit Workers.

## Troubleshooting

| You see | Why | What to do |
|---|---|---|
| `curl` shows Cloudflare's block page and no line appears | A Cloudflare rule answered before the Worker | See [Rules that answer first](#rules-that-answer-first). |
| `curl` shows your own site's 404 or its normal page | The route is not attached, the hostname is not proxied, or the path is not in `TRAPS` | Check the domain in every route, that the DNS record has the orange cloud, and the path against the list. Run `npx wrangler deploy` again. |
| Lines show in `wrangler tail`, and RemotePower shows nothing | The Worker name differs, the token lacks the Workers Observability row, or no account id is set | Check **Worker names**, the token and the account id on the Edge sources card, then press **Test connection**. |
| **Test connection** says `Skipped` for the honeypot log | No account id is set | Add it ([Step 2](edge-sources.md#step-2-find-your-account-id)). |
| The address is listed and not reported | It has fewer hits than **Report after attempts** | Wait for more hits, or lower the number. The status names how far it is. |
| Every line says `allowlisted` | The address is in `ALLOW` | Expected for your own address. Test from another network. |
| Nothing at all in the log | Workers Logs is off, or nobody has asked yet | Check that `[observability]` is in `wrangler.toml` and deploy again, then ask for `/.env` yourself. |

## Turn it off

1. Untick **Honeypot Worker log** on the Edge sources card. RemotePower stops reading at once.
2. Delete the Worker with `npx wrangler delete trap-sink`.
3. Open the Workers Routes page of each zone and remove any route that is left.
