# More traps for your honeypot Worker

[Run a honeypot Worker on Cloudflare](honeypot-worker.md) builds a Worker with two kinds of trap, which is enough to start. This page replaces its script with one that has the rest: a `robots.txt` decoy, a fake git repository, a fake backup directory, WordPress probes, a password that the fake files hand out, and decoy host names.

It is still one script and one config file. It holds no Cloudflare token and never bans. The routes in `wrangler.toml` decide which traps are live, so you switch a trap on or off by adding or deleting its route.

On this page: [Before you start](#before-you-start) · [What each trap catches](#what-each-trap-catches) · [Step 1: Replace the script](#step-1-replace-the-script) · [Step 2: Replace the config](#step-2-replace-the-config) · [Step 3: Choose your traps](#step-3-choose-your-traps) · [Step 4: Deploy and check each one](#step-4-deploy-and-check-each-one) · [The planted password](#the-planted-password) · [Decoy hosts](#decoy-hosts) · [What RemotePower does with them](#what-remotepower-does-with-them) · [What this page leaves out](#what-this-page-leaves-out) · [Limits](#limits) · [Security](#security) · [Troubleshooting](#troubleshooting) · [Go back to the first script](#go-back-to-the-first-script)

## Before you start

- The Worker from [Run a honeypot Worker on Cloudflare](honeypot-worker.md) is deployed, and RemotePower reads its log. Nothing changes on the RemotePower side.
- Your own addresses are in `ALLOW`. Keep them there while you test, and test one trap at a time.
- Do not trap a path your site really serves. That goes for every line on this page, including the `robots.txt` decoys and `/backups`. A WordPress site serves `/wp-login.php` and `/xmlrpc.php`, and the config below has routes for both: [Step 3](#step-3-choose-your-traps) says what to delete.

## What each trap catches

| Trap | `kind` | The visitor asked for | Filed as | Needs |
|---|---|---|---|---|
| Loot and exploit paths | `bait` | `.env`, `.git/HEAD`, `.git/config`, `.aws`, `.ssh`, SQL dumps, `actuator`, `phpunit` | Probing for exposed files and admin pages | A route for each path |
| Login pages | `login` | `wp-login.php`, `xmlrpc.php`, `phpmyadmin`, `administrator` | Probing for exposed files and admin pages | A route for each path. On a WordPress site, none for `wp-login.php` or `xmlrpc.php` |
| A fake git repository | `gitdump` | What a git dump tool asks for after `HEAD`: `objects`, `refs`, `logs`, `index`, `packed-refs` | Probing for exposed files and admin pages | The `.git` route |
| robots.txt decoys | `robots` | A path that only `robots.txt` names | Unwanted web crawling | Routes for `/robots.txt` and each decoy path |
| A fake backup directory | `mazeentry`, `maze`, `mazeloot` | The directory, a folder in it, an archive in it | Probing for exposed files and admin pages | The `/backups` route |
| WordPress probes | `wpprobe`, `wpenum` | The debug log, `wp-includes`, the user list | Probing for exposed files and admin pages | Routes you switch on, for sites that are not WordPress |
| A planted password | `canary_use` | The password that the fake `.env` handed out, sent to a fake login or in a Basic header | Using a credential planted in a decoy file | `CANARY_PASSWORD` |
| Decoy hosts | `decoy`, `decoy_login` | A host name nobody was told about, and signing in there | Probing for exposed files and admin pages, and signing in to a decoy service | A Custom Domain and `DECOY_HOSTS` |

## Step 1: Replace the script

Replace `worker.js` with this. It does everything the first script did and adds the rest.

```js
// The fuller honeypot Worker for RemotePower. It answers decoy paths, a fake git
// repository, a fake backup directory and decoy host names, and prints one
// `trap hit` line for each visit, which RemotePower reads from Workers Logs. It
// holds no Cloudflare credentials and calls no API. Every other path goes through
// to your site untouched. Which traps are live is decided by the routes in
// wrangler.toml: a path with no route never reaches this script.

// [kind, lower-case path prefix]; the first match wins. Each prefix needs a route in
// wrangler.toml. Delete a line, and its route, if your site really serves that path.
const TRAPS = [
  // A fake git repository. HEAD and config are answered; the rest is what dump tools ask for.
  ["gitdump", "/.git/objects/"],
  ["gitdump", "/.git/refs/"],
  ["gitdump", "/.git/logs/"],
  ["gitdump", "/.git/index"],
  ["gitdump", "/.git/packed-refs"],
  ["bait", "/.git"],
  // Loot and exploit paths.
  ["bait", "/.env"],
  ["bait", "/.aws/"],
  ["bait", "/.ssh/"],
  ["bait", "/backup.sql"],
  ["bait", "/dump.sql"],
  ["bait", "/database.sql"],
  ["bait", "/actuator"],
  ["bait", "/vendor/phpunit/"],
  // Login pages your site does not have.
  ["login", "/wp-login.php"],
  ["login", "/xmlrpc.php"],
  ["login", "/phpmyadmin"],
  ["login", "/administrator"],
  // Paths that only robots.txt names. Choose names of your own: a bot that ignores
  // robots.txt asks for them, and nobody else has a reason to.
  ["robots", "/old-backups/"],
  ["robots", "/private-files/"],
  ["robots", "/site-archive/"],
  // WordPress paths. Keep these, and their routes, only if your site is not WordPress.
  ["wpprobe", "/wp-content/debug.log"],
  ["wpprobe", "/wp-includes/"],
  ["wpenum", "/wp-json/wp/v2/users"],
];

// A fake backup directory: a small tree that lists itself and ends in "loot" files.
const MAZE_ROOT = "/backups";
const MAZE = {
  "/backups/": ["db/", "www/", "readme.txt"],
  "/backups/db/": ["site-2024-11-02.sql.gz", "users-2024-11-02.sql.gz"],
  "/backups/www/": ["site-files.tar.gz", "uploads.zip"],
};
const LOOT = /\.(gz|zip|sql|bak|tar)$/;

// What a visitor gets back. All of it is made up. A planted password is set by you,
// in wrangler.toml, and is only handed out when you have set one.
const FAKE_GIT = {
  "/.git/head": "ref: refs/heads/main\n",
  "/.git/config": "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n",
  "/.git/refs/heads/main": "3f786850e387550fdab836ed7e6dc881de23001b\n",
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

// A comma separated variable as a list of trimmed, lower-case entries.
function list(value) {
  return String(value || "")
    .split(",")
    .map((a) => a.trim().toLowerCase())
    .filter(Boolean);
}

// The planted password counts only when you have set one of 12 characters or more.
function planted(env) {
  const pw = String(env.CANARY_PASSWORD || "");
  return pw.length >= 12 ? pw : "";
}

function fakeEnv(env) {
  const pw = planted(env);
  const lines = [
    "APP_ENV=production",
    "APP_DEBUG=false",
    "DB_HOST=127.0.0.1",
    "DB_DATABASE=app",
    "DB_USERNAME=app",
    "DB_PASSWORD=change-me",
  ];
  if (pw) lines.push("ADMIN_USER=" + (env.CANARY_USER || "admin"), "ADMIN_PASSWORD=" + pw);
  return lines.join("\n") + "\n";
}

// Was the planted password sent? The header is read for any trap. A body is read only
// for a POST to a login page, only up to 4 KB, only to compare it, and is never logged.
// A body that cannot be read is no match, so the visit is still logged and answered.
async function usedPlanted(request, pw, withBody) {
  if (!pw) return false;
  const auth = request.headers.get("authorization") || "";
  if (/^basic /i.test(auth)) {
    try {
      if (atob(auth.slice(6).trim()).includes(pw)) return true;
    } catch (e) {
      // not base64: nothing to compare
    }
  }
  if (!withBody || request.method !== "POST") return false;
  const length = Number(request.headers.get("content-length"));
  if (!(length > 0 && length <= 4096)) return false;
  try {
    const text = await request.text();
    return text.includes(pw) || decodeURIComponent(text.replace(/\+/g, " ")).includes(pw);
  } catch (e) {
    return false; // the body did not arrive, or is not valid percent-encoding
  }
}

// A path as the directory it names, with its trailing slash.
function dirOf(path) {
  return path.endsWith("/") ? path : path + "/";
}

// Which trap is this path? {kind, missing} for the fake backup directory, else the table.
function classify(path) {
  if (path === MAZE_ROOT || path.startsWith(MAZE_ROOT + "/")) {
    const dir = dirOf(path);
    if (dir === "/backups/") return { kind: "mazeentry" };
    if (MAZE[dir]) return { kind: "maze" };
    const parent = path.slice(0, path.lastIndexOf("/") + 1);
    const name = path.slice(parent.length);
    const real = Boolean(MAZE[parent] && MAZE[parent].includes(name));
    return { kind: LOOT.test(name) ? "mazeloot" : "maze", missing: !real };
  }
  const trap = TRAPS.find(([, prefix]) => path.startsWith(prefix));
  return trap ? { kind: trap[0] } : null;
}

function page(body, type, status) {
  return new Response(body, {
    status: status || 200,
    headers: {
      "content-type": type,
      "cache-control": "no-store",
      "x-robots-tag": "noindex, nofollow",
      "x-content-type-options": "nosniff",
    },
  });
}

function listing(dir) {
  const items = MAZE[dir].map((n) => '<li><a href="' + dir + n + '">' + n + "</a></li>").join("");
  return (
    "<!doctype html><title>Index of " + dir + "</title><h1>Index of " + dir + "</h1><ul>" +
    items + "</ul>"
  );
}

// What the visitor is shown, by the kind of trap they walked into.
function decoy(env, shape, path, missing) {
  const html = "text/html; charset=utf-8";
  const text = "text/plain; charset=utf-8";
  if (shape === "decoy" || shape === "decoy_login" || shape === "login") {
    return page(LOGIN_PAGE, html);
  }
  if (shape === "mazeentry" || shape === "maze" || shape === "mazeloot") {
    const dir = dirOf(path);
    if (missing) return page("Not found\n", text, 404);
    if (MAZE[dir]) return page(listing(dir), html);
    if (shape === "mazeloot") return page("Not an archive.\n", text);
    return page("Nightly backups.\n", text);
  }
  if (path.startsWith("/.env")) return page(fakeEnv(env), text);
  if (FAKE_GIT[path]) return page(FAKE_GIT[path], text);
  return page("Not found\n", text, 404);
}

// Your own robots.txt with the decoy lines added to each group in it, right under its
// User-agent lines. A crawler that finds a group for itself reads only that group, so a
// decoy left out of it would not be off limits to that crawler. A file with no
// `User-agent: *` group gets one for every other crawler.
function withDecoys(text, lines) {
  const out = [];
  let agent = -1;
  let everyone = false;
  for (const line of text.split("\n")) {
    const bare = line.replace(/#.*/, "").trim();
    if (/^user[- ]?agent\s*:/i.test(bare)) {
      agent = out.length;
      if (/:\s*\*$/.test(bare)) everyone = true;
    } else if (bare && agent >= 0) {
      out.splice(agent + 1, 0, ...lines);
      agent = -1;
    }
    out.push(line);
  }
  if (agent >= 0) out.splice(agent + 1, 0, ...lines);
  const own = out.join("\n").trimEnd();
  if (everyone) return own + "\n";
  return (own ? own + "\n\n" : "") + "User-agent: *\n" + lines.join("\n") + "\n";
}

// robots.txt: your own file with the decoys added. Only a file is added to. When your
// site has none (404 or 410) the decoys go alone. Any other answer goes back unchanged:
// a 5xx tells crawlers to stay out until your site answers, and a redirect points them
// at the file to read.
async function robots(request) {
  const lines = TRAPS.filter(([k]) => k === "robots").map(([, p]) => "Disallow: " + p);
  if (!lines.length) return fetch(request);
  let site;
  let text = "";
  try {
    site = await fetch(request);
    if (site.ok) text = await site.text();
  } catch (e) {
    return page("Service unavailable\n", "text/plain; charset=utf-8", 503);
  }
  if (!site.ok && site.status !== 404 && site.status !== 410) return site;
  return page(withDecoys(text, lines), "text/plain; charset=utf-8");
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.toLowerCase();
    const host = url.hostname.toLowerCase();

    let kind;
    let missing = false;
    if (list(env.DECOY_HOSTS).includes(host)) {
      kind = request.method === "POST" ? "decoy_login" : "decoy";
    } else if (path === "/robots.txt") {
      return robots(request);
    } else {
      const hit = classify(path);
      if (!hit) return fetch(request);
      kind = hit.kind;
      missing = Boolean(hit.missing);
    }

    const shape = kind;
    const ip = request.headers.get("cf-connecting-ip") || "";
    const own = list(env.ALLOW).includes(ip.toLowerCase());
    const login = shape === "login" || shape === "decoy" || shape === "decoy_login";
    if (await usedPlanted(request, planted(env), login)) kind = "canary_use";

    if (ip && shouldLog(kind + " " + ip)) {
      console.log(
        JSON.stringify({
          msg: "trap hit",
          kind,
          ip,
          action: own ? "allowlisted" : "recorded",
          at: new Date().toISOString(),
          host,
          method: request.method,
          path: url.pathname.slice(0, 200),
          ua: (request.headers.get("user-agent") || "").slice(0, 160),
          country: (request.cf && request.cf.country) || "",
        }),
      );
    }
    return decoy(env, shape, path, missing);
  },
};
```

## Step 2: Replace the config

Replace `wrangler.toml` with this. Compared with the first config, the routes are grouped by trap, and there are three more variables.

```toml
name = "trap-sink"
main = "worker.js"
compatibility_date = "2025-01-01"
workers_dev = false

# One route per trap. Replace example.com with your domain in every line. Delete the
# lines of any trap you do not want: a path with no route never reaches the script.
routes = [
  # Loot and exploit paths
  { pattern = "*example.com/.env*", zone_name = "example.com" },
  { pattern = "*example.com/.git*", zone_name = "example.com" },
  { pattern = "*example.com/.aws/*", zone_name = "example.com" },
  { pattern = "*example.com/.ssh/*", zone_name = "example.com" },
  { pattern = "*example.com/backup.sql*", zone_name = "example.com" },
  { pattern = "*example.com/dump.sql*", zone_name = "example.com" },
  { pattern = "*example.com/database.sql*", zone_name = "example.com" },
  { pattern = "*example.com/actuator*", zone_name = "example.com" },
  { pattern = "*example.com/vendor/phpunit/*", zone_name = "example.com" },
  # Login pages. On a WordPress site, delete the wp-login.php and xmlrpc.php lines.
  { pattern = "*example.com/wp-login.php*", zone_name = "example.com" },
  { pattern = "*example.com/xmlrpc.php*", zone_name = "example.com" },
  { pattern = "*example.com/phpmyadmin*", zone_name = "example.com" },
  { pattern = "*example.com/administrator*", zone_name = "example.com" },
  # robots.txt decoys: the Worker adds these paths to your own robots.txt
  { pattern = "*example.com/robots.txt", zone_name = "example.com" },
  { pattern = "*example.com/old-backups/*", zone_name = "example.com" },
  { pattern = "*example.com/private-files/*", zone_name = "example.com" },
  { pattern = "*example.com/site-archive/*", zone_name = "example.com" },
  # A fake backup directory
  { pattern = "*example.com/backups*", zone_name = "example.com" },
  # WordPress paths: remove the # only if your site is not WordPress
  # { pattern = "*example.com/wp-content/debug.log*", zone_name = "example.com" },
  # { pattern = "*example.com/wp-includes/*", zone_name = "example.com" },
  # { pattern = "*example.com/wp-json/wp/v2/users*", zone_name = "example.com" },
  # A decoy host: one line for each name in DECOY_HOSTS. The name must not exist yet.
  # { pattern = "vpn-portal.example.com", custom_domain = true },
]

# Without this, Workers Logs is off and RemotePower has nothing to read.
[observability]
enabled = true

[vars]
# Your own addresses, comma separated. Visits from these are logged as
# "allowlisted" and RemotePower sets them aside.
ALLOW = ""
# A password that the fake .env hands out and the fake login pages recognise.
# 12 or more random letters, digits, - or _. Empty means off.
CANARY_PASSWORD = ""
CANARY_USER = "admin"
# Decoy host names, comma separated. Each needs a Custom Domain line above.
DECOY_HOSTS = ""
```

## Step 3: Choose your traps

1. Replace `example.com` with your domain in every route line.
2. Delete the routes of the traps you do not want. The script can stay as it is, because a path with no route never reaches it.
3. Rename the `robots.txt` decoys. Edit the three `robots` lines in `TRAPS` and the three matching routes. Pick names that sound worth stealing and that your site does not have.
4. If your site is not WordPress, remove the `#` from the three WordPress routes. On a WordPress site leave them off, and delete the routes for `/wp-login.php` and `/xmlrpc.php` as well. All five paths are real there, and with those two routes on, your own logins and anything that uses XML-RPC would get the fake page instead of WordPress.
5. To use the planted password and the decoy hosts, follow [The planted password](#the-planted-password) and [Decoy hosts](#decoy-hosts). Leave both empty to skip them.

## Step 4: Deploy and check each one

```sh
npx wrangler deploy
npx wrangler tail trap-sink
```

Ask for each trap in another terminal and watch the `kind` in the log:

| Ask for | You should see | `kind` |
|---|---|---|
| `curl -i https://example.com/.git/refs/heads/main` | A 40 character hash | `gitdump` |
| `curl https://example.com/robots.txt` | Your own file, with the decoy `Disallow:` lines added under each `User-agent:` group. A file with no `User-agent: *` group gets one at the end | No line: the file is the bait, not a hit |
| `curl -i https://example.com/old-backups/` | A `404` | `robots` |
| `curl https://example.com/backups/` | A directory listing | `mazeentry` |
| `curl https://example.com/backups/db/` | A listing of two archives | `maze` |
| `curl https://example.com/backups/db/site-2024-11-02.sql.gz` | A short text | `mazeloot` |
| `curl -i https://example.com/wp-content/debug.log` | A `404` | `wpprobe` |
| `curl -i https://example.com/wp-json/wp/v2/users` | A `404` | `wpenum` |
| `curl https://example.com/wp-login.php` | The fake login page | `login` |
| `curl https://example.com/.env` | The settings, and two more lines when a password is set | `bait` |
| `curl -d 'log=admin&pwd=YOUR-PASSWORD' https://example.com/wp-login.php` | The fake login page | `canary_use` |
| `curl -i https://vpn-portal.example.com/` | The fake login page | `decoy` |
| `curl -d 'a=b' https://vpn-portal.example.com/login` | The fake login page | `decoy_login` |

From an address in `ALLOW` every line says `allowlisted`, with the same `kind`. The WordPress rows answer only when you switched their routes on, the password row only when `CANARY_PASSWORD` is set, and the decoy host rows only when you set up a decoy host.

## The planted password

The fake `.env` can hand out a user name and a password. A visitor who read the file and then sends that password to a fake login page is using a credential that only the honeypot handed out. No ordinary visitor can have it, which makes it the strongest sign on this page.

1. Make a password of 12 or more random letters, digits, `-` or `_`. Node can do it:

```sh
node -e "console.log(require('crypto').randomBytes(18).toString('base64url'))"
```

2. Put it in `CANARY_PASSWORD` in `wrangler.toml` and run `npx wrangler deploy`. Do not use a real password, and do not reuse one you have used anywhere else.

What the script does with it:

- The fake `.env` gains `ADMIN_USER` and `ADMIN_PASSWORD` lines. With `CANARY_PASSWORD` empty, or under 12 characters, it hands out nothing and nothing counts.
- A `Basic` authorization header on any trap is read and compared.
- A `POST` to a fake login page or a decoy host is read, up to 4 KB, and only if the request states its length. The body is searched for the password and then dropped. It is never logged.
- A match is logged as `canary_use` instead of `login`.

## Decoy hosts

A decoy host is a name nobody was told about. Nothing links to it, so a request for it comes from something that guessed it or found it: a DNS brute-force tool, a scanner working through common names, or one that watches certificate logs. The certificate that Cloudflare issues for a Custom Domain names the host, and certificates are public, so the name is not secret.

1. Choose a name that does not exist, such as `vpn-portal.example.com`. Look it up first, and pick another if it answers. A Custom Domain for a name that is in use would replace that service.
2. Remove the `#` from the Custom Domain line in `routes`, and put your name in it.
3. Put the same name in `DECOY_HOSTS`. Separate several names with commas, and give each its own line in `routes`.
4. Run `npx wrangler deploy`.

Cloudflare creates the DNS record and a certificate for a [Custom Domain](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/) and sends every path on the name to the Worker, so the Worker is the whole site and there is no origin to reach. It will not create one on a name that already has a CNAME record.

A `GET` is logged as `decoy` and a `POST` as `decoy_login`. Either shows the fake login page.

## What RemotePower does with them

RemotePower files each line by its `kind`, as the first table says, and reports an address when its hits reach **Report after attempts**, which is 10 unless you changed it ([Limits on API use](ip-intel.md#limits-on-api-use)).

RemotePower reports an address at once only when the Worker banned it, and this Worker never bans. So a use of the planted password or a sign-in to a decoy host counts as one hit, like a visit to `/.env`. To block one of those addresses now, press **Ban** on its row ([Ban an address by hand](edge-sources.md#ban-an-address-by-hand)). [Block what it finds](honeypot-worker.md#block-what-it-finds) says how reports become blocks.

## What this page leaves out

- **Crawlers that claim to be a search engine.** Telling a real one from a fake one needs a list of the search engines' networks, and that list goes stale. Cloudflare's bot rules already tell verified crawlers apart, so use them in a WAF rule.
- **Private host names.** The decoy hosts above cover the idea. Names that belong to your own network are for you to choose.
- **Answering back.** Some honeypots send a decompression bomb or a slow stream to whatever asks. This one does not, and you should think hard before you add that. The visitor can be a researcher, a crawler or a compromised machine that belongs to someone else, and every answer costs a Worker request.
- **A ban in the Worker.** That needs a Cloudflare token inside a Worker that faces the internet, and a job to expire the bans. RemotePower's [Edge blocklist](edge-sources.md#edge-blocklist) does the same thing from one place.

## Limits

- **Requests.** Every request that reaches the Worker counts against the plan's daily total, including each `robots.txt` fetch and each page a crawler walks in the fake directory. The log throttle limits log lines, not requests. The fake directory is small and fixed, so a crawl of it ends.
- **The planted password.** Only a request that states a length of 4 KB or less is read. A chunked `POST` is not compared.
- **Decoy hosts.** Custom Domains match the exact name and do not support wildcards.
- **Routes.** The rules of the first guide apply: paths are case sensitive, and a route cannot have a wildcard in the middle or a query string.

## Security

- The Worker holds no Cloudflare token and calls no API.
- Every answer is fixed text. Nothing the visitor sent is echoed, and the directory listing only names entries that the script lists.
- A visitor's password reaches the Worker when a login page is posted to. The Worker compares it with the planted one and drops it, and never writes it to the log.
- The planted password is not a secret from the visitor, by design. Never make it a password that opens anything real.
- The fake directory and the fake git repository serve no real file and no archive.

## Troubleshooting

| You see | Why | What to do |
|---|---|---|
| `robots.txt` shows only the decoy lines | Your site has no `robots.txt`: it answered `404` or `410` | Expected. The Worker sends the decoys alone. |
| `robots.txt` answers with an error or a redirect | Your site answered that way, and the Worker passes on any answer that is not a file. If it cannot reach your site at all, it answers `503` | Expected. Crawlers follow a redirect, and a `5xx` keeps them out until your site answers, as it would without the Worker. |
| `robots.txt` is unchanged | The route for `/robots.txt` is missing | Add the route and deploy again. |
| The password is used and the line says `login` | `CANARY_PASSWORD` is empty or under 12 characters, the request states no length or more than 4 KB, or the password differs | Check the variable, then send the password as `pwd=...` in a short `POST`. |
| `.env` has no `ADMIN_PASSWORD` line | `CANARY_PASSWORD` is empty or under 12 characters | Set it and deploy again. |
| The decoy host name does not resolve | The Custom Domain was not created. Cloudflare will not create one on a name that already has a CNAME record | Read what `npx wrangler deploy` said, and pick a name that does not exist. |
| The decoy host shows an error page, or the log says `bait` or `login` instead of `decoy` | The name is not in `DECOY_HOSTS`, or is spelled differently there. The Worker then treats the visit as one to your site, and a decoy host has no site behind it | Put the name in `DECOY_HOSTS` exactly as in its route, and deploy again. |
| A WordPress path answers `404` from your own site | Its route is off | Remove the `#` from the route, only if your site is not WordPress. |

## Go back to the first script

Put the first guide's `worker.js` and `wrangler.toml` back and run `npx wrangler deploy`. If a decoy host is still listed in the Worker's settings in the Cloudflare dashboard, remove it there.
