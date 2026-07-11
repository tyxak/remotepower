# Agent push channel — near-instant command dispatch

**Status: opt-in, off by default.** This is a genuine, working
implementation, but it has not been load-tested against a real fleet with
hundreds of concurrently-connected agents (docs/master-improvement-scoping-
internal.md #1 records why: no environment to spin that up in). Turn it on
for a small/medium fleet you can watch, and report back before relying on
it at real scale. Use the **Test daemon connection** button next to the
toggle (Settings → Advanced) for a quick reachability check, and see
"Verifying it's actually working" below for the full end-to-end procedure.

## What it does, and deliberately does NOT do

The agent normally polls the server every `poll_interval` seconds (default
60s) and picks up queued commands on that cycle. This channel does **one**
thing: when an agent is connected, the server can send it a tiny "wake up
and poll now" nudge over a WebSocket, cutting worst-case command-dispatch
latency from up to 60s down to near-instant.

It does **not** replace polling, and it does **not** carry command payloads.
The agent's existing poll-and-execute code path — already correct, already
covers quarantine/audit-mode/dedup — runs exactly as before; the nudge just
makes it run sooner. Two consequences:

- If the push channel is never installed, misconfigured, or the daemon
  crashes, nothing breaks. Every device just falls back to (never leaves)
  its normal poll cadence — this is a pure latency optimization, not a new
  point of failure for command delivery.
- The daemon is a separate async process (`server/push/remotepower-push.py`,
  same shape as the existing web-terminal daemon,
  `server/webterm/remotepower-webterm.py`), not built into the main
  gunicorn app server. A WebSocket held open per agent would otherwise pin
  a thread out of gunicorn's fixed pool (`--workers 4 --threads 8`) for as
  long as the agent stays connected — fine for one browser terminal
  session, not for potentially hundreds of always-on agent connections.

## Enable it

**On a fresh install it's already installed — flip one switch.** As of v6.1.1
both `install-server.sh` and the Docker image install and start the push daemon
by default (opt out with `--no-push` / `RP_WITH_PUSH=0`), and nginx already
routes `/api/push/connect` to it. The daemon sits idle until you turn the channel
on, so enabling push is a single toggle:

1. **Settings → Advanced → Agent push channel** (`push_enabled`). Off by default.
   Turning it on makes the heartbeat response advertise `push_enabled: true`,
   which is what makes each agent start its listener thread — nothing happens
   fleet-wide until you flip this.
2. **Make sure `websockets` is present on the agent hosts** (optional — the agent
   degrades gracefully without it, like it does for `psutil`):
   `apt/dnf/pacman install python3-websockets`, or
   `pip install --break-system-packages 'websockets>=10'`. Without it the agent
   simply never starts the listener and keeps polling normally — no error, just
   no latency benefit. The server host needs it too (it already does if the web
   terminal is installed).

That's it. Confirm on the **Server status → Distributed subsystems** card, or with
the **Test daemon connection** button under Settings.

### Upgrading an existing install (or a hand-rolled vhost)

If you installed before v6.1.1, or you maintain your own nginx vhost, add the
three pieces `install-server.sh` now ships:

```bash
# 1. the daemon binary + service (runs as the web user; reads the storage backend)
sudo install -m 0755 server/push/remotepower-push.py /usr/local/bin/remotepower-push
sudo cp server/conf/remotepower-push.service /etc/systemd/system/
#    (set User=/Group= to your web user if not www-data)
sudo systemctl daemon-reload && sudo systemctl enable --now remotepower-push

# 2. the nginx route — the shipped snippet already has it; a custom vhost needs
#    `location = /api/push/connect { … proxy_pass http://127.0.0.1:8766; … }`
#    (see server/conf/remotepower-locations.conf) plus the $connection_upgrade
#    map (server/conf/remotepower-ws-map.conf, in an http{} include).
sudo nginx -t && sudo systemctl reload nginx
```

`install -m 0755` (not `cp`) matters: the source isn't executable in git, so a
plain `cp` yields a non-executable copy and systemd fails the unit with
`status=203/EXEC`.

## Verifying it's actually working

The quickest check is **`sudo rp doctor`** ([cli.md](cli.md)) — it inspects the
push daemon, its nginx route, the `$connection_upgrade` map, and the
backend=json-under-Postgres failure class, and tells you the fix. The manual
steps:

1. Confirm the daemon and its nginx proxy are up: `systemctl status
   remotepower-push`, and `sudo journalctl -u remotepower-push -f` — keep
   this open, it logs every connect/disconnect.
2. Enable the toggle (above) and save. Click **Test daemon connection**
   right next to it — this is a TCP-reachability check from the server to
   the daemon's own port (8766 by default). It confirms the daemon is
   running and its port is up; it does **not** prove nginx is proxying
   `/api/push/connect` correctly or that a real device can authenticate.
3. An agent only picks up `push_enabled: true` on its *next* heartbeat (up
   to `poll_interval`, default 60s). Once it does, the daemon's journal
   logs `push: <device_id> connected (N total)`. If nothing shows up after
   ~2× the poll interval, check the nginx proxy config and that the agent
   host actually has `websockets` installed (it degrades silently, no
   error, if the package is missing).
4. The real functional test is **latency, not just connectivity**: queue a
   command against a connected device. With push working it runs in well
   under a second; without it (or with the toggle off), it waits up to
   `poll_interval` seconds for the agent's next scheduled poll. Comparing
   that latency on vs. off is what actually proves the nudge is doing its
   job — a successful connection alone only proves the WebSocket path
   works.

## Auth model

An agent authenticates to the push daemon with the exact same device token
it already sends on every heartbeat (`DEVICES_FILE[dev_id]['token_hash']` —
the daemon ports the identical constant-time comparison logic from
`api.py`'s `_device_token_ok()`, since it's a separate process and can't
import api.py directly). `device_id` travels in the connect URL's query
string (not sensitive — it's not secret anywhere else in the product
either); the token travels in a custom `X-RP-Push-Token` header rather than
the query string specifically so it doesn't land in nginx's default
access-log line the way a query-string secret would.

## Deployment (v6.1.1) — backend, nginx, and self-update

Three things must line up for push to actually connect. All three only bite on
an *installed* server (not the repo test tree), so verify them on the box:

1. **nginx must proxy the WebSocket to the daemon.** The shipped
   `remotepower-locations.conf` already forwards `/api/push/connect` to
   `127.0.0.1:8766` with the WS upgrade headers (plus the `$connection_upgrade`
   map from `remotepower-ws-map.conf`), so fresh installs get this for free.
   Only a **hand-maintained vhost** needs to add the exact
   `location = /api/push/connect { … }` block itself — without it the WS falls
   through to the generic `/api/` proxy (port 8090, the app) and the handshake
   fails. On a private (IP-allowlisted) vhost, include your allowlist in the
   location too, exactly like the webterm block.
2. **The daemon is backend-aware.** Under the default Postgres/SQLite backend the
   `*.json` files don't exist on disk — the daemon reads device tokens through
   the app's storage layer. It locates `server/cgi-bin/storage*.py` automatically
   (repo layout, `/var/www/remotepower/cgi-bin`, …; override with `RP_CGI_BIN`)
   and, on Postgres, pulls the DSN from the storage marker
   (`/var/lib/remotepower/storage_backend.json`) just like the app — so no extra
   env is normally needed. Confirm the startup line reads `backend=postgres`
   (not `backend=json`) with no `storage backend detection failed` warning.
3. **Deploy an agent fix to BOTH copies.** The agent self-updates by comparing
   its sha256 to the one the server advertises from
   `/var/www/remotepower/agent/remotepower-agent`. If you only replace the
   running `/usr/local/bin/remotepower-agent`, the next self-update **reverts it**
   to the server's copy. Always update the distribution copy too (drop its
   `.sha256` sidecar to force a rehash) — `deploy-server.sh` does both at once.

## Operational notes

- The daemon reads device/command state through the active storage backend
  (v6.1.1) — flat JSON files under the JSON backend, or the DB under
  Postgres/SQLite — read-only, sharing only the data directory with the app.
- Token rotation (or a brand-new enrollment) takes effect on the very next
  connection attempt — the daemon's device cache is keyed on the file's
  own mtime, not a time-based TTL, so there's no window where a just-
  rotated token still authenticates.
- A wake nudge for the same still-pending command is throttled to at most
  once every 30 seconds per device (new work always nudges immediately
  regardless of that cooldown) — bounds how often a connected agent gets
  woken while one command sits queued for a while.
- Disabling `push_enabled` after an agent's listener thread has already
  started does not stop that thread until the agent restarts — an
  accepted limitation for what's purely a latency optimization; worst case
  the thread keeps trying to connect and has nothing useful to receive.
