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

1. **Settings → Advanced → Agent push channel.** Off by default. Turning it on
   makes the heartbeat response advertise `push_enabled: true` to agents,
   which is what makes an agent start its listener thread — nothing
   happens fleet-wide until you flip this.
2. **Install `python3-websockets` on the server host** (same package the
   web-terminal daemon already needs) and start the daemon:
   ```bash
   sudo apt install python3-websockets   # or dnf/pacman/apk/zypper equivalent
   sudo install -m 755 server/push/remotepower-push.py /usr/local/bin/remotepower-push
   sudo cp packaging/remotepower-push.service /etc/systemd/system/
   sudo useradd -r -s /usr/sbin/nologin -d /var/lib/remotepower rp-push
   # Join whichever group actually owns /var/lib/remotepower on this box
   # (www-data on Debian/Ubuntu, nginx on Fedora/RHEL, http on Arch —
   # there is no fixed "rp-www" user/group, nothing creates one) so the
   # daemon can read devices.json/commands.json.
   sudo usermod -a -G "$(stat -c '%G' /var/lib/remotepower)" rp-push
   sudo systemctl enable --now remotepower-push
   ```
   `install -m 755` (not `cp`) matters here: the source script isn't marked
   executable in git, so a plain `cp` produces a non-executable copy and
   systemd fails the unit with `status=203/EXEC`.
3. **Proxy the WebSocket through nginx** — drop `packaging/nginx-push.conf`
   into your `server {}` block (above any catch-all `location /`), same
   pattern as `nginx-webterm.conf`. Needs the same `$connection_upgrade`
   map nginx-webterm.conf documents.
4. **Install `websockets` on agent hosts too** (optional — the agent
   degrades gracefully without it, exactly like it already does for
   `psutil`): `pip install --break-system-packages 'websockets>=10'` or your
   distro's `python3-websockets` package. An agent without it simply never
   starts the listener thread and polls normally, forever — no error, no
   degraded behavior beyond "no latency benefit."

## Verifying it's actually working

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

1. **nginx must proxy the WebSocket to the daemon.** Add a location that
   forwards `/api/push/connect` to `127.0.0.1:8766` **with the WS upgrade
   headers** — an exact `location = /api/push/connect { … }` (see
   `packaging/nginx-push.conf`). Without it, the WS falls through to the generic
   `/api/` proxy (port 8090, the app) and the handshake fails. On a private
   (IP-allowlisted) vhost, include your allowlist in the location too, exactly
   like the webterm block.
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
