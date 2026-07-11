# Agent push channel — near-instant command dispatch (experimental)

**Status: opt-in, off by default, unverified under real multi-agent
concurrent-connection load.** This is a genuine, working implementation —
not a stub — but it has not been load-tested against a real fleet with
hundreds of concurrently-connected agents (docs/master-improvement-scoping-
internal.md #1 records why: no environment to spin that up in). Turn it on
for a small/medium fleet you can watch, and report back before relying on
it at real scale.

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

1. **Settings → (Advanced) → push_enabled.** Off by default. Turning it on
   makes the heartbeat response advertise `push_enabled: true` to agents,
   which is what makes an agent start its listener thread — nothing
   happens fleet-wide until you flip this.
2. **Install `python3-websockets` on the server host** (same package the
   web-terminal daemon already needs) and start the daemon:
   ```bash
   sudo apt install python3-websockets   # or dnf/pacman/apk/zypper equivalent
   sudo cp server/push/remotepower-push.py /usr/local/bin/remotepower-push
   sudo cp packaging/remotepower-push.service /etc/systemd/system/
   sudo useradd -r -s /usr/sbin/nologin -d /var/lib/remotepower rp-push
   sudo usermod -a -G rp-www rp-push
   sudo systemctl enable --now remotepower-push
   ```
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

## Operational notes

- The daemon reads `devices.json`/`commands.json` directly (read-only) —
  it shares only the on-disk data directory with the main app, not a
  process or a network API.
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
