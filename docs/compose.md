# docker compose dropdown

*(v2.1.0)*

Per-device buttons for **Up / Down / Restart / Pull / Logs (last 50)**
on every `docker-compose.yml` the agent finds under `/opt`, `/home`,
`/docker`, or `/srv`. Discovery is push-based — the agent scans on its
own schedule and reports the project list in the heartbeat. The server
never typesheets a path that the agent didn't first volunteer; that's
the security boundary.

## What gets scanned

The agent's `get_compose_projects()` shells out to `find` over four
roots:

```
/opt   /home   /docker   /srv
```

with `-maxdepth 4`. So a project at `/opt/stack/postgres/docker-compose.yml`
is found; one at `/opt/stack/postgres/db/files/compose.yml` (five levels)
is not. Cap is 50 projects per device — anything beyond is dropped.

Files matched:

```
docker-compose.yml      docker-compose.yaml
compose.yml             compose.yaml
```

Excluded subdirs (prune list): `.git`, `node_modules`, `.cache`,
`__pycache__`, `venv`, `.venv`. So a Node project that ships its own
`docker-compose.yml` inside `node_modules` won't pollute the listing.

The scan has a **5 s timeout**. If `find` doesn't return in time
(unlikely on the configured roots; possible on very large /home trees
with millions of files), the report is empty for that heartbeat —
heartbeats are not blocked.

If `docker` isn't installed at all, the scan is skipped — there's no
point reporting projects we can't act on.

Reporting cadence matches the existing container reporting: every
`CONTAINER_CHECK_EVERY` polls, which is once every ~5 minutes by
default. So a freshly added project shows up within 5 minutes, not
immediately.

## Heartbeat payload

The agent adds a top-level `compose_projects` key:

```json
{
  "device_id": "…",
  "token":     "…",
  "compose_projects": [
    {
      "path":  "/opt/stack/postgres/docker-compose.yml",
      "dir":   "/opt/stack/postgres",
      "name":  "postgres",
      "mtime": 1715000000
    }
  ]
}
```

`name` is the **parent directory's basename** — that's what
`docker compose` itself uses for `COMPOSE_PROJECT_NAME` when nothing
overrides it, so matching the convention here keeps UI labels honest.

An empty list (`"compose_projects": []`) is meaningful — it clears any
stale entry the server had cached.

## Server-side sanitisation

`handle_heartbeat` validates every entry:

1. **Absolute paths only.** `path` and `dir` must start with `/`.
   Relative paths are silently dropped. Defends against an agent (or
   middlebox) feeding us paths that some other admin tool might
   resolve from a different CWD.
2. **`path` must live inside `dir`.** `path.startswith(dir + "/")`.
   Rejects a malicious or buggy agent reporting `{"dir": "/opt/stack",
   "path": "/etc/passwd"}` to trick the action button into pointing at
   the wrong place.
3. **Length limit.** `MAX_COMPOSE_PATH_LEN = 1024` for each of
   `path` and `dir`.
4. **Per-device cap.** First 50 entries kept, rest dropped.

Stored on the device record:

```json
{
  "compose_projects":    [ … ],
  "compose_projects_ts": 1715000000
}
```

`/api/devices` surfaces `compose_projects_count` (an integer) and
`compose_projects_ts` (last update). The full list is only available
via `GET /api/devices/<id>/compose`.

## API

### `GET /api/devices/<id>/compose`

List the compose projects this device reported in its last heartbeat.

```json
{
  "device_id":   "abc123",
  "projects":    [ { "path": "...", "dir": "...", "name": "...", "mtime": 0 } ],
  "reported_at": 1715000000,
  "docker_seen": true
}
```

`docker_seen` is `true` if the agent has ever reported a non-null
compose_projects list (so the UI can distinguish "checked, none found"
from "never checked"). Read access — viewer or admin.

### `POST /api/devices/<id>/compose/action`

Admin only. Queues `compose:<action>:<dir>` against the agent's exec
channel.

```json
{
  "action": "up",
  "dir":    "/opt/stack/postgres"
}
```

Validates:

- `action` ∈ `{up, down, restart, pull, logs}` — the only actions the
  agent recognises (see below).
- `dir` is non-empty and ≤ 1024 chars.
- `dir` **is one of the directories the agent reported in this device's
  last heartbeat.** This is the security boundary: even a stolen admin
  token can't aim `compose:up` at `/etc` or `/var`. Defence-in-depth —
  the agent enforces the same check independently.

If `dir` isn't in the reported set, you get:

```json
{
  "error": "dir not in this device's reported compose projects (refresh the listing if you just added the project)"
}
```

If the project was added on disk after the last heartbeat, the operator
needs to wait for the next `CONTAINER_CHECK_EVERY` cycle (max 5 min by
default) or restart the agent to force an immediate scan.

### Agent-side command handling

When the agent dequeues `compose:<action>:<dir>` it:

1. Splits on the **first two** colons (so paths containing `:` survive).
2. Validates `action` against `COMPOSE_ALLOWED_ACTIONS` again — the
   agent enforces the allowlist independently of the server.
3. `pathlib.Path(dir).resolve()` to canonicalise; rejects if the
   directory doesn't exist or doesn't contain any recognised compose
   file.
4. Invokes `docker compose` via **argv** (never `shell=True`):
   - `up`      → `docker compose up -d`
   - `down`    → `docker compose down`
   - `restart` → `docker compose restart`
   - `pull`    → `docker compose pull`
   - `logs`    → `docker compose logs --no-color --tail=50`
5. 180 s timeout (pull + up can be slow on cold caches).
6. Output capped at 64 KB.

Output is returned via the existing exec channel, so it lands in the
device's **Command output** panel the same way an `exec:` command's
output would.

## UI

Device card → **⋯ dropdown** → **docker compose (N)** appears whenever
the device's reported `compose_projects_count > 0`. If the agent hasn't
reported yet, the entry doesn't show at all.

The modal shows:

- A project picker dropdown (label is `<name> — <dir>`).
- Five action buttons: **Up**, **Down**, **Restart**, **Pull**,
  **Logs (last 50)**. Down has a JS-level `confirm()` since it's the
  most disruptive.
- A status / output area. Initially:
  > Queue an action — output arrives on the next heartbeat (~60s).

When an action is queued, the area shows a "Waiting for next
heartbeat" message. The actual `docker compose` output is read from the
device's `cmd_output` and rendered alongside the device's other command
output.

## Security caveats

- **The agent runs as root.** `docker compose up` therefore runs as
  root. That's the same posture as every other agent operation; it's
  worth restating because compose can pull arbitrary images.
- **Image pulls are unrestricted.** Anyone with admin role can trigger
  a `compose pull` that downloads any image listed in any reported
  compose file. The compose files themselves are not vetted by the
  dashboard — what's on disk on the device is what runs.
- **No private-registry credential handling here.** If `compose pull`
  needs auth, the agent's user already needs `docker login` to have
  been done out-of-band. The dashboard doesn't store, distribute, or
  manipulate registry credentials.
- **No support for `docker-compose-override.yml`** beyond what
  `docker compose` itself picks up. If `compose.override.yml` is in the
  same directory, compose loads it normally; the dashboard makes no
  effort to detect or surface this.

## Limitations

- **No project add/remove from the UI.** Discovery is push-only; if you
  want a project to appear in the listing, drop a `docker-compose.yml`
  under one of the four scan roots and wait for the next scan.
- **No exec-into-container support.** Use the device's webterm or
  a custom command for that.
- **No image-tag pinning enforcement.** Whatever is in the compose file
  is what compose runs.
- **No per-project policy.** Every project on a device is acted upon
  by the same admin role.
