# Script library

*(v2.1.0)*

Multi-line bash scripts, kept separate from the existing single-line
Command Library. Lint with `bash -n` and a dangerous-command sweep before
they leave the dashboard; run on a single device from the device
dropdown, or on a multi-select batch from the action bar.

## Why a separate page

The 2.0 Command Library is for one-liners you pick from the exec modal:
`systemctl status nginx`, `apt-get clean`, `ip a`. Editing it in a
textarea always felt wrong, and the data model (one snippet = one line)
hard-coded the assumption.

Scripts have a different shape:

- **Multi-line.** Up to 64 KB of body. Same execution path as `exec:` —
  the script body becomes `exec:<body>` when queued — so the agent
  doesn't need any new capability.
- **Validated.** `bash -n` syntax check + a regex sweep for dangerous
  patterns. Both run on save and on demand via the Dry-run button.
- **Audited differently.** Snippets are usually trivial; scripts are
  often runbooks. Every CRUD operation and every dispatch writes an
  audit log entry.
- **Multi-select-friendly.** The batch action bar's "Run script" button
  fans the same script out to every selected device with a single click
  and a single audit-log entry.

## Storage

```
/var/lib/remotepower/scripts.json
```

Single file. Same flat-JSON pattern as everything else. Shape:

```json
{
  "scripts": [
    {
      "id":          "a1b2c3d4e5f6",
      "name":        "rotate-nginx-logs",
      "description": "Move /var/log/nginx/*.gz to backup mount",
      "body":        "#!/usr/bin/env bash\nset -euo pipefail\n…",
      "created":     1715000000,
      "updated":     1715100000,
      "created_by":  "alice",
      "last_lint":   {
        "ok":           true,
        "syntax_error": null,
        "dangerous":    []
      }
    }
  ]
}
```

Limits (`api.py`):

| | |
|---|---|
| Max scripts per server | 500 |
| Max name length        | 80 |
| Max description length | 512 |
| Max body length        | 65 536 bytes (64 KB) |

## API

All endpoints require an authenticated session or API key. Mutating
endpoints require **admin** role.

### `GET /api/scripts`

List scripts. Body is omitted to keep the response small on fleets with
long scripts.

```json
[
  {
    "id":          "a1b2c3d4e5f6",
    "name":        "rotate-nginx-logs",
    "description": "Move /var/log/nginx/*.gz to backup mount",
    "created":     1715000000,
    "updated":     1715100000,
    "created_by":  "alice",
    "body_len":    412,
    "dangerous":   false
  }
]
```

### `GET /api/scripts/<id>`

Returns the full record, including `body` and `last_lint`.

### `POST /api/scripts`

Create. Admin only.

```json
{
  "name":        "rotate-nginx-logs",
  "description": "Optional",
  "body":        "#!/usr/bin/env bash\nset -e\n…"
}
```

Server returns `201 Created` with the new record + lint result.
Validates: `name` non-empty + ≤ 80 chars; `body` non-empty (after
stripping ASCII control chars except `\t` and `\n`) + ≤ 64 KB; total
scripts ≤ 500.

### `PUT /api/scripts/<id>`

Update. Admin only. Partial: send only the fields you want to change.
If `body` changes, `last_lint` is recomputed.

### `DELETE /api/scripts/<id>`

Delete. Admin only. Audit-logged.

### `POST /api/scripts/<id>/dry-run`

Re-run `bash -n` + the dangerous-command sweep and persist the result
on the record. Admin only. Idempotent.

```json
{
  "ok":    true,
  "lint":  {
    "ok":           true,
    "syntax_error": null,
    "dangerous":    []
  }
}
```

Possible `syntax_error` values:

- `null` — clean
- A bash error message (truncated to 2000 chars)
- `"__skipped__"` — bash isn't installed on the *server*. The dashboard
  shows a yellow "syntax check skipped" banner; the script will still
  run on the agent, which has its own bash.

## Dry run: what gets checked

### `bash -n`

The script body is piped into `bash -n` via stdin (5 s timeout). Catches:

- Unterminated quotes / heredocs
- Missing `fi` / `done` / `esac`
- Mismatched braces
- Other syntactic errors that would fail at parse time

It does **not** catch runtime issues (undefined variables, missing
binaries, permission errors, network failures). For that, set
`set -euo pipefail` at the top of every script and let it fail loud on
the agent.

### Dangerous-command sweep

11 regex patterns flag common foot-guns. The full list lives in
`_DANGEROUS_PATTERNS` in `api.py`; the current set is:

| Pattern | Example match |
|---|---|
| `rm -rf /` | `rm -rf /` |
| `rm -rf /*` | `rm -rf /*` |
| `rm --no-preserve-root /` | `rm -rf --no-preserve-root /` |
| Fork bomb | `:(){ :\|:& };:` |
| `dd` to block device | `dd if=/dev/zero of=/dev/sda` |
| `mkfs` against raw device | `mkfs.ext4 /dev/sdb1` |
| `chmod` against `/` | `chmod -R 777 /` |
| `chown -R` against `/` | `chown -R alice:alice /` |
| Redirect to block device | `cat foo > /dev/sda` |
| `shred` against block device | `shred /dev/sdb` |
| `curl … \| bash` | `curl https://example.com/install.sh \| bash` |
| `wget … \| bash` | `wget -O - https://… \| bash` |
| Touches `/etc/shadow` | reads or writes `/etc/shadow` |

False positives are **acceptable**. The lint is a confirmation prompt,
not a block. `echo "rm -rf / is bad"` will flag — that's the regex
doing its job, the operator can override at dispatch time with
`confirm_dangerous: true`.

### What dry-run does **not** do

- It doesn't sandbox-execute the script.
- It doesn't validate `set -euo pipefail` is present (recommended but
  not required).
- It doesn't check that commands referenced in the script actually exist
  on the target devices — that's the device's responsibility.

## UI

### Scripts page

Sidebar → **Admin** → **Scripts**. Lists every saved script with a
filter box, name, description, size, last-updated, and a `⚠ DANGER`
badge if any dangerous patterns were detected on last lint.

Each row has:

- **Edit** — opens the editor modal with the full body + last lint
  result.
- **Dry run** — re-runs lint and toasts the result. Updates the row's
  badge.
- **Delete** — confirms then removes.

The header has a **New script** button which opens the editor with a
shebang + `set -euo pipefail` skeleton pre-filled.

### Run modal

Two entry points:

- Device dropdown → **Run script…**
- Batch action bar → **Run script** (only visible when devices are
  selected)

Both open the same modal. Pick a script from the dropdown; if it has
dangerous patterns the consent checkbox appears. Click Queue.

The modal closes immediately and a batch-job status modal opens that
polls `/api/exec/batch/<id>` every 10 s. Output appears per-device as
each agent's next heartbeat returns it.

### Batch-job status modal

One row per target device showing:

- Name
- Status pill (`pending`, `rc=0`, `rc=1`, or a reason if skipped:
  `not_found`, `agentless`)
- For completed devices: the script output (capped at 8 KB) and the
  finished-at timestamp

Polling stops automatically once every queued device has returned
output, or after 1 hour (the job's TTL). Close button stops polling.

## Security

- **Admin-only** for every mutation, dispatch, and dry-run. Listing and
  read are session-auth.
- **No shell interpolation** of the script body. It goes verbatim into
  the agent's `exec:` channel, which runs it through `subprocess.run(…,
  shell=True)` on the agent. That's the same execution surface the
  one-liner exec uses.
- **64 KB body cap** — well below `MAX_CMD_OUT_BYTES` so script content
  can't blow up the command queue.
- **Control characters stripped** from the body on save (everything
  below ASCII 0x20 except `\t` and `\n`). Defends against agents that
  log bodies to a terminal naïvely.
- **Audit log entry** on every create / update / delete / batch dispatch.

There is currently **no per-device allowlist** for scripts. The
existing exec allowlist matches exact one-liners; arbitrary script
bodies wouldn't match. If you need a device that can't run scripts,
don't grant the dispatcher admin role on that fleet. A per-device
script-policy feature is on the roadmap.

## Examples

### Save a runbook from the CLI

```bash
curl -X POST https://rp.example.com/api/scripts \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name":        "rotate-nginx-logs",
    "description": "Move /var/log/nginx/*.gz to /mnt/backup",
    "body":        "#!/usr/bin/env bash\nset -euo pipefail\nfind /var/log/nginx -name \"*.gz\" -mtime +7 -exec mv {} /mnt/backup/ \\;\n"
  }'
```

### Dispatch via API

```bash
# Get the script ID
SCRIPT_ID=$(curl -s -H "Authorization: Bearer $API_KEY" \
  https://rp.example.com/api/scripts | jq -r '.[0].id')

# Run on a tag
curl -X POST https://rp.example.com/api/exec/batch \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"script_id\":  \"$SCRIPT_ID\",
    \"tag\":        \"web\"
  }"
```

### Poll for results

```bash
JOB_ID="..."  # from the previous response
curl -s -H "Authorization: Bearer $API_KEY" \
  https://rp.example.com/api/exec/batch/$JOB_ID | jq .
```
