# Custom Monitoring Scripts

*(v2.5.0)*

Define arbitrary bash scripts server-side, assign them to any enrolled
devices, and get fleet-wide pass/fail status every five minutes — no
SSH, no Ansible, no separate monitoring stack.

---

## How it works

1. An admin creates a script in the **Custom Scripts** page (sidebar).
2. The server pushes the script body to assigned devices via their
 regular heartbeat response.
3. The agent runs each assigned script every **5 minutes** using
 `/bin/bash`, captures stdout + stderr (merged), and reports results
 in the next heartbeat.
4. The server stores the latest result per device per script and shows
 it on the Custom Scripts page.
5. Status changes fire **edge-triggered webhooks** — once on
 OK → FAIL, once on FAIL → OK.

No new network connections are opened. Scripts travel over the same
HTTPS channel the agent already uses.

---

## Exit code convention

| Exit code | Meaning |
|-----------|---------|
| **0** | OK — check passed |
| **non-zero** | FAIL — check failed |

This is a binary signal, not MRPE's four-level severity. Keep your
scripts simple: succeed or fail.

---

## Creating a script

### Paste a script

1. **Custom Scripts → New script**
2. Fill in **Name** (required) and **Description** (optional).
3. Paste the bash body into the **Script body** field.
4. Pick devices using the **device picker**.
5. **Save**.

The script is delivered to assigned agents on their next heartbeat
(within 60 seconds) and runs at the next 5-minute mark.

### Generate with AI

If RemotePower's AI assistant is configured (Settings → AI assistant),
the modal has a **Generate with AI** row:

1. Type a plain-English description of what to check.
2. Click ** Generate**.
3. Review the generated script — always read it before saving.
4. Edit if needed, then Save.

The AI uses the `generate_script` system prompt and is instructed to:
- Exit 0 on success, non-zero on failure
- Print a brief status line to stdout
- Stay within the 25-second budget (30 s hard timeout)
- Return only the script body (no explanations)

Generated scripts go through the same execution path as hand-written
ones — there is no special trusted path for AI output.

---

## Script execution environment

| Property | Value |
|----------|-------|
| Interpreter | `/bin/bash` |
| User | Agent user (typically **root**) |
| Timeout | **30 seconds** (hard) |
| stdout + stderr | Merged, capped at **4 KB** |
| Temp file | Written to a private temp file (chmod 700), deleted after execution |
| Working directory | Inherited from agent process |
| Environment | Inherited from agent process (includes `PATH`) |

The 4 KB output cap means only the first ~4000 characters of combined
stdout/stderr reach the server. Long output is truncated — keep script
output concise.

---

## Viewing results

**Custom Scripts → Refresh** loads the current fleet-wide result table:

| Column | Meaning |
|--------|---------|
| Script | Script name (click the definition card to edit) |
| Device | Enrolled device that ran it |
| Group | Device group for filtering |
| Status | ● OK or ● FAIL with time of last status change |
| Last output | First 80 chars of stdout/stderr — click for full output |
| Last run | When the script last executed |
| Duration | Wall-clock time for the script to complete |

The **definitions panel** below the table shows one card per script
with aggregate pass/fail counts across all assigned devices.

---

## Alerts

Two webhook events are emitted on state transitions (never on every
failing run):

```json
{ "event": "custom_script_fail",
 "device_id": "dev_abc123", "name": "web01",
 "script_id": "cs_a1b2c3d4", "script_name": "Check nginx",
 "output": "curl: (7) Failed to connect", "rc": 7 }

{ "event": "custom_script_recover",
 "device_id": "dev_abc123", "name": "web01",
 "script_id": "cs_a1b2c3d4", "script_name": "Check nginx" }
```

Configure delivery under **Settings → Webhooks**. Both events are
enabled by default. Supported destinations: Discord, ntfy, Slack,
Gotify, generic JSON POST.

**Edge-triggered:** the `custom_script_fail` event fires exactly once
when a script first fails. It does not re-fire on every subsequent
failing run. It re-arms when the script recovers. This prevents alert
fatigue from a persistently broken check.

**First-run:** no alert is fired when a script produces its first
result, regardless of outcome. This avoids a flood of `_fail` events
when you assign a new script to many devices at once.

---

## Limits

| Limit | Value |
|-------|-------|
| Scripts fleet-wide | 50 |
| Scripts per device | 10 |
| Script body | 32 KB |
| Output captured | 4 KB |
| Run cadence | Every 5 minutes |
| Timeout | 30 seconds |

---

## Script examples

### Check a web service responds

```bash
#!/bin/bash
curl -sf --max-time 10 http://localhost/ > /dev/null
echo "HTTP OK"
```

### Verify a backup file is fresh

```bash
#!/bin/bash
BACKUP=/var/backups/db.dump
if [[ ! -f "$BACKUP" ]]; then
 echo "FAIL: backup file missing"
 exit 1
fi
AGE=$(( $(date +%s) - $(stat -c %Y "$BACKUP") ))
if (( AGE > 90000 )); then # > 25 hours
 echo "FAIL: backup is ${AGE}s old"
 exit 1
fi
echo "OK: backup is ${AGE}s old"
```

### Check a TCP port is open

```bash
#!/bin/bash
HOST=localhost PORT=5432
timeout 5 bash -c "echo > /dev/tcp/$HOST/$PORT" 2>/dev/null \
 && echo "OK: $HOST:$PORT is open" \
 || { echo "FAIL: $HOST:$PORT not reachable"; exit 1; }
```

### Confirm a cron sentinel file exists

```bash
#!/bin/bash
SENTINEL=/var/run/my-cron-ran
MAX_AGE=7200 # 2 hours
if [[ ! -f "$SENTINEL" ]]; then
 echo "FAIL: sentinel missing — cron may not have run"
 exit 1
fi
AGE=$(( $(date +%s) - $(stat -c %Y "$SENTINEL") ))
if (( AGE > MAX_AGE )); then
 echo "FAIL: sentinel is ${AGE}s old (max ${MAX_AGE}s)"
 exit 1
fi
echo "OK: sentinel is ${AGE}s old"
```

### Check free disk space on a specific mount

```bash
#!/bin/bash
MOUNT=/data THRESHOLD=90
PCT=$(df --output=pcent "$MOUNT" 2>/dev/null | tail -1 | tr -d ' %')
if [[ -z "$PCT" ]]; then
 echo "FAIL: cannot read disk usage for $MOUNT"
 exit 1
fi
if (( PCT >= THRESHOLD )); then
 echo "FAIL: $MOUNT is ${PCT}% full (threshold: ${THRESHOLD}%)"
 exit 1
fi
echo "OK: $MOUNT is ${PCT}% full"
```

---

## Security considerations

- Scripts run as the **agent user** (root by default). Treat script
 creation as a privileged admin operation — only admins can create,
 edit, or delete scripts.
- The script body is transmitted over the same HTTPS channel as all
 other RemotePower data. It is stored in `custom_scripts.json` on the
 server (mode 0600, owned by the CGI user).
- Scripts are written to a private temp file (mode 0700) before
 execution and deleted immediately after. They do not persist on the
 agent host between runs.
- The trust boundary is identical to the existing `exec:` command
 channel. If you trust an operator to run arbitrary shell commands
 via RemotePower, they can already run arbitrary shell as root. Script
 creation does not expand that boundary.
- Output is captured and capped at 4 KB. Scripts cannot exfiltrate
 large files through the output channel.

---

## API reference

All endpoints require authentication (`X-Token` header).

```
GET /api/custom-scripts List all script definitions (name, desc, assignments; no body)
POST /api/custom-scripts Create a script (admin)
GET /api/custom-scripts/:id Full script detail including body
PUT /api/custom-scripts/:id Update name, description, body, or assignments (admin)
DELETE /api/custom-scripts/:id Delete script and clear all stored results (admin)
GET /api/custom-scripts/results Fleet-wide current results (all devices × all scripts)
```

### POST /api/custom-scripts — body shape

```json
{
 "name": "Check nginx",
 "description": "Verifies nginx is responding on localhost",
 "body": "#!/bin/bash\ncurl -sf http://localhost/ > /dev/null && echo OK",
 "assigned_devices": ["dev_abc123", "dev_def456"]
}
```

### GET /api/custom-scripts/results — response shape

```json
{
 "results": [
 {
 "device_id": "dev_abc123",
 "device_name": "web01",
 "group": "prod",
 "online": true,
 "script_id": "cs_a1b2c3d4",
 "script_name": "Check nginx",
 "description": "Verifies nginx is responding on localhost",
 "ok": true,
 "output": "OK",
 "rc": 0,
 "ran_at": 1716124800,
 "duration_ms": 43,
 "changed_at": 1716100000
 }
 ],
 "scripts": [
 { "id": "cs_a1b2c3d4", "name": "Check nginx", "description": "..." }
 ]
}
```

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
