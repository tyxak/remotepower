# Custom Monitoring Scripts

*(v2.5.0)*

Define arbitrary bash scripts server-side, assign them to any enrolled
hosts, and get fleet-wide pass/fail status every five minutes — no
SSH, no Ansible, no separate monitoring stack.

---

## How it works

1. An admin creates a script in the **Custom Scripts** page (sidebar).
2. The server pushes the script body to assigned hosts via their
 regular heartbeat response.
3. The agent runs each assigned script every **5 minutes** using
 `/bin/bash`, captures stdout + stderr (merged), and reports results
 in the next heartbeat.
4. The server stores the latest result per host per script and shows
 it on the Custom Scripts page.
5. Status changes fire **edge-triggered webhooks** — once on
 OK → FAIL, once on FAIL → OK.

No new network connections are opened. Scripts travel over the same
HTTPS channel the agent already uses.

---

## Exit code convention

By default a script is **pass or fail**:

| Exit code | Meaning |
|-----------|---------|
| **0** | OK — check passed |
| **non-zero** | FAIL — check failed |

Keep these scripts simple: succeed or fail. If you want four states and
performance data instead, read the script as a Nagios plugin (next section).

### Read it as a Nagios plugin *(7.4.9)*

Under **How the result is read**, pick **Nagios plugin** and the exit code
becomes one of four states, the way a Nagios, Icinga or Sensu check does it:

| Exit code | State |
|-----------|-------|
| **0** | OK |
| **1** | WARNING |
| **2** | CRITICAL |
| **3**, or anything else | UNKNOWN (a script the agent could not run, or one that timed out, is UNKNOWN too) |

That lets you run the plugins you already have, such as `check_disk`,
`check_procs`, `check_http` or an NRPE command, as they are. Put the plugin's
command in the script body:

```bash
#!/bin/sh
/usr/lib/nagios/plugins/check_disk -w 20% -c 10% -p /
```

The plugin's first line is the status text, and it can end with performance
data after a `|`:

```text
DISK WARNING - free space: / 4012 MB (18%) | /=17988MB;19000;20000;0;22000 inodes=41%;80;90
```

- **Status text.** The part before the `|` is what the Checks page, the alert and
  every notification say. The rest of the output stays in the full output dialog.
- **Performance data.** Each `label=value[unit];warn;crit;min;max` item is kept
  (up to 20), and the results table shows the first three. A label with spaces is
  written in single quotes, `'free space'=12MB`, and a value of `U` means unknown.
  The warning and critical fields are kept as the plugin wrote them, ranges such as
  `10:20` or `~:5` included.
- **Alerts.** The first result raises nothing. After that, a change of state raises
  **Custom script failed** (the title says *warning* or *unknown* for those states)
  and a return to OK closes it. A script that goes from warning to critical raises
  the open alert to high; a warning or unknown alert is medium, a critical one is
  high, as a failing script always was. Going from critical back to warning does not
  lower the open alert, and a return to OK closes it.
- **Checks and Needs attention.** The script's row on the Checks page has the four
  states. Needs attention counts a critical plugin as critical and the others as
  warnings.
- **Prometheus.** `remotepower_script_state` is 0, 1, 2 or 3 (a pass-or-fail script
  is 0 or 2), and `remotepower_script_perf_value` carries each numeric performance
  value with its `label` and `unit`, so a Grafana panel can graph a plugin.
- **No agent update needed.** The agent already reports the exit code; the server
  reads it. A script you do not switch keeps reading exactly as before.

---

## Creating a script

### Paste a script

1. **Custom Scripts → New script**
2. Fill in **Name** (required) and **Description** (optional).
3. Paste the bash body into the **Script body** field.
4. Pick hosts using the **host picker**.
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
| Interpreter | `/bin/bash` (Linux, macOS) — see *Windows* below |
| User | Agent user (typically **root** / **SYSTEM**) |
| Timeout | **30 seconds** (hard) |
| stdout + stderr | Merged, capped at **4 KB** |
| Temp file | Written to a private temp file (chmod 700), deleted after execution |
| Working directory | Inherited from agent process |
| Environment | Inherited from agent process (includes `PATH`) |

The 4 KB output cap means only the first ~4000 characters of combined
stdout/stderr reach the server. Long output is truncated — keep script
output concise.

**Observe-only hosts never run them.** A host with the operator-owned
`audit-mode` marker refuses custom scripts along with every other command
channel — this runs server-supplied script text as root, which is exactly what
that mode exists to block.

### Platform support *(v6.4.1)*

Scripts are assigned by **host**, not by OS, and until v6.4.1 only the Linux
agent read them — so a script assigned to a Windows or Mac host silently did
nothing and its results page stayed empty forever. All three agents run them now.

| Platform | Interpreter | Notes |
|---|---|---|
| Linux | `/bin/bash` | |
| macOS | `/bin/bash` | Same body as Linux. Mind GNU vs BSD tool differences (`sed -i`, `date`, `stat`) — the script runs, but a GNU-only flag will fail on it |
| Windows | PowerShell or `cmd` | The body **must declare itself** (below) |

**Windows needs an interpreter marker.** A `/bin/bash` body cannot run on
Windows, and guessing would push your shell script through PowerShell and report
whatever came out. So the first line of the body says what it is:

```
#!ps
Get-Service -Name wuauserv | Where-Object { $_.Status -ne 'Running' } | ForEach-Object { exit 1 }
```

```
#!cmd
@echo off
sc query wuauserv | find "RUNNING" >nul || exit /b 1
```

Accepted markers: `#!ps` / `#!powershell`, and `#!cmd` / `#!bat` / `#!batch`.
The marker line is stripped before execution. A body with **no** marker on a
Windows host is reported as a **failed run** whose output tells you to add one —
a visible red result rather than silence, so an unrunnable
assignment can't look like a passing one.

The same script can therefore target one OS family at a time. To cover a mixed
fleet, create one script per platform and assign each to the right hosts.

---

## Viewing results

**Custom Scripts → Refresh** loads the current fleet-wide result table:

| Column | Meaning |
|--------|---------|
| Script | Script name (click the definition card to edit) |
| Host | Enrolled host that ran it |
| Group | Host group for filtering |
| Status | ● OK or ● FAIL with time of last status change |
| Last output | First 80 chars of stdout/stderr — click for full output |
| Last run | When the script last executed |
| Duration | Wall-clock time for the script to complete |

The **definitions panel** below the table shows one card per script
with aggregate pass/fail counts across all assigned hosts.

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

Configure delivery under **Settings → Notifications**. Both events are
enabled by default. Supported destinations: Discord, ntfy, Slack,
Gotify, generic JSON POST.

**Edge-triggered:** the `custom_script_fail` event fires exactly once
when a script first fails. It does not re-fire on every subsequent
failing run. It re-arms when the script recovers. This prevents alert
fatigue from a persistently broken check.

**First-run:** no alert is fired when a script produces its first
result, regardless of outcome. This avoids a flood of `_fail` events
when you assign a new script to many hosts at once.

---

## Limits

| Limit | Value |
|-------|-------|
| Scripts fleet-wide | 50 |
| Scripts per host | 10 |
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
 server (mode 0600, owned by the app-server user).
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
GET /api/custom-scripts/results Fleet-wide current results (all hosts × all scripts)
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
