# Mitigation runners

Diagnostic, AI suggestion and a confirmed fix for an active alert. Open the guided
flow from any of these:

- the **Fix** button on a row in the Alerts inbox;
- the **Investigate** button (the magnifier) on a Needs Attention card;
- the **Fix** action on a row of the Problems page.

## Three-tab flow

1. **1 · Diagnostic**: the server queues a read-only command on the agent. The
   output comes back and the page polls it every 2 seconds, for up to 6 minutes.
2. **2 · AI analysis**: when the diagnostic completes, the AI runs automatically
   with a prompt written for that kind of alert. It returns a root cause (one or
   two sentences) and one specific fix command wrapped in `BEGIN_FIX` /
   `END_FIX` markers. **Re-run AI** asks again, and **Use this as fix command**
   copies the suggestion to the next tab. This step needs the AI assistant to be
   switched on under **Settings → AI assistant**. Without it the tab shows an
   error, and you can still write your own fix on the next tab. The page waits up
   to 4 minutes for the model and offers **Abort** after 30 seconds.
3. **3 · Apply fix**: choose the pre-approved playbook fix, the AI-suggested fix,
   or your own command. A safety check runs before anything is queued.

## Supported alert kinds

Playbooks exist for these alert kinds: `patches`, `disk`, `drift`,
`service_down`, `failed_units`, `reboot`, `brute_force`, `memory`, `swap`, `cpu`,
`cve`, `container`, `av_posture`, `agent_version`, `os_eol`, `hardware`,
`backup`, `ssh_key`, `new_port`, `agent_integrity` and `log_alert`. An alert in
the inbox shows **Fix** when its event maps to one of these kinds and it names a
host. A few examples:

| Kind | Diagnostic | Pre-approved fix |
|---|---|---|
| `patches` | `apt list --upgradable` / `dnf check-update` / `pacman -Qu` + reboot flag + kernel | (use the existing upgrade action) |
| `disk` | `df -h` and inode use, the 20 largest top-level directories, `/var`, `/home` and `/opt` two levels deep, files >500MB, journal disk usage | (none, the AI suggests) |
| `drift` | `/etc` git status, files modified in last 7 days | (none) |
| `service_down` | `systemctl status` + last 100 journal lines for the unit | `systemctl restart <unit>` |
| `failed_units` | `systemctl --failed` + recent journal lines for the failed units | (none, the AI suggests) |
| `reboot` | Reboot reason, packages requiring reboot, kernel mismatch | `reboot` (sensitive, you must type `RUN`) |
| `brute_force` | Recent auth failures, top offending IPs, fail2ban status, active SSH sessions | (none, manual review) |

Diagnostics are **server-defined**: user input never flows into the shell. For
`service_down`, the unit name comes from the attention item's `target` field but
goes through a strict regex (`^[a-zA-Z0-9._@-]+$`) before template substitution.
Anything else, such as `;`, backticks, `$()`, pipes, redirects and spaces, is
rejected and no diagnostic is queued.

## Safety model

Two tiers of friction between an AI suggestion and the agent's shell.

### Hard denylist (refused outright)

The server refuses to queue any command matching these patterns. You can still
copy and paste one by hand if you really insist, but RemotePower will not run it.

- `rm -rf /` (root only: `rm -rf /tmp/foo` passes through)
- `dd of=/dev/{sd,nvme,xvd,vd,hd}*`
- `mkfs.*`
- `shred /dev/...`
- Fork bombs (`:(){:|:& };:`)
- Redirects to block devices
- `chmod -R 000/777 /`
- Redirects to `/etc/passwd` or `/etc/shadow`
- `DROP DATABASE`

### Sensitive (requires typing `RUN`)

Allowed, but you must type `RUN` in the confirmation box before the command goes
out. This applies to anything that is not the playbook's pre-approved fix, plus:

- `reboot`, `shutdown`, `halt`, `poweroff`
- `kill -9`, `pkill -9`
- `systemctl stop|disable|mask`
- `iptables -F|-X`, `nft flush`
- `userdel`, `groupdel`
- `apt-get purge|remove`, `dnf remove`, `pacman -R*`
- `curl... | bash` / `wget... | sh`

The page mirrors the server's classifier as a preview, but the **server is
authoritative**. Bypassing the page check just gets you a 400 with
`{"error": "confirmation required"}`. A command can be at most 2,000 characters.

## Who can use it, and where the command goes

- Running a diagnostic or a fix needs the **mitigate** permission on the host
  (admins have it). A viewer, an `mcp` key and a custom role without it are
  refused.
- Asking for the AI analysis needs a role that can write. Reading the captured
  output only needs a sign-in and access to the host.
- A fix is checked against the host's own command allowlist too, the same as any
  command you queue by hand.
- The command goes through the normal command queue. Server maintenance mode,
  host quarantine, audit mode, the per-host queue limit and change approval
  (**Settings → Security**) all apply. If a second admin has to approve the fix,
  the dialog says so and the command waits on the Confirmations page.

## Did the fix work?

When you start a fix from an alert, RemotePower remembers which alert it was for.
About five minutes later it checks whether that alert has closed and records the
answer with the run. If the alert is still open, you get a **Fix Did Not Work**
alert (`mitigation_unverified`) that names the host, the kind and who ran the
fix. A fix that worked is kept as precedent, which
[Autonomy](autonomy.md) can use as evidence when it decides what to do about the
same problem. Logs and run records older than 30 days are deleted.

## AI customisation

Per-category prompt keys in **Settings → AI assistant → Prompt customization**,
one per playbook category (`mitigate_cpu`, `mitigate_memory`, `mitigate_disk`,
`mitigate_service`, `mitigate_patches`, `mitigate_failed_units`,
`mitigate_cve`, `mitigate_container`, `mitigate_av`, `mitigate_agent_version`,
`mitigate_os_eol`, `mitigate_hardware`, `mitigate_backup`, `mitigate_ssh_key`,
`mitigate_new_port`, `mitigate_agent_integrity`, `mitigate_log`).

Some kinds share a prompt: `swap` uses `mitigate_memory`, `drift` uses
`mitigate_disk`, and `reboot` and `brute_force` use `mitigate_service`.

Each ships with a conservative default prompt that tells the model to propose
exactly one shell command, marked between `BEGIN_FIX` / `END_FIX`, and to never
propose destructive operations without flagging them. Edit per key as needed for
your model (for example terser for small local models, more cautious for
less-tuned ones). Clearing a field goes back to the default.

Per-key inference parameters (temperature, top_p, max_tokens, num_ctx and
reasoning effort) live on the same page, under each prompt's **Fine-tuning**.

### What the AI step sends

The AI analysis sends the captured diagnostic output (up to 32 KB) to your AI provider after the same redaction as every other
AI request. Bearer tokens, cloud access keys and long hexadecimal strings are always removed. Addresses and host names are
replaced by `<IP>` and `<HOST>` unless you allowed them under **Settings → AI assistant → Privacy**. The redaction works on
patterns and is best effort, so a secret that does not look like one of those patterns can still be in the output. If the
output must not leave your network, use a local model (Ollama or LocalAI) as the provider. See [AI assistant](ai.md).

## Storage

- Action logs: `mitigate_logs/<host id>__<action id>.log` in the data directory
  (256 KB cap).
- Meta sidecars: `<host id>__<action id>.meta.json` with `kind`, `target`, `phase`
  (`investigate` or `fix`), `destructive`, `queued_at`, `actor`, the alert it was
  for, and on completion `rc` and `done_at`. A fix started from an alert gets
  `verified` after the five-minute check. The AI summary is kept as `ai_summary`
  and `ai_suggested_fix`, and the status endpoint returns them. Opening the dialog
  again queues a new diagnostic and asks the model again.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/mitigate/<dev_id>/investigate` | Queue the diagnostic; body `{kind, target, alert_id?}` |
| POST | `/api/mitigate/<dev_id>/fix` | Queue a fix; body `{kind, target, command, confirmation, alert_id?}` |
| GET | `/api/mitigate/<dev_id>/status/<action_id>` | Poll the captured output and meta |
| POST | `/api/mitigate/<dev_id>/ai/<action_id>` | Run the AI analysis on the captured output |

Queuing a diagnostic or a fix is audit-logged as `mitigate_investigate` or
`mitigate_fix`, with the action id and target.

## See also

- [AI assistant](ai.md): providers, privacy and prompts.
- [Needs Attention](attention.md) and [Alerts](alerts.md): where the buttons live.
- [Autonomy](autonomy.md): acting on recurring problems without a click.
