# Mitigation runners

Diagnostic + AI suggestion + confirmed fix for active alerts. Click the **Investigate** button on a Needs Attention card (or **Fix** on an alert row) to open the guided remediation flow.

## Three-tab flow

1. **Diagnostic** — server queues a hardcoded read-only command on the agent. Output streams back, live-polled every 2s.
2. **AI Analysis** — when the diagnostic completes, AI runs automatically with a playbook-specific system prompt. Returns root cause (1-2 sentences) + one specific fix command wrapped in `BEGIN_FIX` / `END_FIX` markers.
3. **Apply Fix** — choose pre-approved playbook fix, AI-suggested fix, or your own command. Safety classifier runs before execution.

## Supported alert kinds

Playbooks exist for 21 alert kinds: `patches`, `disk`, `drift`, `service_down`,
`failed_units`, `reboot`, `brute_force`, `memory`, `swap`, `cpu`, `cve`,
`container`, `av_posture`, `agent_version`, `os_eol`, `hardware`, `backup`,
`ssh_key`, `new_port`, `agent_integrity`, and `log_alert`. A few examples:

| Kind | Diagnostic | Pre-approved fix |
|---|---|---|
| `patches` | `apt list --upgradable` / `dnf check-update` / `pacman -Qu` + reboot flag + kernel | (use existing /upgrade endpoint) |
| `disk` | `df -h`, top 20 dirs (`du --max-depth=2 /`), files >500MB, journal disk usage | (none — AI suggests) |
| `drift` | `/etc` git status, files modified in last 7 days | (none) |
| `service_down` | `systemctl status` + last 100 journal lines for the unit | `systemctl restart <unit>` |
| `failed_units` | `systemctl --failed` + recent journal lines for the failed units | (none — AI suggests) |
| `reboot` | Reboot reason, packages requiring reboot, kernel mismatch | `reboot` (DANGEROUS — requires RUN confirmation) |
| `brute_force` | Recent auth failures, top offending IPs, fail2ban status, active SSH sessions | (none — manual review) |

Diagnostics are **server-defined** — user input never flows into the shell. For `service_down`, the unit name comes from the attention item's `target` field but goes through a strict regex (`^[a-zA-Z0-9._@-]+$`) before template substitution. Shell metachars (`;`, backticks, `$()`, pipes, redirects, `..`, newlines) are rejected.

## Safety model

Two tiers of friction between an AI suggestion and the agent's shell.

### Hard denylist (refused outright)

The server refuses to queue any command matching these patterns. The operator can still copy and paste manually if they really insist, but RemotePower will not run them.

- `rm -rf /` (root only — `rm -rf /tmp/foo` passes through)
- `dd of=/dev/{sd,nvme,xvd,vd,hd}*`
- `mkfs.*`
- `shred /dev/...`
- Fork bombs (`:(){ :|:& };:`)
- Redirects to block devices
- `chmod -R 000/777 /`
- Redirects to `/etc/passwd` or `/etc/shadow`
- `DROP DATABASE`

### Sensitive (requires typing `RUN`)

Allowed but the operator must type `RUN` in the confirmation box before exec. This applies to anything not in the playbook's pre-approved fix slot, plus:

- `reboot`, `shutdown`, `halt`, `poweroff`
- `kill -9`, `pkill -9`
- `systemctl stop|disable|mask`
- `iptables -F|-X`, `nft flush`
- `userdel`, `groupdel`
- `apt-get purge|remove`, `dnf remove`, `pacman -R*`
- `curl ... | bash` / `wget ... | sh`

The client mirrors the server's classifier as a UI preview, but the **server is authoritative**. Bypassing the client check just gets you a 400 with `{"error": "confirmation required"}`.

## AI customisation

Per-category prompt keys in **Settings → AI assistant Assistant** — one per playbook
category (`mitigate_cpu`, `mitigate_memory`, `mitigate_disk`,
`mitigate_service`, `mitigate_patches`, `mitigate_failed_units`,
`mitigate_cve`, `mitigate_container`, `mitigate_av`, `mitigate_agent_version`,
`mitigate_os_eol`, `mitigate_hardware`, `mitigate_backup`, `mitigate_ssh_key`,
`mitigate_new_port`, `mitigate_agent_integrity`, `mitigate_log`).

Each ships with a conservative default prompt that instructs the model to propose exactly one shell command, marked between `BEGIN_FIX` / `END_FIX`, and to never propose destructive operations without flagging them. Edit per-key as needed for your model (e.g. terser for small local models, more cautious for less-tuned ones).

Per-key inference parameters (temperature, max_tokens, num_ctx) live under the same Settings page in the AI parameters section.

## Storage

- Action logs: `/var/lib/remotepower/mitigate_logs/<safe_did>__<action_id>.log` (256 KB cap)
- Meta sidecars: `<safe_did>__<action_id>.meta.json` with `kind`, `target`, `phase` (`investigate`/`fix`), `destructive`, `queued_at`, `actor`, and on completion `rc` + `done_at`. AI summary persisted as `ai_summary` + `ai_suggested_fix` so re-opening the modal doesn't re-burn tokens.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/mitigate/<dev_id>/investigate` | Queue diagnostic; body `{kind, target}` |
| POST | `/api/mitigate/<dev_id>/fix` | Queue fix; body `{kind, target, command, confirmation}` |
| GET | `/api/mitigate/<dev_id>/status/<action_id>` | Poll captured output + meta |
| POST | `/api/mitigate/<dev_id>/ai/<action_id>` | Trigger AI analysis on captured output |

All audit-logged as `mitigate_investigate` / `mitigate_fix` with action_id and target.
