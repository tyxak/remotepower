# Agent commands

The Linux agent is one script, `remotepower-agent`. It runs as a systemd service, and
you can also call it by hand.

```bash
remotepower-agent status                 # enrollment info, version, network interfaces
sudo remotepower-agent enroll            # enroll with a PIN (asks for URL, PIN and name)
sudo remotepower-agent re-enroll         # enroll again, keeping the host's ID and history
sudo remotepower-agent enroll-token --server https://rp.example --token <token>
sudo remotepower-agent update            # check for a newer agent now
sudo remotepower-agent integrity         # compare the binary's SHA-256 with the server's
sudo remotepower-agent send_current_configs   # send this host's config once, for Host config
sudo remotepower-agent run               # run in the foreground (debug); the default

systemctl status remotepower-agent
journalctl -u remotepower-agent -f
systemctl restart remotepower-agent
```

| Option | Used by | Meaning |
|---|---|---|
| `--server URL` | `enroll`, `re-enroll`, `enroll-token` | The server's address. The agent only speaks HTTPS and adds `https://` when you leave it out. |
| `--pin PIN` | `enroll`, `re-enroll` | The 6-digit PIN from **Hosts → Enroll host**. Skips the prompt. |
| `--token TOKEN` | `enroll-token` | A one-time enrollment token. It can also come from `$REMOTEPOWER_ENROLL_TOKEN` or the file `/etc/remotepower/enroll-token`. |
| `--name NAME` | `enroll-token` | The host's display name. Defaults to its hostname. |
| `--interval SECONDS` | `run` | Poll interval. Defaults to 60. |

`enroll-token` is the unattended route for Ansible, cloud-init and golden images. Mint
the token with `POST /api/enrollment-tokens`: it is single use, lasts 24 hours by
default (7 days at most), and can carry a default group, tags and a label. See
[install.md](install.md).

The agent keeps its settings in `/etc/remotepower/agent.conf` and its credentials in
`/etc/remotepower/credentials` (mode 600, root only). When you stop the service
normally, the agent tells the server first, so the host shows as "agent stopped" and
not as an unexplained offline. A killed process still shows as offline.

### Optional: metrics collection

```bash
pip install psutil --break-system-packages
sudo systemctl restart remotepower-agent
```

Without `psutil` the agent still runs and sends heartbeats, but it does not report CPU,
memory and disk figures or interface throughput.

## Read-only audit mode

To make an agent refuse every change while it keeps observing and reporting, create an
operator-owned marker file:

```bash
sudo touch /etc/remotepower/audit-mode        # Linux / macOS
#  Windows: create  %ProgramData%\RemotePower\audit-mode  (no extension)
```

The agent then refuses:

- every command the server sends (exec, reboot, and so on);
- file-manager writes, uploads, creates and deletes (reads still work);
- custom scripts and host-config applies;
- agent self-update;
- canary files, Integrity Guard quarantine checks and guard restore or delete actions;
- backup integrity checks and restore drills (they start `restic`, `borg` or `tar` as root).

Read-only assessments such as Lynis, OpenSCAP and CVE scans keep running. The agent
reports `audit_mode: true` in its heartbeat, the host shows an **AUDIT** badge, and the
server refuses to queue commands for it. The server cannot clear the file. Only someone
with access to the host can, by removing it. The Linux, Windows and macOS agents all
enforce it.

## Signed commands

The same trust model as signed self-update, applied to **every dispatched command**.
The server signs each command with the release signing key (**Admin → Release
Signing**, one key to pin), and the signature covers the command text, the **target
host ID** and an **issue timestamp**. To enforce it on a host:

```bash
# 1. Pin the server's public key (the same file the signed self-update uses):
sudo install -m 0644 release.pub /etc/remotepower/release.pub
# 2. Opt in to fail-closed enforcement:
sudo touch /etc/remotepower/require-signed-commands
#  Windows: create  %ProgramData%\RemotePower\require-signed-commands
#  macOS:   same /etc/remotepower paths (needs gpg: `brew install gnupg`)
```

With the flag set, the agent **refuses** any command that is unsigned, fails
verification, targets a different host, carries a timestamp outside a 15-minute window,
or repeats a command it already accepted. It reports the refusal as the command's output
(exit code 126), so a blocked command shows up in the UI instead of vanishing. The
memory of accepted commands lives in the running process, so a restart inside the
window forgets it.

**Scripts, host config and quarantine are declined too.** The flag exists for one
situation: you no longer trust the server or its database. Three other things that
arrive in the heartbeat can run code or move files with the agent's privileges: assigned
**custom scripts** (shell, as root), pushed **host configuration** (system file writes
and `systemctl`) and the **quarantine** action of Integrity Guard checks. Signatures do
not cover those payloads, so while the flag is set the agent declines them and says so
in its log. Detection keeps working. Turning the flag on therefore narrows what works:
scripts, host-config push and quarantine stop applying on that host.

**What this buys, and what it does not.** Tampering with the server's command queue at
rest (a database compromise, storage tampering, a leaked database credential), a
man-in-the-middle past TLS, and replaying a captured command to another host or at a
later time can no longer execute anything. The attacker would need the signing key, not
just write access to the database. A full compromise of the application server can still
sign, because the key lives on the server in the convenient mode. Sign off-server for
the strongest guarantee. Like `audit-mode`, the flag is a local file that the server can
never clear.

## Conditional reboot: `reboot-if-required`

On Windows and macOS, patch paths (auto-patch policies, rollout rings, scheduled
`upgrade_and_reboot` jobs) queue this command instead of a plain `reboot` when the
policy's "Reboot after upgrade if required" box is ticked. The Windows agent checks its
pending-reboot signals and reboots only when one is set. The macOS agent reports "no
reboot required" because Homebrew upgrades never need one, and skips it. Linux hosts do
the check inline in the upgrade shell (the reboot-required marker, `needs-restarting -r`,
or a newer installed kernel). An older agent answers "unsupported command" and stays up,
which is the safe outcome. The command counts as a reboot for four-eyes approval. The
explicit `reboot` command is always unconditional.

## Per-command timeout

A queued exec command can carry its own timeout with a `to=<seconds>:` prefix, for
example `exec:to=600:restic backup …`. The value is clamped to 1 to 3600 seconds and
overrides the default of 300 seconds (1800 seconds for package-upgrade and reboot
commands). All three agents honour it.

## Agent and server version compatibility

`GET /api/agent-compat` compares each agent's version with the server's. An agent on
the same major version is fine, and one with a lower version is offered an update. An
agent more than one major version behind is marked incompatible and should be
reinstalled instead of self-updating. An agent with a higher major version than the
server is marked incompatible too, and you should upgrade the server first.

## Backup integrity verification

Point the agent at backup files or repositories to verify (`restic`, `borg` or `tar`
checks) under **Settings → Alerting → Backup file monitoring**. Results ride the
heartbeat and raise `backup_verify_failed` and `backup_verified`, so a silently corrupt
backup is caught before you need it. See [backups.md](backups.md).

See also: [windows-client.md](windows-client.md) for the Windows agent,
[docker-agent.md](docker-agent.md) for the container agent, and
[security.md](security.md) for how the command channel is protected.

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
