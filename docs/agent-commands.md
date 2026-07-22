# Agent commands

```bash
remotepower-agent status        # Show enrollment info, version, all interfaces
sudo remotepower-agent enroll   # Enroll interactively
sudo remotepower-agent re-enroll  # Re-enroll preserving history/tags/group/notes
sudo remotepower-agent update   # Force self-update check immediately
sudo remotepower-agent integrity  # Verify binary SHA-256 vs server
sudo remotepower-agent run      # Run in foreground (debug)

systemctl status remotepower-agent
journalctl -u remotepower-agent -f
systemctl restart remotepower-agent
```

### Optional: metrics collection

```bash
pip install psutil --break-system-packages
sudo systemctl restart remotepower-agent
```

## Read-only audit mode (v5.0.0)

To make an agent refuse every command (exec, reboot, config apply, self-update)
while it keeps observing and reporting, create an operator-owned marker file:

```bash
sudo touch /etc/remotepower/audit-mode        # Linux / macOS
#  Windows: create  %ProgramData%\RemotePower\audit-mode  (no extension)
```

The agent then rejects all commands at the source, reports `audit_mode: true` in
its heartbeat (the device shows an **AUDIT** badge), and the server refuses to
even queue commands for it. The server cannot clear the file — only someone with
access to the host can. Remove the file to restore normal operation. Enforced
identically by the Linux, Windows and macOS agents.

## Signed commands (v6.4.0)

The same trust model as signed self-update, applied to **every dispatched
command**. The server detach-signs each command with the release signing key
(Settings → Agent signing — one key to pin), binding the command text to the
**target device id** and an **issue timestamp**. To enforce on a host:

```bash
# 1. Pin the server's public key (same file the signed self-update uses):
sudo install -m 0644 release.pub /etc/remotepower/release.pub
# 2. Opt in to fail-closed enforcement:
sudo touch /etc/remotepower/require-signed-commands
#  Windows: create  %ProgramData%\RemotePower\require-signed-commands
#  macOS:   same /etc/remotepower paths (needs gpg — `brew install gnupg`)
```

With the flag set the agent **refuses** any command that is unsigned, fails
verification, targets a different device, or carries a timestamp outside a
15-minute freshness window — and reports the refusal as the command's output
(rc 126), so a blocked command is visible in the UI, never a silent drop.

**What this buys / what it doesn't.** Tampering with the server's command
queue at rest (database compromise, storage tampering, a leaked DB
credential), MITM past TLS, and replaying a captured command to another host
or at a later time — none of these can execute anything anymore: the attacker
needs the signing key, not just DB write access. A *full* application-server
compromise can still sign (the key lives on the server in the convenient
mode) — the same honest boundary as server-side release signing; sign
off-server for the strongest guarantee. Like `audit-mode`, the flag is an
operator-owned local file the server can never clear.

## Per-command timeout (v5.0.0)

A queued exec command can carry its own timeout with a `to=<seconds>:` prefix,
for example `exec:to=600:restic backup …`. The value is clamped to 1–3600s and
overrides the default (300s, or 1800s for package-upgrade/reboot commands). All
three agents honour it.

## Agent / server version compatibility (v5.0.0)

The server tracks each agent's version against its own. An agent on the same major
version is fine; one a major behind is offered an update; one more than a major
behind is flagged for a clean reinstall rather than a self-update; an agent newer
than the server (downgrade risk) is flagged so you upgrade the server first.

## Backup integrity verification (v4.10.0)

Point the agent at backup files/repos to verify (restic / borg / tar `check`) via
`backup_monitors` in the agent config. Results ride the heartbeat and raise
`backup_verify_failed` / `backup_verify_passed` events so a silently-corrupt
backup is caught before you need it.

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
