"""
RemotePower SSH exec — v3.4.0.

Minimal, pure-stdlib SSH execution for agentless devices that have no
RemotePower agent and no management API for the job at hand. Today its one
job is the Synology "Upgrade DSM & reboot" button: a NAS has no API to
trigger a DSM upgrade, but root SSH + `synoupgrade` does it.

There is no pip (no paramiko), so this shells out to the system `ssh`
binary via subprocess (argv list, never shell=True). Two auth modes:

  * key      — `ssh -i <keyfile>` (preferred: no extra package, no
               password on disk; add RemotePower's public key to the
               device's authorized_keys once).
  * password — `sshpass` feeding the password via the SSHPASS env var
               (so it never lands in argv / `ps`). Requires sshpass on
               the server; if it's missing we say so clearly.

The DSM upgrade is launched **detached** (nohup, output to a logfile) so
the call returns immediately and the reboot at the end of the script
doesn't surface as a connection error.
"""

import os
import shutil
import subprocess
import tempfile

DEFAULT_TIMEOUT = 30
# Log to /tmp, not /var/log: the SSH user may be a non-root dedicated account
# (e.g. a sudo-scoped "reboot" user), and the shell-level output redirect runs
# AS that user — it can't write root-owned /var/log, which would silently
# abort the detached launch.
DSM_UPGRADE_LOG = "/tmp/rp-dsm-upgrade.log"

# The built-in DSM upgrade + reboot script, run on the NAS over SSH. Shipped
# with RemotePower (not a per-device path) so any operator gets the same
# behaviour. Mirrors the field-proven synoupgrade sequence: check, and only
# if a new DSM is offered, apply + force-start + reboot.
# POSIX sh (not bash): the dedicated user's login shell may be plain sh, and
# we invoke it via `sh <file>` rather than executing the file, because DSM
# mounts /tmp noexec — a chmod +x file there still can't be exec()'d, but
# `sh file` only reads it.
DSM_UPGRADE_SCRIPT = r"""#!/bin/sh
set -u
echo "=== $(date) RemotePower: DSM upgrade ==="
# Run privileged commands directly when root, else via non-interactive sudo —
# so a dedicated low-privilege user works given a NOPASSWD sudoers entry for
# synoupgrade + reboot.
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo -n"; fi
CHECK_RESULT="$($SUDO synoupgrade --check 2>&1 || true)"
echo "check: $CHECK_RESULT"
case "$CHECK_RESULT" in
    *UPGRADE_CHECKNEWDSM*) ;;   # a new DSM is offered — continue
    *) echo "No DSM update available — nothing to do."; exit 0 ;;
esac
echo "Applying DSM update..."
$SUDO synoupgrade --autoupdate=1 || true
echo "Waiting for the upgrade to initialise..."
sleep 60
echo "Forcing upgrade start..."
$SUDO synoupgrade --start-force || true
echo "Waiting before reboot..."
sleep 120
echo "Rebooting NAS..."
$SUDO reboot
"""


class SshError(Exception):
    pass


def _ssh_base_argv(host, user, port, key_path=None, password=False):
    """Build the ssh (optionally sshpass-wrapped) argv up to user@host."""
    opts = [
        "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "PreferredAuthentications="
              + ("publickey" if key_path else "password,keyboard-interactive"),
        "-o", "NumberOfPasswordPrompts=1",
        "-p", str(int(port or 22)),
    ]
    argv = ["ssh"]
    if key_path:
        argv += ["-i", key_path, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes"]
    argv += opts + [f"{user}@{host}"]
    if password:
        if not shutil.which("sshpass"):
            raise SshError("password auth needs the 'sshpass' package on the "
                           "RemotePower server, which isn't installed. Use an "
                           "SSH key instead, or install sshpass.")
        argv = ["sshpass", "-e"] + argv   # reads the password from $SSHPASS
    return argv


def run_script(host, user, port, script, *, password=None, key=None,
               remote_cmd=None, timeout=DEFAULT_TIMEOUT):
    """Run `script` (fed on stdin) on the remote host. `remote_cmd` is the
    shell command that consumes it (defaults to `bash -s`). Returns
    {ok, code, stdout, stderr}. Raises SshError on setup problems."""
    if not host or not user:
        raise SshError("host and user required")
    if not password and not key:
        raise SshError("an SSH key or password is required")

    key_file = None
    env = dict(os.environ)
    try:
        if key:
            fd, key_file = tempfile.mkstemp(prefix="rp-ssh-key-")
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(key if key.endswith("\n") else key + "\n")
        if password:
            env["SSHPASS"] = password
        argv = _ssh_base_argv(host, user, port, key_path=key_file,
                              password=bool(password))
        argv.append(remote_cmd or "bash -s")
        try:
            p = subprocess.run(argv, input=(script or "").encode(),
                               capture_output=True, timeout=timeout, env=env)
        except subprocess.TimeoutExpired:
            raise SshError(f"ssh timed out after {timeout}s")
        except FileNotFoundError:
            raise SshError("the 'ssh' client isn't available on the server")
        out = p.stdout.decode("utf-8", "replace")
        err = p.stderr.decode("utf-8", "replace")
        return {"ok": p.returncode == 0, "code": p.returncode,
                "stdout": out, "stderr": err}
    finally:
        if key_file:
            try:
                os.remove(key_file)
            except OSError:
                pass


def synology_upgrade(host, user, port, *, password=None, key=None,
                     timeout=DEFAULT_TIMEOUT):
    """Launch the built-in DSM upgrade + reboot script, detached, so the call
    returns immediately and the reboot doesn't read back as an error. Output
    on the NAS goes to DSM_UPGRADE_LOG."""
    # Write the script to a temp file on the NAS (cat must finish reading the
    # script from stdin before we background it), then nohup it detached so the
    # call returns immediately and the final reboot doesn't read back as an
    # error. Grouping the nohup in `{ … & }` keeps cat/chmod in the foreground.
    # Invoke via `sh <file>` (not by executing the file) — DSM mounts /tmp
    # noexec, so a +x file there still can't be run directly.
    remote = (
        "cat > /tmp/rp-dsm-upgrade.sh && "
        "{ nohup sh /tmp/rp-dsm-upgrade.sh > " + DSM_UPGRADE_LOG + " 2>&1 </dev/null & } && "
        "echo rp-upgrade-started"
    )
    res = run_script(host, user, port, DSM_UPGRADE_SCRIPT,
                     password=password, key=key, remote_cmd=remote, timeout=timeout)
    if res["ok"] and "rp-upgrade-started" in res.get("stdout", ""):
        return {"ok": True, "message": "DSM upgrade started on the NAS — it "
                "will check for a new DSM and, if found, apply it and reboot. "
                f"Progress logs to {DSM_UPGRADE_LOG}."}
    detail = (res.get("stderr") or res.get("stdout") or "").strip()[:300]
    return {"ok": False, "error": detail or f"ssh exited {res.get('code')}"}
