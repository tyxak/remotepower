# Remote access

RemotePower gives you interactive, browser-based access to a host — a shell, its
files, and its local accounts. Most of it rides the agent poll and the audited
command pipeline, so the host needs no inbound port and the same permissions,
quarantine and change-approval controls apply. The web terminal, the SFTP file
browser and the remote desktop are the exception: they open an SSH connection from
the server to the host (see [Permissions & safety](#permissions--safety)).

## Web terminal (SSH in the browser)

Open a host's drawer and click **Web terminal** to get an xterm.js terminal
connected to that host over SSH. You fill in the SSH host, port, user and password,
and your own RemotePower password. The SSH credentials are not stored. (**Run
command** in the same drawer is something else: it queues one command through the
agent.)

- A small daemon (`remotepower-webterm.service`) brokers the WebSocket; nginx
  proxies `/api/webterm/connect` to it. The frontend loads xterm.js on demand.
  The daemon is a separate install: `packaging/install-webterm.sh` on a bare-metal
  server, or `RP_WITH_WEBTERM=1` for the Docker image (see [install.md](install.md)).
- Each session starts with `POST /api/webterm/auth`, which **re-prompts for your
  password** and issues a single-use ticket that is valid for 60 seconds — the
  WebSocket is useless without it. Only an administrator account can get a ticket.
  Ticket issue, the end of each session (its duration, traffic and host-key
  outcome) and any auth failure are written to the audit log
  (`webterm_ticket_issued`, `webterm_session`, `webterm_auth_failed`).
- The daemon URL and shared secret are set with the `webterm_daemon_url` /
  `webterm_daemon_secret` config keys. The Docker image takes the secret from
  `RP_WEBTERM_SECRET` or creates one in the data volume.
- On a Windows host, the button first offers the [Agent console](#agent-console),
  because the terminal needs an SSH server that Windows hosts rarely run. You can
  still choose **Use SSH anyway**.

### The host's SSH key is checked first

Before your password is sent, RemotePower compares the SSH key the host presents
against the key fingerprints it already has on file for that host. The agent
reports them with every heartbeat, so on an enrolled host this needs no setup.
The SFTP file browser and the remote desktop use the same check.

- **The key matches.** The session opens as usual.
- **The key does not match.** The connection is refused during the handshake,
  before your password leaves the browser, and the terminal tells you what
  happened. If the host was rebuilt or its keys were rotated, wait for the agent
  to report the new key, then reconnect. If nothing about the host changed,
  treat it as you would any other host-key warning.
- **RemotePower has no keys for the host.** This is the case for an agentless
  host, or an agent that has not reported since enrolling. The session opens and
  the audit entry records it as `host_key=unverified` with the fingerprint that
  was presented, so a later change is visible.

The audit line for every session carries the outcome, which makes "which
sessions actually reached a host we can vouch for" a question you can answer.

## Remote file manager

There are two ways to reach a host's files.

| Where | How it connects | Needs |
| --- | --- | --- |
| **Access → Files** (the File manager page) | Through the agent. No SSH, no inbound port, no second credential. | The `command` permission on the host |
| Host drawer → **Files** | SFTP over the same SSH path as the web terminal. You enter the SSH host, port, user and password and your RemotePower password; nothing is stored. | An administrator account |

### The File manager page

It browses, views, edits, deletes, uploads and downloads files on a host, and **New
folder** creates a directory. There is no switch to turn it on.

- Access is confined to an **allowlist of root paths**: `/etc`, `/var/log`,
  `/var/lib`, `/home`, `/opt`, `/srv`, `/tmp` and `/usr/local` by default, and
  never `/proc`, `/sys` or `/dev`. Replace the list with `file_manager.roots` in
  the server config (up to 40 paths, set through `POST /api/config`). The agent
  applies its own list as well, `/etc/remotepower/file-roots` on the host (one
  absolute path per line, the same defaults when the file is missing), and a path
  has to be allowed by both. The browser can never escape those roots, and the
  agent follows symbolic links before it checks.
- Limits: a file you view or download is cut at 256 KiB (a cut file opens read-only,
  and a binary file cannot be edited; use **Download as .tar.gz** for anything
  bigger), a file you save is at most 512 KiB, and an upload is at most 8 MiB. An
  upload from the page does not replace an existing file; the API accepts
  `overwrite` for that.
- **Download as .tar.gz** packs the open folder on the host and streams it back in
  chunks. The archive is limited to 200 MiB compressed, and a job that makes no
  progress for 10 minutes is marked failed.
- Operations map to `GET/POST /api/devices/{id}/files` (`list`, `read`, `write`,
  `mkdir`, `delete`, `upload`). Paths and contents are base64-wrapped end to
  end, so a filename can never inject a shell command. Every operation is audited
  as `file_manager`.
- **Reads are allowed under quarantine / audit-mode; writes are blocked** — the
  incident-response posture (look, don't touch).

### The SFTP browser in the drawer

It lists, reads, writes, renames, deletes and creates folders over SFTP, with no
allowlist of roots: it can reach whatever the SSH user can. Transfers are limited
to 32 MiB. The host-key check above applies.

## Remote desktop and RDP

- **Remote desktop** (host drawer): a noVNC viewer in the browser. The server's
  daemon tunnels the host's loopback VNC port (5900 unless you change it in the
  dialog) over SSH, so the VNC port is never exposed to the network. You need a VNC
  server listening on the host's loopback address.
- **RDP (Windows)** (host drawer): off until you tick **Settings → General → RDP
  remote access**. The action issues a one-time session ticket for a tunnel to the
  host's loopback RDP port (3389) and shows a command for a bridge program that
  opens `localhost:PORT` on your own machine, for `mstsc` or Remmina. There is no
  RDP client in the browser. The bridge program the dialog names
  (`remotepower-rdp-bridge`) is not part of RemotePower, so today the action only
  prepares the session.

Both use the same ticket, password prompt and audit entries as the web terminal.

## Host accounts, SSH keys & firewall

From the drawer you can manage the host itself, not just monitor it:

| Action | Where | Needs |
| --- | --- | --- |
| Add / lock / unlock / delete a **Unix user**, add or revoke an **SSH key** | drawer → **Users & keys** (`POST …/user-action`) | `ssh` permission |
| Add / remove a **firewall** rule (ufw / firewalld) | drawer → **Firewall** (`POST …/firewall-action`) | `command` permission |
| Save the desired **host config** (see [host-config.md](host-config.md)) | drawer → **Host config** (`GET/PUT …/host-config`) | an administrator to save it |

Usernames are validated against `^[a-z_][a-z0-9_-]{0,31}$` and SSH keys against a
strict public-key pattern before anything is queued.

## Permissions & safety

- The web terminal, the drawer's SFTP browser, the remote desktop, the RDP tunnel
  and the Agent console need an **administrator**. The File manager page and
  firewall rules need the **`command`** permission; user and SSH-key management
  needs **`ssh`**. A viewer can do none of these. Scoped operator roles are limited
  to hosts in their scope, and a tenant's administrator to that tenant's hosts.
- The agent-based actions (the File manager page, Users & keys, Firewall, Agent
  console) are **queued as audited host commands**. They apply on the host's next
  check-in, are recorded in the audit log, and are **skipped on a quarantined
  host** (writes) and refused by an **audit-mode** agent. Change approval
  (**Settings → Security**) parks Users & keys and Firewall changes for a second
  admin when **Run command** is among the actions that require approval, and parks
  every Agent console command whenever change approval is on. File manager page
  writes (write, create folder, delete, upload) are parked the same way when **Run
  command** is among those actions, because a file written into a cron directory is
  code that runs; the Confirmations page shows the path and size, for example
  `write file /etc/hosts (212 bytes)`. Listing and reading are never held. Writes
  that are not parked run as soon as the agent collects them, within the allowed roots.
- The agent always dials out to the server over HTTPS, so the agent-based actions
  need no inbound firewall rule on the host. The web terminal, the SFTP browser,
  the remote desktop and the RDP tunnel are different: the server's daemon opens an
  SSH connection to the host, so the host's SSH port has to be reachable from the
  server.

## Agent console

The web terminal above opens an **SSH** session. On Windows that only works if
OpenSSH Server was installed and exposed separately — which RemotePower's own
Windows onboarding never does — so on most Windows fleets the terminal button
used to present a login form that could only fail to connect.

**Agent console** (host drawer → *Agent console*) runs commands through the
agent's existing run-and-wait exec channel instead: **no SSH server, no inbound
port, no second credential**. Pick PowerShell or `cmd.exe` on Windows, or the
shell elsewhere, type a command, read the output, run the next one.

Opening the web terminal on a Windows host now offers the console instead — and
still lets you proceed with SSH, since some Windows fleets do run OpenSSH
Server.

**It is not a PTY, and does not pretend to be.** Each command runs as its own
process, so:

- there is no persistent shell state — `cd` does not carry over between
  commands;
- interactive programs (`vim`, a paging `more`, anything prompting for input)
  will hang until the timeout;
- output arrives when the command finishes, not as it is produced.

For a full interactive desktop on Windows, use the **RDP (Windows)** action from
the same drawer (see [Remote desktop and RDP](#remote-desktop-and-rdp)).

Every command goes through the same path as the drawer's *Run command*:
admin-only, per-host allowlist enforced, and audit-logged. With change approval on,
the command is parked for a second admin and the console says so. The console is
not a way around those controls.

## Related

- [Agent commands](agent-commands.md) — the commands the agent runs for you.
- [Host config](host-config.md) — declare a host's desired state.
- [Windows client](windows-client.md) — what the Windows agent supports.
