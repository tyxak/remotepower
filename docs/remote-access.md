# Remote access

RemotePower gives you interactive, browser-based access to a host — a shell, its
files, and its local accounts — without opening any inbound port on the client.
Everything rides the same agent poll + audited command pipeline as the rest of
the product, so the same permissions, quarantine and change-approval controls
apply.

## Web terminal (SSH in the browser)

Open a device's drawer and click **Run command** to get an xterm.js terminal
connected to that host over SSH.

- A small daemon (`remotepower-webterm.service`) brokers the WebSocket; nginx
  proxies `/api/webterm/connect` to it. The frontend loads xterm.js on demand.
- Each session starts with `POST /api/webterm/auth`, which **re-prompts for the
  admin password** and issues a single-use, short-lived ticket — the WebSocket is
  useless without it. Ticket issue, session start/end and any auth failure are
  written to the audit log (`webterm_ticket_issued`, `webterm_session`,
  `webterm_auth_failed`).
- The daemon URL and shared secret are set with the `webterm_daemon_url` /
  `webterm_daemon_secret` config keys.

## Remote file manager

The drawer's **Files** button (page **Files**) browses, uploads and downloads
files on a host.

- Opt-in: enable it with `file_manager.enabled`. Access is confined to an
  **allowlist of root paths** (`file_manager.roots`, or a safe default set) — the
  browser can never escape those roots. Writes are size-capped.
- Operations map to `GET/POST /api/devices/{id}/files` (`list`, `read`, `write`,
  `mkdir`, `delete`, `upload`). Paths and contents are base64-wrapped end to
  end, so a filename can never inject a shell command.
- **Reads are allowed under quarantine / audit-mode; writes are blocked** — the
  incident-response posture (look, don't touch).

## Host accounts, SSH keys & firewall

From the drawer you can manage the host itself, not just monitor it:

| Action | Where | Needs |
| --- | --- | --- |
| Add / lock / unlock / delete a **Unix user**, add or revoke an **SSH key** | drawer → **Users & keys** (`POST …/user-action`) | `ssh` permission |
| Add / remove a **firewall** rule (ufw / firewalld) | drawer → **Firewall** (`POST …/firewall-action`) | `command` permission |
| Push a declarative **host config** (services / cron / packages) | drawer → **Host config** (`GET/PUT …/host-config`) | `mitigate` permission |

Usernames are validated against `^[a-z_][a-z0-9_-]{0,31}$` and SSH keys against a
strict public-key pattern before anything is queued.

## Permissions & safety

- Web terminal + file writes need the **`command`** permission; SSH-key/user
  management needs **`ssh`**. A viewer can do none of these; scoped operator roles
  are limited to hosts in their scope.
- Every action is **queued as an audited host command** — it applies on the
  host's next check-in, is recorded in the audit log, and is **skipped on a
  quarantined host** (writes) and refused by an **audit-mode** agent.
- Destructive/interactive actions honour the per-device **4-eyes
  confirmation** gate (`require_confirmation`) where enabled.
- No inbound firewall rule is ever needed on the client — the agent always dials
  out to the server over HTTPS.

## Agent console *(v6.4.2)*

The web terminal above opens an **SSH** session. On Windows that only works if
OpenSSH Server was installed and exposed separately — which RemotePower's own
Windows onboarding never does — so on most Windows fleets the terminal button
used to present a login form that could only fail to connect.

**Agent console** (device drawer → *Agent console*) runs commands through the
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

For a full interactive desktop on Windows, use the **RDP tunnel** from the same
drawer.

Every command goes through the same path as the drawer's *Run command*:
admin-only, per-device allowlist enforced, and audit-logged. The console is not
a way around those controls.
