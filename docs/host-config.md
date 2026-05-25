# Host Configuration

*(v2.6.0)*

Declare the desired state of each enrolled Linux host server-side.
The agent applies changes on the next heartbeat (~60 s) and reports
current state every 15 minutes so the server can detect drift.

---

## How it works

1. An admin opens **Devices → device dropdown → Host Config**.
2. The modal loads the current desired config (if any) and shows drift
   from the last agent report.
3. The admin edits one or more sections and clicks **Save & push to agent**.
4. The server stores the desired config in `devices.json`.
5. On the agent's next heartbeat the server includes `host_config_desired`
   in the response.
6. The agent applies each section independently, logs the result, and
   carries on. A failed section never blocks others.
7. Every 15 polls (~15 min at 60 s cadence) the agent collects current
   state from the host and sends it as `host_config_current` in the
   heartbeat payload.
8. The server compares desired vs current, stores the diff, and fires a
   `config_drift` webhook if any section has diverged.

No SSH. No Ansible. No extra network ports.

---

## Sections

| Section | Desired content | Applied via | Where it's written |
|---|---|---|---|
| `repos` | Full text of repo file | File write | `/etc/apt/sources.list` (APT) or `/etc/yum.repos.d/remotepower.repo` (DNF) |
| `netplan` | Full YAML | File write + `netplan apply` | `/etc/netplan/01-remotepower.yaml` |
| `nmcli` | Full NM connection file | File write + `nmcli connection reload` | `/etc/NetworkManager/system-connections/remotepower-managed.nmconnection` |
| `resolv_conf` | Full text | File write (resolves symlinks) | `/etc/resolv.conf` |
| `hosts` | Full text | File write | `/etc/hosts` |
| `services` | List of unit names | `systemctl enable --now` per unit | systemd unit state |
| `users` | List of user objects | `useradd`/`usermod` + SSH key write | `/etc/passwd`, `/home/<user>/.ssh/authorized_keys` |
| `groups` | List of group objects | `groupadd` | `/etc/group` |
| `sudoers` | Full sudoers rules text | File write (validated first) | `/etc/sudoers.d/remotepower` |
| `motd` | Full text | File write | `/etc/motd` |

---

## Using the editor

### Opening

**Devices** page → three-dot or action menu on any device → **Host Config**.

The modal loads:
- Current desired config (what the server will push)
- Drift information from the last agent report (which sections differ)

### Section tabs

Click any tab to switch sections. Unsaved changes in other tabs are
preserved until you close the modal or save.

### Fetch current

Each tab has a **⬇ Fetch current** button. It loads the last state
the agent reported (collected every 15 minutes). Use it to:

- Pre-fill a section from the live host before editing
- See exactly what's on the host now
- Compare against what you're about to push

If the agent hasn't reported yet (first 15 minutes after install),
the button shows an info message and leaves the field empty.

### Saving

Click **Save & push to agent** to write the desired config. The agent
picks it up on its next heartbeat (~60 s) and applies immediately.

Each section is saved only if it contains content. Leave a tab empty
to exclude that section from management.

---

## Services

The services list contains systemd unit names that **must be enabled**.
One per line. Example:

```
nginx.service
docker.service
ssh.service
postgresql.service
```

The agent runs `systemctl enable --now <unit>` for each. Units not on
the list are **not disabled** — the list is additive, not exhaustive.

Drift is reported if any desired unit is not in the host's enabled list.

---

## Users

Each user entry has:

| Field | Required | Notes |
|---|---|---|
| `name` | Yes | Unix username |
| `shell` | No | Default: `/bin/bash` |
| `groups` | No | Comma-separated supplementary groups |
| `authorized_keys` | No | Full content of `~/.ssh/authorized_keys` |

**No passwords** — authentication uses SSH keys only. If you need
password-based login, manage it outside RemotePower.

The agent creates the user with `useradd -m` if it doesn't exist, or
updates shell and groups with `usermod` if it does. The `authorized_keys`
file is written with mode 0600 and correct ownership.

---

## Groups

Each group entry has:

| Field | Required | Notes |
|---|---|---|
| `name` | Yes | Unix group name |
| `gid` | No | Numeric GID; omit to let the OS choose |

Groups are created with `groupadd` if they don't exist. Existing groups
are not modified (GID conflicts are ignored).

---

## Sudoers

The sudoers content is written to `/etc/sudoers.d/remotepower`.
Before writing, the agent validates the content with:

```bash
visudo -c -f /etc/sudoers.d/.remotepower.tmp
```

If validation fails, the file is **not written** and the error is logged.
This prevents locking yourself out of sudo.

Leave the sudoers tab empty to remove the file (if it exists).

Example:

```
jakob ALL=(ALL) NOPASSWD:ALL
deploy ALL=(ALL) NOPASSWD:/usr/bin/systemctl restart nginx
```

---

## Drift detection

The agent collects current host state every **15 minutes** and sends
it to the server. The server compares:

| Section | Drift condition |
|---|---|
| Text sections | Desired ≠ current (ignoring trailing whitespace and `\r\n` vs `\n`) |
| `services` | Any desired unit is not in the current enabled list |
| `users` | Any desired user is missing, has wrong shell, wrong groups, or wrong authorized_keys |
| `groups` | Any desired group is missing |

**Edge-triggered:** The `config_drift` webhook fires **once** when drift
is first detected. It does not re-fire on every 15-minute check while
drift persists. It re-arms when the drift is resolved.

**Audit-only:** The server never auto-remediates drift. If a host's
config drifts away from desired, RemotePower reports it — you decide
what to do (re-save to re-push, investigate manually, or update desired
to match reality).

---

## Webhook event

```json
{
  "event":    "config_drift",
  "device_id": "dev_abc123",
  "name":     "web01",
  "sections": ["repos", "motd"]
}
```

Configure delivery under **Settings → Webhooks**. Supported destinations:
Discord, ntfy, Slack, Gotify, generic JSON POST.

---

## Security considerations

- Only **admin users** can write host configuration.
- Content is stored in `devices.json` (mode 0600).
- Sudoers content is syntax-checked with `visudo -c` before writing.
- `authorized_keys` files are written with mode 0600 and correct ownership.
- No passwords are stored anywhere — SSH keys only.
- The trust boundary is the same as the existing exec: command channel.
  If an operator can run arbitrary shell commands via RemotePower, they
  can already make arbitrary changes as root. Host Config does not expand
  this boundary.
- Netplan and nmcli changes take effect immediately on the host after
  `netplan apply` / `nmcli connection reload`. Test network changes
  carefully to avoid losing connectivity.

---

## API reference

All endpoints require authentication.

```
GET  /api/devices/:id/host-config          Desired config + current state + drift
PUT  /api/devices/:id/host-config          Save desired config (admin)
GET  /api/devices/:id/host-config/current  Current state only (for Fetch current button)
```

### PUT body shape

```json
{
  "repos":       "deb http://deb.debian.org/debian bookworm main\n",
  "netplan":     "network:\n  version: 2\n  ethernets:\n    eth0:\n      dhcp4: true\n",
  "nmcli":       "",
  "resolv_conf": "nameserver 1.1.1.1\nnameserver 8.8.8.8\n",
  "hosts":       "127.0.0.1 localhost\n::1 localhost\n",
  "services":    ["nginx.service", "docker.service"],
  "users": [
    {
      "name":            "jakob",
      "shell":           "/bin/bash",
      "groups":          ["sudo", "docker"],
      "authorized_keys": "ssh-ed25519 AAAA... jakob@workstation\n"
    }
  ],
  "groups": [
    { "name": "docker", "gid": 999 }
  ],
  "sudoers": "jakob ALL=(ALL) NOPASSWD:ALL\n",
  "motd":    "Welcome to production. All access is logged.\n"
}
```

### GET response shape

```json
{
  "desired":              { "...": "..." },
  "current":              { "...": "..." },
  "desired_at":           1716124800,
  "current_collected_at": 1716124815,
  "drift": {
    "sections":   ["motd"],
    "checked_at": 1716124815,
    "clean":      false
  }
}
```

---

← [Back to docs index](README.md) · [Features overview](features.md)
