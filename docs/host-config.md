# Host Configuration

Declare the desired state of each enrolled Linux host server-side.
The server compares it with the current state the agent reports and shows
drift. By default that is all it does: the config is a drift baseline and
nothing is written to the host. Tick **Enforce on host** (see
[Enforcement](#enforcement)) and the agent also applies it on its next
heartbeat (~60 s).

---

## How it works

1. An admin opens a host (click it on the **Hosts** page), goes to **Actions & settings** and clicks **Host config**.
2. The modal loads the current desired config (if any) and shows drift
   from the last agent report.
3. The admin edits one or more sections and clicks **Save**.
4. The server stores the desired config in `devices.json`.
5. If **Enforce on host** is ticked (or a fleet policy asks for it), the
   server includes `host_config_desired` in the agent's next heartbeat
   response. Without it the config is never sent to the host.
6. The agent applies each section independently, logs the result, and
   carries on. A failed section never blocks others.
7. The agent collects the current state of the host and sends it as
   `host_config_current` when you ask for it: **Collect all current** in the
   editor, **Collect all host configs** on the Drift page, or
   `remotepower-agent send_current_configs` on the host. The agent does not
   send it on a timer.
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
| `logrotate` | Full logrotate config | File write | `/etc/logrotate.d/remotepower` |
| `cron` | Root crontab lines | `crontab -u root` | The whole root crontab |

A text section can hold up to 64 KB.

---

## Using the editor

### Opening

**Hosts** page → click a host, or use the three-dot menu on its row →
**Actions & settings** → **Host config**. The button is disabled for
hosts without an agent.

The modal loads:
- Current desired config (what the server will push)
- Drift information from the last agent report (which sections differ)

When no desired config is saved yet, the editor is pre-filled with what the
agent last reported, and a note says so.

### Section tabs

Click any tab to switch sections. Unsaved changes in other tabs are
preserved until you close the modal or save.

### Fetch current

Each tab has a **Fetch current** button. It loads the last state
the agent reported. Use it to:

- Pre-fill a section from the live host before editing
- See exactly what's on the host now
- Compare against what you're about to push

If the agent hasn't reported yet, the button shows an info message and
leaves the field empty.

**Collect all current** at the bottom asks the agent to collect and send
every section now. The result arrives on the agent's next heartbeat (about a
minute); open the editor again to see it. Without a collect, the state you
see is whatever the agent last sent.

### Saving

Click **Save** to write the desired config. Whether the agent also applies
it depends on the two checkboxes described under [Enforcement](#enforcement).

Each section is saved only if it contains content. Leave a tab empty
to exclude that section from management.

---

## Enforcement

Two checkboxes at the bottom of the editor decide whether the server
sends the saved config to the host:

| Setting | What the server does |
|---|---|
| Neither ticked (default) | Keeps the config as a drift baseline. It compares it with the agent's reports and fires `config_drift`. Nothing is sent to the host. |
| **Enforce on host** | Sends the config with every heartbeat. The agent applies it when it receives a config it has not applied yet (after you save a change, or after the agent restarts). |
| **Correct on drift** | Sends the config only while the last report found drift. This is lighter than **Enforce on host**. The agent applies it by the same rule: a config it has already applied is not applied again. |

The **Drift** page also has an **Enforcement policy** panel. It switches on
**Enforce on host** (*Apply every poll*) or **Correct on drift** for every
host that carries a tag or sits in a group. A policy adds to the host's own
checkboxes and the stronger setting applies, so a host cannot turn a policy
off. It only affects hosts that already have a desired config. See
[drift.md](drift.md#enforcement-policy).

Things that stop an apply:

- Only the **Linux** agent applies host config. For a Windows or macOS host
  the server still stores the config as a policy record, and Save tells you
  that nothing will be enforced there.
- An agent in **audit mode**, or one with **require-signed-commands** set,
  refuses the push. See [agent-commands.md](agent-commands.md).
- The containerized agent never applies host config
  ([docker-agent.md](docker-agent.md)).

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
updates shell and groups with `usermod` if it does. A user name must be a
POSIX name (lowercase letters, digits, `_` and `-`, starting with a letter or
`_`, at most 32 characters); the agent skips any other name and logs the
error. The `authorized_keys` file is written with mode 0600 and correct
ownership.

**Fetch current** and the drift check list only accounts with a UID of 1000
or higher (and not `nobody`).

---

## Groups

Each group entry has:

| Field | Required | Notes |
|---|---|---|
| `name` | Yes | Unix group name |
| `gid` | No | Numeric GID; omit to let the OS choose |

Groups are created with `groupadd` if they don't exist. Existing groups
are not modified (GID conflicts are ignored). Group names follow the same
POSIX rule as user names. **Fetch current** lists only groups with a GID of
1000 or higher.

---

## Sudoers

The sudoers content is written to `/etc/sudoers.d/remotepower`.
Before writing, the agent validates the content with:

```bash
visudo -c -f /etc/sudoers.d/.remotepower.tmp
```

If validation fails, the file is **not written** and the error is logged.
This prevents locking yourself out of sudo.

An empty tab in the editor leaves the section unmanaged. To remove the
file, send `"sudoers": ""` through the API (see below); the agent then
deletes `/etc/sudoers.d/remotepower` if it exists.

Example:

```
jakob ALL=(ALL) NOPASSWD:ALL
deploy ALL=(ALL) NOPASSWD:/usr/bin/systemctl restart nginx
```

---

## Logrotate and cron

`logrotate` is written to `/etc/logrotate.d/remotepower`. An empty value
sent through the API removes the file.

`cron` is the **whole root crontab**. When the agent applies it, it loads
the text with `crontab -u root` and replaces every line root had before. An
empty value sent through the API removes root's crontab (`crontab -r`). The
**Cron (root)** tab shows the current crontab when you click **Fetch
current**, so start from that and add your lines.

---

## Drift detection

Each time the agent sends its current host state (see step 7 above), the
server compares it with the desired config, section by section:

| Section | Drift condition |
|---|---|
| Text sections | Desired ≠ current (ignoring trailing whitespace and `\r\n` vs `\n`) |
| `services` | Any desired unit is not in the current enabled list |
| `users` | Any desired user is missing, has wrong shell, wrong groups, or wrong authorized_keys |
| `groups` | Any desired group is missing |

**Edge-triggered:** The `config_drift` webhook fires **once** when drift
is first detected. It does not re-fire on every later report while
drift persists. It re-arms when the drift is resolved, or when you save the
desired config again.

**Audit-only by default:** Unless you tick **Enforce on host** or **Correct
on drift** (or a fleet policy does), the server never auto-remediates
drift. If a host's config drifts away from desired, RemotePower reports it
and you decide what to do (re-save to re-push, investigate manually, or
update desired to match reality). See [Enforcement](#enforcement).

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

The body above is the event's own part. A generic JSON destination also gets
`ts`, `title`, `message` and `priority`. Configure delivery under **Settings →
Notifications**. The destination formats (Discord, Slack, ntfy, Gotify and
others) are listed in [webhooks.md](webhooks.md).

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
  this boundary. An agent in audit mode, or one with
  require-signed-commands set, refuses a push
  ([agent-commands.md](agent-commands.md)).
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
POST /api/host-config/collect-all          Ask agents to send their current config now (admin)
GET  /api/host-config/export               One JSON bundle of every host's desired + current config
GET  /api/drift-policies                   Fleet enforcement policies (by tag or group)
PUT  /api/drift-policies                   Replace the policy list (admin)
```

### Collect and export for the whole fleet

The **Drift** page toolbar has two buttons for this. **Collect all host
configs** queues the collect command on every agent host you can see, so each
agent reports its live config on its next heartbeat. **Export all host
configs** downloads `host-configs.json`: for each host that has a desired
config or a reported one, its desired config, current config, drift, and
whether **Enforce on host** and **Correct on drift** are on. Use it to keep a
copy outside RemotePower or to diff hosts. The export has the config text
in it, so keep the file as private as the hosts.

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
  "motd":    "Welcome to production. All access is logged.\n",
  "apply_enabled": false,
  "enforce":       false
}
```

The body replaces the whole desired config: a section you leave out is no
longer managed. `apply_enabled` is **Enforce on host** and `enforce` is
**Correct on drift**; each keeps its old value when you leave the key out.
The reply carries both flags, plus `supported: false` and a `note` when the
host is a Windows or macOS host that will not apply the config.

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
  },
  "apply_enabled":        false,
  "enforce":              false
}
```

---

← [Back to docs index](README.md) · [Features overview](features.md)
