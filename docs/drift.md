# Configuration drift detection

*(v2.2.0)*

Per-host file integrity monitoring. The agent computes SHA-256
hashes of a list of watched config files on every few heartbeats
and reports them. The server compares against a stored baseline
and fires a `drift_detected` webhook when a hash diverges.

**Hash-only by design.** The contents of `/etc/sudoers`,
`/etc/ssh/sshd_config`, etc. never cross the wire on routine
polling. To see what actually changed, the operator triggers a
separate "fetch contents" action that queues a `cat` command
through the existing exec mechanism (subject to the same audit and
permission checks as any other command).

## What gets watched

The default watched list (configurable):

| Path | Why |
|---|---|
| `/etc/ssh/sshd_config` | SSH daemon config — port, auth methods, root login policy |
| `/etc/sudoers` | Sudo policy — privilege escalation rules |
| `/etc/fstab` | Mount points — drive layout, NFS / CIFS mounts |
| `/etc/crontab` | System cron — scheduled root-owned jobs |
| `/etc/hosts` | Local DNS overrides |
| `/etc/resolv.conf` | DNS resolver config |
| `/etc/nsswitch.conf` | Name service order (files vs DNS vs LDAP) |
| `/etc/pam.d/sshd` | PAM stack for SSH logins |

Each one is operationally significant — a change here is either a
considered operator action or something that should make you look
twice. Files that legitimately change often (`/etc/passwd` on
distros that update it on login, `/etc/mtab`, runtime-generated
configs) are *not* in the default list.

### Customising

**Global default** — edit `cfg['drift']['default_watched_files']` in
`config.json` to change the default list for new hosts.

**Per-host override** — set `devices[<id>]['watched_files']` to a
list to replace the global default for that host. The agent picks
up the new list on its next heartbeat.

**Drift profiles** *(v3.13.0)* — reusable, named sets of watched
files, managed from the **Drift** page (the *Drift profiles* panel:
create, edit, delete). Assign a profile to a **host**, **tag**, or
**group** and every matching host monitors that set — no need to edit
each host individually.

Resolution precedence for a host's watched list:

1. an **explicit per-host** `watched_files` list (set in the host
   drawer) — always wins;
2. an **assigned profile** — host assignment, then tag, then group;
3. the **global default** above.

Endpoints: `GET`/`POST /api/drift/profiles`,
`PUT`/`DELETE /api/drift/profiles/<id>`, and `POST /api/drift/assign`
(`{scope_type: device|tag|group, scope_value, profile_id}`; a null
`profile_id` clears the assignment). Profiles and assignments live
under `cfg['drift']['profiles']` / `['assignments']`. Admin-only to
mutate; changes take effect on each host's next heartbeat.

A host's **drift detail** view shows *how* its watched list was
resolved — `device-override`, `profile:<device|tag|group>` (with the
profile name), `default`, or `disabled` — so it's never a mystery
which rule won.

### What an entry can be *(v7.4.1)*

One entry per line, in the host drawer, in a drift profile or in a host
profile:

| Entry | Watches |
|---|---|
| `/etc/ssh/sshd_config` | that file |
| `/etc/apt/sources.list.d/` | every regular file directly in the folder (a trailing `/`) |
| `/etc/apt/sources.list.d/*.list` | every file whose name matches |
| `/home/*/.ssh/authorized_keys` | a wildcard can stand in any part of the path |

A wildcard matches one part of the path (`*`, `?` and `[abc]` work; `**`
does not). Hidden files are included. Subfolders are not searched, and a
link to a file counts as that file. Patterns are case-sensitive, except on
Windows. A pattern with `..` in it matches nothing.

A folder or pattern is read for the first time when you add it, and what it
lists then is its baseline. After that:

- a **new file** is drift, shown as *Added* on the Drift page, and fires
  `drift_detected` once. Accept it as the baseline when it is expected;
- a file that **changed** is drift, as for any watched file;
- a file that **leaves** the folder is handled like any file that goes
  missing: after three reports without it, it goes dormant and fires the event
  once.

If a folder holds more files than the agent will look at (200 in all), the
agent says it stopped looking and nothing is read as removed.

### Adding to the default instead of replacing it *(v7.4.1)*

A list without the markers below replaces the list it would otherwise get, as
before. Two markers let a host's list, or a profile's list, build on it
instead:

- `@defaults` stands for the list the host would otherwise get, at that
  position. For a host with a profile that is the profile's list; for a
  profile it is the global default.
- `-<entry>` removes that entry, written exactly as it is in the list it comes
  from. It needs `@defaults` in the same list.

A host that has no `/etc/apt/sources.list` because it keeps its apt sources
in `sources.list.d`:

```
@defaults
-/etc/apt/sources.list
/etc/apt/sources.list.d/
```

It keeps following the default as the default grows, drops the file it does
not have, and watches the folder. The global default list itself cannot use
the markers: there is nothing for it to inherit.

A file that was never on a host does not raise a *removed* alert when it goes
dormant. Only a file that was there and left does.

## How it works

1. On every poll, the server hands the agent the current
   watched-files list in the heartbeat response.
2. Every few polls (`DRIFT_EVERY` in the agent), the agent walks
   the list and computes:
   - SHA-256 of the file content
   - File size
   - mtime
   - existence flag (some watched files are conditional)
   A folder or pattern entry is expanded first. Each file it finds is
   reported with `via`, the entry it came from, and the entries the agent
   expanded are listed in `drift_patterns`.
3. Submits this report as the `drift` field in the next heartbeat.
4. Server's `_ingest_drift_report`:
   - On first sighting → records as baseline, drift_count=0.
   - On unchanged hash → updates `last_check`, no event.
   - On hash change → adds to history, increments `drift_count`,
     fires `drift_detected` webhook **once** (not on every
     subsequent poll that reports the same new hash — debounced
     via `prior_hash`).
5. Operator sees the drift on the Drift page, can drill into the
   host-detail modal to see when each file changed.

## "Drift" vs "drift count"

A file is **drifted** if `current_hash != baseline_hash`.

`drift_count` is the number of *distinct* changes that have
crossed the baseline boundary. It only increments when a change
crosses *from* baseline to non-baseline — repeated reports of the
same new hash don't bump it. This means a one-time legitimate
config change shows `drift_count=1` even after weeks of polls;
true noise (an attacker who keeps editing a file) shows a high
count.

## Re-baselining

When you've reviewed a drifted file and decided the change is
legitimate, click **Accept as baseline** on that row. The current
hash becomes the new baseline, `drift_count` resets to 0, and
future changes are measured from the new baseline.

**Accept all current as new baseline** on the host modal does
this for every drifted file on that host in one click — useful
after a planned config change rollout.

## Webhook payload

`drift_detected` events carry:

```json
{
  "device_id":     "WKFB...",
  "device_name":   "web01.example.com",
  "path":          "/etc/ssh/sshd_config",
  "exists":        true,
  "baseline_hash": "sha256:original...",
  "current_hash":  "sha256:new...",
  "reason":        "file_added"
}
```

`reason` is only there when there is one: `file_added` for a new file in a
watched folder, `file_absent` for a file that went missing. `baseline_hash` is
`null` for an added file.

Route these to a Slack / Discord / ntfy channel you actually
check. Configuration changes during business hours are usually
legitimate; the same alert at 3am is the one you want to see.

## What this is not

- **Not a remediation tool.** Drift detection tells you *that* a
  file changed; rolling back is your call, done via whatever
  configuration management you already use (Ansible, manual edit,
  `etckeeper`).
- **Not full file integrity monitoring** in the AIDE / Tripwire
  sense — those tools watch every binary in `/usr`, signed
  manifests, kernel modules, etc. RemotePower watches a small
  list of high-signal config files. The two complement each
  other; this is the lightweight always-on baseline, not the
  forensic deep-dive.
- **Not change attribution.** We see *that* the hash changed, not
  *who* changed it. For attribution, look at `auth.log` on the
  host, or pair this with `auditd` rules on the watched paths.

## Compliance angle

Configuration drift detection is an expected control for SOC 2
(CC6.1, CC6.6), ISO 27001 (A.12.4.3, A.14.2.4), HIPAA (164.312(c)),
PCI DSS (11.5), and FedRAMP. The audit-log entries the server
writes when baselines are reset (`drift_baseline` events with
actor and timestamp) are designed to be readable as evidence.

## Endpoints

```
GET    /api/drift                          — fleet-wide overview
GET    /api/devices/<id>/drift             — full drift state for one host
POST   /api/devices/<id>/drift/baseline    — accept current as new baseline
                                              body: {paths: [...]} or {all: true}
DELETE /api/devices/<id>/drift             — wipe drift state (re-bootstrap)
```

All require authentication. Baseline-acceptance is audit-logged.

## Storage

`data/drift_state.json`, one entry per host:

```json
{
  "WKFB...": {
    "files": {
      "/etc/ssh/sshd_config": {
        "current_hash":    "sha256:...",
        "current_size":    3024,
        "current_mtime":   1700000000,
        "baseline_hash":   "sha256:...",
        "baseline_size":   3024,
        "baseline_set_at": 1700000000,
        "baseline_set_by": "admin",
        "first_seen":      1700000000,
        "last_check":      1700000000,
        "drift_count":     0,
        "exists":          true,
        "history": [
          {"ts": 1700000000, "hash": "sha256:...", "size": 3024, "exists": true}
        ]
      }
    }
  }
}
```

Per-file history capped at the last 20 changes.

For files found through a folder or pattern, the record also has `via` (the
entry), and an added file has `"added": true` until you accept it as the
baseline. Each host has a `patterns` map of the entries the agent has
expanded. A record also has `ever_present`, which says whether the file has
ever been seen on the host.

## Agent requirements

Folders and patterns need **agent v7.4.1+** (Linux, Windows and macOS). An
older agent would read `/etc/apt/sources.list.d/*` as the name of one file, so
it is sent the plain entries of the list only and ignores the rest.

Drift reporting needs **agent v2.2.0+**. Older agents simply don't
send the `drift` field; the host shows up as "no data" on the
Drift page until the agent is upgraded.

To check your agent versions: Hosts page, the OS column shows
"agent vX.Y.Z" for each agent-managed host. The standard agent
update flow (Hosts page → Force-upgrade agent) works for the
drift upgrade just like any other agent release.
