# Configuration drift detection

Per-host file integrity monitoring, on **Security → Drift**. The agent computes SHA-256
hashes of a list of watched config files and reports them. The server compares them against a
stored baseline and fires a `drift_detected` event when a hash diverges.

The Drift page lists every host with its number of **Files watched**, **Drift**, **Missing** files and
**Last check**. Click **Detail** on a host for the per-file detail. The toolbar has **AI triage** (asks your AI
provider whether a drift looks benign, a mistake or a compromise), **Collect all host configs** and
**Export all host configs** (see [host-config.md](host-config.md)).

**Hash-only by design.** The contents of `/etc/sudoers`,
`/etc/ssh/sshd_config`, etc. never cross the wire on routine
polling. To see what actually changed, click **Show diff** on a drifted
file, then **Fetch current content**. That queues a `cat` command through
the existing exec mechanism (subject to the same audit and permission checks
as any other command, so it needs the `command` permission), and the text
arrives on the agent's next heartbeat. RemotePower keeps the last two
captures of a file (up to 256 KB each) and the diff compares those two: the
first fetch is your reference, and a fetch after the next change shows what
moved. `/etc/shadow`, `/etc/gshadow` and their rotated copies are never
fetched. Only files on the host's watch list can be fetched.

## What gets watched

The default watched list (configurable):

| Path | Why |
|---|---|
| `/etc/ssh/sshd_config` | SSH daemon config — port, auth methods, root login policy |
| `/etc/sudoers` | Sudo policy — privilege escalation rules |
| `/etc/passwd` | Account list — additions and removals |
| `/etc/group` | Group membership changes |
| `/etc/login.defs` | Password policy and UID range |
| `/etc/pam.d/sshd` | PAM stack for SSH logins |
| `/etc/pam.d/common-auth` | PAM authentication stack |
| `/etc/fstab` | Mount points — drive layout, NFS / CIFS mounts |
| `/etc/crontab` | System cron — scheduled root-owned jobs |
| `/etc/hosts` | Local DNS overrides |
| `/etc/resolv.conf` | DNS resolver config |
| `/etc/nsswitch.conf` | Name service order (files vs DNS vs LDAP) |
| `/etc/apt/sources.list` | Package sources. A changed source is a supply-chain warning sign |

Each one is operationally significant. A change here is either a considered operator action or
something that should make you look twice. Files that change all the time (`/etc/mtab`,
runtime-generated configs) are *not* in the default list.

### Customising

**Global default** — edit `cfg['drift']['default_watched_files']` in
`config.json` to change the default list for new hosts.

**Per-host override** — open the host, go to **Actions & settings** and fill in **Drift watch
files**, one entry per line. The agent picks up the new list on its next heartbeat. A list can hold
up to 50 entries.

**Drift profiles** — reusable, named sets of watched
files, managed from the **Drift** page (the *Drift profiles* panel:
create, edit, delete). Assign a profile to a **host**, **tag**, or
**group** and every matching host monitors that set — no need to edit
each host individually.

Resolution precedence for a host's watched list:

1. an **explicit per-host** `watched_files` list (set in the host
   drawer) — always wins;
2. an **assigned profile** — host assignment, then tag, then group;
3. the **global default** above.

You can create up to 100 profiles, and profile names are unique. Endpoints: `GET`/`POST /api/drift/profiles`,
`PUT`/`DELETE /api/drift/profiles/<id>`, and `POST /api/drift/assign`
(`{scope_type: device|tag|group, scope_value, profile_id}`; a null
`profile_id` clears the assignment). Profiles and assignments live
under `cfg['drift']['profiles']` / `['assignments']`. Admin-only to
mutate; changes take effect on each host's next heartbeat.

A host's **drift detail** view shows *how* its watched list was
resolved — `device-override`, `profile:<device|tag|group>` (with the
profile name), `default`, or `disabled` — so it's never a mystery
which rule won.

### What an entry can be

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

### Adding to the default instead of replacing it

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
2. About once an hour (every 60 polls at the default interval), and at once when a watched
   file's size or modification time has changed, the agent walks the list and computes:
   - SHA-256 of the file content
   - File size
   - mtime
   - existence flag (some watched files are conditional)
   A file over 5 MB is not hashed. A folder or pattern entry is expanded first. Each file it finds is
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

## Ignoring a file

A watched file can be missing on purpose on one host, such as
`/etc/pam.d/common-auth` on a host that does not use that PAM stack. Click
**Ignore** on its row in the host's drift detail and, if you like, give a
reason. An ignored file no longer counts in the **Drift** and **Missing**
columns and no longer turns the host red. It stays in the list, greyed out,
with the state it is really in and your reason. **Un-ignore** puts it back.
Ignoring takes an administrator.

A file the agent cannot find for three reports in a row goes **Dormant** by
itself, which also takes it out of the counts. Ignoring is your decision;
dormancy is automatic and clears when the file comes back.

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

## Enforcement policy

The **Enforcement policy** panel on the Drift page is for
[host configuration](host-config.md), not for the watched-file list. It
makes every host that carries a tag, or sits in a group, apply its desired
host config. Pick **Tag** or **Group**, type its name, choose **Correct on
drift** or **Apply every poll**, and click **Add policy**. Only hosts that
already have a desired host config are affected. A host's own **Enforce on
host** and **Correct on drift** boxes add to the policy, and the stronger
setting applies. Changing the list takes an administrator. See
[Enforcement](host-config.md#enforcement) for what each setting does.

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
POST   /api/devices/<id>/drift/ignore      — ignore or un-ignore one file
                                              body: {path, ignored, reason}
POST   /api/devices/<id>/drift/fetch_content — queue a read of a watched file's current text
                                              body: {paths: [...]} (for Show diff; denied for secret files)
GET    /api/devices/<id>/drift/content?path=…  — the stored text of a file, up to two captures
DELETE /api/devices/<id>/drift             — wipe drift state (re-bootstrap)
GET    /api/drift-policies                 — enforcement policies
PUT    /api/drift-policies                 — replace the policy list
                                              body: {policies: [{scope: tag|group, value, mode: apply|enforce}]}
```

All require authentication. Accepting a baseline and wiping a host's drift
state need the `mitigate` permission, fetching text needs `command`, and
ignoring a file or changing profiles, assignments and policies needs an
administrator. With tenant isolation on, only the platform operator can
change profiles, assignments and policies. Baseline acceptance is
audit-logged (`drift_baseline`).

## Watching Compose files

Tick **Settings → Security → Compose drift watch** and every `docker-compose.yml` the agent finds on a
host is added to that host's watch list, up to 80 files in all. It is off by default, and it adds to
the list you chose and never replaces it.

## What is stored

For each file the server keeps its current and baseline hash, size and modification time, when the
baseline was set and by whom, the drift count, and the last 20 changes. For a file found through a
folder or pattern it also keeps the entry it came from, and an added file stays marked *Added* until
you accept it as the baseline. It keeps whether the file has ever been present on the host, so a file
that was never there raises no *removed* alert.

## Agent requirements

Folders and patterns need **agent 7.4.1 or later** (Linux, Windows and macOS). An
older agent would read `/etc/apt/sources.list.d/*` as the name of one file, so
it is sent the plain entries of the list only and ignores the rest.

An agent that does not report drift at all shows "no data" on the Drift page until you update
it. To find old agents, filter **Fleet → Query** by **Agent version contains**. Update one from
the host's drawer (**Update agent**, or **Force-upgrade** to push the bundled agent whatever version
it reports).
