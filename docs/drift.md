# Configuration drift detection

*(v2.2.0)*

Per-device file integrity monitoring. The agent computes SHA-256
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
deliberate operator action or something that should make you look
twice. Files that legitimately change often (`/etc/passwd` on
distros that update it on login, `/etc/mtab`, runtime-generated
configs) are *not* in the default list.

### Customising

**Global default** — edit `cfg['drift']['default_watched_files']` in
`config.json` to change the default list for new devices.

**Per-device override** — set `devices[<id>]['watched_files']` to a
list to replace the global default for that device. The agent picks
up the new list on its next heartbeat.

## How it works

1. On every poll, the server hands the agent the current
   watched-files list in the heartbeat response.
2. Every few polls (`DRIFT_EVERY` in the agent), the agent walks
   the list and computes:
   - SHA-256 of the file content
   - File size
   - mtime
   - existence flag (some watched files are conditional)
3. Submits this report as the `drift` field in the next heartbeat.
4. Server's `_ingest_drift_report`:
   - On first sighting → records as baseline, drift_count=0.
   - On unchanged hash → updates `last_check`, no event.
   - On hash change → adds to history, increments `drift_count`,
     fires `drift_detected` webhook **once** (not on every
     subsequent poll that reports the same new hash — debounced
     via `prior_hash`).
5. Operator sees the drift on the Drift page, can drill into the
   device-detail modal to see when each file changed.

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

**Accept all current as new baseline** on the device modal does
this for every drifted file on that device in one click — useful
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
  "current_hash":  "sha256:new..."
}
```

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
  device, or pair this with `auditd` rules on the watched paths.

## Compliance angle

Configuration drift detection is an expected control for SOC 2
(CC6.1, CC6.6), ISO 27001 (A.12.4.3, A.14.2.4), HIPAA (164.312(c)),
PCI DSS (11.5), and FedRAMP. The audit-log entries the server
writes when baselines are reset (`drift_baseline` events with
actor and timestamp) are designed to be readable as evidence.

## Endpoints

```
GET    /api/drift                          — fleet-wide overview
GET    /api/devices/<id>/drift             — full drift state for one device
POST   /api/devices/<id>/drift/baseline    — accept current as new baseline
                                              body: {paths: [...]} or {all: true}
DELETE /api/devices/<id>/drift             — wipe drift state (re-bootstrap)
```

All require authentication. Baseline-acceptance is audit-logged.

## Storage

`data/drift_state.json`, one entry per device:

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

## Agent requirements

Drift reporting needs **agent v2.2.0+**. Older agents simply don't
send the `drift` field; the device shows up as "no data" on the
Drift page until the agent is upgraded.

To check your agent versions: Devices page, the OS column shows
"agent vX.Y.Z" for each agent-managed device. The standard agent
update flow (Settings → Agent updates → Push update) works for the
drift upgrade just like any other agent release.
