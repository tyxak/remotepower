# Integrity Guard (Security → Protect)

Most server compromises don't trip a firewall. The attacker signs in with a
valid credential and uses the application's own features — so nothing looks
malicious in transit. What *does* change is the **filesystem**: a file appears
where none belongs, a config is edited, a persistence hook is dropped.

**Integrity Guard** watches for exactly that, and can act on it. It is built out
of ordinary checks, so everything you already know about scoping, silencing,
alerting and on-call applies unchanged.

**Security → Protect** is its page: apply hardening checks, see what they found,
and review anything the agent quarantined.

---

## Quick start

1. Go to **Security → Protect**.
2. Click **Baseline protect checks**, choose a scope (whole fleet, a group, a
   tag, or **a specific host**), tick the templates you want, and **Apply**.
3. Results appear on **Monitoring → Checks** within ~10 minutes (see
   [Why is everything "unknown"?](#why-is-everything-unknown)).
4. Tune or remove anything that doesn't fit under **Protect checks**.

To watch a web root and *neutralise* anything dropped into it, see
[Auto-quarantine](#auto-quarantine).

---

## The six check types

These are agent-side checks: the server pushes them in the heartbeat response,
the agent evaluates them **on-host**, and reports results back. They're
available anywhere you define a check, and take a single **param**.

### `file_hash` — a pinned file must not change

    param:  /etc/sudoers

SHA-256 of one file. The **first evaluation records the current hash as the
baseline** and reports OK ("baseline set"). Every later evaluation compares
against it: unchanged → OK, changed → **critical**, file gone → **critical**.

Apply it to a host whose state you currently trust — the baseline is whatever
is there the first time it runs.

### `dir_baseline` — nothing new may appear in a directory

    param:  /var/www::*.php          (path, optionally  path::glob)
    param:  /etc/systemd/system

Records `{path → size:mtime}` for a subtree on first run, then alerts on any
file **added, changed or removed**. Bounded to 5,000 files; the noise
directories `cache`, `tmp`, `temp`, `log`, `logs`, `.git`, `.cache`,
`node_modules` and `vendor` are skipped.

The optional `::glob` scopes it to filenames you care about — `/var/www::*.php`
watches only PHP under the web root, which is what a dropped web shell looks
like, and ignores uploaded images and cache churn.

The baseline is **not** auto-updated after a change is detected — the check
stays critical until you deal with it (a tripwire, not a rolling snapshot). To
accept a new state, delete and re-add the check.

### `file_contains` — no file may match a pattern

    param:    /var/www::*.php
    pattern:  eval\s*\(\s*(base64_decode|gzinflate|str_rot13)

The signature half of Guard. `dir_baseline` tells you a file **appeared**; this
tells you a file **looks malicious** — so it catches a filename nobody has ever
seen, which is exactly what a packed web shell is. Files under the path/glob are
scanned for the regex and any match is **critical**.

Bounded on every axis: the first 256 KB of each file, at most 2,000 files and 50
hits per run, the same noise directories skipped. Binary files are decoded
leniently rather than raising.

Unlike an antivirus scan this needs no daemon, no signature database and no file
ownership assumptions — it is just a bounded grep, so it keeps working when the
AV stack does not.

### `egress_flagged` — no outbound connection to a flagged address

    param:  203.0.113.0/24, 198.51.100.7

Reads the host's active outbound connections and alerts if any remote endpoint
falls inside your list of flagged IPs/CIDRs (comma- or space-separated). An
empty list is OK (nothing to match). Use it with a threat-intel feed or the
indicators from an incident.

### `egress_baseline` — no *new* outbound destination

    param:  10.0.0.0/8, 203.0.113.0/24      (an IGNORE-list, optional)

The version of egress monitoring that works with **no threat intel at all**.
It learns which external networks the host normally reaches, then alerts the
**first** time it reaches somewhere new — which is what a beacon to an unknown
C2 looks like. Each new destination alerts once and is then remembered, so it
converges instead of nagging.

Two details keep it usable rather than noisy: inbound connections are excluded
(a connection whose local port is one the host LISTENS on is a visitor, not
egress — otherwise every web client would look like a new destination), and
destinations are grouped by **/24** (v4) or **/64** (v6) so a CDN rotating
addresses inside one network doesn't flap. Private, loopback, link-local and
multicast are never counted.

Use `egress_flagged` when you already know the bad address; use this when you
don't.

### `auth_new_source` — no SSH login from a network you've never seen

    param:  10.0.0.0/8, 192.168.0.0/16      (an IGNORE-list, optional)

Learns which source networks successfully authenticate over SSH, then alerts the
first time someone signs in from somewhere new.

This is the signal a **stolen credential or key** actually produces. The login
*succeeds*, so an auth-failure-rate check sees nothing — there is no brute-force
burst, no failure spike, nothing anomalous except **where it came from**. Each
new network alerts once and is then remembered, and the output names the user
(`root@203.0.113.0/24`).

Private ranges are deliberately **not** excluded here (unlike `egress_baseline`):
a new *internal* source is just as interesting — that is what lateral movement
looks like. Put your office and VPN ranges in the ignore-list instead.

**Scope:** this covers SSH, read from the journal. Application logins (a
WordPress admin, for example) never touch the host in an observable way, so they
are not covered — catching those needs the web application's auth log routed
through the syslog receiver, which is a separate ingest path.

> **Platform:** these six are Linux-first. On Windows they report `unknown`
> ("not applicable"), which is harmless — no false alerts.

---

## Auto-quarantine

A `dir_baseline` check can do more than alert. Tick **Auto-quarantine new
files** on the check (or use the *Web root code integrity* template) and the
agent will **move any new matching file into a vault on the host** instead of
leaving it live.

- Vault: `/var/lib/remotepower/guard-quarantine/` (files stored `0600`).
- Each file gets a `.meta` sidecar recording where it came from, so the vault is
  **self-describing** and a file stays restorable regardless of log rotation.
- An append-only `guard-quarantine.log` is kept as the audit trail.
- **Only NEW files are ever moved.** Changed or removed files are reported and
  never touched — Guard will not delete or overwrite something you edited.
- Bounded to 50 files per evaluation.

Because the file is gone from its original location, the check returns to **OK**
on the next run. That's intentional: the alert reads *"detected and
neutralised"* rather than sitting critical forever.

### Reviewing, restoring and deleting

**Security → Protect → Quarantine vault** lists every quarantined file across
the fleet (host, original path, when), scoped to what you're allowed to see.

- **Restore** puts the file back at its original path — **only if that path is
  still free**. If something else now occupies it, the restore is refused rather
  than clobbering the newer file; clear the path first and retry. The agent logs
  the reason.
- **Delete** removes it from the vault permanently.

Both are queued as one-shot directives and applied by the agent on its **next
check-in**, so allow a poll interval before the row disappears.

---

## Safety rails

Automatic response is only trustworthy if it refuses to fire on legitimate
change. Two rails are always on:

**1. Maintenance windows.** While a host is inside an active maintenance window
(device, group, or global), auto-quarantine is **suppressed** — integrity checks
degrade to report-only for the duration. A declared deploy is not an intrusion.

**2. Mass change.** If more than **25** new files appear in a single
evaluation, that's a rollout or a restore, not a dropped payload. The agent
**refuses to quarantine**, leaves everything on disk, and reports
`N new (mass change — NOT quarantined)` for a human to judge. This is the guard
against the worst failure mode: vaulting an entire site.

---

## The template catalog

**Baseline protect checks** ships ~63 hardening templates, applied by checkbox
to any scope. They're grouped by intent:

| Category | What it covers |
|---|---|
| Hardening — services | fail2ban, AppArmor, sshd, journald, rsyslog, the AV signature updater **and the AV scanning daemon** (an updater without a running daemon scans nothing — on-access protection fails silently) |
| Hardening — must not listen | 17 ports that should not be reachable: FTP, rsh/rlogin, rpcbind, NFS, SMB/NetBIOS, VNC, RDP, the unauthenticated **Docker API (2375)**, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, memcached, SNMP |
| Integrity — critical files | `/etc/shadow`, `/etc/group`, `/etc/sudoers`, `sshd_config`, `hosts`, `nsswitch.conf`, PAM, `fstab`, `resolv.conf`, apt sources |
| Integrity — persistence paths | `/etc/cron.d`, `cron.daily`, `cron.hourly`, `/etc/systemd/system`, `/etc/sudoers.d`, `/root/.ssh`, `/etc/profile.d`, `/usr/local/bin`, `sources.list.d`, `ld.so.conf.d` |
| Integrity — must not exist | `/etc/ld.so.preload` (userland-rootkit tell), `/root/.rhosts`, `/etc/hosts.equiv` |
| Detection — log signals | auth-failure bursts, sudo misuse, AppArmor/SELinux denials, segfaults, filesystem/IO errors |
| Freshness — scheduled jobs | apt index freshness, AV signature freshness |
| Web / application security | web-root code integrity, **obfuscated-PHP-loader signature**, WordPress **mu-plugins** + `wp-config.php`, accounts/crontab/cron.d integrity, outbound-to-flagged |

Params suit Debian/Ubuntu and are **editable after applying** (e.g.
`sshd.service` instead of `ssh.service` on RHEL). Applying is **idempotent** —
de-duplicated on (type, param, scope), so re-applying adds nothing.

The catalog is **text-filterable** (name / path / description) so you find a
template among the ~78 without scrolling, and each row's **"Applied to …"**
annotation shows exactly where it landed — with a **remove** action per scope
(and per host in the expandable list), so you can un-apply a check from a tag,
group or single host straight from the card. Removing is a deferred-commit with
**Undo**, and it stops the agent evaluating the check on its next check-in.

> The operational templates (agent running, time sync, firewall, Docker/nginx by
> tag, …) live in the separate **Monitoring → Checks → Baseline checks** picker.
> Same mechanics, different question.

---

## Where results and alerts appear

- **Results:** every protect check evaluates like any other check and shows on
  **Monitoring → Checks** as OK/WARN/CRIT with its output text.
- **Definitions:** **Security → Protect → Protect checks** lists what's applied,
  with edit/delete and a `guard` badge where auto-quarantine is on.
- **Alerts:** a failing check raises `custom_check_failed` through your normal
  channels — inbox, webhooks, on-call, escalation. Recovery raises
  `custom_check_recovered`, which auto-resolves the alert.

### Alerting semantics — worth understanding

The **first** definitive observation of a check is **seeded silently**. That
stops a storm when you apply 40 templates at once and several fail immediately.
A check **still failing on its next report alerts**, then stays quiet until it
recovers. So a genuinely broken check pages you one report late — never not at
all.

---

## Troubleshooting

### Why is everything "unknown / not yet reported by agent"?

Agent-side checks are evaluated on the host and returned inside `sysinfo`, which
rides only **every 10th poll** — with the default 60s poll that's **once every
~10 minutes**. Right after applying, every row is legitimately `unknown`. Wait
for the next sysinfo beat; the agent log shows
`Config updated: agent_checks = N check(s)` when it received them.

### A `file_hash` / `dir_baseline` check says "baseline set"

That's success on first run — it recorded the current state as known-good. It
only alerts on *later* change. Apply these when the host is in a state you
trust; if you applied them to a host you're unsure about, verify it first, then
delete and re-add the checks.

### "AV signature updater running" is critical

The check is doing its job: `clamav-freshclam` is installed but not running, so
signatures are going stale. Fix the host, not the check:

    sudo systemctl enable --now clamav-freshclam
    sudo systemctl status clamav-freshclam

### "AV signatures updated recently" is critical / file missing

The template checks **both** `/var/lib/clamav/daily.cld` and `daily.cvd` and
uses the freshest — freshclam ships `daily.cvd` on a fresh install but rewrites
it as `daily.cld` once it starts applying incremental updates (the steady state
on a running host), so you never have to guess which extension yours uses. Once
freshclam is running, this clears on its own.

**Multiple paths.** Any file check (`file_hash`, `file_present`, `file_absent`,
`job_fresh`) accepts several candidate paths separated by `|`, and glob
patterns — it matches whichever **exists** (the freshest, for job freshness).
Point a WordPress `wp-config.php` check at every site root at once, for example:
`/var/www/site-a/wp-config.php|/var/www/site-b/wp-config.php`. Edit the check's
param on **Security → Protect** (or the custom-check editor) to set yours.

### Accepting a legitimate change ("Reset baseline")

When a protect check fires on a change you made on purpose, click **Reset
baseline** on the check's row (Monitoring → Checks) or on Security → Protect.
The check returns to OK immediately — the acceptance is recorded on the server,
so it holds through a page refresh — its open alert resolves, and the agent
re-baselines on its next check-in so its own on-host baseline agrees. A
genuinely *new* change (a different value) re-fires. For a check applied across
a tag or group, one Reset fans the acceptance out to every host it covers.

### A check fails for software that isn't installed

Expected when a broad set is applied fleet-wide — `AppArmor active` on a host
without AppArmor is a genuine "not hardened" signal, but if it doesn't apply to
that host, delete the check or narrow its scope (a tag rather than the fleet).

### Restore didn't put the file back

The original path is occupied, or the vault payload is gone. Guard refuses to
overwrite a file that now lives at that path. Clear it and retry; the agent
logs the exact reason.

---

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/guard/quarantine` | The fleet vault — scope- and tenant-filtered |
| `POST` | `/api/guard/action` | `{device_id, id, op: restore\|delete}` |
| `GET` | `/api/checks/baseline-catalog` | Templates, each labelled `kind: ops\|protect` |
| `POST` | `/api/checks/baseline-apply` | `{ids[], target_kind: all\|host\|tag\|group, target}` |
| `GET`/`POST` | `/api/checks/custom` | List / define a check (incl. `protect: quarantine`) |

Reads require authentication; quarantine actions require a write-capable role
and are audited. Everything is tenant- and scope-filtered.

---

## Related

- [Checks](checks.md) — the rollup page and the check model these build on
- [Drift](drift.md) — watched-file baselines, the config-oriented sibling
- [Alerts](alerts.md) — routing, on-call and escalation
- [Security](security.md) — the wider security posture surface
