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

## The three check types

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

### `egress_flagged` — no outbound connection to a flagged address

    param:  203.0.113.0/24, 198.51.100.7

Reads the host's active outbound connections and alerts if any remote endpoint
falls inside your list of flagged IPs/CIDRs (comma- or space-separated). An
empty list is OK (nothing to match). Use it with a threat-intel feed or the
indicators from an incident.

> **Platform:** these three are Linux-first. On Windows they report `unknown`
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

**Baseline protect checks** ships ~57 hardening templates, applied by checkbox
to any scope. They're grouped by intent:

| Category | What it covers |
|---|---|
| Hardening — services | fail2ban, AppArmor, sshd, journald, rsyslog, AV updater |
| Hardening — must not listen | 17 ports that should not be reachable: FTP, rsh/rlogin, rpcbind, NFS, SMB/NetBIOS, VNC, RDP, the unauthenticated **Docker API (2375)**, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, memcached, SNMP |
| Integrity — critical files | `/etc/shadow`, `/etc/group`, `/etc/sudoers`, `sshd_config`, `hosts`, `nsswitch.conf`, PAM, `fstab`, `resolv.conf`, apt sources |
| Integrity — persistence paths | `/etc/cron.d`, `cron.daily`, `cron.hourly`, `/etc/systemd/system`, `/etc/sudoers.d`, `/root/.ssh`, `/etc/profile.d`, `/usr/local/bin`, `sources.list.d`, `ld.so.conf.d` |
| Integrity — must not exist | `/etc/ld.so.preload` (userland-rootkit tell), `/root/.rhosts`, `/etc/hosts.equiv` |
| Detection — log signals | auth-failure bursts, sudo misuse, AppArmor/SELinux denials, segfaults, filesystem/IO errors |
| Freshness — scheduled jobs | apt index freshness, AV signature freshness |
| Web / application security | web-root code integrity, accounts/crontab/cron.d integrity, outbound-to-flagged |

Params suit Debian/Ubuntu and are **editable after applying** (e.g.
`sshd.service` instead of `ssh.service` on RHEL). Applying is **idempotent** —
de-duplicated on (type, param, scope), so re-applying adds nothing.

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

The template points at `/var/lib/clamav/daily.cld`. freshclam ships `daily.cvd`
on a fresh install but rewrites it as `daily.cld` once it starts applying
incremental updates — the steady state on a running host. If yours differs,
edit the check's param. Once freshclam is running, this clears on its own.

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
