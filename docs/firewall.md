# Firewall & fail2ban

**Security → Firewall** gives you fleet-wide visibility *and* editing for host
firewalls and [fail2ban](https://www.fail2ban.org/) in one place. It builds on
the firewall posture the agent already reports, so existing agents light up as
soon as they upgrade.

## Host firewalls

The top table lists every host that reports firewall data, one row each:

| Column | Meaning |
| --- | --- |
| **Device** | Host name (unmonitored hosts still show, flagged) |
| **Backends** | Which firewall tools are present — `nftables`, `iptables`, `ufw`, `firewalld`, `ebtables` — with the default policy on hover |
| **State** | `active` / `inactive` / `unknown` (unknown = the agent couldn't read the ruleset without root — never counted as "off") |
| **Rules** | Total rule count across backends |
| **Drift fingerprint** | A short hash of the ruleset; it only changes when a *real* rule changes (volatile packet counters are zeroed first). A change raises a `firewall_changed` alert when the listening-port & firewall audit is enabled |

Click **Rules** on a row to see that host's actual ruleset, grouped by backend.

### Editing rules

In the per-host rule view you can **add** or **delete** rules:

- **ufw / firewalld** — add a port rule (`allow 22/tcp`, `--add-port=22/tcp`) or
  delete an existing one by clicking **Delete** next to it.
- **nftables / iptables** — add a raw rule by entering its spec
  (`-A INPUT -p tcp --dport 22 -j ACCEPT`, or
  `add rule inet filter input tcp dport 22 accept`), or delete a listed rule
  (iptables by spec, nftables by handle).

Before anything is queued, the confirm dialog shows the **exact command** that
will run on the host. Where the backend has a native check mode (**ufw**
`--dry-run`, **nftables** `nft -c`), you can optionally run an **on-host
dry-run** first (v6.4.1): the check command is sent through the run-and-wait
exec path and the host's own verdict — pass/fail and its output — is folded
into the confirm dialog before you commit. iptables and firewalld have no
native dry-run, so their preview shows the command only.

Every edit is **queued as a host command** — it applies on the host's next
check-in, is recorded in the audit log, and is skipped on a quarantined host.

> **Lock-out warning.** Raw firewall edits can lock you out of a host (e.g.
> dropping your own SSH rule). Review rules before deleting, and prefer keeping
> an out-of-band path (console/IPMI) for recovery.

## fail2ban

The second table lists each host's fail2ban jails and how many IPs they have
banned. Hosts without fail2ban report it as **not available** (this includes the
containerized agent, which has no access to the host's fail2ban socket).

Click **Manage** to:

- **Ban** an IPv4/IPv6 address in a jail, or **Unban** a currently-banned one.
- **Start** or **Stop** a jail.

As with firewall edits, each action is queued through the audited command pipeline.

## Permissions & safety

- **Viewing** firewall and fail2ban posture needs only normal authentication.
- **Editing** (rules, bans, jails) requires the **`command`** permission for the
  target device — a viewer cannot make changes. Custom scoped operator roles can
  edit only hosts in their scope.
- Rule specs and references are **strictly validated server-side**, so a rule
  field can never inject a second shell command. A spec you *type* accepts only
  letters, digits and rule punctuation; an iptables *delete* reference is the
  host's own `iptables -S` line, so quoted comments
  (`-m comment --comment "kube-proxy service portals"`) and `!` negations are
  kept intact and every argument is shell-quoted before the command runs.
- Edits never bypass **quarantine** or the **4-eyes change-approval** controls
  that already gate the command queue.


## Appliance configuration archive *(v6.4.2)*

RemotePower can keep a versioned copy of each **RouterOS** and **OPNsense**
device's running configuration — the RANCID/Oxidized job, done from the
appliance integrations you already configured.

Switch it on under **Settings → Security → Appliance config archive**. It is
off by default: archiving authenticates to every appliance in the fleet and
stores its full configuration, which may embed secrets.

- Runs **daily** (`netconfig_backup_interval_s` tunes it), keeps the last **10
  revisions per device**, and raises **`netconfig_changed`** when a config
  differs from the last archived copy.
- An **identical** config is not archived again — only the "last verified"
  timestamp moves, so a quiet device is distinguishable from a broken poll.
- The **first** archive of a device is a baseline and fires nothing; otherwise
  switching the feature on would alert on every appliance at once.
- Each appliance's drawer gets a **Configuration archive** panel: back up now,
  view a revision, download it, or diff it against the one before.
- A config over **256 KB** is archived as a hash and size only. Change
  detection still works, but there is no body to diff — a *truncated* config in
  an archive looks complete and is not, which is worse than storing none.
- Reading the archive list needs any signed-in role; reading or downloading a
  configuration **body**, and running a backup, are admin-only.

`GET|POST /api/devices/{id}/netconfig`,
`GET /api/devices/{id}/netconfig/{revision}[?format=download|diff&against=…]`
