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
- Rule specs and references are **strictly validated server-side** — only
  letters, digits and rule punctuation are accepted, so a rule field can never
  inject a second shell command.
- Edits never bypass **quarantine** or the **4-eyes change-approval** controls
  that already gate the command queue.
