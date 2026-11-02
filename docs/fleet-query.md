# Fleet Query

**Fleet → Query** filters the whole fleet by ad-hoc criteria and gives you a live table of the
matching hosts. All conditions are **ANDed**: a host must match every box you fill in. Boxes you
leave empty are ignored.

Fill in the criteria, click **Run**, and read the table. Click a column heading to sort. Click a host
name to open its timeline.

## What you can filter on

| Family | Criteria |
| --- | --- |
| Identity | Group, Tag, OS contains, Kernel contains, Platform contains (for example `debian` or `arm64`), Agent version contains, Pkg manager (`apt`, `dnf`, `pacman`), **Has package** |
| State | Online, Monitored, Agentless, Quarantined, Offline for more than N days, Uptime over or under N days, Cores over or under N |
| Patching | Pending updates over N, Reboot required, Kernel outdated, 3rd-party updates pending, Integrity (agent file verified, mismatch or unknown), **CVE (crit+high)** at least N |
| Resources | Busiest disk %, Memory %, CPU %, Swap %, Load (1 minute), busiest Inode %, File descriptors %, Conntrack % |
| Problems | Failed units, Timer failed, Config drift, Mount issue, Storage degraded, Clock skew (NTP), Gateway unreachable, Recent OOM kill, Container stopped, Container restarting, SMART failed, UPS on battery, Over temperature |
| Security posture | World-exposed port, Brute-force active, No host firewall, Weak SSH config, Auto-updates off |

Notes:

- **Has package** matches part of a package name. The table then gets a **Matched package** column
  with the installed version (up to three matches per host).
- **CVE (crit+high)** counts the way the dashboard does: a finding you accepted as a risk is left
  out, and with the [CVE count option](cve.md#counting-only-what-an-update-can-fix) on, so is every
  finding no update can clear.
- **No host firewall** and **Auto-updates off** cover Linux, Windows and macOS hosts. **Weak SSH
  config** needs the host to report its sshd settings (Linux). A host that could not report the
  value does not match.
- Unmonitored hosts are included unless you set **Monitored** to *monitored*, so inventory
  questions get complete answers.
- You only see the hosts your role and tenant allow.

## The result table

Each row shows the host, group, OS, status, pending updates, CPU %, memory % and the critical and
high CVE count (a dash means the value is not known). The count above the table is the number of
matching hosts.

## Saving and sharing queries

- **Save query** stores the current criteria under a name. You choose whether to share it with
  your team or keep it private.
- Saved queries appear next to the **Save query** button. Click one to fill in its criteria and run
  it. The small buttons beside it rename it, share it with your team, duplicate it or delete it.
- Saved queries live on the server, not in your browser, so they follow you to another browser.
  Queries saved by an older version in your browser move to the server the first time you open
  the page.

## Exporting

- **Export CSV** and **Export XML** download the current result with the same filters.
- **Print / PDF** opens a printable page that runs the same query.

## Typical uses

- "Which hosts still run agent version 7.3?" Set **Agent version contains** to `7.3`.
- "Which hosts have `openssl` installed, and which version?" Set **Has package** to `openssl`. The
  **Matched package** column shows the versions.
- "Offline hosts tagged `production`": **Tag** `production`, **Online** offline.
- "Reboot needed and more than 30 days up": **Reboot required** yes, **Uptime over** 30 days.

## API

`GET /api/fleet/query` takes the same criteria as query parameters (`group`, `tag`, `os`,
`version`, `has_package`, `online`, `pending_gt`, `cve_min`, `disk_gt`, `firewall_off`,
`ssh_weak`, and so on). Add `format=csv` or `format=xml` to download instead of JSON. Saved
queries are under `/api/query/templates`. See [api.md](api.md) for authentication.

## When you want more than ANDed conditions

Fleet Query is simple. When you need nested AND/OR/NOT, or you want to query security posture,
capacity, or CVE and drift rows rather than hosts, use the
**[Data Explorer](data-explorer.md)**. It uses the same saved-query store and the same scoping.

For a one-off question in plain words, ask the [AI assistant](ai.md). It reads the same fleet
data.

## See also

[data-explorer.md](data-explorer.md), [bulk-operations.md](bulk-operations.md),
[navigation.md](navigation.md).
