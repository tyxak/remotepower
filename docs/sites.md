# Sites & teams

**Fleet → Sites** groups the fleet one level above host groups: by location,
team or customer. A host belongs to at most one site. Sites then scope reports
and roll-ups across the app (network metrics, billing per customer, the status
board, the customer portal, custom roles and scheduled reports).

The page has three tabs. **Site map** and the sites table are the core. **Groups**
holds the tools that place and configure hosts. **Racks** is for physical layout
and IP planning, see [ipam.md](ipam.md).

## Creating and assigning sites

- **New site** (admin only) takes a name, a note, and an optional latitude and
  longitude. Names are unique (not case-sensitive) and up to 64 characters, and
  you can keep up to 500 sites. The table shows each site's name, a slug, its host
  count and when it was created. **Rename** edits the name, note and coordinates.
  **Delete** removes the site and leaves its hosts unassigned.
- **Assign a host** with **Assign site** in the host drawer, or in bulk with the
  site field of the bulk attributes dialog (a site that does not exist is rejected,
  so create it first). Only admins can assign. Auto-placement rules (below) assign
  new hosts when they enrol.
- **Site report.** The **Report (CSV)** and **JSON** buttons on a site's row
  download a posture report for that site alone: hosts, patches, SLA, CVEs and
  health. It is also available as `GET /api/report/site/{id}?format=json|csv`, and
  you can send one to a customer on a schedule by choosing the site in a
  report definition on the Reports page. A role limited to some hosts, groups or
  tags cannot pull a whole-site report. Only a role that covers the site can.

## Site map

Sites with coordinates are plotted on a world map. A dot is **green** when every
host at the site is online, **amber** when some are offline, and **red** when all
are. Click a dot to filter the table. Sites without coordinates are listed in the
table but not on the map. The same map is part of the [Status board](status-board.md).

## Where a site is used

- **Network metrics** can roll up by site, so a site that stands for a customer
  doubles as a per-customer throughput view ([network-metrics.md](network-metrics.md)).
- **Billing.** Invoices are raised per site, and each site carries its own rate
  card and fees on the [Billing](time-billing.md) page.
- **Customer portal.** A contact with a site and portal access sees only that
  site's tickets ([customer-portal.md](customer-portal.md)).
- **Custom roles** can be limited to chosen sites. Operators then see and act on
  only those hosts. See Users & Roles → Custom roles.
- **Targeting.** A site can be the target of an auto-patch policy, a ring in a
  staged rollout, the scope of a service baseline, and the scope of a scheduled
  report.

## The Groups tab

**Auto-placement rules.** When a new host enrols, the first matching rule sets its
group, site and tags. A rule matches a hostname (regular expression) or the
source address (CIDR). Enrolment-token defaults always win, and rules never touch
hosts that are already enrolled. See [fleet-management.md](fleet-management.md).

**Host profiles.** A named bundle of per-host settings: poll interval, watched
units, log watches, drift-watched files and metric thresholds (disk, memory, swap,
CPU load and temperature). **Apply…** copies the fields a profile defines onto the
hosts you pick (up to 500 at a time). It is a one-shot copy, so each host stays
editable afterwards. Thresholds are merged with the host's own, so per-mount disk
overrides survive. You can keep up to 100 profiles. Only admins manage them.

**Smart groups.** A saved query whose members are re-evaluated about once a
minute. All rules must match (AND). The form offers: group equals, has tag, OS
contains, memory, disk or CPU percent above a value, has configuration drift, and
reboot required. The API also accepts a site, several groups or tags, the agent
version, monitored and agentless. A smart group does not change a host's real
group. Use it as a targeting scope: type `smart:NAME` where a group name is
accepted (a custom role's group list, a service baseline), or pick **smart group**
as a ring type in a staged rollout. Names use lowercase letters, digits, `-` and
`_`. You can keep up to 100, and only admins manage them.

## Role scoping

Custom roles can be restricted to specific sites. Super-admins always see every
site. The site list itself is shared, but counts only include hosts the viewer is
allowed to see.

## API

| Method | Path | Notes |
|---|---|---|
| GET | `/api/sites` | Sites with host counts. Any signed-in user. |
| POST | `/api/sites` | `{name, note?, lat?, lng?}`. Admin. |
| PUT | `/api/sites/{id}` | Rename or edit the note and coordinates. Admin. |
| DELETE | `/api/sites/{id}` | Admin. Unassigns the site's hosts. |
| GET | `/api/sites/map` | Sites with coordinates and rolled-up health. |
| PATCH | `/api/devices/{id}/site` | `{site}`. Assign a host, or `""` to unassign. Admin. |
| GET | `/api/report/site/{id}` | Per-site posture report. |
| GET, POST | `/api/device-profiles`, `/api/smart-groups` | Host profiles and smart groups. Admin. |

## With multi-tenancy

The sites belong to the organisation that runs the installation. With tenant isolation on, only users of the default tenant can open or change them. Users of every other tenant are refused, and the dashboard leaves them out of its summaries.

See also: [fleet-management.md](fleet-management.md), [ipam.md](ipam.md),
[time-billing.md](time-billing.md), [status-board.md](status-board.md).
