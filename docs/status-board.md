# Status board, status endpoint and public status page

This page covers the three ways RemotePower shows fleet status to people and
tools that are not working in the full interface:

- the **Status board**, a wall view for your own screens,
- the **status endpoint**, a small JSON summary for Uptime Kuma, Homepage,
  Grafana and Home Assistant,
- the **public status page**, a read-only page you can share with customers,
  with components, incidents and planned maintenance.

## Status board

**Monitoring → Status Board** is the wall view for a network operations screen. It
stays readable at fleet scale: instead of one tile per host, it rolls the fleet up
by **group**, **site** or **tag** into big health tiles, and lists every unhealthy
host in a problem strip above them, whatever the size of the fleet.

- **Group / Site / Tag** switch at the top right picks how the tiles are cut.
  A host with several tags counts under each tag. Hosts with none are counted
  under `(untagged)`, `(no group)` or `(no site)`.
- **Vitals row.** Hosts, Online, Offline, Alerting and Unmonitored. *Online*
  includes hosts that are online with an open alert. *Alerting* is an online host
  with an open high or critical alert. *Unmonitored* is a host you switched
  monitoring off for. Agentless hosts count as well, using their reachability
  checks.
- **Needs attention strip.** Every host that is offline or alerting, offline
  hosts first and then by name. It shows up to 80 and reads "80 of 412" when
  there are more, so a large outage is never mistaken for the whole count. Click a
  host to open it. The reason is `offline` or the title of its alert.
- **Rollup tiles.** One per group, site or tag, showing online hosts out of the
  total and a bar split into healthy, alerting, offline and unmonitored. The
  tiles with the most offline hosts come first, and the board shows up to 120.
  Click a tile to open the Hosts page filtered to it.

The board is cut down to the hosts your role and tenant may see, and any signed-in
user can open it. It refreshes itself every 60 seconds and pauses while its browser
tab is hidden.

### Putting it on a display

Open the board in kiosk mode: `https://YOUR-SERVER/?kiosk=1#board`. Kiosk mode
hides the sidebar and fills the screen. To rotate through several pages every 30
seconds, use `https://YOUR-SERVER/?kiosk=1&cycle=30&pages=board,home,alerts`
instead. Press **Esc** to leave.

Kiosk mode only changes what is shown. The API still enforces the role of whoever
is signed in, so sign the display in with a **viewer** account if it should stay
read-only. See [alerts.md](alerts.md).

## Status endpoint

**Settings → Integrations → Status endpoint** gives you a status token. With it,
an outside tool can poll a fleet summary without a login:

```
GET /api/status?token=YOUR-TOKEN
```

```json
{"health": "ok", "devices_online": 41, "devices_offline": 1, "devices_total": 42,
 "attention": {"critical": 0, "warning": 2, "info": 3, "total": 5},
 "version": "x.y.z", "generated": 1767225600}
```

`health` is `critical` if anything needs attention at critical level, `warning` for
warning level, and `ok` otherwise. Hosts you do not monitor and agentless hosts
are not counted. The token works only for this summary and the two endpoints
below. It does not open `/api/self/status`, which needs a session or an API key
(see [self-monitoring.md](self-monitoring.md)).

- **Generate status token** creates it. **Rotate token** replaces it, and the old
  one stops working at once. **Disable endpoint** removes it, and every URL that
  used it answers an error.
- The endpoint answers 403 when no token is set, and 401 for a wrong token.
- Treat the URL like a password. Anyone who has it can read the summary. Only the
  platform operator can create or change the token when multi-tenancy is on.

### Home Assistant

The same token opens `GET /api/ha?token=YOUR-TOKEN`, flat JSON shaped for a Home
Assistant REST sensor. `state` is `ok`, `warning` or `critical`, and the other
fields (`devices_online`, `devices_offline`, `alerts_critical`, `alerts_warning`,
`health_score`, `health_grade`, and `problem` as `on` or `off`) are plain values
you can use as attributes:

```yaml
sensor:
  - platform: rest
    resource: https://YOUR-SERVER/api/ha?token=YOUR-TOKEN
    value_template: "{{ value_json.state }}"
    json_attributes: [devices_online, devices_offline, alerts_critical, alerts_warning, health_score]
```

It is one-way. Nothing here can control a host.

## Public status page

**Settings → Integrations → Public status page** turns the token into a shareable
page at `https://YOUR-SERVER/status.html?token=YOUR-TOKEN`. It needs no login and
shows no host names, addresses or alert text. Only the names you choose, derived
states and times appear.

Settings:

- **Enable the public status page** and a **Public title** (the server name is
  used if you leave it blank).
- **Show incident history** and the **Incident window (days)**, from 1 to 90
  (default 30).
- **Components.** Click **+ Add component**, name it, optionally give it a group
  heading, and add hosts and monitors to it (up to 20 components, with up to 50
  hosts and 50 monitors each). A component is *operational* when all its members
  are up, *degraded* when some are down, and a *major outage* when all are. Hosts
  inside an active maintenance window show the component as *under maintenance*
  instead.

The page shows an overall banner (All systems operational, Degraded performance,
Major outage or Under maintenance), the components grouped by heading with their
uptime over the window, the recent outage history of those components, any
incidents you posted, announced maintenance, and the monitors' up and down counts.
The uptime figure counts how long alerts on a component's hosts stayed open.

### Incidents

Under the same settings, **Incidents** lets you post a note that appears above the
components with its own running update log:

1. Enter a **title**, pick an **impact** (Minor, Major or Maintenance) and a
   **status** (Investigating, Identified, Monitoring or Resolved), write a message
   and click **Post incident**.
2. Change the status or **Post an update** on a listed incident as things move.
   Setting it to Resolved closes it. Resolved incidents leave the page after the
   incident window.
3. Enter **Subscriber emails** and click **Save subscribers** to email them when an
   incident opens and when it resolves. This needs SMTP set up under **Settings →
   Notifications**.

An open incident darkens the overall banner (a Major impact reads as a major
outage). Incidents opened automatically from an alert storm carry an **auto**
badge, see **Settings → Notifications → Incident auto-promotion**. Only admins can
post, update or delete incidents, and RemotePower keeps up to 500.

### Planned maintenance

A [maintenance window](maintenance.md) changes a component to *under maintenance*
while it is active. The page also announces the window when it is created through
the API with `public` set and a `public_title`. Only that title and the times are
published, never the reason or the host names. To leave planned maintenance off the
page altogether, set `status_page.show_maintenance` to `false` through the API (the
default is `true`); the components then show as up or down and the windows are not
announced.

## API

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/api/board?by=group\|site\|tag` | signed in | Vitals, tiles and the capped problem list for the board. |
| GET | `/api/status?token=` | status token | The fleet summary above. |
| GET | `/api/ha?token=` | status token | Home Assistant shape. |
| GET | `/api/public/status?token=` | status token | Data for the public page: health score, host and monitor counts, components, incidents. |
| POST | `/api/status-token` | admin | `{"enabled": true}` creates or rotates the token. `{"enabled": false}` removes it. |
| GET, POST | `/api/incidents` | admin | List and post incidents. |
| PATCH, DELETE | `/api/incidents/{id}` | admin | `{status?, body?}` posts an update or changes the status. |

The flat monitor list in that answer names its entries `Monitor 1`, `Monitor 2` and so on. A monitor's label is free text and usually holds a host name or an address, and anyone who has the token can read this answer. To show a monitor by name, put it in a component and give the component the name you want visitors to see.

See also: [sites.md](sites.md), [dashboard.md](dashboard.md),
[attention.md](attention.md), [maintenance.md](maintenance.md).
