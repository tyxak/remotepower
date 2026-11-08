# Business services

A host list tells you which machines are up. A monitor tells you whether one address answers. Neither tells you whether
**Checkout** works, because Checkout is a web server, a database, a cache and a payment monitor, and someone has to add
them up in their head. A business service writes that sum down.

**Business Services** (sidebar, under Monitoring) lists the services you defined, each with its state, the rule that
decides it, how many of its parts are up, since when, and its availability over 30 days.

## A service is a name, parts and a rule

**Parts** can be:

| Part | It is up when |
|---|---|
| **Host** | the host is reporting |
| **Monitor** | the last result of one of your [monitors](monitors.md) was up |
| **systemd unit** | the unit is `active` on a host that is reporting (the unit has to be watched under [Services](services.md)) |
| **Container** | the container is running and not unhealthy on a host that is reporting |
| **Custom script** | the last result of a [custom script](custom-scripts.md) on that host is OK (a script read as a Nagios plugin can also be a warning) |
| **Business service** | the other service is up, so a service can be made of services, up to five levels deep |

A part that is not up is **down**, or **degraded** when it is only a warning (an unhealthy container, a plugin that
says warning). A part with no data yet is **not known**. A unit, container or script on a host that has stopped
reporting is down, because what that host last said is out of date.

**The rule** says how the parts add up:

| Rule | Use it for | The service is |
|---|---|---|
| **All parts have to be up** | a chain: the web server and the database and the cache | up when every part is up, otherwise as bad as its worst part |
| **At least one part has to be up** | redundancy: either of two load balancers | up when all are up, **degraded** while at least one is, down when none is |
| **At least N parts have to be up** | a quorum: two of three database nodes | up when all are up, **degraded** while N or more are, down below N |

A part that is down but not needed makes the service *degraded*, not down. A redundant pair that lost one member shows
what it is: still serving, with less margin.

## Create one

1. **Business Services → New service.**
2. Give it a name, and a description if you like.
3. Pick the rule. For the quorum rule, set the number.
4. Add the parts. Choose the kind, fill in its fields (a host, plus the unit name, the container name or the script) and
   press **Add part**.
5. **Save.** The page shows the state at once.

A name has to be unique, a service holds at most 50 parts, and you can have 100 services. A service cannot contain itself,
two services cannot contain each other, and a service that another one holds has to be taken out of that one before you
delete it.

Click a service's name for the detail view: every part with its state and the reason, the rule, the availability, and the
last changes.

## Being told

Once a minute RemotePower reads the state of every service. A change has to hold for **two reads in a row** before anyone
is told, so one missed report does not page. Then:

- **Business service down** is raised when a service goes down (critical) or degraded (medium). A service that gets worse,
  from degraded to down, raises the same alert to critical. A service that is already broken when you create it is
  reported on its first read.
- **Business service up** closes the alert when the service is up again.
- A service whose parts report nothing (not known) changes no one's mind. What was last known stays the state of record
  until something definite replaces it.

Both events go through the [notification routing](webhooks.md) like any other, under the kind **Business service degraded
/ down**, and they show in the Alerts inbox and the activity feed. Deleting a service closes its open alert.

## On a host

Open a host's drawer (Actions and settings) and **Business services that depend on this host** lists every service that has
the host as a part, with its state. A service that holds another service which holds the host is listed too, marked
*through another service*. Select a name to open the service. A host that is in no service shows no section.

## Availability

The 30-day figure is the share of the last 30 days the service was not down. Degraded counts as up, because it still
serves. A stretch in which the service was not known is left out. It is worked out from the changes RemotePower recorded,
so it starts counting when you create the service.

## Who can use it

Business services are a view across the installation's own hosts, monitors and scripts, so on an installation with
[tenancy](scaling.md) they belong to the organisation that runs it. Administrators create, change and delete them. Other
signed-in users of that organisation see the services whose hosts they can see. Users of a tenant do not see the page, and they are not shown the alerts and activity entries a service raises either. The same
rule covers the alert, the Problems list, the activity feed and the notifications: a person sees what a service raises only if
they can see every host it names, because the text lists its parts by name.

## API

| Route | What it does |
|---|---|
| `GET /api/business-services` | every service you can see, with the state of each part |
| `POST /api/business-services` | create one (administrators): `name`, `description`, `rule`, `members` |
| `GET /api/business-services/{id}` | one service with its history and availability |
| `PUT /api/business-services/{id}` | replace its name, description, rule and parts (administrators) |
| `DELETE /api/business-services/{id}` | delete it (administrators) |
| `GET /api/business-services/impact?device_id=` | the services that depend on a host, directly or through another service |

A rule is `{"type": "all"}`, `{"type": "any"}` or `{"type": "min", "min": 2}`. A part is an object with a `kind`:

```json
{"kind": "host", "device_id": "dev-abc123"}
{"kind": "monitor", "label": "shop homepage"}
{"kind": "unit", "device_id": "dev-abc123", "unit": "nginx.service"}
{"kind": "container", "device_id": "dev-abc123", "name": "web"}
{"kind": "script", "device_id": "dev-abc123", "script_id": "cs_1a2b3c"}
{"kind": "service", "service_id": "bs_4d5e6f7a8b"}
```
