# Racks & IPAM

*Racks and IPAM introduced in v6.0.0; duplicate-MAC detection added in v6.1.2.*

Two related inventory features, both living on the **Sites & teams** page
(sidebar → Sites):

- **Racks** — model your physical racks and place assets in them, with a
  front elevation view that flags overlapping rack units.
- **IP address management (IPAM)** — define your subnets and get a derived
  occupancy view of every address in use, plus static reservations. A
  background sweep raises an alert when the same IP — or the same MAC — shows
  up on two devices.

Neither feature changes anything on the hosts. Racks and subnets are pure
records; occupancy and conflicts are *derived* from what the fleet already
reports.

---

## Racks

### Defining a rack

**Sites & teams → Racks → New rack.** A rack is just `{name, site, height_u}`:

- **Name** — required, max 64 chars.
- **Site** — optional; must reference an existing site (the elevation card
  shows the site name next to the rack).
- **Height** — 1–60 U, default 42.

Up to 500 racks. Creating, editing and deleting racks is **admin-only**;
viewing the list and elevations needs any signed-in user.

### Placing an asset

Placement lives on the **CMDB record**, not the rack: open the asset in the
CMDB and set its rack, **bottom U** (1-based) and **height in U** (default 1).
From the API it's the normal CMDB patch:

```bash
curl -sSf -X PUT https://your-server/api/cmdb/dev-abc123 \
  -H "X-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{"rack_id": "RACK_ID", "rack_unit": 12, "rack_height_u": 2}'
```

`rack_unit: 0` (or `rack_id: ""`) unplaces the asset. Deleting a rack
automatically unplaces every asset that referenced it — the devices themselves
are untouched.

### The elevation view

Click **Elevation** on a rack row. `GET /api/racks/{id}/elevation` returns the
model the UI draws: the rack's height, every placed asset
(`{device_id, name, rack_unit, rack_height_u, top_u, conflict}`, sorted
top-down) and a `conflicts` list of rack units where two assets' U spans
overlap. Overlapping assets are flagged in red with a "⚠ Overlapping units"
banner — the classic "two people racked something in U12 on paper" mistake.

---

## IPAM

### Defining a subnet

**Sites & teams → IP address management → New subnet.** A subnet is
`{cidr, site, vlan, notes}`:

- **CIDR** — required, any valid IPv4/IPv6 network (normalised on save, so
  `10.0.0.7/24` becomes `10.0.0.0/24`).
- **Site** — optional; must reference an existing site. Operators with a
  site-scoped role only see subnets for their sites.
- **VLAN** — free text, max 64 chars.
- **Notes** — max 512 chars.

Up to 1000 subnets. Writes are admin-only; reads need any signed-in user.
Deleting a subnet removes only the definition — devices are unaffected.

### Occupancy

Click **Occupancy** on a subnet row. `GET /api/ipam/subnets/{id}/occupancy`
builds the address inventory by collecting every address the server already
knows about and keeping the ones inside the subnet:

- the device record's primary IP (source `device`),
- each CMDB interface IP (source `nic`),
- each CMDB interface NAT IP (source `nat`),
- plus any static **reservations** on the subnet.

The header shows `used / reserved / free of total` (IPv4 subnets of /30 or
larger subtract the network and broadcast addresses from the total). An IP
held by more than one distinct device is marked as a **conflict** in red. The
device set is filtered through your role scope and tenant, so you only count
addresses of devices you can see.

### Reservations

Reservations are a per-subnet `{ip: label}` map (max 500 entries, labels up to
128 chars) for addresses that are spoken for but not held by an enrolled
device — a gateway, a DHCP pool boundary, that printer nobody enrolls. They
show in the occupancy table with their label. There is no UI editor;
manage them via the API:

```bash
curl -sSf -X PATCH https://your-server/api/ipam/subnets/SUBNET_ID \
  -H "X-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{"reservations": {"10.0.0.1": "gateway", "10.0.0.53": "pihole"}}'
```

The same `PATCH` also updates `vlan`, `notes` and `site`.

---

## Conflict detection — `ip_conflict` and `mac_conflict`

A maintenance sweep (`run_ipam_conflicts_if_due`) runs at most every
**5 minutes** and checks two things:

- **Duplicate IP** — the same address assigned to two or more devices,
  *judged only inside a defined subnet* (without a subnet there's no "same
  network" to judge against). Fires **`ip_conflict`**.
- **Duplicate MAC** — the same MAC address (from the device record and its
  interfaces; decommissioned devices excluded) on two devices. This half runs
  **whether or not any subnet is defined** — a duplicate MAC is wrong
  everywhere, and it's almost always a cloned VM whose NIC was never
  regenerated. Fires **`mac_conflict`**.

Both events are severity **high**, kind **network**: they land in the Alerts
inbox and fan out to your webhook destinations under the normal `network`
channel routing. Payloads name the IP/MAC and the devices involved. The
detection is **edge-triggered** — each conflict fires once when first seen
(state kept in `ipam_state.json`), stays quiet while it persists, and will
fire again if it clears and later returns. There is no auto-resolve event;
acknowledge/resolve the alert once you've fixed the address plan (or
regenerated the cloned NIC).

There are no config keys for any of this — the sweep is always on and does
nothing until it has devices (and, for the IP half, subnets) to look at.

---

## API reference

All paths under `/api`, auth via the usual `X-Token` header.

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| GET    | `/racks` | any | List racks with placed-asset counts. |
| POST   | `/racks` | admin | Body: `{name, site, height_u}`. Returns `{id}`. |
| PATCH  | `/racks/{id}` | admin | Update `name` / `site` / `height_u`. |
| DELETE | `/racks/{id}` | admin | Removes the rack and unplaces its assets. |
| GET    | `/racks/{id}/elevation` | any | Occupancy model + overlap conflicts. |
| PUT    | `/cmdb/{device_id}` | any | Placement fields: `rack_id`, `rack_unit`, `rack_height_u`. |
| GET    | `/ipam/subnets` | any | List subnets (site-scoped roles see only their sites). |
| POST   | `/ipam/subnets` | admin | Body: `{cidr, site, vlan, notes}`. Returns `{id}`. |
| PATCH  | `/ipam/subnets/{id}` | admin | Update `vlan` / `notes` / `site` / `reservations`. |
| DELETE | `/ipam/subnets/{id}` | admin | Definition only; devices unaffected. |
| GET    | `/ipam/subnets/{id}/occupancy` | any | Derived address inventory. |

Rack and subnet writes are audit-logged (`rack_create` / `rack_update` /
`rack_delete`, `ipam_subnet_create` / `ipam_subnet_update` /
`ipam_subnet_delete`).

Implementation: `server/cgi-bin/rack_ipam_handlers.py` (handlers + the
conflict sweep), placement fields in `server/cgi-bin/cmdb_handlers.py`, UI in
`app.js` (`loadRacks` / `loadIpam` and friends) on the Sites & teams page.
