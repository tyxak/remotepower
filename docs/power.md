# Power & energy

**Hardware → Power** tracks UPS status and measured power draw across the
fleet. Hosts currently **on battery** are listed first.

- **UPS** — Linux agents read NUT (`upsc`) or apcupsd (`apcaccess`) state:
  online or on battery, charge, load and runtime estimate. Going on battery
  raises an alert; recovery resolves it.
- **Power draw** — the UPS load in watts when a host reports one (NUT
  `ups.realpower` or `ups.power`; for apcupsd, the nominal power times the load
  percentage). A host with no UPS reading uses the sum of its GPUs' power draw
  (NVIDIA and AMD). A host with neither shows no power draw. The fleet total is
  the sum of these figures.
- **Laptop battery** — for hosts with a battery (`BAT*` power
  supplies) the agent reports charge %, charging status, cycle count and
  current-vs-design **wear** — shown as a Battery pill in the host
  drawer's System info. Servers and VMs are unaffected. External UPSes
  remain the separate NUT/apcupsd channel above.
- **Energy cost** — set your electricity price per kWh on the page to convert
  the fleet total into an estimated cost per day and per month. The price is
  kept in your browser. The monthly figure is the current draw projected over a
  month.
- **Cost allocation (chargeback)** — the card below the table splits the
  monthly estimate by group and by tag: hosts, watts, kWh a month and cost a
  month. A host with no group counts as `ungrouped`. Hosts you do not monitor
  are left out of the allocation, while the table above still lists them.

The page shows the latest readings. RemotePower keeps no history of power draw,
so [Trends](trends.md) has no power chart. A host's drawer lists its UPS and
GPUs under **Health & hardware**.

## UPS-critical auto-shutdown

Going on battery is one alert; a UPS approaching cutoff is another,
threshold-based one — **UPS Battery Critical**, raised once when the reporting
UPS is on battery and its battery percentage or estimated runtime drops at or
below the configured thresholds (**Settings → Alert parameters → Hardware &
power**: **UPS battery (%)**, default 20, and **UPS runtime (s, 0=off)**,
default 180). It auto-resolves the same way `ups_on_battery` does, when the
UPS returns to line power.

Optionally, and **off by default**, crossing into critical can trigger a
graceful shutdown of *other* hosts that depend on that UPS — e.g. a NAS
and a hypervisor sharing one UPS, where the NAS agent is the one that can
actually read `upsc`. Two things must both be true for anything to happen:

1. **Auto-shutdown hosts dependent on a UPS that goes critical** is ticked under
   **Settings → Security → UPS auto-shutdown**, fleet-wide.
2. The dependent host has a **UPS dependency** set (host drawer → UPS
   dependency), pointing at the host that reports the UPS.

The shutdown is queued as the same command the manual **Shut down** button
uses, and bypasses change-approval (Settings → Security) — this
is an unattended safety response to a UPS that is about to lose power, not
an operator-initiated change, so parking it for a second admin to approve
would defeat the point. Quarantined and audit-mode hosts are still
skipped, same as every other command path. Nothing is queued while server
[maintenance mode](maintenance.md#maintenance-mode-is-something-else) is on, and
a host whose command queue is full is skipped.

## Laptop battery wear

A laptop battery whose wear drops below the limit raises **Battery Health Low**
(**Settings → Alert parameters → Lifecycle → Battery health low (%, 0=off)**,
50 by default). The alert follows the battery's health (current full capacity
against design capacity), not its charge. It raises once and clears with
**Battery Health OK** when the battery is back above the limit.

## Power control through a smart plug

When a host hangs and its agent cannot answer, you can cut and restore its power
through a smart plug. In the host drawer, open **Power (PDU)** and fill in the plug:

- **Type**: Tasmota, Shelly (gen 1) or Shelly (gen 2+).
- **Host / IP**: the plug's address. The RemotePower server has to reach it.
- **Outlet** (optional): the relay number, for a plug with more than one. Leave it
  empty for a single relay.

**Save mapping** stores it (admins only; choosing no type removes it). **Power on**,
**Power off** and **Power cycle** then send the request from the server to the plug
over HTTP. A cycle switches off, waits five seconds and switches on. Each action asks
you to confirm first, and off and cycle warn that they cut power at once. Addresses
on your LAN work; loopback and cloud-metadata addresses are refused. The request
carries no password, so a plug that asks for one cannot be used.

Using it needs the `command` permission for the host, and every use is audited
(`device_power_control`; saving the mapping is `device_pdu_config`). The request goes
from the server to the plug, not through the agent. Quarantine and audit mode do not
apply to it: they stop commands to the agent, and cutting the power is still how you
stop a host you no longer trust. Change approval (**Settings → Security**) does apply:
with **Shut down** among the actions that require approval, **Power off** is parked for
a second admin, and with **Reboot** gated so is **Power cycle**. **Power on** is never held.

## API

- `GET /api/fleet/power` — the hosts with a UPS or a power reading, the fleet
  total in watts and how many are on battery. Hosts on battery come first.
- `GET /api/fleet/chargeback` — power and kWh a month per group and per tag.
  The price per kWh is applied in the browser.
- `GET` and `PATCH /api/devices/{id}/pdu` — read, save or clear a host's smart-plug
  mapping (`kind`: `tasmota`, `shelly1` or `shelly2`; `host`; `outlet`). Saving is
  admin-only.
- `POST /api/devices/{id}/power-control` — `{"action": "on" | "off" | "cycle"}`.

## Related

- [GPUs](gpus.md) — GPU power draw counts toward the total when a host has no UPS reading.
- [Alert parameters](alert-parameters.md#hardware--power) — the UPS limits, and the battery wear limit under Lifecycle.
