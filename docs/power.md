# Power & energy

**Hardware → Power** tracks UPS status and measured power draw across the
fleet. Hosts currently **on battery** are listed first.

- **UPS** — agents read NUT/apcupsd state: online/on-battery, charge,
  runtime estimate. Going on battery raises an alert; recovery resolves it.
- **Power draw** — measured watts where the platform exposes them (RAPL,
  IPMI, smart-UPS load). The fleet total is live.
- **Laptop battery** *(v6.3.0)* — for hosts with a battery (`BAT*` power
  supplies) the agent reports charge %, charging status, cycle count and
  current-vs-design **wear** — shown as a Battery pill in the device
  drawer's System info. Servers and VMs are unaffected. External UPSes
  remain the separate NUT/apcupsd channel above.
- **Energy cost** — set your electricity price on the page to convert the
  live total into an estimated cost per day/month.

History is sampled so the [Trends](trends.md)/drawer views can show draw
over time.

## UPS-critical auto-shutdown *(v6.1.1)*

Going on battery is one alert; a UPS approaching cutoff is another,
threshold-based one — **UPS Battery Critical**, raised when the reporting
UPS's battery percentage or estimated runtime drops at or below the
configured threshold (Settings → Security → **UPS auto-shutdown**, default
20% / 180s). It auto-resolves the same way `ups_on_battery` does, when the
UPS returns to line power.

Optionally, and **off by default**, crossing into critical can trigger a
graceful shutdown of *other* devices that depend on that UPS — e.g. a NAS
and a hypervisor sharing one UPS, where the NAS agent is the one that can
actually read `upsc`. Two things must both be true for anything to happen:

1. **Settings → Security → UPS auto-shutdown** is turned on fleet-wide.
2. The dependent device has a **UPS dependency** set (device drawer → UPS
   dependency), pointing at the device that reports the UPS.

The shutdown is queued as the same command the manual **Shut down** button
uses, and deliberately bypasses change-approval (Settings → Security) — this
is an unattended safety response to a UPS that is about to lose power, not
an operator-initiated change, so parking it for a second admin to approve
would defeat the point. Quarantined and audit-mode devices are still
skipped, same as every other command path.
