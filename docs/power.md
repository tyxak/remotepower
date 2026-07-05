# Power & energy

**Hardware → Power** tracks UPS status and measured power draw across the
fleet. Hosts currently **on battery** are listed first.

- **UPS** — agents read NUT/apcupsd state: online/on-battery, charge,
  runtime estimate. Going on battery raises an alert; recovery resolves it.
- **Power draw** — measured watts where the platform exposes them (RAPL,
  IPMI, smart-UPS load). The fleet total is live.
- **Energy cost** — set your electricity price on the page to convert the
  live total into an estimated cost per day/month.

History is sampled so the [Trends](trends.md)/drawer views can show draw
over time.
