# Thermal health

**Hardware → Thermal** lists the hottest hosts across the fleet from the
CPU, chipset and disk temperatures agents already report. Each host shows
its single hottest sensor; the list sorts hottest-first and anything over
its threshold is flagged.

- Sensor sources: hwmon/lm-sensors, NVMe/SMART temperatures, GPU sensors.
- Per-host thermal history is sampled into a rolling store (charted in the
  device drawer).
- Sustained over-threshold temperatures raise a thermal alert; thresholds
  are tunable per device.
