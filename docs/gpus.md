# GPUs

**Hardware → GPUs** shows GPU state across the fleet — NVIDIA and AMD.
Utilisation, VRAM, temperature, power draw and fan speed for every
reporting host, sorted hottest/busiest first.

- Agents collect via `nvidia-smi` / `rocm-smi` when present; hosts without
  the tools simply don't report.
- Per-GPU history is sampled into a rolling store, so the device drawer can
  chart utilisation/temperature over time.
- Threshold alerts (temperature, sustained utilisation) can be attached via
  device metric thresholds.
- Unmonitored hosts are listed and flagged (inventory principle) — only
  monitored hosts alert.
