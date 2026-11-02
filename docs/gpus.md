# GPUs

**Hardware → GPUs** shows the GPUs in your fleet, NVIDIA and AMD. Each GPU is a card with its
utilisation, memory use, temperature, power draw and fan speed. The hottest GPUs come first,
then the busiest. A line above the cards gives the totals: GPUs and hosts, how many are NVIDIA
and AMD, the combined power draw, and how many are hot.

Use the box on the page to filter by host or GPU name, and **Refresh** to reload.

## How hosts report

- The Linux agent reads NVIDIA cards with `nvidia-smi` and AMD cards with `rocm-smi`. If
  `rocm-smi` is missing it falls back to the kernel's `amdgpu` interface.
- The Windows agent reads NVIDIA cards with `nvidia-smi`.
- A host without these tools, or without a GPU, does not appear on the page.
- GPU data travels with the hardware report, about every five minutes. A freshly started agent
  reports within a minute.

## Trends

Each card draws two small charts, temperature and utilisation, for the last four hours or so.
The server keeps about 24 hours of samples per GPU. The host drawer lists the same GPUs under
**Audit → Health & hardware**.

## Alerts

GPU temperatures use the same alert as the other hardware sensors, so there is nothing extra to
set up:

- A GPU at or above the temperature threshold raises **High Temperature** (`temp_high`). It
  clears with `temp_normal` when the GPU cools down. The threshold is **Settings → Alert
  parameters → Hardware & power → Temperature (°C)**, 85 °C by default.
- **Settings → Alert parameters → Thermal & GPU → GPU hot** (85 °C by default) only sets where the
  page marks a GPU as hot. It colours the temperature and feeds the "hot" count. It does not send
  an alert.
- There is no alert for sustained utilisation.

GPU temperatures also appear on the [Thermal](thermal.md) page, and GPU power draw counts
toward the total on the [Power](power.md) page when a host has no UPS reading.

Hosts you do not monitor are listed and flagged **unmonitored**, but they do not alert.

## Troubleshooting

| Problem | What to check |
| --- | --- |
| "No GPUs reported yet" | Run `nvidia-smi` or `rocm-smi` as the agent's user on the host. Wait up to five minutes for the next hardware report. |
| A card is missing | Only NVIDIA and AMD cards are read. Intel graphics and other vendors are not. Without `rocm-smi`, an AMD card needs the `amdgpu` driver. |
| Temperature shows as a dash | The tool did not return a value for that field. Some cards and virtual GPUs report no fan speed or power. |

## See also

[Thermal](thermal.md), [Power](power.md) and [Alert parameters](alert-parameters.md).
