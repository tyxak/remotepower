# Thermal health

**Hardware → Thermal** lists the hottest hosts across the fleet from the
CPU, chipset and disk temperatures agents already report. Each row shows
that host's single hottest sensor; the list sorts hottest-first and anything over
its threshold is flagged. Per-host thresholds live in the metric-threshold UI;
the global hot/critical °C defaults are tunable in **Settings → Alert
parameters**.

- Sensor sources: hwmon/lm-sensors, NVMe/SMART temperatures, GPU sensors.
- The **Trend (~24h)** sparkline in each row comes from the live sample ring —
  one reading per hardware cycle, roughly the last day.
- Sustained over-threshold temperatures raise a thermal alert; thresholds
  are tunable per device.
- Unmonitored hosts are listed and flagged (inventory principle) — only
  monitored hosts alert.

## Dead and unconnected sensors

A hardware monitoring chip — Nuvoton NCT67xx, ITE IT87xx and friends — exposes
every thermal pin on its die whether or not your board wired anything to that
pin. An unconnected pin does not report "absent". It reports whatever rail its
ADC floats to, which is frequently a plausible-looking number and occasionally
an absurd one. A common real example is `nct6798-isa-0290/AUXTIN2` reading
115-127 °C on a machine whose CPU cores are at 35 °C.

Left alone, one dead pin becomes the host's *hottest sensor*, and from there
sets the headline temperature, fires `temp_high`, and feeds the overheating risk
factor. RemotePower handles this in two ways, on purpose of different strength:

**Impossible readings are discarded.** A reading of exactly 127.0 °C or
-128.0 °C — the signed-byte rails an open circuit produces — or one outside any
physically meaningful range, never enters the store. Nothing is lost: these are
not measurements.

**Doubtful readings are flagged, never dropped.** A sensor reading at or above
its *own* critical limit while the host is up and heartbeating is almost
certainly a dead pin — hardware cuts power at crit, so a machine that is
genuinely there is not genuinely past it. Expand the host and that sensor is
marked **Implausible**. RemotePower will not silently discard it, because
"almost certainly" is the wrong confidence level at which to stop alerting on a
machine that might really be overheating.

**You decide.** Next to each sensor is **Ignore**. An ignored sensor:

- no longer counts as the host's hottest sensor,
- no longer fires `temp_high` (and if it was the reason a `temp_high` was open,
  that alert resolves on the next heartbeat),
- no longer contributes to the overheating check or risk factor,
- no longer appears in the temperature roll-up's max — so the chart stops
  showing a spike that was never real.

It stays in the per-sensor table, greyed, with **Restore** to count it again.
The list is per device and is stored alongside that device's metric thresholds,
so resetting your thresholds does not un-ignore a pin you deliberately muted.

## The temperature timeline

Expand a row (the caret in the **Sensors** column) and you get two things: the
per-sensor table, and above it a full temperature timeline for that host —
**Min / Avg / Max** per point, so you see the envelope rather than an average
that hides the peaks.

Pick the window with the four buttons above the chart:

| Range | Reads | Resolution |
|---|---|---|
| 24 hours | 5-minute roll-up, clipped to the last day | 5 minutes |
| 8 days | 5-minute roll-up, in full | 5 minutes |
| 30 days | hourly roll-up | 1 hour |
| 2 years | daily roll-up | 1 day |

Those are the three tiers RemotePower keeps, and each one is trimmed to its own
retention: 5-minute points for 8 days, hourly for 30 days, daily for about two
years. That is the same layout the per-device metrics history uses, so a
temperature question and a CPU question are answered over the same spans.

The line the row's sparkline draws and the line the timeline draws come from
different stores. The sparkline reads the raw sample ring, which only goes back
about a day; the timeline reads the roll-up, which is **folded once an hour**.
So on a freshly installed server the sparkline appears within minutes and the
timeline stays empty until the first fold — it says so rather than looking
broken — and the 30-day and 2-year views only become interesting once the
server has been running that long. Nothing is lost in the meantime: folding is
additive, and the roll-up simply starts from the day the host began reporting.

Two things the caption under the chart tells you:

- **Where the history actually starts**, when the host has noticeably less
  history than the range you picked. A 2-year view of a host enrolled three
  months ago is three months of data, and the caption says so instead of letting
  the line imply it is the whole story.
- **Whether points were averaged for display.** A full 8-day 5-minute window is
  a few thousand points; the chart folds them so it stays readable. The averaging
  applies to the Avg line only — the Min and Max lines still carry the true
  extremes of every bucket that went into a point.

## Pinpointing a window

Both this chart and the per-device metrics chart on
[Trends](trends.md) support the same time-pinpointing control, for when you
know roughly when something happened and want to look at exactly that.

- **Drag across the chart** to select a window; release to zoom into it.
- **Double-click the chart** — or press **Reset** — to go back to the full range.
- **Type the exact window.** The **From** / **To** fields under the chart take a
  date and time; press Enter or **Apply**. This is also the keyboard path: the
  fields, Apply and Reset are all reachable by tab, so pinpointing never depends
  on being able to drag.

While a window is pinned it survives a refresh of the page's data, so a chart
that reloads on a timer won't yank you back out to the full range mid-look. The
y-axis rescales to what's actually in the window, which is usually the point —
a 3 °C excursion is invisible against a full-range axis and obvious against a
zoomed one. On the thermal chart the caption re-computes for the pinned window,
so the min / avg / max under the chart describe what you are looking at rather
than the whole range. On the metrics chart, narrowing to a short recent window
re-fetches a finer tier rather than stretching the points already on screen.

## API

- `GET /api/devices/<id>/thermal/rollup?tier=fivemin|hourly|daily` — aggregated
  hottest-sensor series for one host, `{ts, temp:{min,avg,max}}` per point. The
  metrics equivalent is `GET /api/devices/<id>/metrics/rollup`, in the same
  shape.
- `GET /api/fleet/thermal` — the fleet table, including the raw ~24h sparkline
  samples. Each per-sensor row carries `ignored` / `suspect` flags.
- `GET|PATCH /api/devices/<id>/metric-thresholds` — `sensor_ignores` is a list
  of sensor labels to leave out of this host's temperature. PATCH replaces the
  list; an empty list clears it.
