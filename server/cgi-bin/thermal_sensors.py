"""A temperature history for every sensor a host reports (pure, stdlib only).

The Thermal page has always charted one series per host: the hottest reading. This module keeps a series for
each row of a host's sensor table as well, so the page can chart any of them.

A series is named after the row it belongs to, "<kind>|<label>": the kind is the row's type (sensor, disk or
gpu) and the label is the text the row prints. Both stores live inside rows that already exist, so no new file
is involved:

  ring    thermal_history.json, the host's row, key "sensors"
          {key: [[ts, temp], ...]}  a point about every 14 minutes, a little over a day
  hourly  thermal_rollup.json, the host's row, key "sensors"
          {"last_ts": n, "hourly": {key: [[hour, min, max, sum, n], ...]}}  30 days

Both are bounded: at most MAX_SERIES series per host, MAX_LABEL characters in a label, and a fixed number of
points in each. The ring is written on a hardware report and the roll-up folds it once an hour, the way the
hottest reading's roll-up does. Every reader and writer here takes what is stored as untrusted: a store that was
edited by hand or half migrated yields fewer series, never an exception.
"""

import math

KINDS = ("sensor", "disk", "gpu")

# What the Thermal page prints for a row that has no name, so a key built here matches the row's own label.
_DEFAULT_LABEL = {"sensor": "sensor", "disk": "disk", "gpu": "GPU"}

# Series kept per host. The page lists 16 rows; a new series waits for a free slot.
MAX_SERIES = 24
MAX_LABEL = 128  # characters of a label that are kept (the agent sends at most 96)
RING_GAP_S = 840  # a report adds points at most this often: about 96 a day for every series
RING_KEEP_S = 25 * 3600  # the ring holds a little over a day, so "24 hours" is never short
RING_MAX_POINTS = 120  # and never more than this many points in one series
HOUR_S = 3600
HOURLY_KEEP_S = 30 * 86400
STALE_S = 7 * 86400  # a series with nothing new for this long gives its slot to a new one

# The same limits the hottest reading uses (api._temp_is_measurement): a value outside them, or an ADC rail,
# is an unconnected pin, not a temperature.
TEMP_MIN = -40.0
TEMP_MAX = 150.0
_RAILS = (127.0, -128.0)


def _number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        out = float(value)
    except (OverflowError, ValueError):
        return None
    return out if math.isfinite(out) else None


def _int(value):
    out = _number(value)
    return int(out) if out is not None else None


def usable(value):
    """True for a reading a sensor could have produced."""
    out = _number(value)
    return out is not None and TEMP_MIN <= out <= TEMP_MAX and out not in _RAILS


def key_for(kind, label):
    """The series name of a row, or None when the kind is not one of KINDS."""
    if kind not in KINDS:
        return None
    text = str(label) if label else _DEFAULT_LABEL[kind]
    return f"{kind}|{text[:MAX_LABEL]}"


def split_key(key):
    """(kind, label) of a well-formed series name, else None."""
    if not isinstance(key, str) or len(key) > MAX_LABEL + 8:
        return None
    kind, bar, label = key.partition("|")
    if not bar or kind not in KINDS or not label or len(label) > MAX_LABEL:
        return None
    return kind, label


def _rows(value):
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def readings(temps, smart, gpus):
    """[(series name, °C)] for what one hardware report carried, one entry for each distinct name.

    The three arguments are the lists the ingest has just sanitized: board sensors ({label, current_c}), SMART
    disks ({device, temperature_c}) and GPUs ({name, temp_c}). A name that appears twice keeps its first
    reading. Pass None for a list the report did not carry, so a value that was only left over from an older
    report is not sampled again under a new time."""
    out = []
    seen = set()

    def add(kind, label, value):
        key = key_for(kind, label)
        if key is None or key in seen or not usable(value):
            return
        seen.add(key)
        out.append((key, round(float(value), 1)))

    for row in _rows(temps):
        add("sensor", row.get("label"), row.get("current_c"))
    for row in _rows(smart):
        add("disk", row.get("device"), row.get("temperature_c"))
    for row in _rows(gpus):
        add("gpu", row.get("name"), row.get("temp_c"))
    return out


# ─── the ring ────────────────────────────────────────────────────────────────


def _clean_points(points):
    out = []
    if not isinstance(points, list):
        return out
    for point in points:
        if isinstance(point, (list, tuple)) and len(point) == 2:
            ts, value = _int(point[0]), _number(point[1])
            if ts is not None and ts > 0 and value is not None:
                out.append([ts, round(value, 1)])
    out.sort(key=lambda p: p[0])
    return out


def _clean_ring(ring, only=None):
    """The series of a stored ring that can be read. `only` names the one a caller wants, so a read of one
    series does not validate the others."""
    out = {}
    if not isinstance(ring, dict):
        return out
    for key, points in ring.items():
        if (only is not None and key != only) or split_key(key) is None:
            continue
        points = _clean_points(points)
        if points:
            out[key] = points
        if len(out) >= 2 * MAX_SERIES:  # a store written by hand cannot make this loop long
            break
    return out


def ring_add(ring, new_readings, now):
    """The ring with one report's readings added: a fresh dict, the stored one is not touched.

    Nothing is added when the newest point is less than RING_GAP_S old, so a host that reports every five
    minutes gets a point about every fifteen. Points older than RING_KEEP_S go, and a series with none left.
    """
    out = _clean_ring(ring)
    now = _int(now) or 0
    cutoff = now - RING_KEEP_S
    for key in list(out):
        out[key] = [p for p in out[key] if p[0] >= cutoff][-RING_MAX_POINTS:]
        if not out[key]:
            del out[key]
    newest = max((points[-1][0] for points in out.values()), default=0)
    if now <= 0 or now - newest < RING_GAP_S:
        return out
    for key, value in new_readings or ():
        if split_key(key) is None or not usable(value):
            continue
        points = out.get(key)
        if points is None:
            if len(out) >= MAX_SERIES:
                continue
            points = out[key] = []
        points.append([now, round(float(value), 1)])
        del points[:-RING_MAX_POINTS]
    return out


def raw_points(ring, key):
    """One series of the ring in the shape the roll-up endpoint answers in: [{ts, temp: {min, avg, max}}].
    A point is a single reading, so the three are equal."""
    points = _clean_ring(ring, only=key).get(key) or []
    return [{"ts": ts, "temp": {"min": value, "avg": value, "max": value}} for ts, value in points]


# ─── the hourly roll-up ──────────────────────────────────────────────────────


def _clean_rollup(rec, only=None):
    """The roll-up record with every row that can be read; with `only`, just that one series."""
    base = rec if isinstance(rec, dict) else {}
    hourly = {}
    raw = base.get("hourly")
    if not isinstance(raw, dict):
        raw = {}
    for key, rows in raw.items():
        if (
            (only is not None and key != only)
            or split_key(key) is None
            or not isinstance(rows, list)
        ):
            continue
        clean = []
        for row in rows:
            if not (isinstance(row, (list, tuple)) and len(row) == 5):
                continue
            hour, low, high, total, count = (
                _int(row[0]),
                _number(row[1]),
                _number(row[2]),
                _number(row[3]),
                _int(row[4]),
            )
            if (
                hour is None
                or hour <= 0
                or None in (low, high, total)
                or count is None
                or count <= 0
            ):
                continue
            clean.append([hour, low, high, total, count])
        if clean:
            clean.sort(key=lambda r: r[0])
            hourly[key] = clean
        if len(hourly) >= 2 * MAX_SERIES:
            break
    return {"last_ts": max(_int(base.get("last_ts")) or 0, 0), "hourly": hourly}


def _evict_stale(hourly, now):
    """Free one slot by dropping the series with the oldest newest bucket, when that is older than STALE_S."""
    victim = min(hourly, key=lambda k: hourly[k][-1][0], default=None)
    if victim is None or hourly[victim][-1][0] >= now - STALE_S:
        return False
    del hourly[victim]
    return True


def fold_hourly(rec, ring, now, hold=False):
    """(roll-up record, changed): the ring's points newer than the record's last_ts folded into hourly buckets.

    Each point is folded once, so a bucket of the current hour grows as the hour goes on. Buckets older than
    HOURLY_KEEP_S are pruned unless `hold` is set (a litigation hold keeps what is already there; folding only
    adds). A new series that finds MAX_SERIES in use is dropped unless one of them has been silent for STALE_S.
    """
    base = _clean_rollup(rec)
    hourly, last = base["hourly"], base["last_ts"]
    newest = last
    changed = False
    now = _int(now) or 0
    for key, points in _clean_ring(ring).items():
        fresh = [p for p in points if p[0] > last]
        if not fresh:
            continue
        rows = hourly.get(key)
        if rows is None:
            if len(hourly) >= MAX_SERIES and not _evict_stale(hourly, now):
                continue
            rows = hourly[key] = []
        by_hour = {row[0]: row for row in rows}
        for ts, value in fresh:
            hour = ts - ts % HOUR_S
            row = by_hour.get(hour)
            if row is None:
                row = by_hour[hour] = [hour, value, value, value, 1]
                rows.append(row)
            else:
                row[1], row[2] = min(row[1], value), max(row[2], value)
                row[3], row[4] = round(row[3] + value, 2), row[4] + 1
            newest = max(newest, ts)
        rows.sort(key=lambda r: r[0])
        changed = True
    if not hold and now > 0:
        cutoff = now - HOURLY_KEEP_S
        for key in list(hourly):
            kept = [row for row in hourly[key] if row[0] >= cutoff]
            if len(kept) != len(hourly[key]):
                changed = True
            if kept:
                hourly[key] = kept
            else:
                del hourly[key]
    return {"last_ts": newest, "hourly": hourly}, changed or newest != last


def hourly_points(rec, key):
    """One series of the roll-up in the shape the roll-up endpoint answers in: [{ts, temp: {min, avg, max}}]."""
    rows = _clean_rollup(rec, only=key)["hourly"].get(key) or []
    return [
        {
            "ts": hour,
            "temp": {"min": round(low, 2), "avg": round(total / count, 2), "max": round(high, 2)},
        }
        for hour, low, high, total, count in rows
    ]
