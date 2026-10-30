"""RemotePower — temperature lines for drives (v7.4.4, issue #54).

A hard disk, a SATA SSD and an NVMe drive run at different temperatures, so one pair of numbers
cannot suit all three. This module holds the two pure parts of holding a drive to its own lines:
which lines apply to it, and what a hardware report does to its alert. Nothing here imports api;
the caller hands in the lines, the drives and the previous state.

Which lines apply. The warning line and the critical line are looked up one at a time, and for each
the first of these that holds a number wins:

    1. the drive's own line, kept against its serial number
    2. the host's line for the drive's type (hdd, ssd or nvme)
    3. the host's line for any drive
    4. the fleet's line for the drive's type
    5. the fleet's line for any drive

So a host that sets only a warning line keeps the fleet's critical line. Nothing is set by default,
and a drive with no line at any level is not judged at all, so an upgrade alerts on nothing new. A
warning line on its own leaves the critical line out of reach, and a critical line on its own is also
the warning, as for the disk busy lines.
"""

from __future__ import annotations

import math
from typing import Any, Callable

# The drive types a line can be set for. A drive of any other type, or of none the agent could tell, is
# judged by the lines for "any drive".
MEDIA = ("hdd", "ssd", "nvme")

# A line is a whole or fractional number of degrees from LINE_MIN to LINE_MAX.
LINE_MIN = 1.0
LINE_MAX = 150.0

# A reading outside this range is a drive or a USB bridge answering with noise (0 and 255 are the usual
# ones), not a temperature. It neither raises an alert nor closes one.
READING_MIN = 1.0
READING_MAX = 150.0

# How many drives one host can keep a line of its own for. More than the 32 drives a report carries, so
# a host that has had drives swapped keeps the lines of the ones it has had.
MAX_PER_HOST = 128

# Reports in a row a drive may be missing from before its open alert is closed. A read that times out
# leaves the drive out of one report, and a drive that is overheating is one that may stop answering, so
# one missing report does not say it has gone.
MISS_LIMIT = 3


def line_keys(media: str = "") -> tuple[str, str]:
    """The names of the warning and the critical line for a drive type, or for any drive ('')."""
    prefix = f"drivetemp_{media}_" if media else "drivetemp_"
    return prefix + "warn_c", prefix + "crit_c"


# Every line name, for the fleet's settings and a host's own. The first pair is "any drive".
ALL_LINE_KEYS: tuple[str, ...] = tuple(k for m in ("",) + MEDIA for k in line_keys(m))


def as_line(value: Any) -> float | None:
    """A line as a float, or None when it is not one: a number from LINE_MIN to LINE_MAX. A bool is not
    a number here, and neither are NaN and infinity."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    # A comparison and no conversion: it is false for NaN and infinity, and it is exact for an integer
    # too big for a float, which float() and math.isfinite() would raise on.
    return float(value) if LINE_MIN <= value <= LINE_MAX else None


def inverted(warn: Any, crit: Any) -> bool:
    """True when both lines of a pair are set and the warning is not below the critical one."""
    w, c = as_line(warn), as_line(crit)
    return w is not None and c is not None and w >= c


def media_of(entry: Any) -> str:
    """'hdd', 'ssd' or 'nvme' for one SMART entry, or '' when it cannot be told. The agent's word
    wins. A drive at /dev/nvme* is NVMe whatever agent reported it, so an older Linux agent still gets
    that one right."""
    if not isinstance(entry, dict):
        return ""
    media = str(entry.get("media") or "").strip().lower()
    if media in MEDIA:
        return media
    device = str(entry.get("device") or "").strip()
    return "nvme" if device.rsplit("/", 1)[-1].startswith("nvme") else ""


def _pair(warn: float | None, crit: float | None) -> tuple[float | None, float | None]:
    """A warning and a critical line as the checks use them. Neither set: (None, None). Warning only:
    the critical line is out of reach (infinity). Critical only: it is also the warning. A warning line
    above the critical one, which two levels can produce between them, is brought down to it.
    """
    if crit is None:
        return (None, None) if warn is None else (warn, math.inf)
    if warn is None:
        return crit, crit
    return min(warn, crit), crit


def resolve(
    serial: str, media: str, own: Any, host: Any, fleet: Any
) -> tuple[float | None, float | None]:
    """The (warn, crit) lines for one drive, or (None, None) when no level sets one.

    `own` is the host's table of per-drive lines, {serial: {"warn": n, "crit": n}}; `host` and `fleet`
    are the dicts that hold the line names from line_keys (a host's metric thresholds, the fleet's
    settings). Pass own=None for the lines the drive would have without its own, which is what the
    page shows in grey under the drive's boxes."""
    entry = own.get(serial) if serial and isinstance(own, dict) else None
    mine = entry if isinstance(entry, dict) else {}
    sources: list[tuple[dict, str, str]] = [(mine, "warn", "crit")]
    types = ((media,) if media in MEDIA else ()) + ("",)
    for scope in (host, fleet):
        if isinstance(scope, dict):
            for m in types:
                warn_key, crit_key = line_keys(m)
                sources.append((scope, warn_key, crit_key))
    warn = next((v for v in (as_line(s.get(w)) for s, w, _ in sources) if v is not None), None)
    crit = next((v for v in (as_line(s.get(c)) for s, _, c in sources) if v is not None), None)
    return _pair(warn, crit)


def reading(entry: Any) -> float | None:
    """A drive's temperature, or None when there is no usable one. A drive that is asleep reports
    none, and a value outside READING_MIN..READING_MAX is noise."""
    if not isinstance(entry, dict):
        return None
    value = entry.get("temperature_c")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if READING_MIN <= value <= READING_MAX else None


def serial_counts(drives: Any) -> dict[str, int]:
    """How many drives in a report carry each serial number."""
    counts: dict[str, int] = {}
    for d in drives if isinstance(drives, list) else []:
        serial = str(d.get("serial") or "").strip() if isinstance(d, dict) else ""
        if serial:
            counts[serial] = counts.get(serial, 0) + 1
    return counts


def drive_key(entry: Any, counts: dict[str, int] | None = None) -> str:
    """What a drive's alert is kept under: its serial number, so the alert follows the drive when its
    letter changes. A serial that several drives in the report share (some USB bridges give every
    disk the same one) cannot tell them apart, so those are kept under the serial and the device. A
    drive with no serial is kept under its device. '' for an entry with neither."""
    if not isinstance(entry, dict):
        return ""
    serial = str(entry.get("serial") or "").strip()
    device = str(entry.get("device") or "").strip()
    if serial and (counts is None or counts.get(serial, 0) <= 1 or not device):
        return serial
    if serial:
        return f"{serial}@{device}"
    return device


def below_recovery(value: float, warn: float, buffer: float) -> bool:
    """True once a reading has dropped far enough under the warning line for the alert to close, so a
    drive hovering at the line does not open and close it on every report. The same rule as the other
    metrics: `buffer` degrees under the line, or a tenth of the line under it, whichever is nearer.
    """
    return value < max(warn - buffer, warn * 0.9)


LinesOf = Callable[[dict], tuple[float | None, float | None]]


def _state_of(prev: Any) -> dict[str, tuple[str, int]]:
    """The previous state as {key: (level, reports missed)}, leaving out anything malformed."""
    out: dict[str, tuple[str, int]] = {}
    if not isinstance(prev, dict):
        return out
    for key, value in prev.items():
        if not isinstance(key, str) or not isinstance(value, dict):
            continue
        level = value.get("l")
        missed = value.get("m", 0)
        if (
            level in ("warning", "critical")
            and isinstance(missed, int)
            and not isinstance(missed, bool)
        ):
            out[key] = (level, max(0, missed))
    return out


def step(
    prev: Any, drives: Any, lines_of: LinesOf, buffer: float = 5
) -> tuple[list[dict], dict[str, dict]]:
    """What a hardware report does to the drives' alerts.

    `prev` is the state this function returned last time, `drives` the SMART entries of the report and
    `lines_of(entry)` the (warn, crit) lines of one entry. Returns (events, state). Each event is
    {"event", "key", "drive", "value", "threshold"} with event one of metric_warning, metric_critical
    and metric_recovered, `drive` the entry (None for a drive that is no longer reported) and `key` what
    the alert is kept under. The state keeps only drives that are over a line.

    A drive with no usable reading, such as one that is asleep, keeps whatever state it had and says
    nothing. A drive left out of the report keeps it for MISS_LIMIT reports and is then let go with a
    recovery, so an alert is never left open for a drive that was taken out. Turning a drive's lines
    off closes its alert on the next report."""
    old = _state_of(prev)
    entries = [d for d in drives if isinstance(d, dict)] if isinstance(drives, list) else []
    counts = serial_counts(entries)
    events: list[dict] = []
    state: dict[str, dict] = {}
    seen: set[str] = set()

    def event(name: str, key: str, drive: dict | None, value: float, threshold: float) -> None:
        events.append(
            {
                "event": name,
                "key": key,
                "drive": drive,
                "value": value,
                "threshold": threshold,
            }
        )

    for d in entries:
        key = drive_key(d, counts)
        if not key or key in seen:
            continue
        seen.add(key)
        was = old.get(key, ("ok", 0))[0]
        warn, crit = lines_of(d)
        value = reading(d)
        if warn is None or crit is None:
            # No line applies now. An alert opened under a line that has since been removed closes.
            if was != "ok":
                event("metric_recovered", key, d, value or 0.0, 0.0)
            continue
        if value is None:
            if was != "ok":
                state[key] = {"l": was, "m": 0}
            continue
        level = "critical" if value >= crit else "warning" if value >= warn else "ok"
        if level == was:
            if was != "ok":
                if below_recovery(value, warn, buffer):
                    event("metric_recovered", key, d, value, warn)
                else:
                    state[key] = {"l": was, "m": 0}
            continue
        if level == "critical":
            event("metric_critical", key, d, value, crit)
            state[key] = {"l": "critical", "m": 0}
        elif level == "warning":
            event("metric_warning", key, d, value, warn)
            state[key] = {"l": "warning", "m": 0}
        elif below_recovery(value, warn, buffer):
            event("metric_recovered", key, d, value, warn)
        else:
            # Under the line but inside the buffer: stay where it was rather than bounce.
            state[key] = {"l": was, "m": 0}

    for key, (was, missed) in old.items():
        if key in seen:
            continue
        if missed + 1 >= MISS_LIMIT:
            event("metric_recovered", key, None, 0.0, 0.0)
        else:
            state[key] = {"l": was, "m": missed + 1}
    return events, state


def view(entry: Any, own: Any, host: Any, fleet: Any) -> dict:
    """What the Hardware tab shows for one drive: its type, the lines it is held to (null when it is
    held to none, and a critical line of null when only a warning line is set), the lines its own
    boxes would inherit, and the lines it has of its own."""
    serial = str(entry.get("serial") or "").strip() if isinstance(entry, dict) else ""
    media = media_of(entry)
    warn, crit = resolve(serial, media, own, host, fleet)
    inherit_warn, inherit_crit = resolve(serial, media, None, host, fleet)
    out: dict[str, Any] = {
        "media": media,
        "warn": warn,
        "crit": None if crit == math.inf else crit,
        "inherit": {
            "warn": inherit_warn,
            "crit": None if inherit_crit == math.inf else inherit_crit,
        },
    }
    mine = own.get(serial) if serial and isinstance(own, dict) else None
    if isinstance(mine, dict):
        out["own"] = {
            "warn": as_line(mine.get("warn")),
            "crit": as_line(mine.get("crit")),
        }
    return out


# The states a reading can be in, mildest first.
LEVELS = ("ok", "hot", "critical")


def level(value: float, warn: Any, crit: Any, fleet_hot: float, fleet_crit: float) -> str:
    """'ok', 'hot' or 'critical' for one temperature reading of a drive (v7.4.6, issue #54).

    `warn` and `crit` are the lines `view` returned for the drive. A drive held to lines of its own is
    judged by them, and a warning line on its own is never 'critical', as for the alerts. A drive with no
    line at any level is judged by the fleet's hot and critical lines, which is how the Thermal page and
    the risk score have always judged every sensor, so an install that sets no drive line sees no change.
    Pass None for both lines to judge a sensor that is not a drive."""
    w, c = as_line(warn), as_line(crit)
    if w is None and c is None:
        w, c = fleet_hot, fleet_crit
    if c is not None and value >= c:
        return "critical"
    if w is not None and value >= w:
        return "hot"
    return "ok"
