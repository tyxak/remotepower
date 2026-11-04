"""RemotePower — named time periods: one model for "when" (7.4.9).

Four places asked the same question in four different ways. Quiet hours held a start, an end and the server's clock. After-hours
detection held a start, an end, the days of the week and the server's clock. The ticket SLA calendar held minutes per weekday, a list
of holidays and a fixed offset from UTC. A maintenance window held either two timestamps or a cron line and a duration. Each had its
own idea of a time zone, of a window that crosses midnight and of a holiday, and a change to one reached none of the others.

A time period is the shape the ticket calendar already had, with a name and a real time zone:

    {"id": "tp-1a2b3c4d", "name": "Office hours", "tz": "Europe/Copenhagen", "tz_offset_min": 0,
     "weekly": {"0": [[540, 1020]], "1": [[540, 1020]], ...}, "holidays": ["2026-12-25"]}

`weekly` maps a weekday (0 is Monday) to ranges of minutes since midnight, each with 0 <= start < end <= 1440. A range that crosses
midnight is written with an end before its start and is stored as two: the rest of its day and the beginning of the next. A holiday
closes the whole calendar day. The time zone is `tz` (a name from the IANA database) when the server knows it, else the fixed
`tz_offset_min`, else (both absent) the clock of the server, which is what quiet hours and after-hours always used.

Everything that decides whether a moment is inside a window calls `is_active` here, and the SLA clock walks the same ranges in
`business_deadline`, so there is one reading of a window, of midnight and of a holiday. Nothing in this module imports api.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any

try:  # the standard library's time zone database; absent on a system with no tzdata
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
except ImportError:  # pragma: no cover
    ZoneInfo = None  # type: ignore[assignment,misc]
    ZoneInfoNotFoundError = KeyError  # type: ignore[assignment,misc]

MAX_PERIODS = 50
MAX_RANGES_PER_DAY = 6
# what int(pair[0]), int(pair[1]) raises for a thing that is not a pair of numbers; a map where a pair belongs is a KeyError
_NOT_A_PAIR = (TypeError, ValueError, IndexError, KeyError, OverflowError)
MAX_HOLIDAYS = 200
_ID_RE = re.compile(r"^tp-[0-9a-f]{8}$")
_TZ_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_+\-]*(?:/[A-Za-z0-9_+\-]+){0,2}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_HHMM_RE = re.compile(r"^(\d{2}):(\d{2})$")


# ── reading a period ─────────────────────────────────────────────────────────────────────────────────────────────────


def zone_of(period: Any) -> tzinfo | None:
    """The time zone a period is read in: its named zone, else its fixed offset, else None (the clock of the server)."""
    if not isinstance(period, dict):
        return None
    name = period.get("tz")
    if isinstance(name, str) and name and ZoneInfo is not None and _TZ_RE.match(name):
        try:
            return ZoneInfo(name)
        except (ZoneInfoNotFoundError, ValueError, OSError):
            pass
    off = period.get("tz_offset_min")
    if isinstance(off, int) and not isinstance(off, bool) and -720 <= off <= 840:
        return timezone(timedelta(minutes=off))
    return None


def local_time(period: Any, ts: float) -> datetime:
    """`ts` as a wall-clock datetime in the period's zone. When the period names none the datetime is naive and on the clock of the
    server, so arithmetic on it and `.timestamp()` follow the server's own summer-time rules."""
    zone = zone_of(period)
    if zone is None:
        return datetime.fromtimestamp(
            int(ts)
        )  # naive, on the clock of the server: its own rules for summer time apply
    return datetime.fromtimestamp(int(ts), zone)


def _ranges(period: dict[str, Any], weekday: int) -> list[tuple[int, int]]:
    weekly = period.get("weekly")
    out: list[tuple[int, int]] = []
    if not isinstance(weekly, dict):
        return out
    wins = weekly.get(str(weekday))
    for win in wins if isinstance(wins, list) else []:
        try:
            s, e = int(win[0]), int(win[1])
        except _NOT_A_PAIR:
            continue
        if 0 <= s < e <= 1440:
            out.append((s, e))
    # 7.5.0: sorted and merged. Ranges that overlap (or touch) counted their shared minutes twice in business_deadline, so asking for
    # more time moved the deadline earlier. A calendar saved before the cleaner merged them is read as stored.
    out.sort()
    merged: list[tuple[int, int]] = []
    for s, e in out:
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))
    return merged


def _is_holiday(period: dict[str, Any], day: datetime) -> bool:
    hol = period.get("holidays")
    return isinstance(hol, list) and day.strftime("%Y-%m-%d") in hol


def is_active(period: Any, ts: float) -> bool:
    """True when `ts` falls inside one of the period's ranges on a day that is not a holiday. A period that is not a map, or has no
    ranges, is never active."""
    if not isinstance(period, dict):
        return False
    when = local_time(period, ts)
    if _is_holiday(period, when):
        return False
    minute = when.hour * 60 + when.minute
    return any(s <= minute < e for s, e in _ranges(period, when.weekday()))


def next_change(period: Any, ts: float, days: int = 14) -> tuple[int, bool] | None:
    """(when, active) for the next moment, within `days`, at which the period turns on or off, or None when it never does in that
    time (always off, or always on). `when` is a whole minute."""
    if not isinstance(period, dict):
        return None
    start = local_time(period, ts).replace(second=0, microsecond=0)
    now_active = is_active(period, ts)
    zone = start.tzinfo
    midnight = start.replace(hour=0, minute=0)
    # the minutes at which the state can change are the edges of the ranges, so only those are tried, day by day
    for d in range(days + 1):
        day = (midnight + timedelta(days=d)).replace(hour=0, minute=0)
        edges = sorted({0, 1440} | {x for s, e in _ranges(period, day.weekday()) for x in (s, e)})
        for m in edges:
            moment = (
                (day + timedelta(minutes=m))
                if m < 1440
                else (day + timedelta(days=1)).replace(hour=0, minute=0)
            )
            if moment.tzinfo is not zone:
                moment = moment.replace(tzinfo=zone)
            t = int(moment.timestamp())
            if t <= int(ts):
                continue
            if is_active(period, t) != now_active:
                return t, not now_active
    return None


def business_deadline(start_ts: float, seconds: float, period: Any) -> int:
    """The instant by which `seconds` of the period's time have passed since `start_ts`: the clock runs inside the ranges and stops
    outside them and on holidays. A period with no ranges at all, or one that never has enough time within about ten years, gives
    plain elapsed time, so a calendar that was set up wrong cannot push a deadline to infinity."""
    if not isinstance(period, dict):
        return int(start_ts) + int(seconds)
    remaining = float(seconds)
    cur = local_time(period, start_ts)
    for _ in range(3700):
        if remaining <= 0:
            return int(cur.timestamp())
        if not _is_holiday(period, cur):
            midnight = cur.replace(hour=0, minute=0, second=0, microsecond=0)
            for s, e in _ranges(period, cur.weekday()):
                w_start = max(cur, midnight + timedelta(minutes=s))
                w_end = midnight + timedelta(minutes=e)
                if w_start >= w_end:
                    continue
                avail = (w_end - w_start).total_seconds()
                if avail >= remaining:
                    return int((w_start + timedelta(seconds=remaining)).timestamp())
                remaining -= avail
        cur = (cur + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return int(start_ts) + int(seconds)


# ── the periods that older settings stand for ────────────────────────────────────────────────────────────────────────


def from_clock_range(start: str, end: str, workdays: Any = None) -> dict[str, Any] | None:
    """The period that a pair of `HH:MM` times stands for on the given weekdays (all seven when none are given), on the clock of the
    server. Quiet hours and after-hours detection stored exactly this. A range that crosses midnight (22:00 to 07:00) belongs to the
    day it is evaluated on, as it always did: both halves are on every listed day. Equal times are an empty range, so None.
    """
    ms, me = _hhmm_to_min(start), _hhmm_to_min(end)
    if ms is None or me is None or ms == me:
        return None
    days = _weekday_list(workdays)
    pieces = [[ms, me]] if ms < me else [[ms, 1440], [0, me]]
    # a piece that ends at 24:00 and one that starts at 00:00 would be a hole at midnight for a range that spans it, but only on the
    # day they are evaluated on, which is how the older check worked
    return {
        "id": "",
        "name": "",
        "tz": "",
        "tz_offset_min": None,
        "weekly": {str(d): [list(p) for p in pieces] for d in days},
        "holidays": [],
    }


def _hhmm_to_min(text: Any) -> int | None:
    m = _HHMM_RE.match(str(text or "").strip())
    if not m:
        return None
    h, mi = int(m.group(1)), int(m.group(2))
    if not (0 <= h <= 23 and 0 <= mi <= 59):
        return None
    return h * 60 + mi


def _weekday_list(workdays: Any) -> list[int]:
    if not isinstance(workdays, list):
        return list(range(7))
    out = sorted(
        {d for d in workdays if isinstance(d, int) and not isinstance(d, bool) and 0 <= d <= 6}
    )
    return out


# ── cleaning what an operator typed ──────────────────────────────────────────────────────────────────────────────────


def clean_weekly(raw: Any) -> dict[str, list[list[int]]]:
    """The ranges of a weekly calendar, validated and in one shape. Anything that is not a range is left out. A range whose end is
    before its start crosses midnight and is stored as the rest of its day plus the beginning of the next. Ranges on a day are
    sorted and joined where they touch or overlap."""
    days: dict[int, list[tuple[int, int]]] = {d: [] for d in range(7)}
    if isinstance(raw, dict):
        for key, wins in raw.items():
            try:
                d = int(key)
            except (TypeError, ValueError, OverflowError):
                continue
            if not (0 <= d <= 6) or not isinstance(wins, list):
                continue
            for w in wins[:MAX_RANGES_PER_DAY]:
                try:
                    s, e = int(w[0]), int(w[1])
                except _NOT_A_PAIR:
                    continue
                s, e = max(0, min(1440, s)), max(0, min(1440, e))
                if s == e:
                    continue
                if s < e:
                    days[d].append((s, e))
                else:
                    if s < 1440:
                        days[d].append((s, 1440))
                    if e > 0:
                        days[(d + 1) % 7].append((0, e))
    out: dict[str, list[list[int]]] = {}
    for d, rs in days.items():
        merged: list[list[int]] = []
        for s, e in sorted(rs):
            if merged and s <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        if merged:
            out[str(d)] = merged[:MAX_RANGES_PER_DAY]
    return out


def clean_period(
    raw: Any, existing_ids: frozenset[str] = frozenset(), new_id: str = ""
) -> dict[str, Any]:
    """One period as it is stored. Raises ValueError with the reason for a value that cannot be used. An id that is given must be of
    the shape ours are; a missing one is `new_id` (the caller makes it)."""
    if not isinstance(raw, dict):
        raise ValueError("a time period must be an object")
    name = re.sub(r"[\x00-\x1f\x7f]", " ", str(raw.get("name") or "")).strip()[:64].strip()   # cut, then strip: a second clean changes nothing
    if not name:
        raise ValueError("a time period needs a name")
    pid = str(raw.get("id") or "").strip() or new_id
    if not _ID_RE.match(pid):
        raise ValueError("the time period has an id that is not one of ours")
    tz = str(raw.get("tz") or "").strip()
    if tz:
        if not _TZ_RE.match(tz):
            raise ValueError(
                "the time zone is not a name from the IANA database, such as Europe/Copenhagen"
            )
        if ZoneInfo is None:
            raise ValueError("this server has no time zone database: use a fixed offset")
        try:
            ZoneInfo(tz)
        except (ZoneInfoNotFoundError, ValueError, OSError):
            raise ValueError("this server does not know that time zone") from None
    off = raw.get("tz_offset_min")
    if off is None or off == "":
        offset: int | None = None
    else:
        try:
            if isinstance(off, bool):
                raise ValueError
            offset = int(off)
        except (TypeError, ValueError, OverflowError):
            raise ValueError("the offset from UTC must be a whole number of minutes") from None
        if not -720 <= offset <= 840:
            raise ValueError("the offset from UTC must be between -720 and 840 minutes")
    holidays: list[str] = []
    hol = raw.get("holidays")
    if isinstance(hol, list):
        for h in hol[:MAX_HOLIDAYS]:
            h = str(h or "").strip()[:10]
            if _DATE_RE.match(h):
                try:
                    datetime.strptime(h, "%Y-%m-%d")
                except ValueError:
                    continue
                if h not in holidays:
                    holidays.append(h)
    return {
        "id": pid,
        "name": name,
        "tz": tz,
        "tz_offset_min": offset,
        "weekly": clean_weekly(raw.get("weekly")),
        "holidays": sorted(holidays),
    }


def clean_periods(raw: Any, make_id: Any) -> list[dict[str, Any]]:
    """The whole list: at most MAX_PERIODS, every period cleaned, names and ids unique. `make_id` returns a fresh id."""
    if not isinstance(raw, list):
        raise ValueError("the time periods must be a list")
    if len(raw) > MAX_PERIODS:
        raise ValueError("a server holds at most 50 time periods")
    out: list[dict[str, Any]] = []
    ids: set[str] = set()
    names: set[str] = set()
    for item in raw:
        pid = ""
        if isinstance(item, dict) and not str(item.get("id") or "").strip():
            for _try in range(20):  # an id that is taken is made again, but not for ever
                pid = make_id()
                if pid not in ids:
                    break
            else:
                raise ValueError("could not make an id for a time period")
        per = clean_period(item, new_id=pid)
        if per["id"] in ids:
            raise ValueError("two time periods have the same id")
        if per["name"].lower() in names:
            raise ValueError("two time periods have the same name")
        ids.add(per["id"])
        names.add(per["name"].lower())
        out.append(per)
    return out


def find(periods: Any, pid: Any) -> dict[str, Any] | None:
    """The period with this id in a stored list, or None."""
    if not isinstance(periods, list) or not isinstance(pid, str) or not pid:
        return None
    for p in periods:
        if isinstance(p, dict) and p.get("id") == pid:
            return p
    return None
