"""RemotePower — the ZFS adaptive replacement cache and the datasets of a host, as the host reports them (7.4.9).

The agent has reported a ZFS pool's health, its last scrub and its newest snapshot since 3.11.0. It said nothing about what the
pool's memory is doing or which dataset holds the space, which is the first thing a ZFS owner asks when a host is slow or a pool
fills up. The Linux agent now reads the kernel's `arcstats` (the cache's size, its limits and its hit and miss counters) and
`zfs list` (each dataset's space, quota and the space snapshots hold).

Everything in a host's report is data from the host. These readers keep only numbers that are numbers (no booleans, no NaN, no
infinity, no 400-digit integers), keep a dataset only when its name is a ZFS name, cap what is kept, and compute the two derived
figures once, here, so the host drawer and the Storage page show the same ones. Nothing here imports api.
"""

from __future__ import annotations

import math
import re
from typing import Any

# The counters read from /proc/spl/kstat/zfs/arcstats. Sizes are bytes; the rest are counters since the module loaded.
ARC_KEYS = (
    "size",
    "c_min",
    "c_max",
    "hits",
    "misses",
    "l2_size",
    "l2_hits",
    "l2_misses",
    "mru_size",
    "mfu_size",
)
MAX_DATASETS = 30  # kept per host, the ones holding the most space
_LIMIT = 2**62  # a 64-bit byte count fits; a 400-digit integer does not
# A ZFS name is made of alphanumerics and `- _ . : space`, with / between its components and @ or # for a snapshot or bookmark
# (not a dataset). A space is allowed by ZFS and rare; it is kept because a dataset with one is still a dataset.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.: -]{0,127}(?:/[A-Za-z0-9_.: -]{1,127}){0,15}$")


def _count(v: Any) -> int | None:
    """A non-negative whole number, or None. Numbers only: a numeric string is not a number here."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    if isinstance(v, float):
        if not math.isfinite(v):
            return None
        v = int(v)
    return v if 0 <= v < _LIMIT else None


def _ratio(v: Any) -> float:
    """A compression ratio: above 0 and below 1000, else 1.0. An integer is compared before it is converted, since an
    integer too large for a float raises when it is."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return 1.0
    if isinstance(v, int):
        return float(v) if 0 < v < 1000 else 1.0
    if not (math.isfinite(v) and 0 < v < 1000):
        return 1.0
    r = round(v, 2)
    return r if r > 0 else 1.0       # 0.0039 rounds to 0.0, which the next clean reads as unknown


def clean_arc(raw: Any) -> dict[str, Any]:
    """The cache's counters from a host's report, kept as numbers, with `hit_ratio` (0 to 1, from the counters since boot) and
    `fill_pct` (the size as a share of its upper limit) added when they can be worked out. {} when there is no usable size.
    """
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    for k in ARC_KEYS:
        n = _count(raw.get(k))
        if n is not None:
            out[k] = n
    if "size" not in out:
        return {}
    total = out.get("hits", 0) + out.get("misses", 0)
    if total > 0 and "hits" in out:
        out["hit_ratio"] = round(out["hits"] / total, 4)
    if out.get("c_max", 0) > 0:
        out["fill_pct"] = round(min(100.0, out["size"] * 100.0 / out["c_max"]), 1)
    return out


def clean_datasets(raw: Any, limit: int = MAX_DATASETS) -> dict[str, Any]:
    """{count, rows} from a host's report: `count` is how many datasets the host has (as it counted them), `rows` the ones that
    hold the most space, each {name, used, avail, refer, quota, snap, ratio, quota_pct}. `quota` is 0 when the dataset has none,
    `snap` is what its snapshots hold, `ratio` its compression ratio (1.0 when unknown) and `quota_pct` how much of the quota is
    used (None without a quota). {} when there is nothing usable."""
    if not isinstance(raw, dict):
        return {}
    rows_in = raw.get("rows")
    if not isinstance(rows_in, list):
        return {}
    rows: list[dict[str, Any]] = []
    for r in rows_in[
        : max(limit, 0) * 4
    ]:  # a few more than kept, so a bad row does not shorten the list
        if not isinstance(r, dict):
            continue
        name = r.get("name")
        if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
            continue
        used = _count(r.get("used"))
        if used is None:
            continue
        row: dict[str, Any] = {"name": name, "used": used}
        for k in ("avail", "refer", "quota", "snap"):
            n = _count(r.get(k))
            row[k] = n if n is not None else 0
        row["ratio"] = _ratio(r.get("ratio"))
        row["quota_pct"] = (
            round(min(1000.0, used * 100.0 / row["quota"]), 1) if row["quota"] > 0 else None
        )
        rows.append(row)
    if not rows:
        return {}
    rows.sort(key=lambda x: (-x["used"], x["name"]))
    seen = _count(raw.get("count"))
    return {
        "count": seen if seen is not None and seen >= len(rows) else len(rows),
        "rows": rows[: max(limit, 0)],
    }
