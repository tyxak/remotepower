"""Telling the mounts of one host apart (pure, stdlib only).

A host reports every mount point it has, and several of them are often one filesystem: the subvolumes of a btrfs
volume (/, /home, /var/log, ...), a bind mount, a container volume that is mounted twice. They have the same size
and the same use, so a chart of "each mount" draws one line over and over and a table of "each disk" says the same
number in every row, and the pages read as if the disk figures never change.

This module says which mounts are one filesystem. Two mounts are one when they have the same size and the same
use, and, when a history is given, when their lines agree at every time both have a point. A mount with no use
to speak of says nothing about which disk it is (two new empty disks look alike), so it is never merged.
The page has the same rule for the table of Monitor -> Host metrics (`_groupMounts` in app.js, held to this by
tests/test_disk_mounts.py).
"""

import math

TOTAL_TOL_GB = 0.02  # sizes are reported to 0.1 GB (Windows, macOS) or 0.01 GB (Linux)
USED_TOL_GB = 0.05  # two mounts of one volume are read a moment apart, so its use can move a little between them
MIN_USED_GB = 0.1  # below this a mount says nothing about which volume it is
LINE_TOL = 0.05  # percentage points
MAX_ALSO = 20  # other mount points named for one filesystem
MAX_PATH = 28  # characters of a path that are shown in a chart legend


def _num(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        out = float(value)
    except (OverflowError, ValueError):
        return None
    return out if math.isfinite(out) else None


def same_filesystem(a, b):
    """True when two reported mounts are one filesystem, going by what they report: the size and the use."""
    ta, tb = _num(a.get("total_gb")), _num(b.get("total_gb"))
    ua, ub = _num(a.get("used_gb")), _num(b.get("used_gb"))
    if ta is None or tb is None or ua is None or ub is None:
        return False
    if ta <= 0 or tb <= 0 or ua < MIN_USED_GB or ub < MIN_USED_GB:
        return False
    if bool(a.get("network")) != bool(b.get("network")):
        return False
    return abs(ta - tb) <= TOTAL_TOL_GB and abs(ua - ub) <= USED_TOL_GB


def same_line(a, b):
    """True when two lines ([{ts, v}]) agree at every time both have a point, and there is such a time."""
    at = {p.get("ts"): _num(p.get("v")) for p in a if isinstance(p, dict)}
    shared = [
        (at[p.get("ts")], _num(p.get("v"))) for p in b if isinstance(p, dict) and p.get("ts") in at
    ]
    return bool(shared) and all(
        x is not None and y is not None and abs(x - y) <= LINE_TOL for x, y in shared
    )


def groups(mounts, points=None):
    """[{path, also: [path, ...]}]: the filesystems among the mounts, in the order they first appear.

    `path` is the shortest mount point of the filesystem and `also` the others, shortest first, at most MAX_ALSO.
    `points` ({path: [{ts, v}]}) makes the history count as well as the size and the use."""
    members = []
    for mount in mounts if isinstance(mounts, list) else []:
        if (
            not isinstance(mount, dict)
            or not isinstance(mount.get("path"), str)
            or not mount["path"]
        ):
            continue
        for group in members:
            if same_filesystem(group[0], mount) and (
                points is None
                or same_line(points.get(group[0]["path"]) or [], points.get(mount["path"]) or [])
            ):
                group.append(mount)
                break
        else:
            members.append([mount])
    out = []
    for group in members:
        paths = sorted({m["path"] for m in group}, key=lambda p: (len(p), p))
        out.append({"path": paths[0], "also": paths[1 : 1 + MAX_ALSO]})
    return out


def short_path(path):
    """A path for a chart legend: the end of it, which is the part that tells mounts apart."""
    text = str(path)
    return text if len(text) <= MAX_PATH else "…" + text[-(MAX_PATH - 1) :]
