"""Resource forecasting + "what changed" diffs over the daily metrics history.

v3.4.0. Pure stdlib, no I/O — the caller (api.py) loads metrics_history.json
and passes the per-device sample list in. Kept side-effect free so it's
trivially unit-testable.

A sample (written by api._maybe_sample_metrics) looks like:

    {
      "date": "2026-05-30", "ts": 1748563200,
      "mounts": [{"path": "/", "used_gb": 12.3, "total_gb": 29.4, "percent": 41.8}],
      "mem_percent": 37.0, "swap_percent": 0,
      "state": {"pkg_upgradable": 4, "ports": ["tcp/22","tcp/443"],
                "reboot_required": false, "failed_units": []}
    }
"""

DAY = 86400

# v3.4.2: ephemeral / tmpfs-style mounts whose usage sawtooths as temp files
# churn. A linear "days to full" projection over them is noise, so they are
# excluded from the forecast by default. Callers may override via `exclude`.
VOLATILE_MOUNTS = ('/tmp', '/var/tmp', '/run', '/dev/shm', '/run/lock', '/run/user')
# Below this least-squares R² the trend is too noisy to trust a fill date.
_MIN_R2 = 0.5

# A fill projection only matters inside an actionable planning window. Past ~2
# years a linear extrapolation of disk growth is both unreliable and not a
# "risk" anyone acts on ("/ fills in 62 months / 2031" is noise, not an alert),
# so beyond this horizon we keep the row but drop the projected date.
_FORECAST_HORIZON_DAYS = 730

# v3.8.0: "has the growth actually stopped?" guard. A one-off spike inside the
# trend window (a big restore, a log burst, a backup run) leaves the
# full-window least-squares slope pointing up long after the growth is over, so
# the page keeps projecting an alarming fill date that will never arrive. We
# re-fit the slope over just the most recent window; if that has flattened (or
# reversed), we treat the mount as stalled — keep the row + current usage, but
# drop the projected date and flag it so the UI can say "growth stalled".
_RECENT_WINDOW_DAYS = 7
# Per-day growth below this (GB/day) counts as "not really climbing".
_CLIMB_FLOOR = 0.001


def _is_volatile_mount(path, exclude):
    p = (path or '').rstrip('/') or '/'
    for v in exclude:
        v = v.rstrip('/')
        if p == v or p.startswith(v + '/'):
            return True
    # any sub-mount of /run or /dev (tmpfs territory) is volatile too
    return p.startswith('/run/') or p.startswith('/dev/')


def _r_squared(xs, ys, slope, intercept):
    """Coefficient of determination of the fit. 1.0 = perfect line, ~0 = noise."""
    n = len(ys)
    if n < 2:
        return 0.0
    mean_y = sum(ys) / n
    ss_tot = sum((y - mean_y) ** 2 for y in ys)
    if ss_tot == 0:
        return 1.0  # flat line, perfectly explained
    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, ys))
    return max(0.0, 1.0 - ss_res / ss_tot)


def linear_fit(xs, ys):
    """Ordinary least-squares slope + intercept for y = slope*x + intercept.

    Returns (slope, intercept). Returns (0.0, mean) when the points are
    degenerate (fewer than two, or all x identical)."""
    n = len(xs)
    if n < 2:
        return 0.0, (ys[0] if ys else 0.0)
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    denom = sum((x - mean_x) ** 2 for x in xs)
    if denom == 0:
        return 0.0, mean_y
    slope = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys)) / denom
    intercept = mean_y - slope * mean_x
    return slope, intercept


def forecast_mounts(samples, min_points=3, exclude=None, min_r2=_MIN_R2):
    """Project days-until-full for every mount with a rising trend.

    Fits used_gb against time (in days) and extrapolates to the mount's
    capacity. Returns a list of dicts, one per mount, sorted soonest-to-fill
    first; mounts that are flat or shrinking get days_to_full = None.

        {path, current_gb, total_gb, current_percent,
         trend_gb_per_day, days_to_full, fill_date_ts, points, noisy, r2}

    v3.4.2: ephemeral mounts (`exclude`, default VOLATILE_MOUNTS — /tmp, /run,
    /dev/shm, …) are dropped entirely; a linear fill date over a sawtoothing
    tmpfs is meaningless. For the mounts that remain, a fill date is only
    reported when the least-squares fit is reasonably clean (R² ≥ min_r2);
    a noisy/fluctuating trend keeps the row (current usage is still useful) but
    sets days_to_full = None and noisy = True instead of inventing a date.
    """
    if not samples:
        return []
    exclude = VOLATILE_MOUNTS if exclude is None else tuple(exclude)

    # Gather a per-mount time series: {path: [(ts, used_gb, total_gb), ...]}.
    series = {}
    for s in samples:
        ts = s.get('ts')
        if not isinstance(ts, (int, float)):
            continue
        for m in s.get('mounts') or []:
            path = m.get('path')
            used = m.get('used_gb')
            total = m.get('total_gb')
            if not path or not isinstance(used, (int, float)) or not isinstance(total, (int, float)):
                continue
            if _is_volatile_mount(path, exclude):
                continue   # v3.4.2: skip ephemeral / tmpfs-style mounts
            series.setdefault(path, []).append((ts, float(used), float(total)))

    # Collapse mounts that are the SAME underlying filesystem. btrfs subvolumes
    # (/, /home, /var/log, /srv, …), bind mounts and the like all report identical
    # used_gb/total_gb at every sample, so projecting each mountpoint separately
    # just prints the same disk five times. Group by the latest (used_gb,
    # total_gb) signature and keep one representative mount per filesystem —
    # prefer '/', else the shallowest/shortest path. The collapsed mountpoints are
    # preserved on the row as `shared_mounts` so the UI can still show them.
    def _sig(pts):
        last = max(pts, key=lambda p: p[0])
        return (round(last[1], 2), round(last[2], 2))

    fs_groups = {}
    for path, pts in series.items():
        fs_groups.setdefault(_sig(pts), []).append(path)
    shared = {}
    for paths in fs_groups.values():
        rep = '/' if '/' in paths else sorted(paths, key=lambda p: (p.count('/'), len(p), p))[0]
        shared[rep] = sorted(paths)
    series = {rep: series[rep] for rep in shared}

    out = []
    for path, pts in series.items():
        if len(pts) < min_points:
            continue
        pts.sort(key=lambda p: p[0])
        t0 = pts[0][0]
        xs = [(t - t0) / DAY for t, _u, _tot in pts]
        ys = [u for _t, u, _tot in pts]
        total = pts[-1][2]
        cur = pts[-1][1]
        slope, intercept = linear_fit(xs, ys)  # GB per day, full window
        r2 = _r_squared(xs, ys, slope, intercept)

        # v3.8.0: re-fit over just the recent window so a stale spike earlier in
        # the window can't keep projecting a fill after growth has stopped.
        recent_slope = None
        latest_ts = pts[-1][0]
        recent = [(t, u) for t, u, _tot in pts if t >= latest_ts - _RECENT_WINDOW_DAYS * DAY]
        if len(recent) >= 2 and (recent[-1][0] - recent[0][0]) >= 0.5 * DAY:
            r_t0 = recent[0][0]
            recent_slope, _ri = linear_fit([(t - r_t0) / DAY for t, _u in recent],
                                           [u for _t, u in recent])

        # "Growth stopped" iff we have a trustworthy recent read and it has
        # flattened/reversed while the long-run trend still points up.
        stalled = (recent_slope is not None and recent_slope <= _CLIMB_FLOOR
                   and slope > _CLIMB_FLOOR)

        days_to_full = None
        fill_ts = None
        noisy = False
        beyond_horizon = False
        # Only forecast a fill when usage is genuinely climbing (>1 MB/day),
        # there's headroom left, and recent growth hasn't stalled.
        if slope > _CLIMB_FLOOR and total > cur and not stalled:
            if r2 >= min_r2:
                # Project from whichever rate is current: if the recent window is
                # trustworthy and slower than the long-run trend (decelerating),
                # use it — it gives a realistic horizon instead of an alarmist one.
                proj_slope = slope
                if recent_slope is not None and _CLIMB_FLOOR < recent_slope < slope:
                    proj_slope = recent_slope
                d2f = (total - cur) / proj_slope
                if d2f <= _FORECAST_HORIZON_DAYS:
                    days_to_full = d2f
                    fill_ts = int(pts[-1][0] + d2f * DAY)
                else:
                    # Fills, but so far out (>2y) it isn't an actionable risk —
                    # keep the row (current usage is useful), drop the date.
                    beyond_horizon = True
            else:
                # v3.4.2: trend too noisy to trust a date — show the row, skip
                # the (misleading) projection. e.g. a disk that fluctuates heavily.
                noisy = True

        out.append({
            'path':             path,
            'current_gb':       round(cur, 2),
            'total_gb':         round(total, 2),
            'current_percent':  round(100.0 * cur / total, 1) if total else 0.0,
            'trend_gb_per_day': round(slope, 3),
            # Recent-window rate (last _RECENT_WINDOW_DAYS); None if too few
            # recent points. `stalled` = long-run trend is up but recent growth
            # has flattened/reversed, so no fill date is projected.
            'recent_gb_per_day': round(recent_slope, 3) if recent_slope is not None else None,
            'stalled':          stalled,
            'days_to_full':     round(days_to_full, 1) if days_to_full is not None else None,
            'fill_date_ts':     fill_ts,
            'noisy':            noisy,
            'beyond_horizon':   beyond_horizon,
            # Other mountpoints on the same filesystem that were collapsed into
            # this row (btrfs subvolumes, bind mounts) — same disk, shown once.
            'shared_mounts':    shared.get(path, [path]),
            'r2':               round(r2, 2),
            'points':           len(pts),
            # Chartable raw series + fitted line (v3.4.0 Forecast page). `series`
            # is the observed samples as [unix_ts, used_gb]; the least-squares
            # line is y = slope*(days since t0_ts) + intercept — enough to draw a
            # scatter + trend line and extrapolate to capacity.
            'series':           [[int(t), round(u, 2)] for t, u, _tot in pts],
            'slope':            round(slope, 5),
            'intercept':        round(intercept, 3),
            't0_ts':            int(t0),
        })

    # Soonest-to-fill first; never-fills (None) sink to the bottom.
    out.sort(key=lambda r: (r['days_to_full'] is None, r['days_to_full'] or 0))
    return out


def _sample_on_or_before(samples, target_ts):
    """Return the latest sample whose ts <= target_ts, or the earliest sample
    if none predates the target (so a short history still yields a baseline)."""
    chosen = None
    for s in samples:
        ts = s.get('ts')
        if not isinstance(ts, (int, float)):
            continue
        if ts <= target_ts:
            if chosen is None or ts > chosen.get('ts', 0):
                chosen = s
    if chosen is None and samples:
        chosen = min(samples, key=lambda s: s.get('ts', 0))
    return chosen


def what_changed(samples, since_days, now):
    """Diff the device's state fingerprint between `since_days` ago and now.

    Returns a structured diff plus a list of human-readable bullet strings:

        {baseline_date, latest_date, changes: [...], detail: {...}}

    `changes` is empty when nothing tracked changed in the window.
    """
    if not samples:
        return {'baseline_date': None, 'latest_date': None,
                'changes': [], 'detail': {}}

    latest = max(samples, key=lambda s: s.get('ts', 0))
    baseline = _sample_on_or_before(samples, now - since_days * DAY)
    if baseline is None or baseline is latest:
        return {'baseline_date': latest.get('date'),
                'latest_date': latest.get('date'),
                'changes': [], 'detail': {}}

    b = baseline.get('state') or {}
    l = latest.get('state') or {}
    changes = []
    detail = {}

    # Packages
    bp, lp = b.get('pkg_upgradable'), l.get('pkg_upgradable')
    if isinstance(bp, int) and isinstance(lp, int) and bp != lp:
        delta = lp - bp
        detail['pkg_upgradable'] = {'from': bp, 'to': lp, 'delta': delta}
        changes.append(
            f"Pending updates {'rose' if delta > 0 else 'fell'} "
            f"{bp} → {lp} ({'+' if delta > 0 else ''}{delta}).")

    # Listening ports
    bports, lports = set(b.get('ports') or []), set(l.get('ports') or [])
    opened = sorted(lports - bports)
    closed = sorted(bports - lports)
    if opened:
        detail['ports_opened'] = opened
        changes.append("Newly listening: " + ", ".join(opened) + ".")
    if closed:
        detail['ports_closed'] = closed
        changes.append("No longer listening: " + ", ".join(closed) + ".")

    # Reboot-required edge
    if bool(b.get('reboot_required')) != bool(l.get('reboot_required')):
        now_req = bool(l.get('reboot_required'))
        detail['reboot_required'] = now_req
        changes.append("Reboot now required." if now_req
                       else "Reboot no longer required (rebooted).")

    # Failed units
    bfu, lfu = set(b.get('failed_units') or []), set(l.get('failed_units') or [])
    newly_failed = sorted(lfu - bfu)
    recovered = sorted(bfu - lfu)
    if newly_failed:
        detail['units_failed'] = newly_failed
        changes.append("Units newly failed: " + ", ".join(newly_failed) + ".")
    if recovered:
        detail['units_recovered'] = recovered
        changes.append("Units recovered: " + ", ".join(recovered) + ".")

    # Disk growth over the window (per mount).
    bmounts = {m.get('path'): m.get('used_gb') for m in (baseline.get('mounts') or [])}
    growth = []
    for m in latest.get('mounts') or []:
        path = m.get('path')
        old = bmounts.get(path)
        new = m.get('used_gb')
        if isinstance(old, (int, float)) and isinstance(new, (int, float)):
            d = round(new - old, 2)
            if abs(d) >= 0.5:   # ignore sub-500MB noise
                growth.append({'path': path, 'delta_gb': d})
    if growth:
        detail['disk_growth'] = growth
        for g in growth:
            changes.append(
                f"{g['path']} {'grew' if g['delta_gb'] > 0 else 'shrank'} "
                f"{abs(g['delta_gb'])} GB.")

    return {
        'baseline_date': baseline.get('date'),
        'latest_date':   latest.get('date'),
        'changes':       changes,
        'detail':        detail,
    }
