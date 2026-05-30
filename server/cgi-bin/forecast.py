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


def forecast_mounts(samples, min_points=3):
    """Project days-until-full for every mount with a rising trend.

    Fits used_gb against time (in days) and extrapolates to the mount's
    capacity. Returns a list of dicts, one per mount, sorted soonest-to-fill
    first; mounts that are flat or shrinking get days_to_full = None.

        {path, current_gb, total_gb, current_percent,
         trend_gb_per_day, days_to_full, fill_date_ts, points}
    """
    if not samples:
        return []

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
            series.setdefault(path, []).append((ts, float(used), float(total)))

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
        slope, intercept = linear_fit(xs, ys)  # GB per day

        days_to_full = None
        fill_ts = None
        # Only forecast a fill when usage is genuinely climbing (>1 MB/day)
        # and there's headroom left.
        if slope > 0.001 and total > cur:
            days_to_full = (total - cur) / slope
            fill_ts = int(pts[-1][0] + days_to_full * DAY)

        out.append({
            'path':             path,
            'current_gb':       round(cur, 2),
            'total_gb':         round(total, 2),
            'current_percent':  round(100.0 * cur / total, 1) if total else 0.0,
            'trend_gb_per_day': round(slope, 3),
            'days_to_full':     round(days_to_full, 1) if days_to_full is not None else None,
            'fill_date_ts':     fill_ts,
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
