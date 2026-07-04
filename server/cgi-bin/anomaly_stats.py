"""v3.4.2: per-host, per-metric statistical anomaly detection.

A pure, dependency-free complement to the AI anomaly scan. It fits a baseline
(mean + standard deviation) over a device's historical metric samples and flags
the latest value when it deviates more than `z` standard deviations from that
baseline. No model, no network — just the daily metrics history RemotePower
already keeps for forecasting.

Designed to be trivially unit-testable: the only input is the `samples` list
from metrics_history.json (each `{date, ts, mounts:[{percent}], mem_percent,
swap_percent, ...}`).
"""
import statistics

DEFAULT_Z = 2.5
MIN_SAMPLES = 7          # need a real baseline before calling anything anomalous
# Floor on the standard deviation (in percentage points). A perfectly flat
# baseline has stdev 0 → an undefined z-score; flooring it means a sharp jump
# off a flat line (the clearest anomaly there is) still flags, while tiny blips
# stay below threshold.
STDEV_FLOOR = 1.0

# Metric key → human label. 'disk_percent' is derived (busiest mount per sample).
METRICS = (
    ('mem_percent',  'Memory %'),
    ('swap_percent', 'Swap %'),
    ('disk_percent', 'Disk % (busiest mount)'),
)


def _series(samples, key):
    """Numeric series for one metric across samples (skips missing values)."""
    out = []
    for s in samples or []:
        if key == 'disk_percent':
            vals = [m.get('percent') for m in (s.get('mounts') or [])
                    if isinstance(m.get('percent'), (int, float))]
            v = max(vals) if vals else None
        else:
            v = s.get(key)
        if isinstance(v, (int, float)):
            out.append(float(v))
    return out


# W4-18: seasonality. Bucket prior samples by (weekday, 4-hour block) so a
# recurring Monday-morning batch spike isn't flagged against a flat all-week
# baseline. Need a warm-up before trusting the finer buckets, and a per-bucket
# minimum before using it (else fall back to the flat baseline for that metric).
import time as _time

SEASONAL_WARMUP = 14        # total samples (≈2 weeks daily) before seasonal kicks in
SEASONAL_MIN_BUCKET = 4     # samples in the matching bucket before it's trusted
_DOW = ('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun')


def _bucket_of(ts):
    """(weekday 0-6, 4-hour block 0-5) for a unix ts, in the server's localtime
    (the operator reads dashboards in localtime). None when ts is unusable."""
    if not isinstance(ts, (int, float)) or ts <= 0:
        return None
    lt = _time.localtime(ts)
    return (lt.tm_wday, lt.tm_hour // 4)


def _bucket_label(bucket):
    dow, blk = bucket
    return f'{_DOW[dow]} {blk * 4:02d}–{blk * 4 + 4:02d}'


def _seasonal_series(samples, key, target_bucket):
    """PRIOR-sample values (all but the last) whose (weekday, block) matches
    target_bucket. Pairs each sample's value with its own ts for bucketing."""
    out = []
    for s in (samples or [])[:-1]:
        if _bucket_of(s.get('ts')) != target_bucket:
            continue
        if key == 'disk_percent':
            vals = [m.get('percent') for m in (s.get('mounts') or [])
                    if isinstance(m.get('percent'), (int, float))]
            v = max(vals) if vals else None
        else:
            v = s.get(key)
        if isinstance(v, (int, float)):
            out.append(float(v))
    return out


def detect_device_seasonal(samples, z=DEFAULT_Z, min_samples=MIN_SAMPLES):
    """W4-18: like detect_device but scores the latest value against the
    mean/stdev of PRIOR samples in the SAME (weekday, 4-hour) bucket. Falls back
    to the flat baseline per-metric until there are SEASONAL_WARMUP samples total
    and SEASONAL_MIN_BUCKET in the matching bucket. Returns the same dicts, each
    tagged with `seasonal` (bool) and, when seasonal, a `bucket` label."""
    samples = samples or []
    if len(samples) < 2:
        return []
    target = _bucket_of((samples[-1] or {}).get('ts'))
    flat = {a['metric']: a for a in detect_device(samples, z=z, min_samples=min_samples)}
    if len(samples) < SEASONAL_WARMUP or target is None:
        for a in flat.values():
            a['seasonal'] = False
        return list(flat.values())
    out = []
    seen = set()
    for key, label in METRICS:
        latest_vals = _series([samples[-1]], key)
        if not latest_vals:
            continue
        bucket_series = _seasonal_series(samples, key, target)
        if len(bucket_series) < SEASONAL_MIN_BUCKET:
            if key in flat:                     # not enough seasonal data → flat verdict
                flat[key]['seasonal'] = False
                out.append(flat[key])
                seen.add(key)
            continue
        latest = latest_vals[-1]
        mean = statistics.fmean(bucket_series)
        stdev = max(statistics.pstdev(bucket_series), STDEV_FLOOR)
        zscore = (latest - mean) / stdev
        seen.add(key)
        if abs(zscore) >= z:
            out.append({
                'metric': key, 'label': label,
                'value': round(latest, 1), 'mean': round(mean, 1),
                'stdev': round(stdev, 2), 'z': round(zscore, 2),
                'direction': 'high' if zscore > 0 else 'low',
                'seasonal': True, 'bucket': _bucket_label(target),
            })
    # Any flat anomaly whose metric we didn't seasonally evaluate still surfaces.
    for key, a in flat.items():
        if key not in seen:
            a['seasonal'] = False
            out.append(a)
    return out


def detect_device(samples, z=DEFAULT_Z, min_samples=MIN_SAMPLES):
    """Anomalies for one device. Compares each metric's LATEST value against the
    mean/stdev of the PRIOR samples; flags when |z-score| >= z. Returns a list
    of {metric, label, value, mean, stdev, z, direction}."""
    anomalies = []
    for key, label in METRICS:
        series = _series(samples, key)
        if len(series) < min_samples + 1:
            continue
        latest, prior = series[-1], series[:-1]
        mean = statistics.fmean(prior)
        stdev = max(statistics.pstdev(prior), STDEV_FLOOR)
        zscore = (latest - mean) / stdev
        if abs(zscore) >= z:
            anomalies.append({
                'metric':    key,
                'label':     label,
                'value':     round(latest, 1),
                'mean':      round(mean, 1),
                'stdev':     round(stdev, 2),
                'z':         round(zscore, 2),
                'direction': 'high' if zscore > 0 else 'low',
            })
    return anomalies
