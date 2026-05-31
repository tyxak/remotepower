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
