#!/usr/bin/env python3
"""Regenerate docs/prometheus-metrics-sample.txt from the LIVE exporter.

The sample had drifted from v1.8.0 to v6.4.0 without anyone noticing (19 of 30
metrics, wrong version string) because it was hand-maintained. This drives the
real generate_metrics() over a small seeded fleet — two devices (one online),
one HTTP monitor with history, one SLA/SLO object — so every data-dependent
gauge family fires.

Run from the repo root after adding/renaming a gauge:
    python3 tools/gen-prometheus-sample.py
tests/test_prometheus_sample.py fails when the sample references a metric the
exporter no longer emits, or is missing a must-have family.
"""
import importlib.util
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / 'server' / 'cgi-bin'
os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-promsample-')
sys.path.insert(0, str(CGI))

_spec = importlib.util.spec_from_file_location('api_promsample', CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
import prometheus_export  # noqa: E402

HEADER = (
    "# Sample GET /api/metrics output (Prometheus text exposition), generated\n"
    "# by tools/gen-prometheus-sample.py from a two-device fleet with one HTTP\n"
    "# monitor attached to one SLA/SLO object. Regenerate after adding gauges:\n"
    "# the exporter is server/cgi-bin/prometheus_export.py.\n"
)


def main():
    now = int(time.time())
    api.save(api.DEVICES_FILE, {
        'abc123': {'name': 'web-1', 'ip': '10.0.0.11', 'group': 'prod',
                   'last_seen': now, 'token': 't',
                   'sysinfo': {'os': 'Debian 12', 'cpu_percent': 12,
                               'mem_percent': 43, 'disk_percent': 61}},
        'def456': {'name': 'nas-1', 'ip': '10.0.0.12', 'group': 'lab',
                   'last_seen': now - 7200, 'token': 't',
                   'sysinfo': {'os': 'TrueNAS', 'cpu_percent': 3,
                               'mem_percent': 70, 'disk_percent': 82}},
    })
    cfg = api.load(api.CONFIG_FILE) or {}
    cfg['monitors'] = [{'label': 'website', 'type': 'http',
                        'target': 'https://example.com/',
                        'slo_ids': ['slo-web']}]
    cfg['slo_objects'] = [{'id': 'slo-web', 'name': 'Public web',
                           'target_pct': 99.9, 'window_days': 30}]
    api.save(api.CONFIG_FILE, cfg)
    api.save(api.MON_HIST_FILE, {'website': [
        {'ts': now - i * 300, 'ok': i != 3, 'ms': 42} for i in range(200)]})
    api._LOAD_CACHE.clear()
    txt = prometheus_export.generate_metrics(api._build_metrics_ctx())
    out = ROOT / 'docs' / 'prometheus-metrics-sample.txt'
    out.write_text(HEADER + txt)
    metrics = sum(1 for line in txt.splitlines() if line.startswith('# HELP'))
    print(f'wrote {out} ({metrics} metrics, {len(txt.splitlines())} lines)')


if __name__ == '__main__':
    main()
