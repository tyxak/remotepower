"""docs/prometheus-metrics-sample.txt must track the live exporter.

The sample sat at v1.8.0 (19 of 30 metrics) for years because nothing tied it
to the code. tools/gen-prometheus-sample.py regenerates it from the real
generate_metrics(); these pins catch both drift directions cheaply:
  - every metric NAME in the sample still exists in prometheus_export.py
    (a renamed/removed gauge makes the sample a lie), and
  - the must-have families are present (a new headline gauge that the
    generator's seed doesn't exercise means the seed needs extending).
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_SAMPLE = ROOT / "docs" / "prometheus-metrics-sample.txt"
_EXPORTER = ROOT / "server" / "cgi-bin" / "prometheus_export.py"

MUST_HAVE = (
    "remotepower_info",
    "remotepower_devices_total",
    "remotepower_device_online",
    "remotepower_fleet_health_score",
    "remotepower_monitor_availability_percent",
    "remotepower_slo_target_percent",
    "remotepower_slo_object_target_percent",
    "remotepower_slo_object_availability_percent",
    "remotepower_slo_object_budget_remaining_percent",
)


class TestSampleTracksExporter(unittest.TestCase):
    def setUp(self):
        if not _SAMPLE.exists():
            self.skipTest("sample excluded from this tree")
        self.sample = _SAMPLE.read_text()
        self.exporter_src = _EXPORTER.read_text()

    def test_generated_by_the_tool(self):
        self.assertIn("tools/gen-prometheus-sample.py", self.sample,
                      "sample lost its generated-by header — regenerate with "
                      "the tool, don't hand-edit")

    def test_no_stale_metric_names(self):
        stale = sorted({
            n for n in re.findall(r"^# HELP (remotepower_\w+)", self.sample,
                                  re.M)
            if n not in self.exporter_src})
        self.assertEqual(stale, [],
                         "sample documents metrics the exporter no longer "
                         "emits — regenerate: python3 "
                         "tools/gen-prometheus-sample.py\n  "
                         + "\n  ".join(stale))

    def test_must_have_families_present(self):
        missing = sorted(n for n in MUST_HAVE
                         if f"# HELP {n}" not in self.sample)
        self.assertEqual(missing, [],
                         "headline gauges missing from the sample — extend "
                         "the generator seed and regenerate:\n  "
                         + "\n  ".join(missing))


if __name__ == "__main__":
    unittest.main()
