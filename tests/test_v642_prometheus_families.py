"""The v6.4.2 /api/metrics families: temperature, SMART, UPS, backup freshness,
disk-fill ETA, risk, reliability and compliance.

These signals all drove the product's own UI already, but none of them reached
the exporter — a Grafana user could not alert on a failing drive or a stale
backup from RemotePower's own metrics. Every test here CALLS generate_metrics()
with a seeded context and parses the exposition it returns; nothing asserts on
the source text, because a substring proves the line exists and never that it
works.
"""

import importlib.util
import math
import re
import unittest
from pathlib import Path

_CGI = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"

_spec = importlib.util.spec_from_file_location(
    "prometheus_export_v642", _CGI / "prometheus_export.py")
prometheus_export = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(prometheus_export)


# Prometheus metric-name grammar (a name outside this is silently unscrapeable).
_NAME_RE = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")
_SAMPLE_RE = re.compile(r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?P<labels>\{.*\})? "
                        r"(?P<value>\S+)$")

NEW_FAMILIES = (
    "remotepower_device_temperature_celsius",
    "remotepower_device_temperature_max_celsius",
    "remotepower_device_smart_disk_healthy",
    "remotepower_device_smart_disks_failed",
    "remotepower_device_smart_reallocated_sectors",
    "remotepower_device_smart_pending_sectors",
    "remotepower_device_smart_power_on_seconds",
    "remotepower_device_smart_wear_ratio",
    "remotepower_device_smart_spare_ratio",
    "remotepower_ups_on_battery",
    "remotepower_ups_battery_charge_ratio",
    "remotepower_ups_load_ratio",
    "remotepower_ups_runtime_seconds",
    "remotepower_ups_input_volts",
    "remotepower_ups_power_watts",
    "remotepower_backup_ok",
    "remotepower_backup_age_seconds",
    "remotepower_backup_max_age_seconds",
    "remotepower_device_disk_fill_eta_seconds",
    "remotepower_device_risk_score",
    "remotepower_risk_devices",
    "remotepower_device_reliability_score",
    "remotepower_reliability_devices",
    "remotepower_compliance_pass_ratio",
    "remotepower_compliance_devices_evaluated",
    "remotepower_device_compliance_pass_ratio",
    "remotepower_compliance_check_devices",
)

NOW = 1_800_000_000


def _base_ctx(**over):
    """The minimum context the pre-v6.4.2 exporter has always required."""
    ctx = {
        "server_version": "6.4.2",
        "now": NOW,
        "online_ttl": 180,
        "devices": {
            "abc123": {"name": "web-1", "group": "prod", "last_seen": NOW,
                       "sysinfo": {"cpu_percent": 12}},
            "def456": {"name": "nas-1", "group": "lab", "last_seen": NOW - 9000,
                       "sysinfo": {"cpu_percent": 3}},
        },
        "monitors": [],
        "monitor_state": {},
        "schedule": [],
        "pending_cmds": {},
        "webhook_log": [],
        "webhook_log_cap": 500,
        "cve_findings": {},
        "cve_ignore": {},
    }
    ctx.update(over)
    return ctx


def _full_ctx(**over):
    ctx = _base_ctx(
        hardware={
            "abc123": {
                "hardware": {"temps": [{"label": "Package id 0", "current_c": 61.5},
                                       {"label": "Package id 0", "current_c": 58.0}]},
                "smart": [{"device": "/dev/sda", "model": "Samsung 870",
                           "health": "PASSED", "failed": False,
                           "reallocated_sectors": 0, "pending_sectors": 0,
                           "power_on_hours": 10000, "wear_pct": 12,
                           "spare_pct": 99, "temperature_c": 35},
                          {"device": "/dev/sdb", "model": "WD Red",
                           "health": "FAILED", "failed": True,
                           "reallocated_sectors": 240, "pending_sectors": 8,
                           "power_on_hours": 42000}],
                "gpus": [{"name": "RTX 3060", "temp_c": 72}],
                "ups": [{"name": "eaton5px", "status": "OB DISCHRG",
                         "battery_pct": 45, "load_pct": 30, "runtime_s": 900,
                         "input_v": 0, "power_w": 210}],
            },
            "def456": {
                "hardware": {"temps": [{"label": "acpitz", "current_c": 40}]},
                "ups": [{"name": "apc900", "status": "OL",
                         "battery_pct": 100, "load_pct": 12}],
            },
        },
        backup_state={
            "abc123:/srv/backups": {"ok": False, "age_h": 96},
            "def456:/mnt/tank/backups": {"ok": True, "age_h": 3},
        },
        backup_monitors=[{"path": "/srv/backups", "label": "web dumps",
                          "max_age_hours": 24}],
        disk_fill_eta={"def456": 4.5},
        risk=[{"device_id": "abc123", "device_name": "web-1", "score": 82,
               "level": "critical", "factors": []},
              {"device_id": "def456", "device_name": "nas-1", "score": 11,
               "level": "low", "factors": []}],
        reliability=[{"device_id": "abc123", "name": "web-1", "score": 74,
                      "level": "critical", "factors": []},
                     {"device_id": "def456", "name": "nas-1", "score": 5,
                      "level": "low", "factors": []}],
        compliance={
            "generated_ts": NOW, "score": 78, "devices_evaluated": 2,
            "checks": [{"id": "cis-1.1", "title": "no root ssh",
                        "severity": "high", "pass": 1, "fail": 1, "na": 0,
                        "failing": ["web-1"]},
                       {"id": "cis-2.4", "title": "firewall on",
                        "severity": "medium", "pass": 2, "fail": 0, "na": 0,
                        "failing": []}],
            "devices": [{"device_id": "abc123", "name": "web-1", "group": "prod",
                         "passed": 1, "applicable": 2, "pct": 50, "fails": ["cis-1.1"]},
                        {"device_id": "def456", "name": "nas-1", "group": "lab",
                         "passed": 2, "applicable": 2, "pct": 100, "fails": []}],
        },
    )
    ctx.update(over)
    return ctx


def _parse(text):
    """(families, samples): {name: type} from the HELP/TYPE headers, and a list
    of (name, labels dict, float value) for every sample line."""
    helps, types, samples = {}, {}, []
    for line in text.splitlines():
        if not line.strip():
            continue
        if line.startswith("# HELP "):
            name, _, doc = line[len("# HELP "):].partition(" ")
            helps.setdefault(name, []).append(doc)
            continue
        if line.startswith("# TYPE "):
            name, _, kind = line[len("# TYPE "):].partition(" ")
            types.setdefault(name, []).append(kind)
            continue
        if line.startswith("#"):
            continue
        m = _SAMPLE_RE.match(line)
        assert m, f"unparseable exposition line: {line!r}"
        labels = {}
        raw = m.group("labels")
        if raw:
            for pair in re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"',
                                   raw):
                labels[pair[0]] = pair[1]
        samples.append((m.group("name"), labels, float(m.group("value"))))
    return helps, types, samples


class _ExpositionCase(unittest.TestCase):
    def setUp(self):
        self.text = prometheus_export.generate_metrics(_full_ctx())
        self.helps, self.types, self.samples = _parse(self.text)

    def series(self, name):
        return [(lbl, val) for n, lbl, val in self.samples if n == name]

    def one(self, name, **match):
        hits = [(lbl, val) for lbl, val in self.series(name)
                if all(lbl.get(k) == v for k, v in match.items())]
        self.assertEqual(len(hits), 1,
                         f"expected exactly one {name}{match}, got {hits}")
        return hits[0][1]


class TestEveryNewFamilyIsDeclared(_ExpositionCase):
    def test_help_and_type_present(self):
        missing = [n for n in NEW_FAMILIES
                   if n not in self.helps or n not in self.types]
        self.assertEqual(missing, [],
                         "families emitted without a HELP/TYPE header: "
                         + ", ".join(missing))

    def test_headers_are_not_duplicated(self):
        # A repeated HELP/TYPE for one family makes Prometheus reject the whole
        # scrape, and is what happens when a family is emitted from two loops.
        dupes = sorted(n for n, v in self.helps.items() if len(v) > 1)
        dupes += sorted(n for n, v in self.types.items() if len(v) > 1)
        self.assertEqual(dupes, [], f"duplicate HELP/TYPE headers: {dupes}")

    def test_help_text_is_non_empty(self):
        blank = sorted(n for n in NEW_FAMILIES if not self.helps[n][0].strip())
        self.assertEqual(blank, [], f"families with an empty HELP: {blank}")

    def test_types_are_gauges(self):
        wrong = sorted(n for n in NEW_FAMILIES if self.types[n][0] != "gauge")
        self.assertEqual(wrong, [], f"not declared as gauges: {wrong}")

    def test_every_sample_belongs_to_a_declared_family(self):
        undeclared = sorted({n for n, _l, _v in self.samples
                             if n not in self.types})
        self.assertEqual(undeclared, [],
                         f"samples with no TYPE header: {undeclared}")


class TestNamingAndUnits(_ExpositionCase):
    def test_names_are_valid_and_prefixed(self):
        for name in NEW_FAMILIES:
            self.assertRegex(name, _NAME_RE, f"{name} is not a legal metric name")
            self.assertTrue(name.startswith("remotepower_"), name)
            self.assertEqual(name, name.lower(), f"{name} is not snake_case")

    def test_total_suffix_is_reserved_for_counters(self):
        # Everything added here is a gauge, so none of it may claim _total.
        bad = [n for n in NEW_FAMILIES if n.endswith("_total")]
        self.assertEqual(bad, [], f"gauges named as counters: {bad}")

    def test_base_units_not_percent(self):
        bad = [n for n in NEW_FAMILIES if n.endswith("_percent")]
        self.assertEqual(bad, [], f"new families must use base units: {bad}")

    def test_hours_are_exported_as_seconds(self):
        # store says age_h=96 and power_on_hours=42000
        self.assertEqual(
            self.one("remotepower_backup_age_seconds", device="abc123"),
            96 * 3600)
        self.assertEqual(
            self.one("remotepower_backup_max_age_seconds", device="abc123"),
            24 * 3600)
        self.assertEqual(
            self.one("remotepower_device_smart_power_on_seconds",
                     device="abc123", disk="/dev/sdb"),
            42000 * 3600)

    def test_days_are_exported_as_seconds(self):
        self.assertEqual(
            self.one("remotepower_device_disk_fill_eta_seconds", device="def456"),
            round(4.5 * 86400))

    def test_percentages_are_exported_as_ratios(self):
        for name, dev, extra, expect in (
            ("remotepower_device_smart_wear_ratio", "abc123",
             {"disk": "/dev/sda"}, 0.12),
            ("remotepower_device_smart_spare_ratio", "abc123",
             {"disk": "/dev/sda"}, 0.99),
            ("remotepower_ups_battery_charge_ratio", "abc123",
             {"ups": "eaton5px"}, 0.45),
            ("remotepower_ups_load_ratio", "abc123", {"ups": "eaton5px"}, 0.30),
            ("remotepower_device_compliance_pass_ratio", "abc123", {}, 0.50),
        ):
            got = self.one(name, device=dev, **extra)
            self.assertAlmostEqual(got, expect, places=4, msg=name)
        self.assertAlmostEqual(
            self.series("remotepower_compliance_pass_ratio")[0][1], 0.78, places=4)

    def test_no_sample_carries_nan_or_infinity(self):
        for name, _lbl, val in self.samples:
            self.assertTrue(math.isfinite(val), f"{name} emitted {val}")


class TestDeviceLabelVocabulary(_ExpositionCase):
    """Every per-device family must use the same `device`/`name`/`group`
    spelling the pre-existing families use, or none of them can be joined."""

    PER_DEVICE = tuple(n for n in NEW_FAMILIES
                       if n not in ("remotepower_risk_devices",
                                    "remotepower_reliability_devices",
                                    "remotepower_compliance_pass_ratio",
                                    "remotepower_compliance_devices_evaluated",
                                    "remotepower_compliance_check_devices"))

    def test_device_label_is_the_device_id(self):
        ids = set(_full_ctx()["devices"])
        for name in self.PER_DEVICE:
            series = self.series(name)
            self.assertTrue(series, f"{name} produced no samples from the seed")
            for lbl, _val in series:
                self.assertIn("device", lbl, f"{name} has no device label")
                self.assertIn(lbl["device"], ids,
                              f"{name} labelled device={lbl['device']!r}, "
                              "which is not a device id")

    def test_name_label_is_the_display_name(self):
        for name in self.PER_DEVICE:
            for lbl, _val in self.series(name):
                if lbl["device"] == "abc123":
                    self.assertEqual(lbl.get("name"), "web-1", name)
                    self.assertEqual(lbl.get("group"), "prod", name)

    def test_no_alternate_device_label_spelling(self):
        for name, lbl, _val in self.samples:
            for alias in ("device_id", "host", "hostname", "dev"):
                self.assertNotIn(alias, lbl,
                                 f"{name} invented a second device label spelling")

    def test_series_identities_are_unique(self):
        seen = {}
        for name, lbl, _val in self.samples:
            key = (name, tuple(sorted(lbl.items())))
            self.assertNotIn(key, seen,
                             f"duplicate series {name}{lbl} — Prometheus drops "
                             "one of the samples")
            seen[key] = True


class TestValuesComeFromTheStores(_ExpositionCase):
    def test_temperatures_cover_board_disk_and_gpu(self):
        sensors = {lbl["sensor"]: val
                   for lbl, val in self.series("remotepower_device_temperature_celsius")
                   if lbl["device"] == "abc123"}
        self.assertEqual(sensors.get("Package id 0"), 61.5)
        # a repeated sensor label must not silently collapse into one series
        self.assertEqual(sensors.get("Package id 0 #2"), 58.0)
        self.assertEqual(sensors.get("disk:/dev/sda"), 35.0)
        self.assertEqual(sensors.get("gpu:RTX 3060"), 72.0)

    def test_max_temperature_is_the_hottest_across_sources(self):
        self.assertEqual(
            self.one("remotepower_device_temperature_max_celsius", device="abc123"),
            72.0)
        self.assertEqual(
            self.one("remotepower_device_temperature_max_celsius", device="def456"),
            40.0)

    def test_smart_health_follows_the_persisted_verdict(self):
        self.assertEqual(self.one("remotepower_device_smart_disk_healthy",
                                  device="abc123", disk="/dev/sda"), 1.0)
        self.assertEqual(self.one("remotepower_device_smart_disk_healthy",
                                  device="abc123", disk="/dev/sdb"), 0.0)
        self.assertEqual(self.one("remotepower_device_smart_disks_failed",
                                  device="abc123"), 1.0)

    def test_ups_on_battery_matches_the_status_flags(self):
        self.assertEqual(self.one("remotepower_ups_on_battery",
                                  device="abc123", ups="eaton5px"), 1.0)
        self.assertEqual(self.one("remotepower_ups_on_battery",
                                  device="def456", ups="apc900"), 0.0)

    def test_backup_rows_are_split_per_device(self):
        # backup_state.json is keyed '<device>:<path>' — reading it unsplit
        # hands every host every other host's rows.
        rows = {(lbl["device"], lbl["path"]): val
                for lbl, val in self.series("remotepower_backup_ok")}
        self.assertEqual(rows, {("abc123", "/srv/backups"): 0.0,
                                ("def456", "/mnt/tank/backups"): 1.0})

    def test_backup_threshold_only_for_configured_paths(self):
        paths = {lbl["path"] for lbl, _v
                 in self.series("remotepower_backup_max_age_seconds")}
        self.assertEqual(paths, {"/srv/backups"},
                         "a threshold was invented for an unconfigured path")

    def test_risk_and_reliability_scores_and_rollups(self):
        self.assertEqual(self.one("remotepower_device_risk_score",
                                  device="abc123"), 82.0)
        self.assertEqual(self.one("remotepower_device_reliability_score",
                                  device="abc123"), 74.0)
        for fam in ("remotepower_risk_devices", "remotepower_reliability_devices"):
            counts = {lbl["level"]: val for lbl, val in self.series(fam)}
            self.assertEqual(counts,
                             {"low": 1.0, "medium": 0.0, "high": 0.0,
                              "critical": 1.0}, fam)

    def test_compliance_per_check_outcomes(self):
        rows = {(lbl["check"], lbl["result"]): val
                for lbl, val in self.series("remotepower_compliance_check_devices")}
        self.assertEqual(rows[("cis-1.1", "pass")], 1.0)
        self.assertEqual(rows[("cis-1.1", "fail")], 1.0)
        self.assertEqual(rows[("cis-1.1", "na")], 0.0)
        sev = {lbl["check"]: lbl["severity"] for lbl, _v
               in self.series("remotepower_compliance_check_devices")}
        self.assertEqual(sev["cis-1.1"], "high")

    def test_devices_evaluated_is_an_integer_sample(self):
        line = [ln for ln in self.text.splitlines()
                if ln.startswith("remotepower_compliance_devices_evaluated ")]
        self.assertEqual(line, ["remotepower_compliance_devices_evaluated 2"])


class TestBackwardCompatibility(unittest.TestCase):
    def test_a_context_without_the_new_stores_still_renders(self):
        text = prometheus_export.generate_metrics(_base_ctx())
        helps, types, samples = _parse(text)
        self.assertIn("remotepower_devices_total", types)
        for name in NEW_FAMILIES:
            self.assertNotIn(name, helps,
                             f"{name} was declared without its backing store")
        self.assertTrue(samples)

    def test_trailing_newline_is_preserved(self):
        self.assertTrue(prometheus_export.generate_metrics(_full_ctx())
                        .endswith("\n"))


class TestMalformedRowsAreSkippedNotRaised(unittest.TestCase):
    """A single corrupt record must never break the scrape for the fleet."""

    def _render(self, **over):
        return prometheus_export.generate_metrics(_full_ctx(**over))

    def test_stores_supplied_as_lists(self):
        # These stores are loaded with `load(FILE) or {}` and can come back as a
        # list on a hand-edited/legacy store.
        text = self._render(
            hardware=[{"device_id": "abc123",
                       "hardware": {"temps": [{"label": "cpu", "current_c": 50}]},
                       "smart": [{"device": "/dev/sda", "failed": False}],
                       "ups": [{"name": "u1", "status": "OL"}]}],
            backup_state=[],
            compliance={"score": 50, "devices": [], "checks": []})
        _h, _t, samples = _parse(text)
        temps = [v for n, lbl, v in samples
                 if n == "remotepower_device_temperature_celsius"
                 and lbl.get("device") == "abc123"]
        self.assertEqual(temps, [50.0])

    def test_non_dict_rows_inside_each_store(self):
        text = self._render(
            hardware={"abc123": {"hardware": {"temps": ["nope", 7, None,
                                                        {"label": "cpu",
                                                         "current_c": 44}]},
                                 "smart": ["nope", None,
                                           {"device": "/dev/sda", "failed": True}],
                                 "gpus": "not-a-list",
                                 "ups": [None, 3, {"name": "u1", "status": "OB"}]},
                      "def456": "this whole record is junk"},
            backup_state={"abc123:/srv/b": None, "nocolon": {"ok": True},
                          "def456:/mnt/b": {"ok": True, "age_h": "12"}},
            risk=[{"device_id": "abc123", "score": "NaN", "level": "critical"},
                  "junk", {"no_device_id": 1}],
            reliability={"abc123": {"device_id": "abc123", "score": 5,
                                    "level": "low"}},
            compliance={"score": None, "devices_evaluated": "2",
                        "devices": ["junk", {"device_id": "abc123", "pct": None},
                                    {"device_id": "def456", "pct": 100}],
                        "checks": ["junk", {"severity": "high"},
                                   {"id": "cis-1.1", "severity": "high",
                                    "pass": 1, "fail": "x", "na": 0}]})
        helps, types, samples = _parse(text)
        by_name = {}
        for n, lbl, v in samples:
            by_name.setdefault(n, []).append((lbl, v))
        # the good rows survived …
        self.assertEqual(
            [v for lbl, v in by_name["remotepower_device_temperature_celsius"]],
            [44.0])
        self.assertEqual(
            [lbl["ups"] for lbl, _v in by_name["remotepower_ups_on_battery"]],
            ["u1"])
        # … the junk ones produced no samples at all
        self.assertNotIn("remotepower_compliance_pass_ratio", helps)
        self.assertEqual(by_name.get("remotepower_device_risk_score"), None)
        self.assertEqual(
            [lbl["device"] for lbl, _v
             in by_name["remotepower_device_compliance_pass_ratio"]], ["def456"])
        # a numeric string in the store is still a usable sample
        self.assertEqual(
            [v for lbl, v in by_name["remotepower_backup_age_seconds"]],
            [12 * 3600])
        # every declared family still has a TYPE, so the payload stays valid
        self.assertEqual(sorted(set(helps)), sorted(set(types)))

    def test_hostile_label_values_are_escaped(self):
        text = self._render(hardware={
            "abc123": {"hardware": {"temps": [
                {"label": 'a"b\\c\nd', "current_c": 30}]}}})
        line = [ln for ln in text.splitlines()
                if ln.startswith("remotepower_device_temperature_celsius{")]
        self.assertEqual(len(line), 1)
        self.assertIn(r'sensor="a\"b\\c\nd"', line[0])
        _h, _t, samples = _parse(text)   # still parses as one sample line
        self.assertTrue(samples)

    def test_generate_metrics_never_raises_on_junk_stores(self):
        for junk in (None, 0, "", [], {}, "string", 12, [1, 2, 3]):
            for key in ("hardware", "backup_state", "backup_monitors",
                        "disk_fill_eta", "risk", "reliability", "compliance"):
                out = prometheus_export.generate_metrics(_full_ctx(**{key: junk}))
                self.assertIn("remotepower_info", out, f"{key}={junk!r}")
                _parse(out)   # asserts every emitted line is parseable


if __name__ == "__main__":
    unittest.main()
