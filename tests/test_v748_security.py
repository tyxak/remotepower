#!/usr/bin/env python3
"""v7.4.8 security pass: what a hostile or broken report can put where the new code reads it.

The release changes no route, no permission and no dependency. What is new is code that reads values a host sends (a
sensor's limit and label, the text `apt-get` prints) and a time the server stores. Each class below feeds that code what
a hostile host, an older agent or a hand edit can produce, through the real functions, and asks two things of every
value: it does not make the code fail, and what comes out is something the page can print.
"""
import importlib.machinery
import importlib.util
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import api  # noqa: E402
import prometheus_export  # noqa: E402
import srcpin  # noqa: E402

NOW = int(time.time())
NVME1 = "nvme-pci-0100/Sensor 1"
BOARD = "coretemp-isa-0000/Package id 0"

# A limit a host can send: not a number, not finite, or not a temperature. The first four of the last six are numbers JSON
# can carry and Python's float() cannot convert (10**400) or compares falsely (NaN).
LIMITS = [float("nan"), float("inf"), -float("inf"), 1e308, -1, 0, 0.5, 150.0001, 10 ** 400, -(10 ** 400),
          "80", "nan", "inf", True, False, None, [], [80], {}, {"v": 80}]
LABELS = [None, 5, [], {}, "", "x" * 100_000, "nvme-pci-0100/" + "y" * 100_000, " NVME-pci-0100/Sensor 1",
          "nvme-pci-0100/\x00\n‮", "drivetemp/", "/", "nvme", "../../etc/passwd", "<img src=x onerror=1>"]
READINGS = [float("nan"), float("inf"), 1e308, 10 ** 400, -300, "45", True, None, [], {}]
LINES = {"drivetemp_nvme_warn_c": 45, "drivetemp_nvme_crit_c": 50, "drivetemp_warn_c": 40, "drivetemp_crit_c": 45}


def name(value):
    return repr(value)[:30]


class _Fleet(unittest.TestCase):
    """One host, its hardware record, and the Thermal page and the risk score read from it."""

    def setUp(self):
        self._orig = {k: getattr(api, k) for k in ("require_auth", "_caller_scope", "_tenant_gate")}
        api.require_auth = lambda require_admin=False: "tester"
        api._caller_scope = lambda: None
        api._tenant_gate = lambda: None
        self.config(LINES)
        api.save(api.DEVICES_FILE, {})
        api.save(api.HARDWARE_FILE, {})

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(api, k, v)
        for f in (api.CONFIG_FILE, api.DEVICES_FILE, api.HARDWARE_FILE, api.THERMAL_HIST_FILE):
            api.save(f, {})
        api._LOAD_CACHE.clear()

    def config(self, cfg):
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()

    def ingest(self, temps):
        """What the server stores of a report: the list of sensors as written."""
        api.save(api.DEVICES_FILE, {"h1": {"name": "h1", "last_seen": NOW, "sysinfo": {}}})
        api._LOAD_CACHE.clear()
        api._ingest_hardware("h1", "h1", {"hardware": {"temps": temps}, "smart": []}, NOW,
                             dev=api.load(api.DEVICES_FILE)["h1"])
        api._LOAD_CACHE.clear()
        return api.load(api.HARDWARE_FILE)["h1"]["hardware"]["temps"]

    def stored(self, temps, smart=(), gpus=()):
        """A hardware record that holds these as they are: an older agent's report, a hand edit, an import."""
        api.save(api.DEVICES_FILE, {"h1": {"name": "h1", "last_seen": NOW, "sysinfo": {}}})
        api.save(api.HARDWARE_FILE, {"h1": {"ts": NOW, "smart": [dict(s) for s in smart], "gpus": [dict(g) for g in gpus],
                                            "hardware": {"temps": [dict(t) for t in temps]}}})
        api._LOAD_CACHE.clear()

    def read(self):
        """The Thermal page and the risk score, which must both answer, and the page must be strict JSON. Returns the row."""
        try:
            api.handle_fleet_thermal()
        except api.HTTPError as e:
            page = e.body
        else:
            self.fail("no answer")
        json.dumps(page, allow_nan=False)
        dev, hw = api.load(api.DEVICES_FILE)["h1"], api.load(api.HARDWARE_FILE)["h1"]
        api._device_risk("h1", dev, {}, {}, {}, NOW, 300, hw_rec=hw)
        rows = [r for r in page["hosts"] if r["device_id"] == "h1"]
        return rows[0] if rows else None


class TestAHostileSensorReport(_Fleet):

    def test_no_limit_a_host_sends_is_stored_unless_it_is_a_temperature(self):
        kept = dropped = 0
        for lim in LIMITS:
            with self.subTest(limit=name(lim)):
                temps = self.ingest([{"label": NVME1, "current_c": 45.9, "crit_c": lim},
                                     {"label": BOARD, "current_c": 52.0, "crit_c": 100.0}])
                by = {t["label"]: t for t in temps}
                got = by[NVME1].get("crit_c")
                self.assertTrue(got is None or (type(got) is float and 1.0 <= got <= 150.0), got)
                self.assertEqual(by[BOARD]["crit_c"], 100.0, "the control: a real limit goes through")
                self.read()
                kept, dropped = kept + (got is not None), dropped + (got is None)
        self.assertEqual((kept, dropped), (0, len(LIMITS)), "every value of the table is hostile, so none is stored")
        self.assertGreater(len(LIMITS), 15, "the table must hold hostile values or this measures nothing")

    def test_a_limit_that_is_a_temperature_is_stored_as_a_float_to_one_place(self):
        for lim, want in ((1.0, 1.0), (150, 150.0), (80, 80.0), (79.96, 80.0), (87.85, 87.8)):
            with self.subTest(limit=lim):
                by = {t["label"]: t for t in self.ingest([{"label": BOARD, "current_c": 52.0, "crit_c": lim}])}
                self.assertEqual(by[BOARD]["crit_c"], want)
                self.assertIs(type(by[BOARD]["crit_c"]), float)

    def test_no_label_a_host_sends_makes_the_server_fail(self):
        for label in LABELS:
            with self.subTest(label=name(label)):
                temps = self.ingest([{"label": label, "current_c": 45.9, "crit_c": 90.0},
                                     {"label": BOARD, "current_c": 52.0}])
                self.assertEqual(len(temps), 2)
                self.assertTrue(all(isinstance(t["label"], str) and len(t["label"]) <= 64 for t in temps))
                self.assertIsNotNone(self.read())

    def test_no_reading_a_host_sends_makes_the_server_fail(self):
        for reading in READINGS:
            with self.subTest(reading=name(reading)):
                temps = self.ingest([{"label": NVME1, "current_c": reading, "crit_c": 80.0},
                                     {"label": BOARD, "current_c": 52.0}])
                self.assertEqual([t["label"] for t in temps], [BOARD], "a reading that is not a temperature is dropped")
                self.read()


class TestAStoredRowOfTheWrongShape(_Fleet):
    """Rows the ingest above never saw. The limit and the label are read again on the way out."""

    def test_a_stored_limit_or_label_of_the_wrong_kind_is_none_and_the_page_answers(self):
        # The store refuses NaN and infinity (save() writes strict JSON), so a stored row cannot hold them.
        storable = [lim for lim in LIMITS if not (isinstance(lim, float) and not math.isfinite(lim))]
        seen = 0
        for lim in storable:
            for label in (NVME1, BOARD, None, 5, [], "x" * 5000):
                with self.subTest(limit=name(lim), label=name(label)):
                    self.stored([{"label": label, "current_c": 45.9, "crit_c": lim}])
                    row = self.read()
                    self.assertIsNotNone(row)
                    self.assertTrue(row.get("crit_c") is None or 1.0 <= row["crit_c"] <= 150.0, row.get("crit_c"))
                    seen += 1
        self.assertEqual(seen, len(storable) * 6)
        self.assertEqual(len(storable), len(LIMITS) - 3)

    def test_a_stored_reading_of_the_wrong_kind_does_not_make_the_page_or_the_score_fail(self):
        storable = [r for r in READINGS if not (isinstance(r, float) and not math.isfinite(r))]
        for reading in storable + [-(10 ** 400), 10 ** 400]:
            for label in (NVME1, BOARD):
                with self.subTest(reading=name(reading), label=name(label)):
                    self.stored([{"label": label, "current_c": reading, "crit_c": 80.0}, {"label": BOARD, "current_c": 52.0}])
                    self.assertIsNotNone(self.read())
        self.assertGreater(len(storable), 6)

    def test_a_stored_drive_or_gpu_reading_of_the_wrong_kind_does_not_make_the_page_or_the_score_fail(self):
        """The same two readers take a drive's SMART reading and a GPU's the same way."""
        storable = [r for r in READINGS if not (isinstance(r, float) and not math.isfinite(r))]
        for reading in storable + [-(10 ** 400), 10 ** 400]:
            with self.subTest(reading=name(reading)):
                self.stored([{"label": BOARD, "current_c": 52.0}],
                            smart=[{"device": "/dev/sda", "serial": "S1", "media": "hdd", "temperature_c": reading}],
                            gpus=[{"name": "g0", "temp_c": reading}])
                self.assertIsNotNone(self.read())


class TestThePrometheusExportOnAStoredRowOfTheWrongKind(unittest.TestCase):
    """The exporter reads the same stores, which are hand-editable JSON. A value float() cannot take is junk like a NaN, and
    junk has to vanish, since one bad sample makes the whole scrape invalid."""

    def test_a_number_too_big_for_a_float_is_no_sample(self):
        for value in (10 ** 400, -(10 ** 400)):
            self.assertIsNone(prometheus_export._num(value))
        self.assertEqual(prometheus_export._num(40.5), 40.5, "the control: a reading is still a sample")
        self.assertEqual(prometheus_export._num("41"), 41.0)

    def test_the_temperature_family_is_written_whatever_one_stored_reading_holds(self):
        rec = {"hardware": {"temps": [{"label": "bad", "current_c": 10 ** 400}, {"label": "good", "current_c": 40.5}]},
               "smart": [{"device": "/dev/sda", "temperature_c": 10 ** 400}], "gpus": [{"name": "g", "temp_c": 10 ** 400}]}
        lines = []
        prometheus_export._emit_temperatures(lines, {"h": {"name": "h"}}, {"h": rec})
        samples = [ln for ln in lines if not ln.startswith("#")]
        self.assertTrue(any('sensor="good"' in ln and ln.rstrip().endswith("40.5") for ln in samples), samples)
        for gone in ('sensor="bad"', "disk:/dev/sda", "gpu:g"):
            self.assertFalse(any(gone in ln for ln in samples), (gone, samples))


def _load_agent():
    loader = importlib.machinery.SourceFileLoader("agent_v748_security", str(ROOT / "client" / "remotepower-agent.py"))
    spec = importlib.util.spec_from_loader("agent_v748_security", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


agent = _load_agent()

# Names apt could print, or a repository could be made to: each is a valid argument or a shell word on its own.
NAMES = ["$(touch${IFS}pwned)", ";id", "`id`", "a|b", "--force-yes", "-o", "../../etc/passwd", "name\x00x", "‮gpj", "x" * 4000]
HEADING = "The following packages have been kept back:\n"


class TestHostileAptOutput(unittest.TestCase):

    def test_odd_and_huge_output_is_read_without_failing(self):
        cases = ["", None, "x" * 5_000_000, HEADING + "".join(f"  p{i}\n" for i in range(200_000)), HEADING + "  a\r\n  b\r\n",
                 HEADING * 10_000, HEADING.strip(), "\x00" * 1000]
        start = time.time()
        for out in cases:
            names = agent._apt_kept_back(out)
            self.assertIsInstance(names, list)
            self.assertTrue(all(isinstance(n, str) for n in names))
        self.assertLess(time.time() - start, 10, "reading the output must not take longer than apt took to print it")

    def run_add(self, names, holds=""):
        calls = []

        def fake(cmd, **kw):
            calls.append((list(cmd), kw))
            if cmd[0] == "apt-mark":
                return holds
            return "".join(f"Inst {n} [1] (2 Debian-Security:13/stable-security [amd64])\n" for n in names)

        result = {"upgradable": 0, "upgradable_names": [], "security_updates": 0}
        with mock.patch("subprocess.check_output", fake):
            agent._add_apt_kept_back(result, HEADING + "".join(f"  {n}\n" for n in names))
        return result, calls

    def test_a_name_apt_prints_is_never_part_of_a_command_and_no_command_goes_through_a_shell(self):
        result, calls = self.run_add(NAMES)
        words = {w for cmd, _ in calls for w in cmd}
        for n in NAMES:
            self.assertNotIn(n, words, name(n))
        self.assertEqual([c[0] for c, _ in calls], ["apt-mark", "apt-get"], "one read of the holds, one simulation")
        for cmd, kw in calls:
            self.assertFalse(kw.get("shell"), cmd)
        self.assertIn("--simulate", calls[1][0])
        self.assertEqual(result["upgradable"], len(NAMES))
        self.assertEqual(result["security_updates"], len(NAMES))

    def test_the_list_of_names_is_capped_whatever_apt_prints(self):
        names = [f"pkg{i}" for i in range(5000)]
        result, _ = self.run_add(names)
        self.assertEqual(len(result["upgradable_names"]), agent._MAX_UPGRADABLE_NAMES)
        self.assertEqual(result["upgradable"], 5000)


@unittest.skipUnless(shutil.which("node"), "node not installed")
class TestTheUpdatedCellOnHostileValues(unittest.TestCase):
    """The Problems table prints a host's last report through timeAgoHtml now. A value of the wrong kind must come out as a
    dash or as a time, never as the text it carried."""

    def test_a_value_of_the_wrong_kind_never_reaches_the_markup(self):
        app = (ROOT / "server/html/static/js/app.js").read_text()
        mod = (ROOT / "server/html/static/js/app-problems.js").read_text()
        # escHtml is one line of regex literals with quotes in them, which srcpin's scanner reads as the start of a string.
        esc = re.search(r"^function escHtml\(s\) \{.*\}$", app, re.M).group(0)
        fns = esc + "\n" + "\n".join(srcpin.js_function(app, n) for n in ("timeAgo", "_relAgo", "timeAgoHtml"))
        fns += "\n" + srcpin.js_function(mod, "_problemUpdated")
        self.assertLess(len(fns), 5000, "a function that is thousands of characters long was cut at the wrong brace")
        stubs = "const _timeDisplayAbsolute = () => false; const _fmtAbsTs = n => 'ABS' + n; const _fmtAgo = (n, u) => n + ' ' + u;\n"
        rows = ("[{updated: '<img src=x onerror=alert(1)>', last_report: 0}, {updated: 0, last_report: '<svg/onload=1>'},"
                " {updated: {a: 1}}, {updated: [1]}, {updated: 1e21, last_report: 0}, {updated: '9'.repeat(400)},"
                " {last_report: Infinity}, {updated: NaN, last_report: -5}, {updated: true}, {updated: '5<script>1</script>'},"
                " {updated: 'ONERROR', last_report: 1}, {updated: 0, last_report: 0}, {updated: 1, last_report: 1}]")
        script = stubs + fns + (f"\nconsole.log(JSON.stringify({rows}.map(r => timeAgoHtml(_problemUpdated(r), "
                                "{clamp: true, empty: '—'}))));")
        run = subprocess.run([shutil.which("node"), "-e", script], capture_output=True, text=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)
        cells = json.loads(run.stdout)
        self.assertEqual(len(cells), 13)
        for cell in cells:
            self.assertTrue(cell == "—" or re.fullmatch(r'<time datetime="[0-9T:.\-Z]*" title="[^"<>]*">[^<>]*</time>', cell), cell)
            for bad in ("<img", "<svg", "<script", "onerror", "onload"):
                self.assertNotIn(bad, cell.lower(), cell)
        self.assertGreater(sum(c == "—" for c in cells), 3, "the table must hold values that come out as a dash")
        self.assertGreater(sum(c.startswith("<time") for c in cells), 3, "and values that come out as a time")


if __name__ == "__main__":
    unittest.main()
