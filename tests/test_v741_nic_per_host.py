#!/usr/bin/env python3
"""v7.4.1, issue #37: NIC error and drop floors for one host.

"Let both be overridden per host, so a busy media server can tolerate more drops
without loosening the check for the rest of the fleet."

A host's own floors live in its `metric_thresholds`, next to the memory, disk and
temperature limits it already has, so they ride the same endpoint
(`PATCH /api/devices/<id>/metric-thresholds`), the same editor and the same host
profiles. The real handlers run here, and the editor's own JavaScript runs under node.

Also covered: an emptied field in that editor now removes its override. It used to be
ignored, and "Reset to defaults" (which clears every override on the host) was the only
way back, which matters now that a drop floor of 0 means something.
"""
import json
import shutil
import subprocess
import sys as _rp_sys
import pathlib as _rp_pl
import tempfile
import unittest

_rp_sys.path.insert(0, str(_rp_pl.Path(__file__).resolve().parent))
from test_v622_alert_params import _SaveBase, ROOT, api  # noqa: E402
import srcpin  # noqa: E402

APP = (ROOT / "server/html/static/js/app.js").read_text()
HTML = (ROOT / "server/html/index.html").read_text()
I18N = (ROOT / "server/html/static/js/i18n.js").read_text()
_NODE = shutil.which("node")


class _Base(_SaveBase):
    def setUp(self):
        super().setUp()
        self._more = {}
        for attr in ("DEVICES_FILE", "POSTURE_STATE_FILE", "DEVICE_PROFILES_FILE"):
            self._more[attr] = getattr(api, attr)
            setattr(api, attr, self.d / self._more[attr].name)
        api.save(api.DEVICES_FILE, {"d1": {"id": "d1", "name": "media01", "token": "t",
                                           "sysinfo": {}, "metric_thresholds": {"mem_warn_percent": 70.0}}})
        api.save(api.CONFIG_FILE, {})
        for f in (api.DEVICES_FILE, api.CONFIG_FILE):
            api._invalidate_load_cache(f)
        self._orig2 = {n: getattr(api, n) for n in ("require_auth", "get_token_from_request")}
        api.require_auth = lambda **k: "jakob"
        self.fired = []
        api.fire_webhook = lambda ev, payload: self.fired.append((ev, payload))

    def tearDown(self):
        for n, v in self._orig2.items():
            setattr(api, n, v)
        for a, v in self._more.items():
            setattr(api, a, v)
        super().tearDown()

    def call(self, method, body=None, fn=None, *args):
        self.cap.clear()
        api.method = lambda: method
        api.get_json_obj = lambda: dict(body or {})
        api.get_json_body = lambda: dict(body or {})
        try:
            (fn or api.handle_device_metric_thresholds)(*(args or ("d1",)))
        except api.HTTPError:
            pass
        return self.cap.get("s"), self.cap.get("b")

    def stored(self):
        api._invalidate_load_cache(api.DEVICES_FILE)
        return api.load(api.DEVICES_FILE)["d1"].get("metric_thresholds", {})


class TestPatch(_Base):
    def test_both_floors_are_stored_as_whole_numbers(self):
        s, b = self.call("PATCH", {"nic_err_alert_min": 12, "nic_drop_alert_min": 4000.0})
        self.assertEqual(s, 200, b)
        mt = self.stored()
        self.assertEqual((mt["nic_err_alert_min"], mt["nic_drop_alert_min"]), (12, 4000))
        self.assertIsInstance(mt["nic_drop_alert_min"], int)
        self.assertEqual(mt["mem_warn_percent"], 70.0, "the host's other overrides are kept")

    def test_a_drop_floor_of_zero_is_stored_it_means_off(self):
        self.call("PATCH", {"nic_drop_alert_min": 0})
        self.assertEqual(self.stored()["nic_drop_alert_min"], 0)

    def test_the_errors_floor_cannot_be_zero(self):
        s, _ = self.call("PATCH", {"nic_err_alert_min": 0})
        self.assertEqual(s, 400)

    def test_bad_values_are_refused_and_nothing_is_stored(self):
        for bad in (-1, 100001, "x", True, 5.7, float("nan"), [3], {"a": 1}):
            for key in ("nic_err_alert_min", "nic_drop_alert_min"):
                with self.subTest(key=key, bad=bad):
                    s, b = self.call("PATCH", {key: bad})
                    self.assertEqual(s, 400)
                    # a fixed sentence per floor, so the dashboard can translate it
                    self.assertIn("NIC error floor" if key == "nic_err_alert_min" else "NIC drop floor",
                                  b["error"])
                    self.assertIn("whole number", b["error"])
        self.assertNotIn("nic_err_alert_min", self.stored())
        self.assertNotIn("nic_drop_alert_min", self.stored())

    def test_null_removes_just_that_override(self):
        self.call("PATCH", {"nic_err_alert_min": 12, "nic_drop_alert_min": 0})
        s, _ = self.call("PATCH", {"nic_drop_alert_min": None})
        self.assertEqual(s, 200)
        mt = self.stored()
        self.assertNotIn("nic_drop_alert_min", mt, "null must remove the key, not store 0")
        self.assertEqual(mt["nic_err_alert_min"], 12)

    def test_null_works_on_the_older_keys_too(self):
        s, _ = self.call("PATCH", {"mem_warn_percent": None})
        self.assertEqual(s, 200)
        self.assertNotIn("mem_warn_percent", self.stored())

    def test_removing_a_key_that_was_never_set_is_fine(self):
        s, _ = self.call("PATCH", {"nic_err_alert_min": None, "temp_crit_celsius": None})
        self.assertEqual(s, 200)

    def test_delete_still_clears_everything(self):
        self.call("PATCH", {"nic_drop_alert_min": 0})
        self.call("DELETE")
        self.assertEqual(self.stored(), {})


class TestGet(_Base):
    def test_a_host_with_none_of_its_own_shows_the_fleets(self):
        api.save(api.CONFIG_FILE, {"nic_err_alert_min": 9, "nic_drop_alert_min": 300})
        api._invalidate_load_cache(api.CONFIG_FILE)
        s, b = self.call("GET")
        self.assertEqual(s, 200)
        self.assertEqual((b["effective"]["nic_err_alert_min"], b["effective"]["nic_drop_alert_min"]), (9, 300))
        self.assertEqual((b["defaults"]["nic_err_alert_min"], b["defaults"]["nic_drop_alert_min"]), (9, 300))
        self.assertNotIn("nic_err_alert_min", b["overrides"])

    def test_with_no_fleet_drop_floor_the_drops_are_null_not_a_number(self):
        s, b = self.call("GET")
        self.assertIsNone(b["effective"]["nic_drop_alert_min"])
        self.assertIsNone(b["defaults"]["nic_drop_alert_min"])
        self.assertEqual(b["effective"]["nic_err_alert_min"], api._NIC_ERR_ALERT_MIN)

    def test_the_hosts_own_values_win_in_effective_and_stay_out_of_defaults(self):
        api.save(api.CONFIG_FILE, {"nic_drop_alert_min": 300})
        api._invalidate_load_cache(api.CONFIG_FILE)
        self.call("PATCH", {"nic_err_alert_min": 2, "nic_drop_alert_min": 0})
        s, b = self.call("GET")
        self.assertEqual((b["effective"]["nic_err_alert_min"], b["effective"]["nic_drop_alert_min"]), (2, 0))
        self.assertEqual(b["defaults"]["nic_drop_alert_min"], 300, "defaults are the fleet's, not the host's")
        self.assertEqual(b["overrides"]["nic_drop_alert_min"], 0)

    def test_the_static_defaults_table_is_not_changed_by_a_get(self):
        self.call("GET")
        self.assertNotIn("nic_err_alert_min", api.DEFAULT_METRIC_THRESHOLDS)


class TestTheAlertFollowsTheHost(_Base):
    """From the PATCH to the alert: the floors a host was given are the ones the sample is judged by."""

    def ingest(self, nio):
        api._invalidate_load_cache(api.DEVICES_FILE)
        dev = api.load(api.DEVICES_FILE)["d1"]
        api._ingest_posture_v3110("d1", "media01", {"mounts": [], "network_io": nio}, dev=dev)

    def test_a_busy_host_tolerates_drops_the_rest_of_the_fleet_does_not(self):
        api.save(api.CONFIG_FILE, {"nic_drop_alert_min": 50})
        api._invalidate_load_cache(api.CONFIG_FILE)
        drops = [{"iface": "eth0", "errors_delta": 0, "drops_delta": 5000, "err_delta": 5000}]
        calm = [{"iface": "eth0", "errors_delta": 0, "drops_delta": 0, "err_delta": 0}]

        # no floors of its own: the fleet's 50 pages it
        api._entity_write_one(api.POSTURE_STATE_FILE, "d1", None)
        self.ingest(calm)
        self.fired.clear()
        self.ingest(drops)
        self.assertEqual([e for e, _ in self.fired], ["nic_errors"])

        # the same sample, once the host has its own, does not
        self.call("PATCH", {"nic_drop_alert_min": 100000})
        api._entity_write_one(api.POSTURE_STATE_FILE, "d1", None)
        self.ingest(calm)
        self.fired.clear()
        self.ingest(drops)
        self.assertEqual(self.fired, [])

        # and a real error on that host still pages at the fleet's errors floor
        self.fired.clear()
        self.ingest([{"iface": "eth0", "errors_delta": api._NIC_ERR_ALERT_MIN, "drops_delta": 0,
                      "err_delta": api._NIC_ERR_ALERT_MIN}])
        self.assertEqual([e for e, _ in self.fired], ["nic_errors"])


class TestProfiles(_Base):
    def validate(self, mt):
        self.cap.clear()
        try:
            return api._validate_device_profile({"name": "media", "metric_thresholds": mt})
        except api.HTTPError:
            return None

    def test_a_profile_can_carry_the_floors(self):
        out = self.validate({"nic_err_alert_min": 8, "nic_drop_alert_min": 0, "mem_warn_percent": 80})
        self.assertEqual(out["metric_thresholds"]["nic_err_alert_min"], 8)
        self.assertEqual(out["metric_thresholds"]["nic_drop_alert_min"], 0)
        self.assertEqual(out["metric_thresholds"]["mem_warn_percent"], 80.0)

    def test_bad_floors_in_a_profile_are_a_400_not_silently_dropped(self):
        for mt in ({"nic_err_alert_min": 0}, {"nic_drop_alert_min": -1}, {"nic_drop_alert_min": "x"},
                   {"nic_err_alert_min": True}, {"nic_drop_alert_min": 100001}, {"nic_err_alert_min": 2.5}):
            with self.subTest(mt=mt):
                self.assertIsNone(self.validate(mt))
                self.assertEqual(self.cap.get("s"), 400)

    def test_applying_one_keeps_the_hosts_other_overrides(self):
        dev = {"metric_thresholds": {"disk_per_mount": {"/var": {"warn": 60.0, "crit": 70.0}},
                                     "nic_drop_alert_min": 5}}
        out = api._apply_profile_to_device(dev, {"metric_thresholds": {"nic_drop_alert_min": 900}})
        mt = out["metric_thresholds"]
        self.assertEqual(mt["nic_drop_alert_min"], 900)
        self.assertEqual(mt["disk_per_mount"], {"/var": {"warn": 60.0, "crit": 70.0}})


@unittest.skipUnless(_NODE, "node is not installed")
class TestTheEditorRunsUnderNode(unittest.TestCase):
    """The real openMetricThresholds / saveMetricThresholds against a stub page."""

    @classmethod
    def setUpClass(cls):
        cls.src = "\n".join([
            "let _currentMetricThresholdsDevice = null;",
            "let _metricThresholdsHad = new Set();",
            cls._fn("openMetricThresholds"),
            cls._fn("saveMetricThresholds"),
        ])

    @staticmethod
    def _fn(name):
        # srcpin starts at the word `function`; these two are `async function`
        body = srcpin.js_function(APP, name)
        assert ("async function " + name) in APP, name + " is no longer async: drop the prefix"
        return "async " + body

    def run_js(self, scenario):
        prelude = """
const els = {};
const el = (id) => els[id] || (els[id] = {id, value: '', placeholder: '', style: {}, textContent: '', innerHTML: ''});
const document = {getElementById: el, querySelector: () => ({textContent: ''}), querySelectorAll: () => []};
const devices = [];
const calls = [];
let DATA = null;
async function api(method, path, body) { calls.push([method, path, body]); return method === 'GET' ? DATA : {ok: true}; }
function openModal() {} function closeModal() {} function toast() {} function addMountThresholdRow() {}
function escHtml(x) { return x; }
const ALL = ['mem-warn','mem-crit','swap-warn','swap-crit','disk-warn','disk-crit','cpu-warn','cpu-crit',
             'snmp-cpu-warn','snmp-cpu-crit','temp-warn','temp-crit','mailq-warn','mailq-crit','nic-err','nic-drop'];
ALL.forEach(k => el('thr-' + k));
el('metric-thresholds-device-id'); el('metric-thresholds-error'); el('metric-thresholds-current'); el('thr-mounts-list');
"""
        code = prelude + self.src + "\n(async () => {\n" + scenario + "\n})().then(() => {}, e => { console.log(JSON.stringify({crash: String(e)})); });"
        with tempfile.TemporaryDirectory() as tmp:
            f = _rp_pl.Path(tmp) / "run.js"
            f.write_text(code)
            r = subprocess.run([_NODE, str(f)], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = [ln for ln in r.stdout.splitlines() if ln[:1] in ("{", "[")]
        self.assertTrue(out, r.stdout + r.stderr)
        res = json.loads(out[-1])
        if isinstance(res, dict):
            self.assertNotIn("crash", res, res)
        return res

    def test_the_fields_load_and_a_null_fleet_drop_floor_is_not_the_word_null(self):
        res = self.run_js("""
DATA = {overrides: {mem_warn_percent: 70, nic_drop_alert_min: 0},
        defaults: {mem_warn_percent: 85, nic_err_alert_min: 5, nic_drop_alert_min: null}};
await openMetricThresholds('d1', 'media01');
console.log(JSON.stringify({
  memWarn: els['thr-mem-warn'].value, dropValue: els['thr-nic-drop'].value,
  errValue: els['thr-nic-err'].value, errPlaceholder: els['thr-nic-err'].placeholder,
  dropPlaceholder: els['thr-nic-drop'].placeholder }));
""")
        self.assertEqual(res, {"memWarn": "70", "dropValue": "0", "errValue": "", "errPlaceholder": "5",
                               "dropPlaceholder": ""})

    def test_typing_sends_numbers_clearing_sends_null_and_an_untouched_blank_sends_nothing(self):
        res = self.run_js("""
DATA = {overrides: {mem_warn_percent: 70, nic_drop_alert_min: 0},
        defaults: {mem_warn_percent: 85, nic_err_alert_min: 5, nic_drop_alert_min: null}};
await openMetricThresholds('d1', 'media01');
els['thr-mem-warn'].value = '';          // had an override: emptied
els['thr-nic-err'].value = '12';         // typed
                                         // thr-nic-drop keeps '0', thr-mem-crit never had one
await saveMetricThresholds();
console.log(JSON.stringify(calls.filter(c => c[0] === 'PATCH')[0][2]));
""")
        self.assertEqual(res, {"mem_warn_percent": None, "nic_err_alert_min": 12, "nic_drop_alert_min": 0})

    def test_a_second_host_does_not_inherit_the_first_hosts_overrides(self):
        res = self.run_js("""
DATA = {overrides: {mem_warn_percent: 70, nic_drop_alert_min: 0}, defaults: {}};
await openMetricThresholds('d1', 'media01');
DATA = {overrides: {}, defaults: {}};
await openMetricThresholds('d2', 'web01');
await saveMetricThresholds();
console.log(JSON.stringify(calls.filter(c => c[0] === 'PATCH')[0].slice(1)));
""")
        self.assertEqual(res, ["/devices/d2/metric-thresholds", {}])


class TestEditorMarkupAndStrings(unittest.TestCase):
    def test_the_two_boxes_are_there_once_with_the_right_bounds(self):
        import re
        self.assertEqual(HTML.count('id="thr-nic-err"'), 1)
        self.assertEqual(HTML.count('id="thr-nic-drop"'), 1)
        self.assertIn('min="1"', re.search(r'<input[^>]*id="thr-nic-err"[^>]*>', HTML).group(0))
        self.assertIn('min="0"', re.search(r'<input[^>]*id="thr-nic-drop"[^>]*>', HTML).group(0))

    def test_every_new_visible_string_has_all_six_languages(self):
        for key in ("NIC errors and drops", "NIC floors (errors, drops)", "NIC drop floor",
                    "New errors or drops on one interface between two reports before an alert. "):
            with self.subTest(key=key[:30]):
                i = I18N.find("'%s" % key)
                if i < 0:
                    i = I18N.find('"%s' % key)
                self.assertGreater(i, 0, "no dictionary entry")
                entry = I18N[i:I18N.index("},", i)]
                for lang in ("zh", "hi", "es", "ar", "de", "fr"):
                    self.assertRegex(entry, r"""["']?%s["']?\s*:""" % lang)

    def test_the_hint_in_the_markup_is_the_dictionary_key(self):
        import re
        m = re.search(r'<div class="isl-200">(New errors or drops on one interface[^<]*)</div>', HTML)
        self.assertTrue(m)
        self.assertIn('"%s"' % m.group(1), I18N, "the hint text and its dictionary key have drifted apart")


if __name__ == "__main__":
    unittest.main()
