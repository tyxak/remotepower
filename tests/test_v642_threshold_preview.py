"""v6.4.2 — a threshold change stops being a fleet-wide surprise.

Settings → Alert parameters exposes ~70 numeric firing thresholds plus the
grade/risk cutoffs and per-factor weights, and `POST /api/config` applied them
fleet-wide on save with no preview step. Nothing computed how many hosts would
newly breach or how many currently do.

An operator wants fewer disk pages, drops `disk_warn_percent` from 90 to 80,
and hits Save. `_host_checks()` is recomputed for the whole fleet on the next
read, so the change fans out instantly: on a 400-host fleet that is a hundred
simultaneous new breaches, a Needs-Attention avalanche and a paging storm — at
which point the only recovery is Settings → Advanced → Configuration history.

The blast-radius idea already existed: `_blast_radius_guard()` gates batch
reboot/shutdown. It was scoped to power actions. And the data needed to answer
"how many hosts sit between 80 and 90 right now" was already loaded on the
server; nothing exposed it before the save.
"""

# A sibling from tests/ is imported inside a test method below.
# `unittest discover -s tests` puts this directory on sys.path for free;
# `python3 -m unittest tests.<this>` does not, and the method then fails
# with ModuleNotFoundError. See tests/test_modules_import_alone.py.
import sys as _rp_sys, pathlib as _rp_pl  # noqa: E402
_rp_sys.path.insert(0, str(_rp_pl.Path(__file__).resolve().parent))
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-thpre-"))

_spec = importlib.util.spec_from_file_location("api_thpre", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):
    """Windows hosts across a spread of CPU percentages. `cpu_pct_warn`
    defaults to 85 and is a real tunable, so moving it walks hosts across the
    boundary in both directions without needing any fixture trickery."""

    PCTS = [50, 70, 80, 88, 92, 97]

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ("DEVICES_FILE", "CONFIG_FILE", "HARDWARE_FILE"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
            api._invalidate_load_cache(getattr(api, attr))
        now = int(time.time())
        api.save(api.DEVICES_FILE, {
            f"w{i}": {"name": f"win{i}", "last_seen": now,
                      "os": "Windows Server 2022",
                      "sysinfo": {"os": "Windows Server 2022", "cpu_percent": p}}
            for i, p in enumerate(self.PCTS)})
        api.save(api.CONFIG_FILE, {})
        for f in (api.DEVICES_FILE, api.CONFIG_FILE):
            api._invalidate_load_cache(f)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ("respond", "method", "get_json_body", "require_admin_auth")}
        api.require_admin_auth = lambda: "jakob"
        api.method = lambda: "POST"

        def _resp(s, b=None):
            self.cap["s"], self.cap["b"] = s, b
            raise api.HTTPError(s, b)
        api.respond = _resp

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for a, v in self._files.items():
            setattr(api, a, v)

    def preview(self, body):
        api.get_json_body = lambda: body
        try:
            api.handle_threshold_preview()
        except api.HTTPError:
            pass
        return self.cap.get("b")


class TestThePreview(_Base):
    def test_tightening_a_threshold_names_the_hosts_it_would_break(self):
        """The whole finding: 85 → 65 walks the 70 % and 80 % hosts across the
        line, and until now the operator found out by being paged."""
        r = self.preview({"cpu_pct_warn": 65})
        self.assertEqual(r["total_newly_breaching"], 2)
        row = r["newly_breaching"][0]
        self.assertEqual(row["check"], "cpu")
        self.assertEqual(sorted(row["examples"]), ["win1", "win2"])

    def test_loosening_one_shows_what_would_stop_breaching(self):
        """The other direction matters too — "will this actually quieten
        anything?" is why the operator is on this page."""
        r = self.preview({"cpu_pct_warn": 95})
        self.assertEqual(r["total_newly_passing"], 2)
        self.assertEqual(sorted(r["newly_passing"][0]["examples"]),
                         ["win3", "win4"])

    def test_an_unchanged_value_previews_nothing(self):
        api.save(api.CONFIG_FILE, {"cpu_pct_warn": 85})
        api._invalidate_load_cache(api.CONFIG_FILE)
        r = self.preview({"cpu_pct_warn": 85})
        self.assertEqual(r["changed"], {})
        self.assertIn("differ", r["note"])

    def test_a_key_that_is_not_tunable_is_ignored(self):
        """The UI posts the whole settings form, so a preview must not choke on
        — or pretend to evaluate — keys the save loops never accept."""
        r = self.preview({"not_a_threshold": 1, "server_name": "x"})
        self.assertEqual(r["changed"], {})

    def test_a_non_numeric_value_is_ignored_rather_than_500ing(self):
        r = self.preview({"cpu_pct_warn": "eighty"})
        self.assertEqual(r["changed"], {})

    def test_it_says_how_many_hosts_it_looked_at(self):
        """A count of affected hosts means nothing without the denominator."""
        self.assertEqual(self.preview({"cpu_pct_warn": 65})["hosts_evaluated"],
                         len(self.PCTS))

    def test_it_reports_the_values_it_compared(self):
        r = self.preview({"cpu_pct_warn": 65})
        self.assertEqual(r["changed"], {"cpu_pct_warn": 65})

    def test_a_change_that_moves_nobody_says_so(self):
        r = self.preview({"cpu_pct_warn": 84})
        self.assertEqual(r["total_newly_breaching"], 0)
        self.assertEqual(r["total_newly_passing"], 0)

    def test_examples_are_capped(self):
        """A hundred hostnames is not a preview, it is the incident."""
        now = int(time.time())
        api.save(api.DEVICES_FILE, {
            f"w{i}": {"name": f"host{i}", "last_seen": now,
                      "os": "Windows Server 2022",
                      "sysinfo": {"os": "Windows Server 2022", "cpu_percent": 70}}
            for i in range(40)})
        api._invalidate_load_cache(api.DEVICES_FILE)
        row = self.preview({"cpu_pct_warn": 65})["newly_breaching"][0]
        self.assertEqual(row["hosts"], 40)
        self.assertLessEqual(len(row["examples"]), 5)

    def test_it_does_not_save_anything(self):
        """A preview that writes is not a preview."""
        self.preview({"cpu_pct_warn": 65})
        api._invalidate_load_cache(api.CONFIG_FILE)
        self.assertEqual(api.load(api.CONFIG_FILE), {})

    def test_it_is_admin_only(self):
        seen = []
        api.require_admin_auth = lambda: (seen.append(1), "j")[1]
        self.preview({"cpu_pct_warn": 65})
        self.assertEqual(len(seen), 1)

    def test_it_rejects_a_GET(self):
        api.method = lambda: "GET"
        self.preview({})
        self.assertEqual(self.cap["s"], 405)


class TestItTellsTheTruth(_Base):
    def test_it_says_open_alerts_are_not_resolved_by_this(self):
        """The obvious assumption is that loosening a threshold clears the
        alerts it opened. It does not — they clear on their own recover events
        or by muting. Letting an operator believe otherwise would be a worse
        kind of missing than having no preview."""
        note = self.preview({"cpu_pct_warn": 95})["note"]
        self.assertIn("not resolved", note)
        self.assertIn("Tuning", note)

    def test_it_uses_the_real_checks_engine(self):
        """A second copy of "what counts as breaching" would drift from the
        first, and a preview that disagrees with what actually happens is worse
        than no preview."""
        from srcpin import py_function
        src = (_CGI / "attention_handlers.py").read_text()
        body = py_function(src, "_preview_check_map")
        self.assertIn("A._host_checks(", body)
        self.assertIn("A._checks_threshold_kwargs(", body)

    def _breaching_cpu(self, cfg):
        """How many hosts' `cpu` check breaches, driving the REAL engine."""
        kwargs = api._checks_threshold_kwargs(cfg)
        n = 0
        for did, dev in (api.load(api.DEVICES_FILE) or {}).items():
            for row in api._host_checks(did, dev, {}, [], int(time.time()), 180,
                                        **kwargs):
                if row.get("key") == "cpu" and row.get("status") in ("warning",
                                                                     "critical"):
                    n += 1
        return n

    def test_the_preview_agrees_with_what_saving_would_do(self):
        """The claim the whole feature rests on. Preview, then actually apply
        the value, and the real fleet result must be the baseline plus exactly
        what the preview predicted.

        The baseline is COMPUTED rather than written down: hardcoding it is how
        a test ends up asserting the author's arithmetic instead of the code's
        behaviour, which is what happened on the first draft of this one.
        """
        before = self._breaching_cpu({})
        predicted = self.preview({"cpu_pct_warn": 65})
        api.save(api.CONFIG_FILE, {"cpu_pct_warn": 65})
        api._invalidate_load_cache(api.CONFIG_FILE)
        after = self._breaching_cpu(api.load(api.CONFIG_FILE))
        self.assertEqual(after - before, predicted["total_newly_breaching"])
        self.assertGreater(predicted["total_newly_breaching"], 0)

    def test_it_agrees_in_the_loosening_direction_too(self):
        before = self._breaching_cpu({})
        predicted = self.preview({"cpu_pct_warn": 95, "cpu_pct_crit": 99})
        after = self._breaching_cpu({"cpu_pct_warn": 95, "cpu_pct_crit": 99})
        self.assertEqual(before - after, predicted["total_newly_passing"])
        self.assertGreater(predicted["total_newly_passing"], 0)


class TestScoping(_Base):
    def test_it_only_counts_hosts_the_caller_can_see(self):
        """A preview that counts hosts outside the caller's scope is a
        host-count leak dressed as a convenience."""
        from srcpin import py_function
        src = (_CGI / "attention_handlers.py").read_text()
        body = py_function(src, "handle_threshold_preview")
        self.assertIn("A._scope_filter_devices(", body)

    def test_a_scoped_caller_sees_a_smaller_fleet(self):
        real = api._scope_filter_devices
        api._scope_filter_devices = lambda d: {"w1": d["w1"]}
        try:
            self.assertEqual(self.preview({"cpu_pct_warn": 65})["hosts_evaluated"], 1)
        finally:
            api._scope_filter_devices = real


class TestWiring(unittest.TestCase):
    def test_the_route_resolves(self):
        self.assertIn(("POST", "/api/config/threshold-preview"),
                      api._build_exact_routes())

    def test_the_handler_lives_in_the_bound_module(self):
        """api.py is at the inline-handler ratchet ceiling."""
        self.assertEqual(api.handle_threshold_preview.__module__,
                         "attention_handlers")

    def test_it_accepts_the_same_keys_the_save_loops_do(self):
        """Derived from the save loops rather than hand-listed, so the next
        threshold added is previewable without a second edit."""
        keys = api._alert_param_config_keys()
        self.assertGreater(len(keys), 50)
        self.assertIn("cpu_pct_warn", keys)

    def test_the_ui_is_wired(self):
        html = ROOT / "server" / "html" / "index.html"
        if not html.exists():
            self.skipTest("excluded from this tree")
        s = html.read_text()
        js = (ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
        self.assertIn('data-action="previewThresholdImpact"', s)
        self.assertIn('id="ap-preview-out"', s)
        self.assertRegex(js, r"\basync function previewThresholdImpact\s*\(")

    def test_the_ui_previews_the_form_not_the_saved_values(self):
        """Previewing what is already saved would always report no change."""
        js = (ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
        body = js[js.index("async function previewThresholdImpact("):]
        body = body[:body.index("\n}\n")]
        self.assertIn("_ALERT_PARAM_FIELDS", body)
        self.assertIn("document.getElementById(id)", body)

    def test_there_is_one_preview_control_not_one_per_section(self):
        """The pane has 25 Save buttons; 25 preview buttons would be chrome,
        and the interesting question spans the whole form anyway."""
        html = ROOT / "server" / "html" / "index.html"
        if not html.exists():
            self.skipTest("excluded from this tree")
        self.assertEqual(html.read_text().count('data-action="previewThresholdImpact"'), 1)


if __name__ == "__main__":
    unittest.main()
