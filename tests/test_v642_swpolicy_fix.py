"""v6.4.2: software-policy violations became actionable.

The page listed the problem — "telnet is banned and present on web01" — and
offered nothing. The remediation existed server-side the whole time: POST
/install and /uninstall route through _resolve_targets (scope- and tenant-safe),
skip quarantined hosts and write a batch job Rollouts tracks. The operator had
to copy the hostname, navigate to Rollouts, find the device and type the package.

Run: python3 -m pytest tests/test_v642_swpolicy_fix.py -q
"""
import os
import re
import sys
import tempfile
import unittest
import importlib.util
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v642_swp", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_APP = (_ROOT / "server/html/static/js/app.js").read_text()
_HTML = (_ROOT / "server/html/index.html").read_text()


class TestTheRowIsActionable(unittest.TestCase):
    def test_the_button_exists(self):
        self.assertIn('data-action="swPolFixViolation"', _APP)

    def test_the_handler_exists(self):
        self.assertRegex(_APP, r"async function swPolFixViolation\(")

    def test_both_routes_it_posts_to_are_registered(self):
        served = {r for r in api._build_exact_routes()} | set(api._dispatcher_routes())
        paths = {r[1] for r in served}
        self.assertIn("/api/install", paths)
        self.assertIn("/api/uninstall", paths)

    def test_the_device_id_survives_the_dispatcher(self):
        """`!isNaN(v) ? Number(v) : v` — an all-digit or hex device id would
        arrive as a Number and _resolve_targets would never match it."""
        fn = re.search(r"async function swPolFixViolation\(.*?\n\}", _APP, re.S).group(0)
        self.assertIn("replace(/^d-/", fn)
        self.assertIn("'d-' + (r.device_id", _APP)

    def test_banned_uninstalls_and_required_installs(self):
        fn = re.search(r"async function swPolFixViolation\(.*?\n\}", _APP, re.S).group(0)
        self.assertIn("type === 'banned'", fn)
        self.assertIn("'/uninstall' : '/install'", fn)

    def test_it_promises_only_that_the_job_was_queued(self):
        """An install cannot satisfy a min_version the distro repo does not
        carry. A toast claiming the violation is fixed would be the
        success-toast-then-silence class."""
        fn = re.search(r"async function swPolFixViolation\(.*?\n\}", _APP, re.S).group(0)
        self.assertIn("Queued", fn)
        self.assertIn("does not guarantee", fn)

    def test_the_column_count_matches_the_header(self):
        """A colspan left at 5 makes the empty state and the error row sit
        wrong under a 6-column header."""
        i = _HTML.index('id="swpol-viol-thead"')
        j = _HTML.index("</thead>", i)
        self.assertEqual(_HTML[i:j].count("<th "), 6)
        fn = re.search(r"function _renderSwViolations\(.*?\n\}", _APP, re.S).group(0)
        self.assertIn('colspan="6"', fn)
        self.assertNotIn('colspan="5"', fn)


class TestTheAlertRowOffersItToo(unittest.TestCase):
    def test_the_event_maps_to_a_playbook_that_exists(self):
        """The consumer does `if kind not in playbooks: continue`, so a mapping
        to a nonexistent playbook is a silent no-op."""
        kind = api._EVENT_TO_MITIGATION.get("software_policy_violation")
        self.assertEqual(kind, "patches")
        self.assertIn(kind, api._MITIGATE_PLAYBOOKS)

    def test_the_annotator_actually_stamps_it(self):
        alerts = [{"id": "a1", "device_id": "d1", "severity": "medium",
                   "event": "software_policy_violation", "payload": {"package": "telnet"}},
                  {"id": "a2", "device_id": "d1", "severity": "low",
                   "event": "made_up_event", "payload": {}}]
        api._annotate_alert_mitigation(alerts)
        self.assertEqual(alerts[0].get("mitigation_kind"), "patches")
        self.assertIsNone(alerts[1].get("mitigation_kind"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
