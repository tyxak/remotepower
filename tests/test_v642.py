"""v6.4.2 "Ver1tyMatters" — feature regressions.

The CURRENT release carries the strict version pins; older test_vXYZ.py files
have theirs loosened to shape checks. Headline: per-container alert mutes and a
container log window that waits for the agent instead of toasting "queued".
Feature behaviour lives in test_v642_container_mute.py / _container_logs.py.
"""

import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v642-"))
_spec = importlib.util.spec_from_file_location("api_v642_pins", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

V = "6.4.2"
CODENAME = "Ver1tyMatters"

_JS = _ROOT / "server/html/static/js"


def _html():
    return (_ROOT / "server/html/index.html").read_text()


def _js(name):
    return (_JS / name).read_text()


# v6.4.3: the strict version pins that lived here have been REMOVED, not
# loosened into self-tracking copies. v6.4.2 is a past release; the CURRENT
# release file (tests/test_v643.py) owns "is the bump complete" for the tree as
# it is now, and a loosened copy per release is how this suite accumulated 472
# duplicated checklist methods across 65 files. What stays below is the part
# only THIS file can assert: that v6.4.2's own features still work.

class TestReleaseSurfaceWiring(unittest.TestCase):
    """The two headline features must be reachable, not just present."""

    def test_container_mute_helpers_exist(self):
        for fn in ("_container_mute_set", "_alert_muted", "_alert_mute_set"):
            self.assertTrue(hasattr(api, fn), f"missing {fn}")

    def test_mute_buttons_are_wired_to_globals(self):
        js = _js("app-containers.js")
        for fn in ("muteContainer", "unmuteContainer"):
            self.assertIn(f'data-action-btn="{fn}"', js)
            self.assertIn(f"function {fn}(", js)

    def test_log_viewer_modal_and_handlers_exist(self):
        html = _html()
        for el in ("container-logs-modal", "container-logs-tail",
                   "container-logs-filter", "container-logs-progress",
                   "container-logs-body"):
            self.assertIn(f'id="{el}"', html, el)
        js = _js("app.js")
        for fn in ("openContainerLogs", "containerLogsRefetch",
                   "containerLogsFilter", "containerLogsToggleAuto",
                   "containerLogsCopy", "containerLogsDownload"):
            self.assertIn(f"function {fn}(", js, fn)

    def test_the_log_modal_is_body_level(self):
        """.container is a z-index:1 stacking context — a fixed overlay nested
        inside it can never rise above the sidebar (CLAUDE.md)."""
        html = _html()
        self.assertGreater(html.index('id="container-logs-modal"'),
                           html.index("<!-- /app -->"))

    def test_docs_cover_both_features(self):
        doc = (_ROOT / "docs/containers.md").read_text()
        self.assertIn("Muting one container", doc)
        self.assertIn("Viewing container logs", doc)
        feats = (_ROOT / "docs/features.md").read_text()
        self.assertIn("per-container mute", feats)
        self.assertIn("Container logs", feats)

    def test_features_md_stays_tables_only(self):
        body = (_ROOT / "docs/features.md").read_text()
        bad = re.findall(r"^### |^## (?:v[0-9]|What.s new|Added in)|```",
                         body, re.M)
        self.assertEqual(bad, [], f"features.md hygiene: {bad}")


if __name__ == "__main__":
    unittest.main()
