"""v6.4.2: the printable report is the artifact an operator hands to a customer,
and it was the one surface that ignored their branding entirely — hardcoded
"RemotePower" in the title, the footer and the meta line, with the RemotePower
wordmark at the top.
"""
import os, re, sys, tempfile, unittest, importlib.util
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v642_wl", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_JS = (_ROOT / "server/html/static/js/report.js").read_text()
_CSS = (_ROOT / "server/html/static/css/report.css").read_text()


class TestServerShipsBrand(unittest.TestCase):
    def _brand(self, name="Acme Ops", accent="#ff8800"):
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg.update({"brand_name": name, "brand_accent": accent})
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()

    def test_full_report_carries_brand(self):
        self._brand()
        self.assertEqual(api._build_fleet_report().get("brand"),
                         {"name": "Acme Ops", "accent": "#ff8800"})

    def test_a_sectioned_report_keeps_it(self):
        """`_filter_report_sections` whitelists metadata keys — a missing entry
        silently drops the branding from every custom report."""
        self._brand()
        sub = api._filter_report_sections(api._build_fleet_report(), ["devices", "cve"])
        self.assertEqual((sub.get("brand") or {}).get("name"), "Acme Ops")
        self.assertNotIn("compliance", sub)

    def test_unbranded_install_is_unchanged(self):
        self._brand("", "")
        self.assertEqual(api._build_fleet_report().get("brand"), {"name": "", "accent": ""})


class TestClientConsumesBrand(unittest.TestCase):
    def test_render_reads_the_brand(self):
        self.assertIn("rep.brand", _JS)

    def test_the_hardcoded_product_name_is_gone_from_the_output(self):
        body = re.search(r"function render\(rep, baseline\) \{.*?\n  \}", _JS, re.S).group(0)
        # The only surviving literal should be the unbranded fallback.
        for lit in ("'RemotePower fleet posture report",
                    "' · RemotePower '"):
            self.assertNotIn(lit, body, f"{lit!r} still hardcoded in the rendered report")

    def test_the_accent_is_actually_read_by_the_stylesheet(self):
        """Setting a custom property nothing consumes is a dead assignment —
        the exact silent no-op this release keeps finding."""
        self.assertIn("--pr-accent", _JS)
        self.assertIn("var(--pr-accent", _CSS)

    def test_the_accent_falls_back_so_unbranded_renders_identically(self):
        for m in re.finditer(r"var\(--pr-accent([^)]*)\)", _CSS):
            self.assertIn(",", m.group(1), "var(--pr-accent) with no fallback value")


if __name__ == "__main__":
    unittest.main(verbosity=2)
