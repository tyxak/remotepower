"""v6.1.2 — UX improvements.

- **Browser-tab alert badge.** A dashboard lives in a background tab; the favicon
  was static and the title never carried a count, so the one place you actually
  glance said nothing.
- **°C / °F display unit.** Zero Fahrenheit support existed. Storage stays
  Celsius — this converts at RENDER time only, so flipping it can't move a
  threshold.
- **Copy host summary.** The homelab support workflow is "paste what your box
  looks like into a forum thread", which meant screenshotting or retyping.
- **Longest-uptime widget.** Required adding a NUMERIC uptime: the only uptime
  ever stored was the `uptime -p` prose ("up 3 weeks"), which cannot be sorted.
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v612-ux-"))
_spec = importlib.util.spec_from_file_location("api_v612_ux", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_APP = (_ROOT / "server/html/static/js/app.js").read_text()
_HTML = (_ROOT / "server/html/index.html").read_text()
_AGENT = (_ROOT / "client/remotepower-agent.py").read_text()


class TestTabAlertBadge(unittest.TestCase):
    def test_title_and_favicon_are_driven_from_the_badge_chokepoint(self):
        self.assertIn("_paintTabAlertBadge(n);", _APP)
        i = _APP.index("function _paintTabAlertBadge")
        block = _APP[i : i + 2000]
        self.assertIn("document.title", block)
        self.assertIn("canvas", block)

    def test_the_base_title_is_captured_once_so_prefixes_cannot_stack(self):
        # Repeated paints must not produce "(1) (2) (3) RemotePower".
        i = _APP.index("function _paintTabAlertBadge")
        block = _APP[i : i + 2000]
        self.assertIn("if (_tabBaseTitle === null) _tabBaseTitle = document.title;", block)

    def test_branding_reapplies_the_badge(self):
        # Branding sets document.title AFTER the first badge paint, which would
        # otherwise wipe the "(N)" count.
        self.assertIn("_tabBaseTitle = document.title;", _APP)
        i = _APP.index("document.title = me.brand.name")
        self.assertIn("_paintTabAlertBadge", _APP[i : i + 600])

    def test_zero_alerts_restores_the_original_favicon(self):
        i = _APP.index("function _paintTabAlertBadge")
        block = _APP[i : i + 2000]
        self.assertIn("if (n === 0) { link.href = _tabFaviconOriginal; return; }", block)


class TestTemperatureUnit(unittest.TestCase):
    def test_the_pref_is_whitelisted_server_side(self):
        # ui_prefs is a strict whitelist — a field not named here is silently
        # dropped and the toggle would appear to work but never persist.
        clean = api._sanitise_ui_prefs({"temp_unit": "f"})
        self.assertEqual(clean.get("temp_unit"), "f")

    def test_a_bogus_unit_is_rejected(self):
        self.assertNotIn("temp_unit", api._sanitise_ui_prefs({"temp_unit": "kelvin"}))
        self.assertNotIn("temp_unit", api._sanitise_ui_prefs({"temp_unit": 42}))

    def test_celsius_is_the_default(self):
        self.assertNotIn("temp_unit", api._sanitise_ui_prefs({}))

    def test_render_sites_go_through_the_formatter(self):
        # A literal °C left in a RENDER path would ignore the pref. The two
        # formatters legitimately contain the °C/°F literals (they emit them),
        # so scan everything else.
        for name in ("app.js", "app-power.js", "app-gpu.js"):
            src = (_ROOT / "server/html/static/js" / name).read_text()
            body = re.sub(r"//[^\n]*", "", src)          # drop comments
            # Drop the formatter bodies themselves.
            body = re.sub(
                r"function fmtTemp(?:Delta)?\([^)]*\)\s*\{.*?\n\}", "", body, flags=re.S
            )
            leftovers = [ln.strip() for ln in body.splitlines() if "°C" in ln]
            self.assertEqual(
                leftovers, [], f"{name} still renders a hard-coded °C: {leftovers[:2]}"
            )

    def test_a_delta_does_not_get_the_offset(self):
        # "5°C of headroom" must render as 9°F, NOT 41°F. Scale, don't offset.
        i = _APP.index("function fmtTempDelta")
        block = _APP[i : i + 400]
        self.assertIn("* 9 / 5", block)
        self.assertNotIn("+ 32", block)

    def test_headroom_uses_the_delta_formatter(self):
        power = (_ROOT / "server/html/static/js/app-power.js").read_text()
        self.assertIn("fmtTempDelta(r.headroom)", power)


class TestNumericUptime(unittest.TestCase):
    """The leaderboard needed a sortable uptime; only prose existed."""

    def test_agent_collects_a_numeric_uptime(self):
        self.assertIn("def get_uptime_seconds", _AGENT)
        self.assertIn("'uptime_seconds': get_uptime_seconds()", _AGENT)

    def test_agent_reads_the_host_not_the_container(self):
        i = _AGENT.index("def get_uptime_seconds")
        self.assertIn("host_path('/proc/uptime')", _AGENT[i : i + 700])

    def test_the_sanitizer_persists_it(self):
        # safe_si is a whitelist: a field the agent sends but the sanitizer
        # drops silently never reaches the UI.
        si = {"uptime": "up 3 weeks", "uptime_seconds": 1814400}
        src = (_CGI / "api.py").read_text()
        i = src.index("safe_si['uptime'] = ")
        self.assertIn("safe_si['uptime_seconds']", src[i : i + 900])

    def test_absurd_values_are_clamped_out(self):
        src = (_CGI / "api.py").read_text()
        i = src.index("safe_si['uptime'] = ")
        self.assertIn("365 * 50", src[i : i + 900])

    def test_agent_extensionless_stays_in_sync(self):
        self.assertEqual(
            (_ROOT / "client/remotepower-agent.py").read_bytes(),
            (_ROOT / "client/remotepower-agent").read_bytes(),
        )


class TestUptimeWidget(unittest.TestCase):
    def test_widget_registries_stay_in_lockstep(self):
        js_keys = re.findall(r"key:\s*'([a-z]+)'", _APP[_APP.index("const DASH_WIDGETS") :])
        js_keys = js_keys[: len(api.DASHBOARD_WIDGETS)]
        self.assertEqual(js_keys, list(api.DASHBOARD_WIDGETS))

    def test_the_widget_has_a_card_and_a_renderer(self):
        self.assertIn('data-widget="uptimetop"', _HTML)
        self.assertIn("home-w-uptimetop-body", _APP)

    def test_offline_hosts_are_excluded(self):
        # An offline host's last uptime is frozen at the moment it died —
        # ranking it would put a long-dead box at the top of an uptime board.
        i = _APP.index("home-w-uptimetop-body")
        block = _APP[max(0, i - 1200) : i + 200]
        self.assertIn("d.online", block)


class TestCopyDeviceSummary(unittest.TestCase):
    def test_it_exists_and_is_wired_into_the_drawer(self):
        self.assertIn("async function copyDeviceSummary", _APP)
        self.assertIn("'Copy summary'", _APP)

    def test_it_does_not_leak_ip_or_device_id_into_a_public_paste(self):
        i = _APP.index("async function copyDeviceSummary")
        block = _APP[i : i + 1800]
        self.assertNotIn("d.ip", block)
        self.assertNotIn("`ID:", block)

    def test_it_uses_the_real_uptime_field(self):
        # `uptime` is the prose field that actually exists on sysinfo.
        i = _APP.index("async function copyDeviceSummary")
        block = _APP[i : i + 1800]
        self.assertIn("si.uptime", block)
        self.assertNotIn("d.uptime_s ", block)


if __name__ == "__main__":
    unittest.main()
