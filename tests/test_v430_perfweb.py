#!/usr/bin/env python3
"""v4.3.0 perf batch — guardrails + behavior pins.

The paint-storm guardrail exists because this class of bug shipped TWICE
(v3.14.0 pulse-green box-shadow keyframes; the v4.3.0 audit found rp-shimmer
animating background-position). An infinite @keyframes that animates a paint
property forces a per-frame repaint — worst in Firefox — and looks perfectly
fine in code review. So: no @keyframes may animate anything but opacity and
transform, and backdrop-filter must never come back (Firefox re-blurs the
backdrop every frame on the sticky header it used to sit on).
"""
import importlib.util
import json
import os
import re
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
_HTML = _ROOT / "server" / "html"
import sys

sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v430pw", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

CSS = (_HTML / "static" / "css" / "styles.css").read_text()
APPJS = (_HTML / "static" / "js" / "app.js").read_text()
I18NJS = (_HTML / "static" / "js" / "i18n.js").read_text()
INDEX = (_HTML / "index.html").read_text()


class TestNoRepaintAnimations(unittest.TestCase):
    """Guardrail: @keyframes may only animate compositor-cheap properties."""

    # Properties that force layout or repaint when animated. Animating any
    # of these in a keyframe loop is the paint-storm bug class.
    FORBIDDEN = ('box-shadow', 'background-position', 'filter', 'width',
                 'height', 'top', 'left', 'right', 'bottom', 'margin',
                 'padding', 'font-size', 'border-width')

    def _keyframes_blocks(self):
        """Yield (name, body) for every @keyframes block in styles.css."""
        for m in re.finditer(r'@keyframes\s+([\w-]+)\s*\{', CSS):
            depth, i = 1, m.end()
            while depth and i < len(CSS):
                if CSS[i] == '{':
                    depth += 1
                elif CSS[i] == '}':
                    depth -= 1
                i += 1
            yield m.group(1), CSS[m.end():i]

    def test_keyframes_animate_only_opacity_and_transform(self):
        blocks = list(self._keyframes_blocks())
        self.assertGreater(len(blocks), 0, "expected @keyframes in styles.css")
        for name, body in blocks:
            for prop in self.FORBIDDEN:
                self.assertNotRegex(
                    body, r'(?:^|[\s;{])' + re.escape(prop) + r'\s*:',
                    f"@keyframes {name} animates '{prop}' — that's a per-frame "
                    f"repaint (the bug class that shipped twice). Animate "
                    f"opacity/transform instead.")

    def test_no_backdrop_filter_declarations(self):
        self.assertNotRegex(
            CSS, r'backdrop-filter\s*:',
            "backdrop-filter is back in styles.css — Firefox re-blurs the "
            "backdrop every frame (the v4.3.0 'sluggish in Firefox' root "
            "cause). Use an opaque background instead.")

    def test_no_transition_all(self):
        self.assertNotIn(
            'transition: all', CSS,
            "transition:all animates every changed property (incl. layout); "
            "list the intended properties explicitly.")

    def test_table_scroll_wrappers_keep_paint_containment(self):
        for sel in ('.scrollable-table-wrap', '.table-card'):
            block = re.search(re.escape(sel) + r'\s*\{[^}]*\}', CSS)
            self.assertIsNotNone(block, f"{sel} rule missing")
            self.assertIn('contain: paint', block.group(0),
                          f"{sel} lost its contain:paint repaint isolation")


class TestClientRenderGuards(unittest.TestCase):
    """Pins for the dashboard diff-guards and render micro-optimizations."""

    def test_setwidget_skips_identical_html(self):
        self.assertIn('_widgetHtmlCache', APPJS)
        m = re.search(r'function _setWidget\(id, html\) \{(.*?)\n\}', APPJS, re.S)
        self.assertIsNotNone(m)
        self.assertIn('_widgetHtmlCache.get(id) === html', m.group(1),
                      "_setWidget must skip the innerHTML write when unchanged")

    def test_loadhome_has_payload_render_guard(self):
        self.assertIn('window._homeLastRender === _renderKey', APPJS,
                      "loadHome lost its identical-payload skip")

    def test_device_grid_is_windowed(self):
        self.assertIn('DEVICE_CARD_PAGE', APPJS)
        self.assertIn('function showMoreDeviceCards', APPJS)
        self.assertIn('data-action="showMoreDeviceCards"', APPJS)

    def test_logs_tail_appends_instead_of_rebuilding(self):
        self.assertIn('function appendLogLines', APPJS)
        self.assertIn('else appendLogLines(data.lines)', APPJS,
                      "pollLogsTail must append new lines, not rebuild the viewer")

    def test_tablectl_filter_is_debounced(self):
        m = re.search(r'function register\(opts\) \{.*?addEventListener\(.input.,(.*?)\n    \}', APPJS, re.S)
        self.assertIsNotNone(m)
        self.assertIn('setTimeout', m.group(1),
                      "tableCtl filter input lost its debounce")

    def test_i18n_english_early_out(self):
        self.assertIn("if (current === 'en' && !_dirty) return;", I18NJS,
                      "i18n apply() lost the English-session early-out")

    def test_heavy_filter_inputs_carry_debounce_attr(self):
        for input_id in ('cs-filter', 'forecast-filter', 'cmdqueue-filter',
                         'device-search-input', 'checks-filter-text'):
            m = re.search(r'<input[^>]*id="' + input_id + r'"[^>]*>', INDEX)
            self.assertIsNotNone(m, f"#{input_id} input missing from index.html")
            self.assertIn('data-input-debounce', m.group(0),
                          f"#{input_id} lost its data-input-debounce")


class TestApiGzip(unittest.TestCase):
    """App-level gzip: only the safe read-only GET endpoints, only when the
    client advertises gzip, never below the size floor."""

    def setUp(self):
        self._env = {k: os.environ.get(k) for k in
                     ('REQUEST_METHOD', 'PATH_INFO', 'HTTP_ACCEPT_ENCODING')}
        os.environ.update(REQUEST_METHOD='GET', PATH_INFO='/api/home',
                          HTTP_ACCEPT_ENCODING='gzip, deflate, br')

    def tearDown(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_gzip_applies_to_safe_get(self):
        self.assertTrue(api._gzip_response_wanted(5000))

    def test_small_bodies_not_compressed(self):
        self.assertFalse(api._gzip_response_wanted(api._GZIP_MIN_BYTES - 1))

    def test_non_get_never_compressed(self):
        os.environ['REQUEST_METHOD'] = 'POST'
        self.assertFalse(api._gzip_response_wanted(5000))

    def test_client_without_gzip_not_compressed(self):
        os.environ['HTTP_ACCEPT_ENCODING'] = 'identity'
        self.assertFalse(api._gzip_response_wanted(5000))

    def test_unlisted_paths_not_compressed(self):
        for p in ('/api/login', '/api/config', '/api/users', '/api/apikeys'):
            os.environ['PATH_INFO'] = p
            self.assertFalse(api._gzip_response_wanted(5000), p)

    def test_whitelist_has_no_secret_bearing_endpoints(self):
        # BREACH defence: compressing a response that carries tokens/secrets
        # is exactly what nginx's json-gzip opt-out protects against.
        for p in api._GZIP_SAFE_GET_PATHS:
            for needle in ('login', 'config', 'apikey', 'token', 'vault',
                           'user', 'secret'):
                self.assertNotIn(needle, p,
                                 f"{p} looks secret-bearing — not gzip-safe")


class TestFleetChecksCache(unittest.TestCase):
    """The fleet-checks matrix is cached 15s (fingerprint-busted) and the
    RBAC scope filter is applied per request AFTER the cache."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ('USERS_FILE', 'CONFIG_FILE', 'DEVICES_FILE', 'HARDWARE_FILE',
                     'CVE_FINDINGS_FILE', 'CVE_IGNORE_FILE', 'CUSTOM_SCRIPTS_FILE',
                     'METRICS_FILE', 'AUDIT_LOG_FILE'):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self._data_dir = api.DATA_DIR
        api.DATA_DIR = self.d
        self._orig = {n: getattr(api, n) for n in
                      ('require_auth', '_scope_filter_devices', 'respond')}
        api.require_auth = lambda require_admin=False: 'jakob'
        api._scope_filter_devices = lambda d: d
        self.cap = {}

        def _resp(s, b=None):
            self.cap['s'] = s
            self.cap['b'] = b
            raise api.HTTPError(s, b)
        api.respond = _resp
        os.environ['QUERY_STRING'] = ''
        api._LOAD_CACHE.clear()
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'alpha', 'last_seen': int(time.time()), 'sysinfo': {}},
            'd2': {'name': 'beta', 'last_seen': int(time.time()), 'sysinfo': {}},
        })
        api.save(api.CONFIG_FILE, {})

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for attr, v in self._files.items():
            setattr(api, attr, v)
        api.DATA_DIR = self._data_dir

    def _call(self):
        api._LOAD_CACHE.clear()
        try:
            api.handle_fleet_checks()
        except api.HTTPError:
            pass
        return self.cap.get('b')

    def test_second_call_within_ttl_skips_host_checks(self):
        calls = {'n': 0}
        real = api._host_checks

        def counting(*a, **k):
            calls['n'] += 1
            return real(*a, **k)
        api._host_checks = counting
        try:
            first = self._call()
            self.assertEqual(first['total'], 2)
            n_after_first = calls['n']
            self.assertGreater(n_after_first, 0)
            second = self._call()
            self.assertEqual(second['total'], 2)
            self.assertEqual(calls['n'], n_after_first,
                             "second request within TTL must come from cache")
        finally:
            api._host_checks = real

    def test_devices_write_busts_cache(self):
        self._call()
        time.sleep(0.05)
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'alpha', 'last_seen': int(time.time()), 'sysinfo': {}},
        })
        out = self._call()
        self.assertEqual(out['total'], 1,
                         "a devices.json write must invalidate the cache "
                         "(mtime bust on the JSON backend)")

    def test_config_fingerprint_busts_cache(self):
        calls = {'n': 0}
        real = api._host_checks

        def counting(*a, **k):
            calls['n'] += 1
            return real(*a, **k)
        self._call()
        api._host_checks = counting
        try:
            api.save(api.CONFIG_FILE, {'exposure_mutes': [{'device': 'd1', 'port': 80}]})
            self._call()
            self.assertGreater(calls['n'], 0,
                               "an exposure-mute change must bust the cache "
                               "immediately (fingerprint)")
        finally:
            api._host_checks = real

    def test_scope_filter_applies_after_cache(self):
        # Admin warms the cache with both hosts…
        warmed = self._call()
        self.assertEqual(warmed['total'], 2)
        # …then a viewer scoped to d1 must NOT be served d2 from that cache.
        api._scope_filter_devices = lambda d: {k: v for k, v in d.items() if k == 'd1'}
        out = self._call()
        self.assertEqual(out['total'], 1)
        self.assertEqual(out['hosts'][0]['device_id'], 'd1',
                         "scope filtering must happen after the shared cache")


if __name__ == '__main__':
    unittest.main()
