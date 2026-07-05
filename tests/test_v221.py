#!/usr/bin/env python3
"""
Tests for v2.2.1 — design polish release.

Covers:
  - Drift content fetch backend: queueing exec:cat commands, denylist
    enforcement, watched-paths validation, content storage, content
    retrieval.
  - Drift content mirror hook: outputs of `exec:cat <path>` get
    mirrored into drift_contents.json when path is watched; ignored
    otherwise.
  - CSS / JS asset presence: distro icons, sparkline, skeleton,
    typography vars, mobile breakpoints, hover affordances, ✨ identity
    classes, diff view, home dashboard tiles, font import.
  - Index dashboard endpoints compose data without errors.
"""

import sys as _cj_sys
from pathlib import Path as _cj_Path
_cj_sys.path.insert(0, str(_cj_Path(__file__).resolve().parent))
from clientjs import client_js
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT    = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_TMPDIR = tempfile.mkdtemp()
os.environ["RP_DATA_DIR"]      = _TMPDIR
os.environ["REQUEST_METHOD"]   = "GET"
os.environ["PATH_INFO"]        = "/"
os.environ["CONTENT_LENGTH"]   = "0"

_spec = importlib.util.spec_from_file_location("api_v221", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status = status
        self.body = body


def _capture_respond():
    def fake_respond(status, data):
        raise _Captured(status, data)
    api.respond = fake_respond


def _stub_auth(username='admin'):
    api.require_auth = lambda **kw: username
    api.require_admin_auth = lambda: username
    # v5.5.0 (H1): handle_drift_fetch_content now gates on require_perm('command',
    # [dev_id]); stub it too or it does a real scope check and 401s the tests.
    api.require_perm = lambda *a, **kw: username


def _set_method(m='GET', body=None, qs=None):
    os.environ['REQUEST_METHOD'] = m
    os.environ['QUERY_STRING'] = qs or ''
    if body is not None:
        b = json.dumps(body).encode('utf-8')
        os.environ['CONTENT_LENGTH'] = str(len(b))
        class _Shim:
            def __init__(self, data): self.buffer = io.BytesIO(data)
        api.sys.stdin = _Shim(b)
    else:
        os.environ['CONTENT_LENGTH'] = '0'


# ─── Drift content fetch backend ──────────────────────────────────────────


class _DriftContentBase(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        api.DATA_DIR             = self._tmp
        api.DEVICES_FILE         = self._tmp / 'devices.json'
        api.CONFIG_FILE          = self._tmp / 'config.json'
        api.DRIFT_STATE_FILE     = self._tmp / 'drift_state.json'
        api.DRIFT_CONTENTS_FILE  = self._tmp / 'drift_contents.json'
        api.CMDS_FILE            = self._tmp / 'cmds.json'
        api.AUDIT_LOG_FILE       = self._tmp / 'audit_log.json'
        api.WEBHOOK_LOG_FILE     = self._tmp / 'webhook_log.json'
        _capture_respond()
        _stub_auth('admin')
        api.fire_webhook = lambda ev, payload: None
        api.log_command = lambda *a, **kw: None
        api.save(api.DEVICES_FILE, {
            'd1': {'id': 'd1', 'name': 'web01', 'token': 'tok'},
        })


class TestDriftFetchContent(_DriftContentBase):

    def test_queues_cat_for_watched_path(self):
        _set_method('POST', {'paths': ['/etc/ssh/sshd_config']})
        try: api.handle_drift_fetch_content('d1')
        except _Captured as c: r = c
        self.assertEqual(r.status, 200)
        self.assertIn('/etc/ssh/sshd_config', r.body['queued'])
        cmds = api.load(api.CMDS_FILE)
        # v4.4.0: the path is shell-quoted with shlex.quote, which leaves a
        # metachar-free path unquoted (the old code hard-wrapped it in single
        # quotes). The mirror hook's _CAT_CMD_RE matches the bare form too.
        self.assertIn("exec:cat /etc/ssh/sshd_config", cmds['d1'])

    def test_denylist_refuses_shadow(self):
        _set_method('POST', {'paths': ['/etc/shadow', '/etc/ssh/sshd_config']})
        try: api.handle_drift_fetch_content('d1')
        except _Captured as c: r = c
        self.assertIn('/etc/shadow', r.body['denied'])
        # The non-denylisted path should still be queued
        self.assertIn('/etc/ssh/sshd_config', r.body['queued'])
        cmds = api.load(api.CMDS_FILE)
        # And the denylisted cmd is NOT in the queue
        self.assertFalse(any('shadow' in c for c in cmds.get('d1', [])))

    def test_denylist_covers_rotated_copies(self):
        _set_method('POST', {'paths': ['/etc/shadow-', '/etc/gshadow', '/etc/gshadow-']})
        try: api.handle_drift_fetch_content('d1')
        except _Captured as c: r = c
        self.assertEqual(set(r.body['denied']),
                         {'/etc/shadow-', '/etc/gshadow', '/etc/gshadow-'})

    def test_non_watched_path_refused(self):
        # Not in DEFAULT_WATCHED_FILES — refusing prevents the endpoint
        # being used as an arbitrary file-read primitive.
        _set_method('POST', {'paths': ['/etc/some/random/path']})
        try: api.handle_drift_fetch_content('d1')
        except _Captured as c: r = c
        self.assertIn('/etc/some/random/path', r.body['not_watched'])
        cmds = api.load(api.CMDS_FILE)
        self.assertFalse(cmds.get('d1'))

    def test_non_absolute_path_ignored(self):
        _set_method('POST', {'paths': ['etc/passwd', '../escape', '']})
        try: api.handle_drift_fetch_content('d1')
        except _Captured as c: r = c
        self.assertEqual(r.body['queued'], [])
        self.assertEqual(r.body['denied'], [])

    def test_unknown_device_404(self):
        _set_method('POST', {'paths': ['/etc/fstab']})
        try: api.handle_drift_fetch_content('nonexistent')
        except _Captured as c: r = c
        self.assertEqual(r.status, 404)

    def test_invalid_body_400(self):
        _set_method('POST', {'paths': 'not-a-list'})
        try: api.handle_drift_fetch_content('d1')
        except _Captured as c: r = c
        self.assertEqual(r.status, 400)


class TestDriftGetContent(_DriftContentBase):

    def test_returns_captures_chronological(self):
        # Pre-populate two captures
        api.save(api.DRIFT_CONTENTS_FILE, {
            'd1': {
                '/etc/fstab': [
                    {'ts': 100, 'rc': 0, 'content': 'first version'},
                    {'ts': 200, 'rc': 0, 'content': 'second version'},
                ]
            }
        })
        _set_method('GET', qs='path=/etc/fstab')
        try: api.handle_drift_get_content('d1')
        except _Captured as c: r = c
        self.assertEqual(r.status, 200)
        self.assertEqual(len(r.body['captures']), 2)
        self.assertEqual(r.body['captures'][0]['content'], 'first version')
        # SHA-256 calculated
        self.assertTrue(r.body['captures'][0]['sha256'].startswith('sha256:'))

    def test_denylist_blocks_get(self):
        # Even if somehow a denylisted entry made it into the store,
        # GET refuses.
        _set_method('GET', qs='path=/etc/shadow')
        try: api.handle_drift_get_content('d1')
        except _Captured as c: r = c
        self.assertEqual(r.status, 403)
        self.assertTrue(r.body.get('denied'))

    def test_missing_path_400(self):
        _set_method('GET', qs='')
        try: api.handle_drift_get_content('d1')
        except _Captured as c: r = c
        self.assertEqual(r.status, 400)

    def test_relative_path_400(self):
        _set_method('GET', qs='path=etc/fstab')
        try: api.handle_drift_get_content('d1')
        except _Captured as c: r = c
        self.assertEqual(r.status, 400)

    def test_no_captures_yet(self):
        _set_method('GET', qs='path=/etc/fstab')
        try: api.handle_drift_get_content('d1')
        except _Captured as c: r = c
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body['captures'], [])


class TestDriftContentMirror(_DriftContentBase):
    """The hook called from the heartbeat output-ingest path. Mirrors
    `exec:cat <watched_path>` outputs into drift_contents.json."""

    def setUp(self):
        super().setUp()
        # Make /etc/fstab watched but /etc/passwd not (it's not in default
        # list anyway).
        api.save(api.CONFIG_FILE, {
            'drift': {'enabled': True,
                       'default_watched_files': ['/etc/fstab']}
        })

    def test_watched_cat_mirrored(self):
        api._maybe_mirror_drift_content(
            'd1', "exec:cat '/etc/fstab'", 'mount line', 0, 1000)
        store = api.load(api.DRIFT_CONTENTS_FILE)
        self.assertIn('/etc/fstab', store['d1'])
        self.assertEqual(store['d1']['/etc/fstab'][-1]['content'], 'mount line')

    def test_unwatched_cat_not_mirrored(self):
        api._maybe_mirror_drift_content(
            'd1', "exec:cat '/etc/passwd'", 'root:x:0', 0, 1000)
        store = api.load(api.DRIFT_CONTENTS_FILE)
        self.assertNotIn('/etc/passwd', store.get('d1', {}))

    def test_non_cat_command_ignored(self):
        api._maybe_mirror_drift_content(
            'd1', "exec:ls /etc/fstab", 'output', 0, 1000)
        store = api.load(api.DRIFT_CONTENTS_FILE)
        self.assertEqual(store, {})

    def test_denylisted_cat_not_mirrored(self):
        # Belt-and-braces: even if /etc/shadow were watched, the mirror
        # function refuses to store it.
        api.save(api.CONFIG_FILE, {
            'drift': {'default_watched_files': ['/etc/shadow']}
        })
        api._maybe_mirror_drift_content(
            'd1', "exec:cat '/etc/shadow'", 'root:$6$hash', 0, 1000)
        store = api.load(api.DRIFT_CONTENTS_FILE)
        self.assertNotIn('/etc/shadow', store.get('d1', {}))

    def test_capture_history_capped(self):
        for i in range(5):
            api._maybe_mirror_drift_content(
                'd1', "exec:cat '/etc/fstab'", f'version {i}', 0, 1000 + i)
        store = api.load(api.DRIFT_CONTENTS_FILE)
        self.assertEqual(len(store['d1']['/etc/fstab']),
                         api.MAX_DRIFT_CONTENT_CAPTURES)
        # The oldest captures evicted; newest preserved
        self.assertEqual(store['d1']['/etc/fstab'][-1]['content'], 'version 4')

    def test_quoted_path_parsing(self):
        # Single quotes
        api._maybe_mirror_drift_content(
            'd1', "exec:cat '/etc/fstab'", 'content', 0, 1000)
        # Double quotes
        api._maybe_mirror_drift_content(
            'd1', 'exec:cat "/etc/fstab"', 'content2', 0, 2000)
        # No quotes
        api._maybe_mirror_drift_content(
            'd1', 'exec:cat /etc/fstab', 'content3', 0, 3000)
        store = api.load(api.DRIFT_CONTENTS_FILE)
        self.assertEqual(len(store['d1']['/etc/fstab']),
                         api.MAX_DRIFT_CONTENT_CAPTURES)


# ─── CSS / JS / HTML asset presence ─────────────────────────────────────
#
# These read the actual served files and assert the v2.2.1 polish
# pieces are in them. A future commit that accidentally strips out the
# distro logos or skeleton CSS will fail these.


class TestPolishAssets(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.css = (_ROOT / 'server/html/static/css/styles.css').read_text()
        cls.js  = client_js()
        cls.html = (_ROOT / 'server/html/index.html').read_text()

    def test_css_typography_fonts_imported(self):
        # CSP L1 (v3.0.4): bunny.net fonts are now self-hosted under
        # /static/vendor/fonts/. styles.css @imports the local copy.
        self.assertIn('inter-jetbrains.css', self.css,
                      'styles.css should @import the self-hosted fonts CSS')
        vendor_css = (_ROOT / 'server' / 'html' / 'static' / 'vendor'
                      / 'fonts' / 'inter-jetbrains.css').read_text()
        self.assertIn('inter', vendor_css.lower())
        self.assertIn('jetbrains-mono', vendor_css.lower())

    def test_css_status_palette_refined(self):
        # The soft+edge variants
        for var in ('--green-soft', '--green-edge', '--amber-soft',
                    '--amber-edge', '--red-soft', '--red-edge'):
            self.assertIn(var, self.css, f'missing CSS var: {var}')

    def test_css_critical_pulse_animation(self):
        self.assertIn('rp-pulse-critical', self.css)
        self.assertIn('prefers-reduced-motion', self.css)

    def test_css_skeleton_loader(self):
        for cls in ('skeleton', 'skeleton-line', 'skeleton-row',
                    'skeleton-card', 'rp-shimmer'):
            self.assertIn(cls, self.css, f'missing skeleton class: {cls}')

    def test_css_sparkline(self):
        self.assertIn('.sparkline', self.css)

    def test_css_distro_icon(self):
        self.assertIn('.distro-icon', self.css)

    def test_css_hover_affordances(self):
        for cls in ('has-hover-actions', 'row-actions'):
            self.assertIn(cls, self.css)

    def test_css_ai_identity(self):
        for cls in ('ai-btn', 'ai-thinking', 'ai-content',
                    'rp-ai-glow', 'rp-sparkle-cycle'):
            self.assertIn(cls, self.css, f'missing ai class: {cls}')

    def test_css_index_dashboard_tiles(self):
        for cls in ('tile-grid', 'tile-label', 'tile-value',
                    'dash-cols', 'dash-card', 'dash-feed-item',
                    'status-stripe'):
            self.assertIn(cls, self.css, f'missing dashboard class: {cls}')

    def test_css_diff_viewer(self):
        for cls in ('diff-view', 'diff-line', 'diff-line.add',
                    'diff-line.del', 'diff-line.hunk'):
            self.assertIn(cls, self.css, f'missing diff class: {cls}')

    def test_css_mobile_breakpoint(self):
        self.assertIn('max-width: 720px', self.css)
        self.assertIn('mobile-burger', self.css)
        self.assertIn('mobile-nav-open', self.css)

    def test_css_empty_state(self):
        self.assertIn('empty-state', self.css)

    def test_js_distro_icons_defined(self):
        # All the distros we want branded logos for
        for key in ('ubuntu', 'debian', 'arch', 'fedora', 'rhel',
                    'suse', 'alpine', 'nixos', 'cachy'):
            self.assertIn(f"  {key}: {{", self.js,
                          f'missing distro entry: {key}')
        self.assertIn('function getDistroIcon', self.js)

    def test_js_sparkline_renderer(self):
        self.assertIn('function renderSparkline', self.js)
        # Picks colour automatically — make sure the helper code is there
        self.assertIn("var(--amber)", self.js)
        self.assertIn("var(--green)", self.js)

    def test_js_status_stripe(self):
        self.assertIn('renderStatusStripe', self.js)

    def test_js_diff_renderer(self):
        self.assertIn('function computeDiff', self.js)
        self.assertIn('function renderDiff', self.js)
        # LCS — the workhorse
        self.assertIn('_diffLCS', self.js)

    def test_js_home_dashboard(self):
        self.assertIn('function loadHome', self.js)
        self.assertIn('_renderHomeTiles', self.js)
        self.assertIn('_renderHomeAttention', self.js)
        self.assertIn('_renderHomeActivity', self.js)
        self.assertIn('_renderHomeFleet', self.js)

    def test_js_drift_diff_modal(self):
        self.assertIn('function openDriftDiff', self.js)
        self.assertIn('function driftFetchCurrent', self.js)
        self.assertIn('_ensureDriftDiffModal', self.js)
        self.assertIn('renderDiff(', self.js)

    def test_js_ai_identity_helpers(self):
        self.assertIn('applyAiIdentity', self.js)
        self.assertIn('aiThinkingHtml', self.js)

    def test_js_mobile_nav(self):
        self.assertIn('toggleMobileNav', self.js)

    def test_js_openlogs_helper(self):
        # Helper used by per-row hover affordance
        self.assertIn('function openLogsForDevice', self.js)

    def test_html_home_page_present(self):
        self.assertIn('id="page-home"', self.html)
        self.assertIn('id="home-tiles"', self.html)
        self.assertIn('id="home-attention"', self.html)
        self.assertIn('id="home-activity"', self.html)
        self.assertIn('id="home-fleet"', self.html)

    def test_html_home_is_default_active_page(self):
        # page-home has 'active' class on initial paint
        self.assertIn('id="page-home" class="page active"', self.html)
        # page-devices does NOT
        self.assertNotIn('id="page-devices" class="page active"', self.html)

    def test_html_logo_points_home(self):
        # CSP L1 (v3.0.4): the logo's inline onclick was removed; JS now
        # adds the click listener via querySelector('.logo-link').
        # v6.0.0: the brand moved into the sidebar and carries an extra class
        # (`logo logo-link brand`) — pin the prefix, the wiring is unchanged.
        idx = self.html.find('class="logo logo-link')
        self.assertGreater(idx, 0, "logo link not found")
        self.assertIn(".logo-link')?.addEventListener('click'", self.js,
                      "JS should bind a click handler to .logo-link")
        # And the handler navigates to 'home', not 'devices'
        wire = self.js[self.js.find(".logo-link')?.addEventListener('click'"):]
        wire = wire[:300]
        self.assertIn("'home'", wire,
                      "logo click should navigate to home dashboard")

    def test_html_burger_button(self):
        # CSP L1: the inline onclick was removed; JS now binds the burger
        # via querySelector('.mobile-burger'). The function is still defined.
        self.assertIn('mobile-burger', self.html)
        self.assertIn(".mobile-burger')?.addEventListener('click', toggleMobileNav", self.js,
                      "JS should bind toggleMobileNav to .mobile-burger")
        self.assertIn('function toggleMobileNav', self.js)

    def test_html_skeleton_loaders_present(self):
        # Verify at least one skeleton-row replaced a Loading… spinner
        self.assertGreater(self.html.count('skeleton-row'), 5)

    def test_html_drift_page_links_to_docs(self):
        # Documentation link in drift page subtitle
        self.assertIn('docs/drift.md', self.html)


if __name__ == '__main__':
    unittest.main(verbosity=2)
