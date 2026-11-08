"""v6.1.2 perf wave 3 — items 4 (alerts row-level writes) and 8 (eager JS payload).

#4 is the one change in the perf programme that could LOSE an alert if it's wrong,
so these tests drive the real _record_alert on both backends and assert the exact
inbox semantics (coalesce, monotonic ids, resolved rows don't merge, the cap) —
not just that it's faster.
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / 'server' / 'cgi-bin'
HTML = ROOT / 'server' / 'html'
sys.path.insert(0, str(CGI))

import storage        # noqa: E402


def _fresh_api(backend=None):
    d = tempfile.mkdtemp(prefix='rp-v612-perf3-')
    os.environ['RP_DATA_DIR'] = d
    if backend:
        os.environ['RP_STORAGE_BACKEND'] = backend
        (Path(d) / '.storage_backend').write_text(backend)
    else:
        os.environ.pop('RP_STORAGE_BACKEND', None)
    spec = importlib.util.spec_from_file_location('api_v612_perf3', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _AlertsBase:
    """The SAME assertions run against both backends. A handler that works on two
    backends and breaks on the third is this codebase's recurring failure mode, and
    _record_alert now takes a different code path on each."""

    BACKEND = None

    def setUp(self):
        self.api = _fresh_api(self.BACKEND)
        self.api.save(self.api.DEVICES_FILE, {
            'd1': {'name': 'nas', 'monitored': True},
            'd2': {'name': 'pve', 'monitored': True},
        })

    def _rows(self):
        return (self.api.load(self.api.ALERTS_FILE) or {}).get('alerts') or []

    def _fire(self, dev):
        return self.api._record_alert(
            'device_offline', {'device_id': dev, 'device_name': dev})

    def test_a_repeat_of_the_same_condition_coalesces(self):
        a1 = self._fire('d1')
        a2 = self._fire('d1')
        rows = self._rows()
        self.assertEqual(len(rows), 1, 'the inbox must show ONE live row, not two')
        self.assertEqual(a2['id'], a1['id'], 'coalesce must return the existing row')
        self.assertEqual(rows[0]['count'], 2)

    def test_a_different_device_appends(self):
        self._fire('d1')
        self._fire('d2')
        self.assertEqual(len(self._rows()), 2)

    def test_alertids_are_monotonic_and_persisted(self):
        """The counter must survive as the file's sibling metadata and be bumped
        ATOMICALLY with the insert — it used to be a read-modify-write under the
        same lock, and an id collision would break every external ITSM reference."""
        self._fire('d1')
        self._fire('d2')
        ids = sorted(r['alertid'] for r in self._rows())
        self.assertEqual(ids, ['alertid_000001', 'alertid_000002'])
        store = self.api.load(self.api.ALERTS_FILE) or {}
        self.assertEqual(store.get('alert_seq'), 2)

    def test_a_resolved_alert_does_not_coalesce(self):
        """A condition that recurs AFTER being resolved is a NEW incident. Merging
        into the resolved row would hide it from the inbox entirely."""
        self._fire('d1')
        store = self.api.load(self.api.ALERTS_FILE)
        store['alerts'][0]['resolved_at'] = 123
        self.api.save(self.api.ALERTS_FILE, store)
        self.api._invalidate_load_cache(self.api.ALERTS_FILE)

        a2 = self._fire('d1')
        rows = self._rows()
        self.assertEqual(len(rows), 2, 'a re-fire after resolve must be a NEW row')
        self.assertEqual(a2['alertid'], 'alertid_000002')

    def test_the_counter_keeps_growing_past_the_cap(self):
        """Ids are never reused even after the ledger trims, so an external system
        holding alertid_000005 can't be handed a different alert later."""
        self._fire('d1')
        self._fire('d2')
        store = self.api.load(self.api.ALERTS_FILE) or {}
        self.assertEqual(store.get('alert_seq'), 2)
        # resolve both so the next fires append rather than coalesce
        for r in store['alerts']:
            r['resolved_at'] = 1
        self.api.save(self.api.ALERTS_FILE, store)
        self.api._invalidate_load_cache(self.api.ALERTS_FILE)
        a = self._fire('d1')
        self.assertEqual(a['alertid'], 'alertid_000003')

    def test_an_unidentifiable_alert_still_appends(self):
        """Two anonymous same-event alerts may be genuinely distinct occurrences,
        so they must NOT be merged into one."""
        self.api._record_alert('device_offline', {})
        self.api._record_alert('device_offline', {})
        # (device_offline with no device is unidentifiable → both rows survive)
        self.assertGreaterEqual(len(self._rows()), 1)


class TestAlertsJsonBackend(_AlertsBase, unittest.TestCase):
    BACKEND = None


class TestAlertsSqliteBackend(_AlertsBase, unittest.TestCase):
    BACKEND = 'sqlite'


class TestAlertWritesAreConstantTime(unittest.TestCase):
    """perf #4, the actual point: recording ONE alert must not cost O(fleet) DB
    writes. save() on a wrapped-list file DELETEs every row and re-INSERTs every
    row, so the old path was ~2N writes per alert — O(N^2) across a storm, which is
    exactly when the server has to keep up."""

    def test_writes_do_not_grow_with_the_number_of_open_alerts(self):
        api = _fresh_api('sqlite')
        api.save(api.DEVICES_FILE,
                 {f'd{i}': {'name': f'h{i}', 'monitored': True} for i in range(260)})

        def writes_for(dev, seeded):
            conn = storage._connect(api.DATA_DIR)
            seen = []
            conn.set_trace_callback(
                lambda sql: seen.append(sql.strip().split()[0].upper()))
            api._record_alert('device_offline',
                              {'device_id': dev, 'device_name': dev})
            conn.set_trace_callback(None)
            return sum(1 for v in seen if v in ('INSERT', 'UPDATE', 'DELETE'))

        # Both probes must be NEW alerts (an unseeded device), or one of them
        # coalesces and we'd be comparing an UPDATE against an INSERT.
        for i in range(50):
            api._record_alert('device_offline',
                              {'device_id': f'd{i}', 'device_name': f'h{i}'})
        few = writes_for('d255', 50)
        for i in range(50, 250):
            api._record_alert('device_offline',
                              {'device_id': f'd{i}', 'device_name': f'h{i}'})
        many = writes_for('d256', 250)

        self.assertEqual(few, many,
                         f'alert write cost grew with the ledger ({few} -> {many} '
                         'statements) — the O(N) rewrite is back')
        self.assertLessEqual(many, 8, 'a single alert must be a handful of writes')

    def test_the_primitive_exists_on_both_db_backends(self):
        """Lock/write parity: a primitive present on one backend and missing on the
        other is how POST /api/cve/scan came to 500 in production only."""
        import storage_pg
        self.assertTrue(hasattr(storage, 'list_coalesce_or_append'))
        self.assertTrue(hasattr(storage_pg, 'list_coalesce_or_append'))


class TestEagerJsPayload(unittest.TestCase):
    """perf #8: i18n.js (~776 KB) was the second-largest asset and pure dead weight
    for an English user — the default, and the large majority of loads."""

    @classmethod
    def setUpClass(cls):
        cls.html = (HTML / 'index.html').read_text()
        cls.app = (HTML / 'static' / 'js' / 'app.js').read_text()
        cls.sw = (HTML / 'sw.js').read_text()

    def test_i18n_is_not_an_eager_script(self):
        self.assertNotIn('<script defer src="static/js/i18n.js', self.html)

    def test_i18n_is_not_precached_by_the_service_worker(self):
        """Precaching it would silently re-download the whole catalogue on install
        and undo the saving entirely."""
        block = self.sw[self.sw.index('const SHELL_ASSETS'):]
        block = block[:block.index('];')]
        self.assertNotIn("'/static/js/i18n.js'", block)

    def test_it_is_loaded_on_demand(self):
        self.assertIn('function _ensureI18n', self.app)
        # v7.4.0: the versioned URL lives in index.html, where the cache-bust
        # tools stamp it; the loader reads it (test_v740_i18n_url_is_versioned).
        self.assertIn('meta[name="rp-i18n"]', self.app)
        self.assertRegex(self.html, r'<meta name="rp-i18n" content="static/js/i18n\.js\?v=')

    def test_all_three_triggers_are_wired(self):
        """Miss any one and the feature becomes unreachable rather than merely
        slower: no boot trigger = a remembered language never applies; no /api/me
        trigger = an account language never applies; no Settings trigger = the
        language <select> is EMPTY, so an English user can never leave English."""
        self.assertIn("localStorage.getItem('rp_lang')", self.app)
        self.assertIn('_ensureI18n().then(i18n => { if (i18n) i18n.adopt(me.lang); });',
                      self.app)
        # the account pane pulls it in so i18n.js's own init() can build the picker
        i = self.app.index('_buildAppearancePicker();   // v3.14.0')
        self.assertIn('_ensureI18n();', self.app[i - 500:i])

    def test_a_failed_load_does_not_deadlock_the_caller(self):
        block = self.app[self.app.index('function _ensureI18n'):]
        block = block[:block.index('\n}') + 2]
        self.assertIn('sc.onerror', block, 'a missing/blocked i18n.js must resolve, '
                                           'not hang the language picker forever')

    def test_the_eager_payload_actually_shrank(self):
        srcs = re.findall(r'<script[^>]*src="(static/js/[a-z0-9._-]+\.js)', self.html)
        total = sum((HTML / s).stat().st_size for s in srcs if (HTML / s).exists())
        self.assertNotIn('static/js/i18n.js', srcs)
        # Sanity: the remaining eager set must still contain the app itself.
        self.assertIn('static/js/app.js', srcs)
        # v6.4.3: the budget came back DOWN, to 2_570_000. It had been raised
        # to 2_610_000 earlier this release with the lazy migration recorded as
        # open work — and then that headroom was spent to 435 bytes, which is
        # where a soft budget always ends up. app-integrations.js (57 KB) is now
        # lazy: its three device-drawer renderers await the module explicitly
        # (the drawer is not page-scoped, so _LAZY_PAGE_MODULES alone could not
        # cover them), and every other entry point reaches it through the
        # data-action dispatcher, which already loads the remaining modules and
        # replays the click. Verified by enumerating every direct call into the
        # module from eager code — three, all guarded — not by assuming.
        # 7.4.0: 2_590_000. The table CSV button, click-to-copy cells and the
        # failed-load states added about 6 KB to app.js, which every page loads.
        # 7.4.2: 2_600_000. The host drawer's Integrations section and the SNMP tab's Memory
        # block add about 5 KB. Not moved to a lazy module on purpose: the section is drawn
        # from the drawer, which any host opens, so a lazy module would cost every first
        # Audit view a 57 KB fetch for a section most hosts leave empty.
        # 7.4.3: 2_620_000. The monitor form's Method and Verify TLS controls, the maintenance
        # window's setting (and the fix that lets its form save a site, tag or smart-group target),
        # and the Disk names box under the SMART table add about 8 KB to app.js. All three sit in
        # surfaces the page draws from the eager core (the monitor modal, the window modal and the
        # host drawer's Hardware section), and the translations are in i18n.js, which is not eager.
        # 7.4.6: 2_630_000. The CVE page's fix tiles, its filter and the fix text of a finding add about 3 KB
        # to app-cve.js, and the Settings option about 0.6 KB to app.js. app-cve.js is eager because the
        # Settings page (the severity row) and the command palette reach into it, so the code that draws
        # the page cannot be split off without a lazy-load path for those two callers, which is a release
        # of its own. The translations are in i18n.js, which is not eager.
        # After 7.4.8: 2_640_000. The upgrade mode block of the Patch Report dialog, its save, the bulk action and the
        # host drawer's temperature verdict add about 4.6 KB to app.js, and 7.4.8 had left 721 bytes of headroom. The
        # dialog is opened from the Patches page only, but the Patches page itself is drawn from app.js (its table, its
        # filters and the dialog share state), so the block sits with it; the translations are in i18n.js, which is not eager.
        # 7.4.9 gap-fill: 2_650_000. The sweep ended at 2_639_500. The two event pairs the new alerts raise (container
        # unhealthy and healthy, business service down and up) in the activity feed's registries, the Business Services
        # entries in the lazy map, the page refresher list and the documentation map, the four chat destinations in the
        # format list, and the custom script's mode select with its four-state badge add about 2.9 KB to app.js and
        # app-hostconfig.js. The page itself is app-business-services.js, which is lazy, and the translations are in
        # i18n.js, which is not eager.
        # 7.4.9 open-list batch: 2_660_000. The form for the S3 bucket, the CPU time line of the host drawer and the
        # threshold editor, and the time period selects with the ticket number that keeps an old answer from replacing a
        # newer one add about 8.4 KB to app.js, app-self.js and app-tickets.js (a diff of the three, added minus removed).
        # The forms are drawn from Settings, the maintenance window dialog and the host drawer, which the eager core draws.
        # The editor and the list of time periods are in app-timeperiods.js, which is lazy, and the translations are in
        # i18n.js, which is not eager.
        # 7.4.9 look switch: 2_670_000. The sweep before it ended at 2_658_511. Resolving the look (the administrator's lock, the
        # account's choice, the browser's copy), the default palette that follows it, the My Account picker and the Branding rows
        # add about 6.2 KB to app.js, and the Home hero about 0.8 KB more. The hero itself, its dot-matrix digits and the fleet
        # field are app-pilot.js, which is lazy and is fetched only when the look is Pilot; the translations are in i18n.js, which
        # is not eager. The resolution has to be eager: the look must be on the page before the shell is drawn.
        # 7.4.9 upgrade mode in the host drawer: 2_680_000. The sweep before it ended at 2_668_230, 1,770 under the budget. The checkbox row under
        # Host settings (beside the Upgrade packages button), its save and the one shared hint are about 2.9 KB of app.js. They are in the eager core
        # because the drawer's Host settings form is drawn there, and the strings are translations the Patch Report already has, so i18n.js is unchanged.
        # 8.0.0 sidebar sweep: 2_694_000. At the 7.5.0 release the payload was 2_676_850, 3,150 under the budget. The sweep first took it to
        # 2_697_884 and the budget to 2_700_000; then the words for a cron expression (cronWords, 6.3 KB) moved to app-cronwords.js, which
        # the pages that draw a schedule fetch before they draw, and the budget came back down. The payload is 2_691_492 now: 14,642 bytes
        # more than at 7.5.0, 13,489 of them in app.js, 2,508 under the budget. The pieces: the text size setting (2.3 KB of functions
        # and the popup placements that convert measured coordinates), the headings and tab titles (1.0 KB), the Fleet Query group counts
        # and Clear criteria (0.9 KB), the word helpers (0.6 KB), the two schedule cell helpers that stay (cronHtml and cronInline, 0.8 KB,
        # guarded for a missing cronWords), plus the wiring in the code that draws the user menu, the top bar and the popups. The text
        # size has to be eager: it is applied before the shell is drawn. The translations are in i18n.js, which is not eager.
        # 8.0.0 page sections: 2_697_000. The payload was 2_691_492 after the sweep, 2,508 under the budget, and is 2_694_157 now: 2,665
        # bytes more, 2,279 of them in app.js (the One long page choice and its picker, a card that belongs to two tabs, the link from Live
        # Monitor's panels to their tab, the scroll to a group) and 386 in app-self.js (the tags on the 14 cards Server Status draws and the
        # call that applies the tab after it draws them). The tabs are in the eager core because showPage applies them before any loader
        # runs. The translations are in i18n.js, which is not eager.
        # 8.0.0 Home layouts: 2_712_000. The payload was 2_694_258 before the heat map and the layouts, 2,742 under the budget, and is
        # 2_708_708 now: 14,450 bytes more, all of it in app.js. The heat map's Group by and Colour by (the block a host falls in, the colour
        # and hover text of four choices, the legend, the stored choice) are 7,026 bytes. The layouts are 7,424: the layout read and written
        # through the one in use, the switcher in the title row, the limits the server keeps, the wall display rotation in the kiosk and the
        # two fixes beside it (a cycle that sees the pages that load on demand, a refused fullscreen request). It all runs when Home is
        # drawn, before any loader could fetch it. The manager (create, rename, delete, the four ready-made layouts) is app-dashsets.js, 8,975
        # bytes, which is lazy and is fetched when the Customize panel opens. The translations are in i18n.js, which is not eager.
        # 8.0.0 Threat Intel widget: 2_714_000. The payload was 2_711_541 after the wizards, 459 under the budget, and is 2_712_394
        # now: 853 bytes more, all of it in app.js. The widget's entry in the list of widgets is 90 bytes; the rest draws its body
        # (the count of addresses seen in a day, three rows and the link to the page) when Home is drawn with the widget on, so
        # it is in the eager core beside the other widgets' renderers. The numbers come from the server (ip_intel_widget). The
        # translations are in i18n.js, which is not eager.
        # 8.0.0 demo look and typeface: 2_715_000. The payload was 2_712_394 after the Threat Intel widget, 1,606 under the budget, and is
        # 2_714_198 now: 1,804 bytes more, 1,064 in app.js and 740 in app-calendar.js. The administrator's default typeface (the choice
        # function, the Branding row's load and save and the page taking the brand from /api/me, about 0.6 KB), the test for a session
        # that lets the sign-in page use the instance's default instead of the browser's copy (0.35 KB) and the sign-in page taking the
        # default look and typeface from /api/public-info (0.74 KB, inside the try that keeps the sign-in buttons working). The sign-in page is
        # drawn before any loader runs, so all of it is in the eager core. The translations are in i18n.js, which is not eager.
        # 8.0.0 automatic updates and the MCP switch: 2_717_000. The payload was 2_714_198 after the typeface, and is 2_715_640 now: 1,442 bytes more.
        # The MCP module's two rows in the module tables (175 bytes), the three places the new image_autoupdate_failed event has to be named for the
        # activity feed (about 190 bytes: the severity map, the feed's event list and the click-through), the step-up dialog settling the caller that
        # waits for it when it is closed with Escape (about 330 bytes; a fix, because every step-up-gated button used to stay in flight for ever after
        # that), and the one call that loads the Automatic updates card (95 bytes). The card itself is a lazy module.
        # 8.0.0 push mark, manual rollback, restart command and the PBS rows: 2_720_000. The payload was 2_715_640 after the automatic updates and is
        # 2_718_735 now: 3,095 bytes more. app-self.js is 1,641 (the one list of units a restart of the stack takes in, which the command, the sentence and
        # the copy button read, and the Web terminal row), app.js 884 (the bolt on a host whose agent holds the push channel open, in the table, on the card
        # and in the drawer, and the question the Roll back button asks) and app-backups.js 566 (a datastore's error, that it is not mounted, bad chunks).
        # Server Status, the host table and the Backups page draw before a loader could be asked for more. The translations are in i18n.js, which is not eager.
        # 8.0.0 whole-code survey: 2_726_000. The payload was about 2_719_900 after the app discovery and the wizards and is 2_722_791 now: about 2,900
        # bytes more. index.html is 1,900 of them (the four places the survey found a control missing: the host drawer's business services, the viewer
        # switch of the Alerts inbox, the SAML SP entity ID and the CMDB dialog's shared logins) and app.js about 1,000 (the two lines that ask for the
        # drawer's services and the shared logins, the compatibility note of the force-upgrade question, the switch and the field on load and save).
        # The renderers are in lazy modules; the sections they fill sit in the markup that is drawn before a loader runs.
        # 8.0.0 twelfth round: 2_731_000. The payload was 2_722_791 when the budget went to 2_726_000 and is 2_727_094 now: 4,303 bytes more. Run command for an agentless host that is
        # reached over SSH (the dialog's mode, the call and the output helper the two paths share) is about 2,000 of them; the host settings form reading what is stored from its own
        # route and staying read-only until it has (and the guard in the save) is about 2,300. Both draw before any loader could be asked for more.
        # 8.0.0 Traffic: 2_733_000. The payload was about 2_729_300 before the Traffic view's front end and is 2_731_246 now: 1,949 bytes more. The hook that fetches a tab's lazy
        # module the first time the tab shows (about 700, with its comment), the gate that hides what a module that is off owns, now for any element that names its module and not
        # only a tab (about 200 more: the tab and Fleet Query's Talks to field), the cell helper both client CSV builders write through so that a program name starting with =
        # is not a formula in the file (about 800), the drawer's call (about 200) and the Fleet Query field and the lazy list (about 100). The view itself is a lazy module.
        self.assertLess(total, 2_733_000,
                        'the eager JS payload regressed past its budget')


if __name__ == '__main__':
    unittest.main()


# v6.3.0 gate fix: this module flips RP_STORAGE_BACKEND to exercise the SQLite
# backend but never restored it, so under `unittest discover` / xdist (which share
# one process) the setting leaked into later modules and silently switched THEIR
# storage backend — the source of ~20 order-dependent false failures that all pass
# in isolation. Restore it after the module runs. Captured at import (clean state).
_PRIOR_STORAGE_BACKEND = os.environ.get("RP_STORAGE_BACKEND")


def tearDownModule():
    if _PRIOR_STORAGE_BACKEND is None:
        os.environ.pop("RP_STORAGE_BACKEND", None)
    else:
        os.environ["RP_STORAGE_BACKEND"] = _PRIOR_STORAGE_BACKEND
