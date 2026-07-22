"""v6.3.1: protect/baseline-check fixes from the field report.

1. Disabling a check must disable it EVERYWHERE — the Disable button used to
   only hide the row server-side while the heartbeat kept pushing the check to
   the agent (which kept evaluating and, for protect checks, kept
   QUARANTINING), and the ingest sweep kept alerting on it.
2. The heartbeat must send `agent_checks` even when the list is EMPTY — the
   agent only updates its set when the key is present, so omitting it meant
   disabling/deleting a device's last check left the agent running the stale
   set until restart.
3. Checks-page rows carry the custom check's type + protect kind, so the UI
   can offer "Reset baseline" inline and badge protect checks.
"""
import os
import importlib.machinery
import importlib.util
import re
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())

_CGI = Path(__file__).parent.parent / 'server' / 'cgi-bin'
_ldr = importlib.machinery.SourceFileLoader('api', str(_CGI / 'api.py'))
_spec = importlib.util.spec_from_loader('api', _ldr)
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

DEV = 'dev-pc-1'
CHECK = {'id': 'ck_00042', 'name': 'Hosts file unchanged', 'type': 'file_hash',
         'param': '/etc/hosts', 'target_kind': 'all', 'target': '',
         'kind': 'protect'}


class TestDisabledCheckIsFullyOff(unittest.TestCase):
    """A per-device disabled check must not alert from the ingest sweep."""

    def setUp(self):
        self.fired = []
        self._fw = api.fire_webhook
        api.fire_webhook = lambda ev, payload=None: self.fired.append((ev, payload))
        api.save(api.CONFIG_FILE, {
            'custom_checks': [CHECK],
            'host_checks_disabled': {DEV: ['custom:ck_00042']},
        })
        api._invalidate_load_cache(api.CONFIG_FILE)
        api.save(api.DEVICES_FILE, {DEV: {'name': 'host1', 'sysinfo': {}}})
        api._invalidate_load_cache(api.DEVICES_FILE)

    def tearDown(self):
        api.fire_webhook = self._fw

    def _report_critical(self):
        devs = api.load(api.DEVICES_FILE) or {}
        d = devs.get(DEV) or {}
        d.setdefault('sysinfo', {})['custom_check_results'] = {
            CHECK['id']: {'status': 'critical', 'output': 'content changed'}}
        devs[DEV] = d
        api.save(api.DEVICES_FILE, devs)
        api._invalidate_load_cache(api.DEVICES_FILE)
        self.fired.clear()
        api._ingest_custom_check_results(DEV, 'host1')
        return [e for e, _ in self.fired]

    def test_disabled_check_never_alerts(self):
        # Two failing beats: an ENABLED check would fire on the second.
        self.assertEqual(self._report_critical(), [])
        self.assertEqual(self._report_critical(), [])
        state = ((api.load(api.DEVICES_FILE) or {}).get(DEV, {})
                 .get('custom_check_state', {}))
        self.assertNotIn(CHECK['id'], state)

    def test_enabled_check_still_alerts_on_second_beat(self):
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg['host_checks_disabled'] = {}
        api.save(api.CONFIG_FILE, cfg)
        api._invalidate_load_cache(api.CONFIG_FILE)
        self.assertEqual(self._report_critical(), [])          # silent seed
        self.assertIn('custom_check_failed', self._report_critical())


class TestHeartbeatPushHonoursDisable(unittest.TestCase):
    """Source-level pins on the heartbeat push (not unit-drivable in isolation)."""

    def setUp(self):
        self.src = (_CGI / 'api.py').read_text()

    def test_push_filters_disabled_checks(self):
        self.assertIn('_disabled_for_dev', self.src)
        self.assertIn(
            'f"custom:{c.get(\'id\', \'\')}" not in _disabled_for_dev', self.src)

    def test_agent_checks_key_always_sent(self):
        # The gate `if _agent_checks:` before the assignment is the bug — an
        # empty list must still reach the agent so it can DROP its last check.
        self.assertIn("common_resp['agent_checks'] = _agent_checks", self.src)
        self.assertNotRegex(
            self.src,
            re.compile(r"if _agent_checks:\s*\n\s*common_resp\['agent_checks'\]"))

    def test_ingest_skips_disabled(self):
        self.assertIn("f'custom:{cid}' in _disabled", self.src)


class TestChecksRowsCarryTypeAndKind(unittest.TestCase):
    def test_protect_row_fields(self):
        import checks
        rows = checks._custom_checks_for(
            DEV, {'sysinfo': {}}, [CHECK], set())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['ctype'], 'file_hash')
        self.assertEqual(rows[0]['kind'], 'protect')
        self.assertEqual(rows[0]['group'], 'protect')

    def test_ops_row_stays_custom(self):
        import checks
        ops = {'id': 'ck_1', 'name': 'proc', 'type': 'process', 'param': 'x',
               'target_kind': 'all', 'target': ''}
        rows = checks._custom_checks_for(DEV, {'sysinfo': {}}, [ops], set())
        self.assertEqual(rows[0]['kind'], 'custom')
        self.assertEqual(rows[0]['group'], 'custom')

    def test_guard_type_is_protect_even_without_kind_stamp(self):
        import checks
        c = dict(CHECK)
        c.pop('kind')
        rows = checks._custom_checks_for(DEV, {'sysinfo': {}}, [c], set())
        self.assertEqual(rows[0]['kind'], 'protect')


class TestJobFreshMultiPath(unittest.TestCase):
    """v6.4.0: job_fresh accepts `|`-separated / glob candidate paths and uses
    the freshest — so the ClamAV check finds daily.cld OR daily.cvd without the
    operator guessing which extension their host uses (the field-reported
    'daily.cvd not found' while daily.cld exists)."""

    def setUp(self):
        import importlib.machinery, importlib.util
        d = tempfile.mkdtemp()
        self.d = d
        Path(d, 'daily.cld').write_text('x')   # only .cld, like a running host
        ldr = importlib.machinery.SourceFileLoader(
            'rp_agent_jf', str(Path(__file__).parent.parent / 'client' / 'remotepower-agent.py'))
        spec = importlib.util.spec_from_loader('rp_agent_jf', ldr)
        self.ag = importlib.util.module_from_spec(spec)
        try:
            ldr.exec_module(self.ag)
        except SystemExit:
            pass

    def test_alternation_finds_the_existing_extension(self):
        c = {'type': 'job_fresh',
             'param': f'{self.d}/daily.cld|{self.d}/daily.cvd', 'max_age_hours': 48}
        self.assertEqual(self.ag._eval_one_agent_check(c)[0], 'ok')

    def test_glob_finds_it(self):
        c = {'type': 'job_fresh', 'param': f'{self.d}/daily.c?d', 'max_age_hours': 48}
        self.assertEqual(self.ag._eval_one_agent_check(c)[0], 'ok')

    def test_missing_still_critical(self):
        c = {'type': 'job_fresh', 'param': f'{self.d}/nope.xyz', 'max_age_hours': 48}
        self.assertEqual(self.ag._eval_one_agent_check(c)[0], 'critical')

    def test_catalog_clamav_entry_checks_both(self):
        import checks
        row = next((t for t in checks.CHECK_BASELINE_CATALOG
                    if t.get('id') == 'clamav_db_fresh'), None)
        self.assertIsNotNone(row)
        self.assertIn('daily.cld', row['param'])
        self.assertIn('daily.cvd', row['param'])
        self.assertIn('|', row['param'])


class TestRebaselineForcesEval(unittest.TestCase):
    """v6.4.0: a rebaseline guard action must force a sysinfo report on the next
    heartbeat so the check clears promptly (custom checks otherwise re-evaluate
    only every SYSINFO_EVERY polls — the 'Reset baseline did nothing' lag)."""

    def test_agent_force_flag_wired(self):
        src = (Path(__file__).parent.parent / 'client' / 'remotepower-agent.py').read_text()
        self.assertIn('_FORCE_CHECK_EVAL', src)
        # set in the rebaseline branch, consumed in the send_sysinfo gate
        self.assertIn('_FORCE_CHECK_EVAL = True', src)
        self.assertIn('or _FORCE_CHECK_EVAL', src)


class TestCatalogRepairAndApply(unittest.TestCase):
    """v6.4.0: applied catalog checks that dropped a top-level field (pattern)
    or predate a param fix (ClamAV .cvd/.cld, apt stamp) are repaired in place,
    and a NEW apply copies the top-level pattern."""

    def test_repair_backfills_pattern_and_upgrades_paths(self):
        import checks
        applied = [
            {'id': 'ck_1', 'name': 'No obfuscated PHP loader in the web root',
             'type': 'file_contains', 'param': '/var/www::*.php'},          # no pattern
            {'id': 'ck_2', 'name': 'AV signatures updated recently',
             'type': 'job_fresh', 'param': '/var/lib/clamav/daily.cvd'},    # old single
            {'id': 'ck_3', 'name': 'WordPress wp-config.php unchanged',
             'type': 'file_hash', 'param': '/opt/site/wp-config.php'},      # custom path
        ]
        n = checks.repair_applied_catalog_checks(applied)
        self.assertEqual(n, 2)
        self.assertTrue(applied[0].get('pattern'))                          # backfilled
        self.assertIn('daily.cld', applied[1]['param'])                     # upgraded
        self.assertIn('|', applied[1]['param'])
        self.assertEqual(applied[2]['param'], '/opt/site/wp-config.php')    # untouched

    def test_apply_handler_copies_top_level_pattern(self):
        from tests import apisrc
        src = apisrc.api_source()
        self.assertIn("if tmpl.get('pattern'):", src)
        self.assertIn("_row['pattern'] = tmpl['pattern']", src)

    def test_migration_registered_in_both_registries(self):
        from tests import apisrc
        self.assertIn('_maybe_repair_baseline_checks', apisrc.api_source())
        sched = (Path(__file__).parent.parent / 'server' / 'cgi-bin' / 'scheduler.py').read_text()
        self.assertIn('_maybe_repair_baseline_checks', sched)


class TestCustomCheckNeedsAttention(unittest.TestCase):
    """v6.4.0: a failing custom/protect check must reach Needs Attention, not
    only the Alerts inbox."""

    def test_failing_check_appears_in_attention(self):
        api.save(api.CONFIG_FILE, {'custom_checks': [CHECK]})
        api._invalidate_load_cache(api.CONFIG_FILE)
        api.save(api.DEVICES_FILE, {DEV: {
            'name': 'host1', 'monitored': True,
            'last_seen': int(__import__('time').time()),
            'custom_check_state': {CHECK['id']: {
                'status': 'critical', 'output': '/etc/hosts changed'}}}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        items = api._compute_attention()
        cc = [i for i in items if i.get('kind') == 'custom_check']
        self.assertTrue(cc, 'a failing custom check must produce a NA item')
        self.assertEqual(cc[0]['severity'], 'critical')

    def test_disabled_check_absent_from_attention(self):
        api.save(api.CONFIG_FILE, {'custom_checks': [CHECK],
                 'host_checks_disabled': {DEV: ['custom:' + CHECK['id']]}})
        api._invalidate_load_cache(api.CONFIG_FILE)
        api.save(api.DEVICES_FILE, {DEV: {
            'name': 'host1', 'monitored': True,
            'last_seen': int(__import__('time').time()),
            'custom_check_state': {CHECK['id']: {'status': 'critical', 'output': 'x'}}}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        items = api._compute_attention()
        self.assertFalse([i for i in items if i.get('kind') == 'custom_check'])


class TestRebaselineEndToEnd(unittest.TestCase):
    """v6.4.0: the guard-action delivery bug + server-authoritative acceptance.

    Root cause of 'Reset baseline does nothing': _DeviceUpdate yields the whole
    devices collection ({id: dev}); _queue_guard_action treated it AS the
    device, so guard_actions landed on the collection's top level and NEVER
    reached the agent (rebaseline/restore/delete were dead since written)."""

    def setUp(self):
        import guard_handlers
        guard_handlers.bind(api.__dict__)
        self.gh = guard_handlers
        self.crit = '/etc/hosts changed (d078 -> cc51)'
        api.save(api.CONFIG_FILE, {'custom_checks': [CHECK]})
        api._invalidate_load_cache(api.CONFIG_FILE)
        api.save(api.DEVICES_FILE, {DEV: {
            'name': 'h1', 'monitored': True,
            'last_seen': int(__import__('time').time()),
            'sysinfo': {'custom_check_results': {
                CHECK['id']: {'status': 'critical', 'output': self.crit}}}}})
        api._invalidate_load_cache(api.DEVICES_FILE)

    def _dev(self):
        api._invalidate_load_cache(api.DEVICES_FILE)
        return (api.load(api.DEVICES_FILE) or {})[DEV]

    def test_guard_action_lands_on_the_device(self):
        # the bug: it landed on the collection top-level, never delivered
        self.gh._queue_guard_action(DEV, CHECK['id'], 'rebaseline')
        dev = self._dev()
        self.assertEqual(dev.get('guard_actions'),
                         [{'id': CHECK['id'], 'op': 'rebaseline'}])
        self.assertNotIn('guard_actions', api.load(api.DEVICES_FILE))  # not on collection

    def test_acceptance_suppresses_and_survives_reload(self):
        import checks
        self.gh._queue_guard_action(DEV, CHECK['id'], 'rebaseline')
        dev = self._dev()                                  # fresh from storage = a "refresh"
        self.assertEqual(dev.get('custom_check_accepted'), {CHECK['id']: self.crit})
        self.assertEqual(checks._eval_custom_check(CHECK, dev)[0], 'ok')
        # a genuinely NEW change re-fires
        dev['sysinfo']['custom_check_results'][CHECK['id']] = {
            'status': 'critical', 'output': 'a DIFFERENT change'}
        self.assertEqual(checks._eval_custom_check(CHECK, dev)[0], 'critical')


class TestUiWiring(unittest.TestCase):
    _JS = Path(__file__).parent.parent / 'server' / 'html' / 'static' / 'js'
    _HTML = Path(__file__).parent.parent / 'server' / 'html' / 'index.html'

    def test_checks_page_offers_reset_baseline(self):
        js = (self._JS / 'app-checks.js').read_text()
        self.assertIn('_CC_BASELINE_TYPES.has(r.ctype)', js)
        # renderChecks row builder emits the rebaseline action
        self.assertIn('data-action="rebaselineCheck"', js)

    def test_catalog_card_can_unapply(self):
        # The "Applied to …" annotation must carry a remove action per scope —
        # the card used to be apply-only (field report: "where do I disable
        # it?!"). Server ships the check id; client wires bcUnapply.
        src = (Path(__file__).parent.parent / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn("'id': c.get('id'),", src)
        js = (self._JS / 'app-checks.js').read_text()
        self.assertIn('function bcUnapply', js)
        self.assertIn('data-action="bcUnapply"', js)
        # inside the <label class="bc-row"> a plain click would toggle the
        # apply-checkbox — the button must carry data-prevent-default.
        self.assertIn('data-action="bcUnapply" data-arg="${escAttr(id)}" data-stop-prop="1" data-prevent-default', js)

    def test_protect_and_vault_tables_filterable(self):
        html = self._HTML.read_text()
        self.assertIn('id="pc-filter"', html)
        self.assertIn('id="gv-filter"', html)
        js = (self._JS / 'app-checks.js').read_text()
        self.assertIn('function pcFilterChanged', js)
        self.assertIn('function gvFilterChanged', js)

    def test_baseline_catalog_is_filterable_and_capped(self):
        # v6.4.0: big-fleet tidiness — the ~76-template catalog needs a text
        # filter, and its list + the applied-host list must be capped (never
        # flood the modal when a template is applied across a huge tag/group).
        html = self._HTML.read_text()
        self.assertIn('id="bc-text-filter"', html)
        # catalog list + host list are scroll-capped
        self.assertIn('id="bc-catalog" class="scroll-cap', html)
        js = (self._JS / 'app-checks.js').read_text()
        self.assertIn('function bcTextFilter', js)
        # the applied-host list is capped + individually filterable
        self.assertIn('scroll-cap-sm', js)
        self.assertIn('function filterHostList', js)


if __name__ == '__main__':
    unittest.main()
