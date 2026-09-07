"""v7.0.3: five more risk factors over signals collected and scored nowhere.

Same shape as the v6.4.1 sweep, and the same reason for the harness. Each of
these five is persisted by `safe_si`, read by a page or by the Checks engine,
and contributed nothing to a host's risk number:

  secure_boot_off      UEFI Secure Boot reported off (Linux EFI var / Windows)
  canary_not_armed     a configured honeytoken the agent could not plant
  files_quarantined    the integrity guard has quarantined files on the host
  timer_failed         a systemd TIMER failed, so a scheduled job is not running
  custom_check_failed  the operator's own checks, failing

Every test drives the REAL `_compute_fleet_risk` rather than `_device_risk`
with hand-built kwargs, because the kwargs are exactly the part that can go
unfilled — `custom_defs` is threaded in by the fleet sweep and a factor whose
input nothing supplies is dead however well it is written.

Two things are pinned NEGATIVELY, and both are the point of the design:

* A host that never reported Secure Boot must not score. The field is
  tri-state; a BIOS machine and a Windows host with Secure Boot disabled are
  different facts, and only the second is a finding.
* A canary in state `watching` must not score. `failed` means the decoy could
  not be planted; `watching` means a real file was already at that path and is
  being monitored for change. Scoring the second would flag a working setup.

ECC counters were the sixth candidate and are left alone: the reliability
score already weights them, and one hardware fault counted by two scores makes
both numbers wrong rather than one of them better.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix='rp-r703-'))
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))

import api  # noqa: E402

DEV = 'r703'
_NEW = ('secure_boot_off', 'canary_not_armed', 'files_quarantined',
        'timer_failed', 'custom_check_failed')


class _RiskCase(unittest.TestCase):
    """Every store the scorer reads is reset here — they are shared across test
    modules in an xdist worker, and a leftover row from another module is the
    order-dependent false-failure class."""

    def setUp(self):
        self._si({})
        for f in (api.CVE_FINDINGS_FILE, api.AV_FILE, api.IMAGE_CVE_FILE,
                  api.SECRETS_FILE, api.CVE_IGNORE_FILE, api.PACKAGES_FILE,
                  api.SOFTWARE_VIOLATIONS_FILE, api.HARDWARE_FILE,
                  api.KEV_EPSS_FILE, api.DATA_DIR / 'backup_state.json'):
            api.save(f, {})
            api._invalidate_load_cache(f)
        self._cfg({})

    def _si(self, si):
        api.save(api.DEVICES_FILE, {DEV: {'name': 'web01',
                                          'last_seen': int(api.time.time()),
                                          'sysinfo': si}})
        api._invalidate_load_cache(api.DEVICES_FILE)

    def _cfg(self, cfg):
        api.save(api.CONFIG_FILE, cfg)
        api._invalidate_load_cache(api.CONFIG_FILE)

    def _factors(self):
        api._invalidate_load_cache(api.CONFIG_FILE)
        rows = [r for r in api._compute_fleet_risk() if r['device_id'] == DEV]
        self.assertEqual(len(rows), 1, 'expected exactly one row for the host')
        return {f['kind']: f for f in rows[0]['factors']}, rows[0]


class TestTheFactorsExist(_RiskCase):

    def test_each_has_a_weight(self):
        missing = [k for k in _NEW if k not in api._RISK_WEIGHTS]
        self.assertEqual(missing, [], f'no weight: {missing}')

    def test_each_is_operator_tunable(self):
        """Weights are saved through _weight_param_specs, whose key set is
        derived from _RISK_WEIGHTS — so this fails only if the derivation is
        replaced by a hand-kept list."""
        keys = {spec[0] for spec in api._weight_param_specs()}
        for k in _NEW:
            self.assertIn(f'risk_weight_{k}', keys)

    def test_a_clean_host_scores_none_of_them(self):
        """Positive control for every assertion below: with an empty sysinfo
        none of these may fire, so a test that later sees one is seeing the
        signal it seeded and not a factor that fires unconditionally."""
        factors, _row = self._factors()
        fired = [k for k in _NEW if k in factors]
        self.assertEqual(fired, [], f'fired on a host with no data: {fired}')


class TestSecureBoot(_RiskCase):

    def test_reported_off_scores(self):
        self._si({'secure_boot': False})
        factors, _ = self._factors()
        self.assertIn('secure_boot_off', factors)
        self.assertEqual(factors['secure_boot_off']['points'],
                         api._RISK_WEIGHTS['secure_boot_off'])

    def test_reported_on_does_not_score(self):
        self._si({'secure_boot': True})
        self.assertNotIn('secure_boot_off', self._factors()[0])

    def test_never_reported_does_not_score(self):
        """Tri-state. A BIOS machine reports nothing, and 'we were never told'
        is not 'we were told no'."""
        self._si({'kernel': '6.9.3'})
        self.assertNotIn('secure_boot_off', self._factors()[0])

    def test_the_windows_producer_is_read_too(self):
        """The Windows agent reports it under win_posture. Reading one producer
        is how the posture columns answered 'unknown' on every Windows host."""
        self._si({'win_posture': {'secure_boot': False}})
        self.assertIn('secure_boot_off', self._factors()[0])


class TestCanary(_RiskCase):

    def test_a_canary_that_could_not_be_planted_scores(self):
        self._si({'canary_status': [
            {'path': '/root/.aws/credentials', 'state': 'failed',
             'detail': 'read-only file system'}]})
        factors, _ = self._factors()
        self.assertIn('canary_not_armed', factors)
        self.assertIn('1', factors['canary_not_armed']['detail'])

    def test_an_armed_canary_does_not_score(self):
        self._si({'canary_status': [{'path': '/root/.k', 'state': 'armed'}]})
        self.assertNotIn('canary_not_armed', self._factors()[0])

    def test_a_watching_canary_does_not_score(self):
        """'watching' means a real file was already there and is being watched
        for change. It is a weaker thing than a honeytoken, not a gap — and
        scoring it would put a working setup on a findings list."""
        self._si({'canary_status': [{'path': '/etc/shadow', 'state': 'watching'}]})
        self.assertNotIn('canary_not_armed', self._factors()[0])


class TestQuarantine(_RiskCase):

    def test_quarantined_files_score(self):
        self._si({'guard_quarantine': [
            {'id': 'q1', 'orig': '/usr/local/bin/x', 'check': 'binary', 'ts': 1},
            {'id': 'q2', 'orig': '/tmp/y', 'check': 'binary', 'ts': 2}]})
        factors, _ = self._factors()
        self.assertIn('files_quarantined', factors)
        self.assertEqual(factors['files_quarantined']['points'],
                         2 * api._RISK_WEIGHTS['files_quarantined'])

    def test_the_count_is_capped(self):
        self._si({'guard_quarantine': [
            {'id': f'q{i}', 'orig': f'/tmp/{i}', 'check': 'b', 'ts': i}
            for i in range(50)]})
        factors, _ = self._factors()
        self.assertEqual(factors['files_quarantined']['points'],
                         api._RISK_CAPS['files_quarantined'])


class TestFailedTimers(_RiskCase):

    def test_a_failed_timer_scores(self):
        self._si({'timers': [
            {'unit': 'backup.timer', 'activates': 'backup.service', 'failed': True},
            {'unit': 'fstrim.timer', 'activates': 'fstrim.service', 'failed': False}]})
        factors, _ = self._factors()
        self.assertIn('timer_failed', factors)
        self.assertIn('backup.timer', factors['timer_failed']['detail'])

    def test_it_is_separate_from_failed_units(self):
        """A timer that cannot fire leaves the unit it activates looking fine,
        because that unit is simply never started — which is why folding this
        into failed_units would hide it."""
        self._si({'timers': [{'unit': 'backup.timer', 'failed': True}],
                  'failed_units': []})
        factors, _ = self._factors()
        self.assertIn('timer_failed', factors)
        self.assertNotIn('failed_units', factors)

    def test_healthy_timers_do_not_score(self):
        self._si({'timers': [{'unit': 'fstrim.timer', 'failed': False}]})
        self.assertNotIn('timer_failed', self._factors()[0])


class TestCustomChecks(_RiskCase):
    """The one factor whose input is threaded in by the fleet sweep rather than
    read off the device record — so these drive _compute_fleet_risk, where an
    unfilled kwarg would show up as silence."""

    def _with_check(self, cdef, si):
        self._si(si)
        self._cfg({'custom_checks': [cdef]})

    def test_a_failing_process_check_scores(self):
        self._with_check(
            {'id': 'c1', 'name': 'nginx must run', 'type': 'process',
             'param': 'nginx'},
            {'proc_names': ['sshd', 'cron']})
        factors, _ = self._factors()
        self.assertIn('custom_check_failed', factors)
        self.assertIn('nginx must run', factors['custom_check_failed']['detail'])

    def test_a_passing_check_does_not_score(self):
        self._with_check(
            {'id': 'c1', 'name': 'nginx must run', 'type': 'process',
             'param': 'nginx'},
            {'proc_names': ['nginx', 'sshd']})
        self.assertNotIn('custom_check_failed', self._factors()[0])

    def test_an_unknown_check_does_not_score(self):
        """No process data reported is 'unknown', not 'critical'. Scoring it
        would put every host that has not reported yet on the findings list."""
        self._with_check(
            {'id': 'c1', 'name': 'nginx must run', 'type': 'process',
             'param': 'nginx'},
            {})
        self.assertNotIn('custom_check_failed', self._factors()[0])

    def test_a_disabled_check_does_not_score(self):
        """The per-device disabled list is honoured because the verdict comes
        from checks._custom_checks_for and not a second implementation."""
        self._si({'proc_names': ['sshd']})
        self._cfg({'custom_checks': [{'id': 'c1', 'name': 'nginx must run',
                                      'type': 'process', 'param': 'nginx'}],
                   'host_checks_disabled': {DEV: ['custom:c1']}})
        self.assertNotIn('custom_check_failed', self._factors()[0])

    def test_an_agent_evaluated_check_scores_too(self):
        """file/job/log checks are evaluated on the host and reported back in
        sysinfo.custom_check_results — a different path from process/port, and
        the one a scorer reading only sysinfo would have covered alone."""
        self._with_check(
            {'id': 'c2', 'name': 'sshd config unchanged', 'type': 'file_hash',
             'param': '/etc/ssh/sshd_config'},
            {'custom_check_results': {'c2': {'status': 'critical',
                                             'output': 'hash changed'}}})
        self.assertIn('custom_check_failed', self._factors()[0])

    def test_a_warning_scores_less_than_a_critical(self):
        self._with_check(
            {'id': 'c2', 'name': 'log quiet', 'type': 'log_errors',
             'param': 'oops'},
            {'custom_check_results': {'c2': {'status': 'warning', 'output': '1'}}})
        warn = self._factors()[0]['custom_check_failed']['points']
        self._with_check(
            {'id': 'c2', 'name': 'log quiet', 'type': 'log_errors',
             'param': 'oops'},
            {'custom_check_results': {'c2': {'status': 'critical', 'output': '1'}}})
        crit = self._factors()[0]['custom_check_failed']['points']
        self.assertLess(warn, crit)

    def test_the_verdict_agrees_with_the_checks_page(self):
        """One evaluator, so the two surfaces cannot disagree about the host."""
        import checks as checks_mod
        cdef = {'id': 'c1', 'name': 'nginx must run', 'type': 'process',
                'param': 'nginx'}
        dev = {'name': 'web01', 'sysinfo': {'proc_names': ['sshd']}}
        rows = checks_mod._custom_checks_for(DEV, dev, [cdef], set())
        self.assertEqual([r['status'] for r in rows], ['critical'])
        self._with_check(cdef, dev['sysinfo'])
        self.assertIn('custom_check_failed', self._factors()[0])


class TestTheUiAndTheModelAgree(unittest.TestCase):
    """test_v622_threshold_configs_b4 already pins this class for the whole
    weight registry; these two name the v7.0.3 factors so a failure says which
    ones rather than 'a factor is missing'."""

    def test_each_new_factor_has_an_input(self):
        html = (ROOT / 'server/html/index.html').read_text()
        for k in _NEW:
            self.assertEqual(html.count(f'id="ap-rw-{k}"'), 1,
                             f'no Settings input for risk_weight_{k}')

    def test_each_new_factor_is_in_the_client_mirror(self):
        app = (ROOT / 'server/html/static/js/app.js').read_text()
        i = app.index('const _SCORE_WEIGHT_DEFAULTS')
        region = app[i:app.index('for (const [idPfx', i)]
        for k in _NEW:
            self.assertIn(f'{k}:', region,
                          f'{k} missing from _SCORE_WEIGHT_DEFAULTS')


if __name__ == '__main__':
    unittest.main()
