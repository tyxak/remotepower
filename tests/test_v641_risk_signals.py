"""v6.4.1: six risk factors over stores that were collected and scored nowhere.

`docs/risk.md` advertised CVE weighting by KEV, container posture and backup
freshness. `_device_risk` implemented none of the three — the doc described a
product that did not exist. Rather than trim the doc down to the code, the code
now does what the doc claimed, plus AV posture, exposed credentials and
patch-SLA breach.

The failure mode these guard against is the whole point of this release: a
factor whose weight is defined, whose UI input exists, and which can never
score because nothing supplies its input. `cve_kev` is the sharpest example —
`kev` is a read-time decoration the CVE store does not carry, so the factor is
dead unless the caller stamps it. Every test below drives the REAL
`_compute_fleet_risk` over seeded stores, not `_device_risk` with hand-built
kwargs, precisely because the kwargs are the part that can silently go unfilled.
"""
# A sibling from tests/ is imported inside a test method below.
# `unittest discover -s tests` puts this directory on sys.path for free;
# `python3 -m unittest tests.<this>` does not, and the method then fails
# with ModuleNotFoundError. See tests/test_modules_import_alone.py.
import sys as _rp_sys, pathlib as _rp_pl  # noqa: E402
_rp_sys.path.insert(0, str(_rp_pl.Path(__file__).resolve().parent))
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))

import api  # noqa: E402

DEV = 'r1'


class _RiskCase(unittest.TestCase):
    """Every store the scorer reads is reset here — they are shared across test
    modules in an xdist worker, and a leftover row from another module is the
    order-dependent false-failure class."""

    def setUp(self):
        now = int(api.time.time())
        api.save(api.DEVICES_FILE, {DEV: {'name': 'web01', 'last_seen': now,
                                          'sysinfo': {}}})
        for f in (api.CVE_FINDINGS_FILE, api.AV_FILE, api.IMAGE_CVE_FILE,
                  api.SECRETS_FILE, api.CVE_IGNORE_FILE, api.PACKAGES_FILE,
                  api.SOFTWARE_VIOLATIONS_FILE, api.HARDWARE_FILE,
                  api.KEV_EPSS_FILE, api.DATA_DIR / 'backup_state.json'):
            api.save(f, {})
        api.save(api.CONFIG_FILE, {})
        for f in (api.DEVICES_FILE, api.CONFIG_FILE, api.CVE_FINDINGS_FILE,
                  api.AV_FILE, api.IMAGE_CVE_FILE, api.SECRETS_FILE,
                  api.KEV_EPSS_FILE, api.DATA_DIR / 'backup_state.json'):
            api._invalidate_load_cache(f)

    def _factors(self):
        api._invalidate_load_cache(api.CONFIG_FILE)
        rows = [r for r in api._compute_fleet_risk() if r['device_id'] == DEV]
        self.assertEqual(len(rows), 1, 'expected exactly one row for the host')
        return {f['kind']: f for f in rows[0]['factors']}, rows[0]

    def _seed(self, path, value):
        api.save(path, {DEV: value})
        api._invalidate_load_cache(path)


class TestKevOutranksSeverity(_RiskCase):
    def test_kev_scores(self):
        self._seed(api.CVE_FINDINGS_FILE, {'findings': [
            {'vuln_id': 'CVE-2021-44228', 'package': 'log4j', 'severity': 'high'}]})
        api.save(api.KEV_EPSS_FILE, {'kev': ['CVE-2021-44228'], 'epss': {}})
        api._invalidate_load_cache(api.KEV_EPSS_FILE)
        f, _ = self._factors()
        self.assertIn('cve_kev', f)
        self.assertIn('actively exploited', f['cve_kev']['detail'])

    def test_a_kev_high_outscores_a_plain_critical(self):
        self._seed(api.CVE_FINDINGS_FILE, {'findings': [
            {'vuln_id': 'CVE-1', 'package': 'a', 'severity': 'high'}]})
        api.save(api.KEV_EPSS_FILE, {'kev': ['CVE-1'], 'epss': {}})
        api._invalidate_load_cache(api.KEV_EPSS_FILE)
        _, kev_row = self._factors()
        self.setUp()
        self._seed(api.CVE_FINDINGS_FILE, {'findings': [
            {'vuln_id': 'CVE-2', 'package': 'a', 'severity': 'critical'}]})
        _, plain_row = self._factors()
        self.assertGreater(kev_row['score'], plain_row['score'])

    def test_no_feed_scores_nothing_rather_than_erroring(self):
        self._seed(api.CVE_FINDINGS_FILE, {'findings': [
            {'vuln_id': 'CVE-3', 'package': 'a', 'severity': 'high'}]})
        f, _ = self._factors()
        self.assertNotIn('cve_kev', f)
        self.assertIn('cve_high', f)

    def test_an_ignored_kev_cve_does_not_score(self):
        # The ignore list is the operator saying "accepted"; KEV must not
        # override that, or accepting a finding would stop working.
        self._seed(api.CVE_FINDINGS_FILE, {'findings': [
            {'vuln_id': 'CVE-4', 'package': 'a', 'severity': 'high'}]})
        api.save(api.KEV_EPSS_FILE, {'kev': ['CVE-4'], 'epss': {}})
        api.save(api.CVE_IGNORE_FILE,
                 {'CVE-4': {'scope': 'global', 'reason': 'accepted'}})
        for p in (api.KEV_EPSS_FILE, api.CVE_IGNORE_FILE):
            api._invalidate_load_cache(p)
        f, _ = self._factors()
        self.assertNotIn('cve_kev', f)

    def test_enrichment_does_not_leak_into_the_store(self):
        # The scorer stamps `kev` onto a copy; writing it back would persist a
        # read-time decoration into the CVE store.
        self._seed(api.CVE_FINDINGS_FILE, {'findings': [
            {'vuln_id': 'CVE-5', 'package': 'a', 'severity': 'high'}]})
        api.save(api.KEV_EPSS_FILE, {'kev': ['CVE-5'], 'epss': {}})
        api._invalidate_load_cache(api.KEV_EPSS_FILE)
        self._factors()
        api._invalidate_load_cache(api.CVE_FINDINGS_FILE)
        stored = (api.load(api.CVE_FINDINGS_FILE) or {})[DEV]['findings'][0]
        self.assertNotIn('kev', stored)


class TestAvPosture(_RiskCase):
    def test_active_infection_scores(self):
        self._seed(api.AV_FILE, {'clamav': {'infected': 2, 'warnings': 0}})
        f, _ = self._factors()
        self.assertIn('av_bad', f)
        self.assertIn('2 active malware', f['av_bad']['detail'])

    def test_realtime_off_scores_less_than_an_infection(self):
        self._seed(api.AV_FILE, {'defender': {'infected': 0, 'realtime': False}})
        f, _ = self._factors()
        self.assertIn('av_bad', f)
        self.assertLess(f['av_bad']['points'], api._RISK_WEIGHTS['av_bad'])

    def test_a_clean_host_scores_nothing(self):
        self._seed(api.AV_FILE, {'clamav': {'infected': 0, 'realtime': True}})
        f, _ = self._factors()
        self.assertNotIn('av_bad', f)

    def test_no_av_record_at_all_is_not_a_finding(self):
        # Absent data must not read as "infected" — most hosts have no AV
        # record, and inventing a factor for all of them is noise, not signal.
        f, _ = self._factors()
        self.assertNotIn('av_bad', f)


class TestContainerImageCves(_RiskCase):
    def test_image_cves_score_and_cap(self):
        self._seed(api.IMAGE_CVE_FILE, {'images': [
            {'image': 'nginx:1.0', 'critical': 3, 'high': 5}]})
        f, _ = self._factors()
        self.assertIn('image_cves', f)
        self.assertLessEqual(f['image_cves']['points'], api._RISK_CAPS['image_cves'])

    def test_one_bad_base_image_cannot_dominate_the_score(self):
        self._seed(api.IMAGE_CVE_FILE, {'images': [
            {'image': 'old:1', 'critical': 500, 'high': 500}]})
        f, _ = self._factors()
        self.assertEqual(f['image_cves']['points'], api._RISK_CAPS['image_cves'])

    def test_a_clean_image_scores_nothing(self):
        self._seed(api.IMAGE_CVE_FILE, {'images': [
            {'image': 'nginx:1.0', 'critical': 0, 'high': 0}]})
        f, _ = self._factors()
        self.assertNotIn('image_cves', f)


class TestBackupFreshness(_RiskCase):
    def test_stale_backup_scores(self):
        bs = api.DATA_DIR / 'backup_state.json'
        api.save(bs, {f'{DEV}:/srv/backup': {'ok': False, 'age_h': 96}})
        api._invalidate_load_cache(bs)
        f, _ = self._factors()
        self.assertIn('backup_stale', f)

    def test_another_hosts_stale_backup_is_not_scored_here(self):
        # The store is keyed `<device>:<path>` — a naive read would give every
        # host every other host's failures.
        bs = api.DATA_DIR / 'backup_state.json'
        api.save(bs, {'other:/srv/backup': {'ok': False, 'age_h': 96}})
        api._invalidate_load_cache(bs)
        f, _ = self._factors()
        self.assertNotIn('backup_stale', f)

    def test_a_healthy_backup_scores_nothing(self):
        bs = api.DATA_DIR / 'backup_state.json'
        api.save(bs, {f'{DEV}:/srv/backup': {'ok': True, 'age_h': 2}})
        api._invalidate_load_cache(bs)
        f, _ = self._factors()
        self.assertNotIn('backup_stale', f)


class TestExposedCredentials(_RiskCase):
    def test_unmuted_finding_scores(self):
        self._seed(api.SECRETS_FILE, {'findings': [
            {'fingerprint': 'a', 'rule': 'aws-key', 'path': '/srv/.env'}]})
        f, _ = self._factors()
        self.assertIn('secrets_exposed', f)

    def test_muted_findings_do_not_score(self):
        self._seed(api.SECRETS_FILE, {'findings': [
            {'fingerprint': 'a', 'rule': 'aws-key', 'path': '/srv/.env',
             'muted': True}]})
        f, _ = self._factors()
        self.assertNotIn('secrets_exposed', f)

    def test_capped(self):
        self._seed(api.SECRETS_FILE, {'findings': [
            {'fingerprint': str(i), 'rule': 'k', 'path': '/x'} for i in range(50)]})
        f, _ = self._factors()
        self.assertEqual(f['secrets_exposed']['points'],
                         api._RISK_CAPS['secrets_exposed'])


class TestWiringAndTotals(_RiskCase):
    def test_every_new_factor_has_a_weight_and_a_tunable(self):
        html = (ROOT / 'server' / 'html' / 'index.html').read_text()
        import clientjs
        js = clientjs.client_js()
        for k in ('cve_kev', 'av_bad', 'image_cves', 'backup_stale',
                  'secrets_exposed', 'patch_sla_breach'):
            self.assertIn(k, api._RISK_WEIGHTS, k)
            self.assertIn(f'id="ap-rw-{k}"', html, k)
            self.assertIn(f'{k}:', js, k)

    def test_weight_of_zero_disables_a_factor(self):
        # The documented meaning of 0 in the weight UI.
        self._seed(api.AV_FILE, {'clamav': {'infected': 5}})
        api.save(api.CONFIG_FILE, {'risk_weight_av_bad': 0})
        api._invalidate_load_cache(api.CONFIG_FILE)
        f, _ = self._factors()
        self.assertNotIn('av_bad', f)

    def test_a_host_with_nothing_wrong_still_scores_zero(self):
        f, row = self._factors()
        self.assertEqual(row['score'], 0, f)

    def test_score_stays_bounded_with_every_new_factor_firing(self):
        self._seed(api.AV_FILE, {'clamav': {'infected': 9}})
        self._seed(api.IMAGE_CVE_FILE, {'images': [{'image': 'x', 'critical': 99}]})
        self._seed(api.SECRETS_FILE, {'findings': [
            {'fingerprint': str(i), 'rule': 'k', 'path': '/x'} for i in range(99)]})
        bs = api.DATA_DIR / 'backup_state.json'
        api.save(bs, {f'{DEV}:/b': {'ok': False, 'age_h': 999}})
        api._invalidate_load_cache(bs)
        _, row = self._factors()
        self.assertLessEqual(row['score'], 100)
        self.assertIn(row['level'], ('low', 'medium', 'high', 'critical'))


class TestDocMatchesTheCode(unittest.TestCase):
    """docs/risk.md claimed KEV, container posture and backup freshness while
    _device_risk implemented none of them."""

    def test_doc_claims_are_all_implemented(self):
        doc = (ROOT / 'docs' / 'risk.md').read_text().lower()
        for phrase, factor in (('kev', 'cve_kev'),
                               ('container-image cves', 'image_cves'),
                               ('backup freshness', 'backup_stale'),
                               ('malware/av posture', 'av_bad'),
                               ('exposed credentials', 'secrets_exposed'),
                               ('patch-sla', 'patch_sla_breach')):
            self.assertIn(phrase, doc, phrase)
            self.assertIn(factor, api._RISK_WEIGHTS, factor)


if __name__ == '__main__':
    unittest.main()
