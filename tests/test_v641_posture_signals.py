"""v6.4.1: the shared reading of posture stores.

Risk and the Security Advisory stay separate systems on purpose — different
question, different model, and merging them would make both worse. What they
share is the layer BELOW that: how a store is read. That is where the
duplication actually was, and it had already produced a real bug (Risk applied
the CVE ignore list, the Advisory did not, so a CVE the operator had accepted
vanished from one and kept driving the other).

`posture_signals` holds the EXTRACTION — which rows count, which read-time
decorations apply, what shape comes out — and never the INTERPRETATION. These
tests pin both halves of that: the behaviour, and the boundary (nothing in the
module may start deciding points or severities, or it becomes the merge the
architecture deliberately avoids).
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))

import posture_signals as ps  # noqa: E402

SRC = (ROOT / 'server' / 'cgi-bin' / 'posture_signals.py').read_text()


class _FakeScanner:
    """Stands in for cve_scanner.apply_ignore_list — same contract: stamps
    `ignored` onto a COPY and returns a new list."""

    @staticmethod
    def apply_ignore_list(findings, ignore_data, dev_id):
        out = []
        for f in findings:
            f = dict(f)
            ig = ignore_data.get(f.get('vuln_id'))
            f['ignored'] = bool(ig and ig.get('scope') in ('global', dev_id))
            out.append(f)
        return out


def _fake_enrich(findings, kev, epss):
    for f in findings:
        if f.get('vuln_id') in kev:
            f['kev'] = True


class TestDecoratedCveFindings(unittest.TestCase):
    def setUp(self):
        self.rec = {'findings': [
            {'vuln_id': 'CVE-1', 'severity': 'critical'},
            {'vuln_id': 'CVE-2', 'severity': 'high'},
        ]}

    def test_applies_both_decorations(self):
        out = ps.decorated_cve_findings(
            self.rec, 'd1',
            ignore_data={'CVE-1': {'scope': 'global'}}, kev={'CVE-2'},
            scanner=_FakeScanner, enrich=_fake_enrich)
        by = {f['vuln_id']: f for f in out}
        self.assertTrue(by['CVE-1']['ignored'])
        self.assertFalse(by['CVE-2']['ignored'])
        self.assertTrue(by['CVE-2'].get('kev'))

    def test_never_mutates_the_input(self):
        # The caller usually holds a load() result other code reads afterwards;
        # a derived field written into it would persist to the store on save.
        before = [dict(f) for f in self.rec['findings']]
        ps.decorated_cve_findings(
            self.rec, 'd1', ignore_data={'CVE-1': {'scope': 'global'}},
            kev={'CVE-1', 'CVE-2'}, scanner=_FakeScanner, enrich=_fake_enrich)
        self.assertEqual(self.rec['findings'], before)

    def test_returns_new_dicts_not_shared_references(self):
        out = ps.decorated_cve_findings(self.rec, 'd1')
        out[0]['scribble'] = True
        self.assertNotIn('scribble', self.rec['findings'][0])

    def test_accepts_a_bare_list_as_well_as_a_record(self):
        self.assertEqual(len(ps.decorated_cve_findings(self.rec['findings'], 'd1')), 2)

    def test_junk_shapes_return_empty_rather_than_raising(self):
        for junk in (None, {}, [], 'x', {'findings': 'x'}, {'findings': None}):
            self.assertEqual(ps.decorated_cve_findings(junk, 'd1'), [], junk)

    def test_non_dict_rows_are_dropped(self):
        out = ps.decorated_cve_findings({'findings': [{'vuln_id': 'A'}, 'junk', None]}, 'd')
        self.assertEqual(len(out), 1)

    def test_a_broken_scanner_degrades_rather_than_500s(self):
        # A rollup that dies because one decoration raised is worse than a
        # rollup missing that decoration.
        class Boom:
            @staticmethod
            def apply_ignore_list(*a, **k):
                raise RuntimeError('bad ignore store')
        out = ps.decorated_cve_findings(self.rec, 'd1',
                                        ignore_data={'x': {}}, scanner=Boom)
        self.assertEqual(len(out), 2)

    def test_no_ignore_data_leaves_findings_untouched(self):
        out = ps.decorated_cve_findings(self.rec, 'd1', scanner=_FakeScanner)
        self.assertNotIn('ignored', out[0])

    def test_live_variant_drops_accepted_findings(self):
        out = ps.live_cve_findings(
            self.rec, 'd1', ignore_data={'CVE-1': {'scope': 'global'}},
            scanner=_FakeScanner)
        self.assertEqual([f['vuln_id'] for f in out], ['CVE-2'])

    def test_device_scoped_ignore_applies_to_that_device_only(self):
        kw = dict(ignore_data={'CVE-1': {'scope': 'd1'}}, scanner=_FakeScanner)
        self.assertEqual(len(ps.live_cve_findings(self.rec, 'd1', **kw)), 1)
        self.assertEqual(len(ps.live_cve_findings(self.rec, 'd2', **kw)), 2)


class TestStaleBackups(unittest.TestCase):
    def test_splits_the_composite_key(self):
        out = ps.stale_backups_by_device({
            'a:/srv/x': {'ok': False, 'age_h': 96},
            'b:/srv/y': {'ok': False, 'age_h': 5},
        })
        self.assertEqual(set(out), {'a', 'b'})

    def test_a_path_containing_a_colon_still_splits_on_the_first(self):
        out = ps.stale_backups_by_device({'a:/srv/x:y': {'ok': False, 'age_h': 1}})
        self.assertEqual(list(out), ['a'])

    def test_healthy_and_malformed_rows_are_skipped(self):
        out = ps.stale_backups_by_device({
            'a:/x': {'ok': True, 'age_h': 1},
            'nokey': {'ok': False},
            'b:/y': 'junk',
        })
        self.assertEqual(out, {})

    def test_label_and_threshold_come_from_the_monitor(self):
        out = ps.stale_backups_by_device(
            {'a:/srv/x': {'ok': False, 'age_h': 96}},
            [{'path': '/srv/x', 'label': 'nightly', 'max_age_hours': 24}])
        self.assertEqual(out['a'], ['nightly — 96h old (threshold 24h)'])

    def test_falls_back_to_the_path_when_no_monitor_matches(self):
        out = ps.stale_backups_by_device({'a:/srv/x': {'ok': False, 'age_h': 96}})
        self.assertIn('/srv/x', out['a'][0])
        self.assertIn('24h', out['a'][0])

    def test_missing_age_reads_as_missing_not_zero_hours(self):
        out = ps.stale_backups_by_device({'a:/x': {'ok': False}})
        self.assertIn('missing', out['a'][0])

    def test_nonsense_age_or_threshold_does_not_raise(self):
        out = ps.stale_backups_by_device(
            {'a:/x': {'ok': False, 'age_h': 'soon'}},
            [{'path': '/x', 'max_age_hours': 'lots'}])
        self.assertEqual(len(out['a']), 1)

    def test_empty_input(self):
        self.assertEqual(ps.stale_backups_by_device(None), {})
        self.assertEqual(ps.stale_backups_by_device({}), {})


class TestLiveSecretFindings(unittest.TestCase):
    def test_muted_dropped(self):
        out = ps.live_secret_findings({'findings': [
            {'fingerprint': 'a'}, {'fingerprint': 'b', 'muted': True}]})
        self.assertEqual([f['fingerprint'] for f in out], ['a'])

    def test_junk_shapes(self):
        for junk in (None, {}, {'findings': None}, {'findings': 'x'}, 'x'):
            self.assertEqual(ps.live_secret_findings(junk), [], junk)


class TestAvVerdict(unittest.TestCase):
    TOOLS = ('clamav', 'rkhunter', 'defender')

    def test_absent_record_is_neither_clean_nor_infected(self):
        for junk in (None, {}, 'x', []):
            self.assertEqual(ps.av_verdict(junk, self.TOOLS),
                             {'infected': 0, 'realtime_off': False}, junk)

    def test_counts_sum_across_tools(self):
        v = ps.av_verdict({'clamav': {'infected': 2},
                           'rkhunter': {'infected': 3}}, self.TOOLS)
        self.assertEqual(v['infected'], 5)

    def test_realtime_off_needs_an_explicit_false(self):
        # Absent means "this tool has no realtime concept", not "disabled".
        self.assertFalse(ps.av_verdict({'clamav': {}}, self.TOOLS)['realtime_off'])
        self.assertTrue(
            ps.av_verdict({'defender': {'realtime': False}}, self.TOOLS)['realtime_off'])

    def test_garbage_counts_do_not_raise(self):
        self.assertEqual(
            ps.av_verdict({'clamav': {'infected': 'many'}}, self.TOOLS)['infected'], 0)


class TestImageCveCounts(unittest.TestCase):
    def test_sums_across_images(self):
        self.assertEqual(ps.image_cve_counts({'images': [
            {'critical': 1, 'high': 2}, {'critical': 3, 'high': 4}]}), (4, 6))

    def test_junk_shapes(self):
        for junk in (None, {}, {'images': None}, {'images': 'x'}, 'x'):
            self.assertEqual(ps.image_cve_counts(junk), (0, 0), junk)

    def test_garbage_entries_are_skipped(self):
        self.assertEqual(
            ps.image_cve_counts({'images': ['x', None, {'critical': 'lots'},
                                            {'critical': 2}]}), (2, 0))


class TestTheBoundaryHolds(unittest.TestCase):
    """The module is the shared EXTRACTION. If it starts deciding points or
    severities it has become the Risk/Advisory merge the architecture
    deliberately avoids, and the two systems lose their separate models."""

    @staticmethod
    def _code_only():
        """Executable source with docstrings and comments removed — the module
        docstring legitimately discusses points and severities in explaining
        why they do NOT belong here."""
        import ast
        tree = ast.parse(SRC)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef)):
                doc = ast.get_docstring(node, clean=False)
                if doc is not None:
                    node.body = node.body[1:]
        return ast.unparse(tree)

    def test_no_scoring_vocabulary_in_the_code(self):
        code = self._code_only()
        for word in ('points', 'weight', '_RISK_', '_finding(', 'severity_rank'):
            self.assertNotIn(word, code,
                             f'{word}: interpretation leaked into the extractor')

    def test_does_not_import_api(self):
        # Same contract as advisory.py: callers pass the stores in. An api
        # import here would also be a circular one.
        self.assertNotIn('import api', SRC)

    def test_takes_its_collaborators_as_arguments(self):
        # cve_scanner / _enrich are injected, which is what keeps this testable
        # without standing up api.py.
        self.assertIn('scanner=None', SRC)
        self.assertIn('enrich=None', SRC)


if __name__ == '__main__':
    unittest.main()
