#!/usr/bin/env python3
"""The restore drill must verify the copy you would actually restore from.

`_restore_drill_core` globbed the LOCAL backup directory only. The off-host
mirror — the copy that exists precisely because it survives losing the machine
— had never been verified by anything. The mirror step reports whether the COPY
succeeded; nothing ever checked the result was readable.

So a green drill meant "the archive on the box that just burned down was fine".

That gap is also load-bearing for a compliance claim: docs/compliance.md maps
"off-host mirroring, test-restore verification" to SOC 2 A1.2 and ISO A.8.13 /
A.5.30, which reads as "the off-host copy is test-restored". It was not.

The verdict is a CONJUNCTION on purpose. If an off-host destination is
configured and its archive fails, the drill fails — a green result has to mean
"the backup I would actually restore from works", not "one of the two does".
When no destination is configured the behaviour is exactly as before.
"""
import importlib.util
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643drill-'))

_spec = importlib.util.spec_from_file_location('api_v643_drill', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)


def _good_archive(directory, name='remotepower_data_20260811.tar.gz'):
    """A structurally valid archive: a remotepower/ root with a real store in
    it. Anything less fails the v6.4.2 hollow-archive check, which would make
    these tests pass for the wrong reason."""
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    payload = d / '_src'
    (payload / 'remotepower').mkdir(parents=True, exist_ok=True)
    (payload / 'remotepower' / 'devices.json').write_text('{"d1": {}}')
    out = d / name
    with tarfile.open(str(out), 'w:gz') as t:
        t.add(str(payload / 'remotepower'), arcname='remotepower')
    return out


class _Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='rp-drill-'))
        self.local = self.root / 'local'
        self.off = self.root / 'offsite'
        self.local.mkdir(parents=True)
        self.off.mkdir(parents=True)

    def _cfg(self, offsite=True):
        api.save(api.CONFIG_FILE, {'backup': {
            'path': str(self.local),
            **({'offsite_dir': str(self.off)} if offsite else {})}})
        api._invalidate_load_cache(api.CONFIG_FILE)

    def _drill(self):
        return api._restore_drill_core()


class TestTheOffHostCopyIsVerified(_Base):
    def test_both_good_passes(self):
        """Positive control first — without it a drill that always failed
        would satisfy every other test here."""
        _good_archive(self.local)
        _good_archive(self.off)
        self._cfg()
        r = self._drill()
        self.assertTrue(r.get('ok'), r.get('error'))
        self.assertTrue((r.get('offsite') or {}).get('ok'))

    def test_a_missing_off_host_archive_fails_the_drill(self):
        """The bug: local fine, off-host EMPTY, drill reported green."""
        _good_archive(self.local)
        self._cfg()
        r = self._drill()
        self.assertFalse(r.get('ok'),
                         'the drill passed while the off-host copy — the one '
                         'that survives losing this machine — was absent')
        self.assertIn('off-host', str(r.get('error')))

    def test_a_corrupt_off_host_archive_fails_the_drill(self):
        _good_archive(self.local)
        (self.off / 'remotepower_data_20260811.tar.gz').write_bytes(b'not a tarball')
        self._cfg()
        r = self._drill()
        self.assertFalse(r.get('ok'))
        self.assertFalse((r.get('offsite') or {}).get('ok'))

    def test_the_error_names_the_destination(self):
        """An operator reading "the drill failed" needs to know WHICH copy."""
        _good_archive(self.local)
        self._cfg()
        r = self._drill()
        self.assertIn(str(self.off), str(r.get('error')))

    def test_it_says_when_the_local_one_passed(self):
        """Distinguishing "only the mirror is broken" from "both are" changes
        what the operator does next."""
        _good_archive(self.local)
        self._cfg()
        r = self._drill()
        self.assertIn('local archive passed', str(r.get('error')))


class TestNoOffsiteConfiguredIsUnchanged(_Base):
    """The common install. A drill that started failing because no off-host
    destination is configured would be a regression, not a fix."""

    def test_a_good_local_archive_still_passes(self):
        _good_archive(self.local)
        self._cfg(offsite=False)
        r = self._drill()
        self.assertTrue(r.get('ok'), r.get('error'))
        self.assertNotIn('offsite', r)

    def test_a_bad_local_archive_still_fails(self):
        (self.local / 'remotepower_data_20260811.tar.gz').write_bytes(b'junk')
        self._cfg(offsite=False)
        self.assertFalse(self._drill().get('ok'))

    def test_no_archives_at_all_still_reports_that(self):
        self._cfg(offsite=False)
        r = self._drill()
        self.assertTrue(r.get('no_archives'))


class TestTheHollowArchiveCheckStillApplies(_Base):
    """v6.4.2 made the drill fail an archive carrying no restorable state. That
    check must run against the off-host copy too, or the weaker of the two
    verdicts is the one nobody sees."""

    def test_a_hollow_off_host_archive_fails(self):
        _good_archive(self.local)
        d = self.off
        empty_src = d / '_empty' / 'remotepower'
        empty_src.mkdir(parents=True)
        with tarfile.open(str(d / 'remotepower_data_20260811.tar.gz'), 'w:gz') as t:
            t.add(str(empty_src), arcname='remotepower')
        self._cfg()
        r = self._drill()
        self.assertFalse(r.get('ok'),
                         'an off-host archive with no restorable state passed')


if __name__ == '__main__':
    unittest.main()
