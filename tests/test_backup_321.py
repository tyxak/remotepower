"""v5.8.0 (B2.2): the 3-2-1 backup-rule score computed in backups_handlers."""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

# backups_handlers binds to api as `A` at import; load api first, then the module.
_aspec = importlib.util.spec_from_file_location('api_b321', _CGI / 'api.py')
api = importlib.util.module_from_spec(_aspec)
_aspec.loader.exec_module(api)
import backups_handlers as BH  # noqa: E402


def _item(path, ok=True, label=None):
    return {'path': path, 'label': label or path, 'ok': ok, 'age_h': 1,
            'max_age_hours': 24}


class TestScore(unittest.TestCase):
    def score(self, items, monitors=None):
        return BH._backup_321_score(items, monitors or [])

    def test_full_321(self):
        items = [_item('/mnt/local1'), _item('/mnt/local2'), _item('/mnt/nas')]
        monitors = [
            {'path': '/mnt/local1', 'target': 'disk-a'},
            {'path': '/mnt/local2', 'target': 'disk-b'},
            {'path': '/mnt/nas', 'target': 's3://offsite-bucket'},
        ]
        s = self.score(items, monitors)
        self.assertEqual(s['score'], 3)
        self.assertTrue(s['legs']['copies']['ok'])   # 3 fresh
        self.assertTrue(s['legs']['media']['ok'])     # 3 targets
        self.assertTrue(s['legs']['offsite']['ok'])   # s3
        self.assertEqual(s['label'], '3-2-1 satisfied')

    def test_stale_copy_does_not_count(self):
        items = [_item('/a'), _item('/b'), _item('/c', ok=False)]
        s = self.score(items, [{'path': p, 'target': p} for p in ('/a', '/b', '/c')])
        self.assertEqual(s['legs']['copies']['value'], 2)   # /c stale
        self.assertFalse(s['legs']['copies']['ok'])

    def test_single_target_fails_media_leg(self):
        items = [_item('/srv/x'), _item('/srv/y'), _item('/srv/z')]
        # all under /srv, no monitor targets → same coarse medium
        s = self.score(items, [])
        self.assertTrue(s['legs']['copies']['ok'])
        self.assertFalse(s['legs']['media']['ok'])
        self.assertEqual(s['legs']['media']['value'], 1)

    def test_offsite_detected_by_hint(self):
        items = [_item('/backup')]
        for tgt in ('pbs://vault', 'rsync://host/x', 'user@host:/backups via ssh://',
                    'backblaze b2'):
            s = self.score(items, [{'path': '/backup', 'target': tgt}])
            self.assertTrue(s['legs']['offsite']['ok'], tgt)

    def test_offsite_flag_field(self):
        s = self.score([_item('/b')], [{'path': '/b', 'offsite_dir': '/mnt/remote'}])
        self.assertTrue(s['legs']['offsite']['ok'])

    def test_no_fresh_backups(self):
        s = self.score([_item('/a', ok=False)], [])
        self.assertEqual(s['score'], 0)
        self.assertEqual(s['label'], 'no fresh backups')

    def test_shape(self):
        s = self.score([_item('/a')], [])
        self.assertEqual(set(s), {'score', 'max', 'legs', 'label', 'detail',
                                  'fresh', 'total'})
        self.assertEqual(s['max'], 3)


class TestFrontend(unittest.TestCase):
    def test_drawer_renders_score(self):
        js = (_ROOT / 'server/html/static/js/app.js').read_text()
        self.assertIn('score_321', js)
        self.assertIn('3-2-1 backup rule', js)


if __name__ == '__main__':
    unittest.main()
