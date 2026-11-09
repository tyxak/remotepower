#!/usr/bin/env python3
"""The public demo shows the new look and typeface (Pilot, B612), and nothing else does unless it is asked to.

The demo is the seeder's data under `RP_READ_ONLY`, re-seeded every two minutes by a systemd unit that `install-demo.sh` writes. The
seeder rewrites the whole configuration each time, so whatever the demo should default to has to be written by the seeder, and the
unit has to carry the flags that ask for it. The seed is also what every rendered gate, the screenshots and most browser tests run
on, and Classic with the system font is the product's own default, so a plain seed must stay exactly that. The one exception is the demo's own
directory, /var/lib/remotepower-demo: a demo installed before the two flags existed has a unit that runs the seeder without them, so it stayed on
Classic for good (its /api/public-info said "look": ""), and the seeder now asks for the new look and typeface there without being told.

What is held here: the flags and the keys they write (not a lock, only what is asked), that nothing is written without them, that
the installer passes them to the first seed AND to the unit (the second is the one that was missing in a first version of any such
change: the demo would be Pilot for two minutes), that `--classic` turns them off, and that what the seeder writes is what the
server accepts. The page's side is in test_v800_brand_typeface_e2e.py.
"""
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEEDER = ROOT / 'packaging' / 'seed-demo-data.py'
INSTALLER = ROOT / 'packaging' / 'install-demo.sh'

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v800-demolook-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v622_alert_params import api  # noqa: E402


def _seeder():
    spec = importlib.util.spec_from_file_location('seed_demo_look', SEEDER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestWhatTheSeederWrites(unittest.TestCase):
    def cfg(self, look='classic', typeface='system'):
        s = _seeder()
        s.DEMO_LOOK, s.DEMO_TYPEFACE = look, typeface
        return s.build_config()

    def test_a_plain_seed_writes_neither_so_it_is_what_it_was(self):
        cfg = self.cfg()
        for key in ('brand_look', 'brand_look_locked', 'brand_typeface'):
            self.assertNotIn(key, cfg, key)

    def test_the_new_look_and_typeface_are_the_instances_default_and_not_a_lock(self):
        cfg = self.cfg('pilot', 'b612')
        self.assertEqual((cfg['brand_look'], cfg['brand_typeface']), ('pilot', 'b612'))
        self.assertNotIn('brand_look_locked', cfg, 'a visitor must still be able to choose their own')

    def test_each_is_asked_for_on_its_own(self):
        a = self.cfg('pilot', 'system')
        self.assertEqual((a.get('brand_look'), 'brand_typeface' in a), ('pilot', False))
        b = self.cfg('classic', 'b612')
        self.assertEqual(('brand_look' in b, b.get('brand_typeface')), (False, 'b612'))

    def test_what_it_writes_is_what_the_server_accepts(self):
        cfg = self.cfg('pilot', 'b612')
        self.assertIn(cfg['brand_look'], api.UI_LOOKS)
        self.assertIn(cfg['brand_typeface'], api.UI_TYPEFACES)

    def test_the_flags_take_the_words_the_server_has_and_no_others(self):
        for flag, words in (('--look', api.UI_LOOKS), ('--typeface', api.UI_TYPEFACES)):
            for w in words:
                r = subprocess.run([sys.executable, str(SEEDER), '--data-dir', tempfile.mkdtemp(prefix='rp-demolook-'), flag, w],
                                   capture_output=True, text=True, timeout=120)
                self.assertEqual(r.returncode, 0, (flag, w, r.stderr[-300:]))
                self.assertIn('Dry-run', r.stdout)
            r = subprocess.run([sys.executable, str(SEEDER), flag, 'neon'], capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 2, 'argparse refuses a word the server would not know: %s' % flag)

    def seed(self, data_dir, *flags):
        r = subprocess.run([sys.executable, str(SEEDER), '--data-dir', data_dir, '--apply', '--quiet', *flags],
                           capture_output=True, text=True, timeout=600)
        self.assertEqual(r.returncode, 0, r.stderr[-400:])
        return json.loads((Path(data_dir) / 'config.json').read_text())

    def test_the_flags_reach_the_file_the_demo_reads(self):
        """The whole run, not build_config alone: both words end up in config.json, and no lock does."""
        cfg = self.seed(tempfile.mkdtemp(prefix='rp-demolook-seed-'), '--look', 'pilot', '--typeface', 'b612')
        self.assertEqual((cfg.get('brand_look'), cfg.get('brand_typeface')), ('pilot', 'b612'))
        self.assertNotIn('brand_look_locked', cfg)

    def test_a_run_without_the_flags_takes_them_away_which_is_why_the_timer_carries_them(self):
        """The seeder writes the whole configuration every time it runs. The demo is re-seeded by a timer, so a unit that forgot the
        flags would make the demo Pilot for two minutes after the install and Classic from then on, for a directory other than the demo's
        own (TestTheDemosOwnDirectory holds that one)."""
        d = tempfile.mkdtemp(prefix='rp-demolook-seed-')
        self.assertEqual(self.seed(d, '--look', 'pilot', '--typeface', 'b612').get('brand_look'), 'pilot')
        cfg = self.seed(d)
        for key in ('brand_look', 'brand_typeface'):
            self.assertNotIn(key, cfg, key)

    def test_a_plain_run_writes_neither(self):
        cfg = self.seed(tempfile.mkdtemp(prefix='rp-demolook-seed-'))
        for key in ('brand_look', 'brand_look_locked', 'brand_typeface'):
            self.assertNotIn(key, cfg, key)

    def test_the_defaults_of_the_flags_are_the_products_own(self):
        text = SEEDER.read_text()
        self.assertIn("'--look', choices=('classic', 'pilot'), default=None", text)
        self.assertIn("'--typeface', choices=('system', 'b612'), default=None", text)
        self.assertIn("DEMO_LOOK = 'classic'", text)
        self.assertIn("DEMO_TYPEFACE = 'system'", text)


class TestTheDemosOwnDirectory(unittest.TestCase):
    """A demo whose timer unit predates the flags runs `seed-demo-data.py --data-dir /var/lib/remotepower-demo --apply --quiet`, and that has to be enough."""

    def dry_run(self, *args):
        r = subprocess.run([sys.executable, str(SEEDER), *args], capture_output=True, text=True, timeout=120, cwd=str(ROOT))
        self.assertEqual(r.returncode, 0, r.stdout[-400:] + r.stderr[-400:])
        return re.findall(r'^Default look and typeface: (\S+), (\S+)$', r.stdout, re.M)

    def test_the_demos_own_directory_is_asked_for_without_a_flag(self):
        s = _seeder()
        self.assertEqual(s.DEFAULT_DATA_DIR, Path('/var/lib/remotepower-demo'), 'the directory install-demo.sh seeds by default')
        self.assertEqual(s.resolve_look(None, None, s.DEFAULT_DATA_DIR), ('pilot', 'b612'))
        self.assertEqual(s.resolve_look(None, None, '/var/lib/remotepower-demo/'), ('pilot', 'b612'), 'a trailing slash is the same directory')

    def test_a_unit_written_before_the_flags_existed_gets_them(self):
        """The command line of the old unit, through the real argument parser (a dry run writes nothing)."""
        self.assertEqual(self.dry_run('--data-dir', '/var/lib/remotepower-demo'), [('pilot', 'b612')])
        self.assertEqual(self.dry_run(), [('pilot', 'b612')], 'no --data-dir at all is the demo\'s directory too')

    def test_any_other_directory_is_the_products_own(self):
        s = _seeder()
        self.assertEqual(s.resolve_look(None, None, tempfile.mkdtemp(prefix='rp-demolook-other-')), ('classic', 'system'))
        self.assertEqual(self.dry_run('--data-dir', tempfile.mkdtemp(prefix='rp-demolook-other-')), [('classic', 'system')])

    def test_a_flag_wins_in_the_demos_own_directory_and_each_is_resolved_on_its_own(self):
        s = _seeder()
        demo = s.DEFAULT_DATA_DIR
        self.assertEqual(s.resolve_look('classic', 'system', demo), ('classic', 'system'), '--classic of the installer')
        self.assertEqual(s.resolve_look('classic', None, demo), ('classic', 'b612'))
        self.assertEqual(s.resolve_look(None, 'system', demo), ('pilot', 'system'))
        self.assertEqual(s.resolve_look('pilot', 'b612', tempfile.mkdtemp(prefix='rp-demolook-other-')), ('pilot', 'b612'), 'asked for, anywhere')
        self.assertEqual(self.dry_run('--data-dir', '/var/lib/remotepower-demo', '--look', 'classic', '--typeface', 'system'), [('classic', 'system')])


class TestWhatTheInstallerAsksFor(unittest.TestCase):
    """The dry run needs no root: a stand-in user, web root and data directory are enough, and it prints both the seed it would run
    and the unit it would write."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix='rp-demolook-inst-'))
        (cls.tmp / 'htdocs' / 'cgi-bin').mkdir(parents=True)

    def dry_run(self, *extra):
        r = subprocess.run(['bash', str(INSTALLER), 'demo.example.org', '--dry-run', '--cgi-user', os.environ.get('USER') or 'root',
                            '--htdocs', str(self.tmp / 'htdocs'), '--data-dir', str(self.tmp / 'data'), *extra],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout[-600:] + r.stderr[-600:])
        return r.stdout

    @staticmethod
    def flags(out):
        """Every `--look X --typeface Y` the dry run prints: the first seed and the unit's ExecStart."""
        return re.findall(r'--look (\S+) --typeface (\S+)', out)

    def test_the_demo_defaults_to_the_new_look_and_typeface_in_the_seed_and_in_the_unit(self):
        out = self.dry_run()
        self.assertEqual(self.flags(out), [('pilot', 'b612'), ('pilot', 'b612')],
                         'the first seed and the re-seed unit, which rewrites the configuration every two minutes')
        self.assertIn('ExecStart=/usr/bin/python3', out)
        unit = [ln for ln in out.splitlines() if 'ExecStart=' in ln and 'seed-demo-data.py' in ln][0]     # the gunicorn unit has one too
        self.assertIn('--look pilot --typeface b612', unit)
        self.assertIn('--apply --quiet', unit, 'the flags were added to the unit, nothing in it was dropped')

    def test_classic_turns_both_off(self):
        out = self.dry_run('--classic')
        self.assertEqual(self.flags(out), [('classic', 'system'), ('classic', 'system')])

    def test_the_help_says_so(self):
        r = subprocess.run(['bash', str(INSTALLER), '--help'], capture_output=True, text=True, timeout=60)
        self.assertIn('--classic', r.stdout)
        self.assertIn('Pilot', r.stdout)

    def test_every_call_of_the_seeder_in_the_installer_carries_the_flags(self):
        """The class, not the two I know of: a third call, added later, that forgets them would put the demo back on Classic."""
        lines = [ln for ln in INSTALLER.read_text().splitlines()
                 if 'seed-demo-data.py' in ln or '$SEED_SCRIPT' in ln]
        calls = [ln for ln in lines if ('--apply' in ln or '--data-dir' in ln) and not ln.lstrip().startswith('#')]
        self.assertGreaterEqual(len(calls), 3, calls)
        for ln in calls:
            self.assertIn('--look', ln, ln)
            self.assertIn('--typeface', ln, ln)

    def test_the_words_the_installer_passes_are_ones_the_seeder_takes(self):
        text = INSTALLER.read_text()
        self.assertIn('DEMO_LOOK="pilot"', text)
        self.assertIn('DEMO_TYPEFACE="b612"', text)
        self.assertIn('DEMO_LOOK="classic"; DEMO_TYPEFACE="system"', text)


if __name__ == '__main__':
    unittest.main()
