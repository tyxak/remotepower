#!/usr/bin/env python3
"""A UPS's state in words: NUT's `OB DISCHRG` reads "On battery, discharging" on the Power page, the code stays in the hover."""
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import srcpin  # noqa: E402

_NODE = shutil.which('node')
_SRC = (_JS / 'app-power.js').read_text(encoding='utf-8')


@unittest.skipUnless(_NODE, 'node not installed')
class TestUpsStatusWords(unittest.TestCase):

    def _run(self, codes):
        table = re.search(r'^const _UPS_WORDS = \{.*?\};$', _SRC, re.S | re.M)
        assert table is not None
        script = table.group(0) + '\n' + srcpin.js_function(_SRC, 'upsStatusWords') + '\nconsole.log(JSON.stringify(%s.map(upsStatusWords)));' % json.dumps(codes)
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / 'run.js'
            p.write_text(script)
            r = subprocess.run([str(_NODE), str(p)], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def test_nut_codes_read_as_words(self):
        got = self._run(['OL', 'OB DISCHRG', 'OL CHRG', 'OB LB', 'OL BYPASS', 'ol', 'ALARM OL'])
        self.assertEqual(got, ['Online', 'On battery, discharging', 'Online, charging', 'On battery, low battery', 'Online, bypass', 'Online',
                               'Alarm, online'])

    def test_apcupsd_codes_read_as_words(self):
        self.assertEqual(self._run(['ONLINE', 'ONBATT', 'COMMLOST', 'LOWBATT']), ['Online', 'On battery', 'Communication lost', 'Low battery'])

    def test_a_code_it_does_not_know_is_shown_as_it_came(self):
        self.assertEqual(self._run(['XYZZY', 'OL XYZZY', '', '   ']), ['XYZZY', 'Online, XYZZY', '', ''])

    def test_the_power_table_words_the_status_and_keeps_the_code_in_the_hover(self):
        self.assertIn("upsStatusWords(r.status)", _SRC)
        self.assertIn('title="${escAttr(r.status || \'\')}"', _SRC)


if __name__ == '__main__':
    unittest.main()
