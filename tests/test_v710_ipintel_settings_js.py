"""The Threat intel settings page fills and sends the new fields.

The inputs exist in the markup and the handler accepts the values, but nothing
joined them: a field the page never sends is a setting nobody can change. This
runs the page's own fill and save functions under node against a stub DOM.
"""
import json
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import srcpin  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_JS = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-ipintel.js').read_text()
_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text()

_IDS = {'ipintel-lookup-budget': 'daily_lookup_budget', 'ipintel-report-budget': 'daily_report_budget',
        'ipintel-cache-hours': 'cache_hours', 'ipintel-comment': 'report_comment'}


@unittest.skipUnless(shutil.which('node'), 'node not installed')
class TestPage(unittest.TestCase):
    def _run(self, script):
        fill = srcpin.js_function(_JS, '_ipiFillSettings')
        # js_function returns the text from `function`, so the `async` before it is restored here.
        save = 'async ' + srcpin.js_function(_JS, 'saveIpIntelSettings')
        prelude = '''
const els = {};
const el = id => (els[id] = els[id] || {value: '', checked: false, placeholder: '', textContent: ''});
const document = {getElementById: el};
let sent = null; let _ipiData = {settings: {}};
async function api(m, p, body) { sent = {m, p, body}; return {ok: true}; }
function toast() {} function loadIpIntel() {} async function uiConfirm() { return true; }
'''
        out = subprocess.run(['node', '-e', prelude + fill + '\n' + save + '\n(async () => {' + script + '})()'],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(0, out.returncode, out.stderr)
        return json.loads(out.stdout.strip().splitlines()[-1])

    def test_every_new_input_exists_in_the_markup(self):
        for i in _IDS:
            self.assertRegex(_HTML, r'id="%s"' % re.escape(i))

    def test_fill_shows_the_stored_values(self):
        got = self._run('''
          _ipiFillSettings({daily_lookup_budget: 300, daily_report_budget: 40, cache_hours: 12,
                            report_comment: 'custom text {count}'}, {});
          console.log(JSON.stringify(Object.fromEntries(%s.map(i => [i, els[i].value]))));''' % json.dumps(list(_IDS)))
        self.assertEqual({'ipintel-lookup-budget': 300, 'ipintel-report-budget': 40,
                          'ipintel-cache-hours': 12, 'ipintel-comment': 'custom text {count}'}, got)

    def test_save_sends_what_was_typed(self):
        got = self._run('''
          el('ipintel-lookup-budget').value = '250'; el('ipintel-report-budget').value = '75';
          el('ipintel-cache-hours').value = '8'; el('ipintel-comment').value = 'my words {what} {count}';
          await saveIpIntelSettings();
          console.log(JSON.stringify(sent));''')
        self.assertEqual(('POST', '/ip-intel/settings'), (got['m'], got['p']))
        b = got['body']
        self.assertEqual(('250', '75', '8', 'my words {what} {count}'),
                         (b['daily_lookup_budget'], b['daily_report_budget'], b['cache_hours'], b['report_comment']))

    def test_the_usage_line_counts_reports_too(self):
        got = self._run('''
          _ipiFillSettings({daily_lookup_budget: 900, daily_report_budget: 50},
                           {abuseipdb: 3, sniffcat: 2, 'report:abuseipdb': 7, 'report:sniffcat': 1});
          console.log(JSON.stringify(els['ipintel-budget'].textContent));''')
        self.assertIn('Reports today: AbuseIPDB 7 / 50, SniffCat 1 / 50', got)
        self.assertIn('Lookups today: AbuseIPDB 3 / 900', got)


if __name__ == '__main__':
    unittest.main()
