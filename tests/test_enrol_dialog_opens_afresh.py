#!/usr/bin/env python3
"""The Enroll dialog opens from scratch every time: the function that does it, run against what an earlier opening left behind.

"Hosts that can use it" is the number of hosts one token may enrol. The dialog kept it between openings, and the Docker block has no field of
its own and reads this one, so an administrator who made a command for 400 hosts and later opened the dialog to add one machine was one click
from a Docker file for 400. The commands printed for the earlier number stayed on screen too, and one of them copied for a single machine
enrols as many hosts as it was made for.

openEnrollModal() now calls _enrollReset() before it asks for a PIN. This module runs that function in node against a fake page that holds
what an earlier opening could leave (a 400 in the field, an invalid mark, both result boxes full, a watch running and a status line), and
reads the order of calls in the opener. The browser side is test_enroll_many_hosts_e2e (a real second opening, and the token the next click
makes).
"""
import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import srcpin  # noqa: E402

_APP = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()


def _run_reset(dirty=True):
    names = ('_enrollReset', 'enrollUsesNote', '_stopEnrollWatch', '_enrollStatusEl')
    code = '\n'.join(srcpin.js_function(_APP, n) for n in names)
    prog = code + """
const els = {};
const mk = (id, extra) => { els[id] = Object.assign({id, textContent: '', className: '', value: '', attrs: {}, toggled: null,
    removeAttribute(n) { delete this.attrs[n]; }, classList: {toggle: (c, on) => { els[id].toggled = [c, on]; }}}, extra); };
mk('enroll-max-uses', DIRTY ? {value: '400', attrs: {'aria-invalid': 'true'}} : {value: '1'});
mk('enroll-uses-note');
mk('enroll-quick-result', DIRTY ? {textContent: 'wget -qO- "https://x/install?t=SECRET" | sudo sh'} : {});
mk('enroll-docker-result', DIRTY ? {textContent: 'RP_ENROLL_TOKEN: "SECRET"'} : {});
mk('enroll-watch-status', DIRTY ? {className: 'enroll-watch c-green', textContent: 'x checked in'} : {className: 'enroll-watch'});
const document = {getElementById: id => els[id] || null};
let _enrollWatchTimer = DIRTY ? 7 : null;
_enrollReset();
console.log(JSON.stringify({value: els['enroll-max-uses'].value, attrs: els['enroll-max-uses'].attrs, note: els['enroll-uses-note'].toggled,
    quick: els['enroll-quick-result'].textContent, docker: els['enroll-docker-result'].textContent,
    status: [els['enroll-watch-status'].className, els['enroll-watch-status'].textContent], timer: _enrollWatchTimer}));
""".replace('DIRTY', 'true' if dirty else 'false')
    out = subprocess.run(['node', '-e', prog], capture_output=True, text=True, timeout=30)
    if out.returncode != 0:
        raise AssertionError(out.stderr)
    return json.loads(out.stdout)


class TestTheReset(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if shutil.which('node') is None:
            raise unittest.SkipTest('node is not installed')

    def test_what_an_earlier_opening_left_is_gone(self):
        got = _run_reset(dirty=True)
        self.assertEqual(got['value'], '1', 'the number of hosts is still what an earlier opening left')
        self.assertEqual(got['attrs'], {}, 'the invalid mark of an earlier opening stays on the field')
        self.assertEqual(got['note'], ['d-none', True], 'the warning for more than one host still shows')
        self.assertEqual(got['quick'], '', 'the command made for the earlier number is still printed')
        self.assertEqual(got['docker'], '', 'the compose file made for the earlier number is still printed')
        self.assertEqual(got['status'], ['enroll-watch', ''], 'the line that waits for a host still has the earlier text')
        self.assertIsNone(got['timer'], 'a poll for the earlier command is still running')

    def test_a_clean_dialog_stays_as_it_is(self):
        # the control of the test above: the function does not invent state, and it leaves a default dialog default
        got = _run_reset(dirty=False)
        self.assertEqual((got['value'], got['attrs'], got['quick'], got['docker'], got['timer']), ('1', {}, '', '', None))

    def test_the_opener_resets_before_it_asks_for_a_pin(self):
        body = srcpin.js_function(_APP, 'openEnrollModal')
        self.assertIn('_enrollReset();', body)
        # the PIN starts its own watch when it is made, so the reset has to come first or it would stop that one
        self.assertLess(body.index('_enrollReset();'), body.index('generateNewPin();'))
        self.assertLess(body.index('generateNewPin();'), body.index("openModal('enroll-modal')"))

    def test_nothing_else_opens_the_dialog(self):
        # one opener: a second one that skipped the reset would bring the stale number back
        scripts = sorted((_ROOT / 'server' / 'html' / 'static' / 'js').glob('*.js'))
        self.assertGreater(len(scripts), 20, 'the scripts were not found')
        total = sum(p.read_text().count("openModal('enroll-modal')") + p.read_text().count('openModal("enroll-modal")') for p in scripts)
        self.assertEqual(total, 1, 'the Enroll dialog is opened from more than one place')


if __name__ == '__main__':
    unittest.main()
