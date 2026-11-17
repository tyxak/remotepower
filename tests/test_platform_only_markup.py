#!/usr/bin/env python3
"""What the page hides from everyone but the platform operator is what the server refuses to them, and nothing else.

index.html marks an element `data-platform-only`, and `_applyPlatformOnly()` in app.js hides it unless /api/me says the caller is an
administrator of the default tenant (the same people the server's `_caller_is_superadmin()` lets through). The Backup & restore card of
Settings > Backups is marked: its four buttons call routes that `_PLATFORM_ROUTES` answers with a 403 for a tenant's administrator, so for
one of them the card was a set of buttons that could only fail (and the redacted export saved the refusal as a .zip, see
test_downloads_check_the_status).

Two directions are held, because either one alone passes by hiding too much or too little:

* every control inside a marked element calls only routes that `_platform_route` covers (a hidden control the server would have answered
  takes a feature away from an administrator of a tenant);
* the card is marked, and the table below names every action in it (a button added to the card later has to be put in the table, with the
  route it calls, or the test fails).

The table is read against the scripts too: the path each action is said to call has to be in the client JS, so the table cannot drift from
what the handlers do. The client's own test of "platform operator" is run in node against the answers /api/me gives, for the four callers
that matter.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_DATA = tempfile.mkdtemp(prefix='rp-platformonly-')
os.environ.setdefault('RP_DATA_DIR', _DATA)
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
for _p in (_ROOT / 'server' / 'cgi-bin', _HERE):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import clientjs  # noqa: E402
import srcpin  # noqa: E402
import wsgi  # noqa: E402  (imports api)

api = wsgi.api

_INDEX = (_ROOT / 'server' / 'html' / 'index.html').read_text()

# data-action (or data-change) of each control in the Backup & restore card -> the routes it calls: (method, path as the server sees it)
BACKUP_CARD = {
    'exportBackup': [('GET', '/api/export')],
    'downloadBackup': [('GET', '/api/backup/download')],
    'pickRestoreFile': [],                                                    # opens the file chooser; restoreBackup reads the file
    'restoreBackup': [('POST', '/api/backup/restore')],
    'openS3Restore': [('POST', '/api/backup/s3-archives'), ('POST', '/api/backup/s3-restore')],
}


def tearDownModule():
    shutil.rmtree(_DATA, ignore_errors=True)


def _marked_blocks(html):
    """The text of every element that carries data-platform-only, whole (the tag is closed by counting the divs, not by a fixed window)."""
    blocks = []
    for m in re.finditer(r'<div\b[^>]*\bdata-platform-only\b[^>]*>', html):
        depth, i = 0, m.start()
        for t in re.finditer(r'<(/?)div\b', html[m.start():]):
            depth += -1 if t.group(1) else 1
            if depth == 0:
                i = m.start() + t.end()
                break
        end = html.index('>', i) + 1
        blocks.append(html[m.start():end])
    return blocks


def _actions(block):
    return set(re.findall(r'data-(?:action|change)="([A-Za-z0-9_]+)"', block))


class TestTheMarkup(unittest.TestCase):

    def test_the_backup_and_restore_card_is_marked_and_nothing_else_is(self):
        blocks = _marked_blocks(_INDEX)
        self.assertEqual(len(blocks), 1, 'the marked elements are: %s' % [b[:80] for b in blocks])
        self.assertIn('Backup &amp; restore', blocks[0][:300], 'the marked element is not the Backup & restore card')

    def test_the_table_names_every_action_in_the_card_and_no_other(self):
        (card,) = _marked_blocks(_INDEX)
        found = _actions(card)
        self.assertTrue(found, 'no action was found in the card: the derivation reads nothing')
        self.assertEqual(found, set(BACKUP_CARD), 'the card and the table of what it calls differ: put a new button in BACKUP_CARD with its route')

    def test_every_route_the_card_calls_is_one_the_server_refuses_a_tenants_administrator(self):
        routes = [(m, p) for calls in BACKUP_CARD.values() for m, p in calls]
        self.assertGreaterEqual(len(routes), 5)
        for method, path in routes:
            self.assertIsNotNone(api._platform_route(path, method), '%s %s is open to a tenant administrator: do not hide its button' % (method, path))

    def test_the_control_is_a_route_the_server_would_answer_a_tenants_administrator_elsewhere(self):
        # the positive control of the line above: a route that is NOT platform-only has to read as open, or the check passes whatever the table says
        self.assertIsNone(api._platform_route('/api/export/monitors', 'GET'))
        self.assertIsNone(api._platform_route('/api/devices', 'GET'))
        self.assertIsNone(api._platform_route('/api/enrollment-tokens', 'POST'))

    def test_the_table_is_what_the_scripts_call(self):
        js = clientjs.client_js()
        for action, calls in BACKUP_CARD.items():
            srcpin.js_function(js, action)                                       # the function exists (a missing name raises)
            for _method, path in calls:
                tail = path[len('/api'):]
                self.assertTrue(("'%s'" % path in js) or ("'%s'" % tail in js) or ('`%s' % path in js) or ("'%s?" % tail in js),
                                '%s is not called by any client script: the table has drifted from %s' % (path, action))


class TestTheWiring(unittest.TestCase):

    def test_loadme_applies_the_marks_as_soon_as_me_has_answered(self):
        js = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        body = srcpin.js_function(js, 'loadMe')
        cache = body.index('_meCache = me;')
        self.assertIn('_applyPlatformOnly();', body[cache:], 'loadMe never applies the marks: the card would be drawn for everyone')
        # right after the answer is stored and before anything that can throw on a half-built page
        self.assertLess(body.index('_applyPlatformOnly();'), body.index("document.getElementById('topbar-avatar')"))

    def test_the_timeline_replay_uses_the_same_test(self):
        # one definition of "platform operator" in the client: the replay button used to carry its own copy of the expression
        js = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        self.assertIn('const canReplay = _isPlatformOperator();', js)


class TestTheClientsOwnTest(unittest.TestCase):
    """_isPlatformOperator() run in node against what /api/me answers."""

    @classmethod
    def setUpClass(cls):
        if shutil.which('node') is None:
            raise unittest.SkipTest('node is not installed')
        js = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        cls.fn = srcpin.js_function(js, '_isPlatformOperator')
        cls.apply = srcpin.js_function(js, '_applyPlatformOnly')

    def _run(self, me):
        prog = (self.fn + '\n' + self.apply + '\n'
                'let _meCache = %s;\n'
                'const hidden = []; const el = {classList: {toggle: (c, on) => hidden.push([c, on])}};\n'
                "const document = {querySelectorAll: () => [el]};\n"
                'console.log(JSON.stringify({op: _isPlatformOperator(), hidden: (_applyPlatformOnly(), hidden)}));\n' % me)
        out = subprocess.run(['node', '-e', prog], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        import json
        return json.loads(out.stdout)

    def test_the_four_callers(self):
        cases = [
            ('{admin: true, tenant: "default"}', True, False),                    # the platform operator
            ('{admin: true}', True, False),                                       # an older answer with no tenant: tenancy was never on
            ('{admin: true, tenant: "tenantB"}', False, True),                    # a tenant's administrator
            ('{admin: false, tenant: "default"}', False, True),                   # a viewer or a custom role
        ]
        for me, op, hide in cases:
            got = self._run(me)
            self.assertEqual(got['op'], op, me)
            self.assertEqual(got['hidden'][-1], ['hidden', hide], me)

    def test_nothing_is_hidden_before_me_has_answered(self):
        got = self._run('null')
        self.assertFalse(got['op'])
        self.assertEqual(got['hidden'], [], 'the card was hidden before /api/me answered: a failed read would hide it from the operator')


if __name__ == '__main__':
    unittest.main()
