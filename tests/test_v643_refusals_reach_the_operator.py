#!/usr/bin/env python3
"""A server that refuses honestly is useless if the client throws the refusal away.

v6.4.2 taught three handlers to answer "saved, but this platform can't do it"
instead of a bare success. Two of the three clients never read the answer, so
the operator still got the green toast — the refusal existed only in the
network tab. That is worse than not having added it: the code now LOOKS like it
handles the case.

The root cause is documented in CLAUDE.md and keeps producing bugs: `api()` in
app.js RESOLVES the body on 200/202/400/403 rather than throwing, so nothing
forces a caller to look at what came back.

This pins the whole class rather than the two instances:

  1. Enumerate every server response that carries an OS-support refusal —
     `_split_targets_by_os_support` / a `supported:` flag / a
     `skipped_unsupported` key.
  2. Assert each one's client reads it.

The enumeration is the part that matters. A fourth handler added later without
a client read fails step 1's completeness check, so the guard grows with the
codebase instead of freezing at today's three.
"""
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'

# handler source marker → (client file, tokens the client must reference)
# Every entry is a place the server can answer "I did less than you asked".
REFUSAL_SURFACES = {
    'handle_device_host_config_put': ('app-hostconfig.js', ('supported', 'note')),
    'handle_backup_job_create': ('app-backups.js', ('note',)),
    'handle_backup_job_update': ('app-backups.js', ('note',)),
    'handle_scap_scan': ('app-compliance.js', ('note',)),
    'handle_image_cve_scan': ('app-cve.js', ('message',)),
}


def _server_sources():
    return {p.name: p.read_text() for p in _CGI.glob('*.py')}


def _find_handler(name):
    """The source of `def <name>` from whichever server module holds it."""
    for src in _server_sources().values():
        m = re.search(r'^def %s\(' % re.escape(name), src, re.M)
        if not m:
            continue
        rest = src[m.start():]
        nxt = re.search(r'\n(?=def |class )', rest[1:])
        return rest[:nxt.start() + 1] if nxt else rest
    return None


class TestEveryRefusalHasAReader(unittest.TestCase):
    def test_each_listed_handler_exists_and_still_refuses(self):
        for handler in REFUSAL_SURFACES:
            with self.subTest(handler=handler):
                src = _find_handler(handler)
                self.assertIsNotNone(src, f'{handler} not found — if it was '
                                          'renamed, update this table')
                self.assertTrue(
                    re.search(r'_split_targets_by_os_support|_device_os_family'
                              r"|'supported'|skipped_unsupported", src),
                    f'{handler} no longer performs an OS-support check — either '
                    'the refusal was dropped (a regression) or this row is stale')

    def test_each_client_reads_the_refusal(self):
        for handler, (js_name, tokens) in REFUSAL_SURFACES.items():
            with self.subTest(handler=handler):
                js = (_JS / js_name).read_text()
                # strip comments so a token merely DESCRIBED in prose doesn't
                # count as a read (the mistake this whole file is about is
                # code that looks like it handles a case)
                code = re.sub(r'//[^\n]*', '', js)
                code = re.sub(r'/\*.*?\*/', '', code, flags=re.S)
                for tok in tokens:
                    self.assertRegex(
                        code, r'\.\s*%s\b' % re.escape(tok),
                        f'{js_name} never reads `.{tok}` from the response, so '
                        f'{handler}\'s refusal is discarded and the operator '
                        'sees a success toast for something that did not happen')

    def test_the_enumeration_is_complete(self):
        """The load-bearing assertion. A NEW handler that splits targets by OS
        support must be added here (and given a client that reads its answer),
        or this fails — which is the only thing standing between a future
        refusal and the same silent discard."""
        found = set()
        for name, src in _server_sources().items():
            for m in re.finditer(r'^def (handle_\w+)\(', src, re.M):
                fn = m.group(1)
                body = src[m.start():]
                nxt = re.search(r'\n(?=def |class )', body[1:])
                body = body[:nxt.start() + 1] if nxt else body
                if re.search(r"_split_targets_by_os_support|'skipped_unsupported'",
                             body):
                    found.add(fn)
        missing = found - set(REFUSAL_SURFACES)
        self.assertEqual(missing, set(), '\n'.join([
            'These handlers report OS-skipped targets but are not listed in '
            'REFUSAL_SURFACES:', *sorted(missing), '',
            'Add each one with the client file that consumes it, and make that '
            'client show the note — otherwise the server refuses honestly and '
            'the UI still says success.']))


class TestTheDetectorWouldHaveFailedBefore(unittest.TestCase):
    """The two clients fixed in v6.4.3 are the reason this file exists; assert
    the specific shape, so a well-meaning simplification back to a bare success
    toast is caught rather than quietly accepted."""

    def test_hostconfig_branches_on_supported_before_claiming_enforcement(self):
        js = (_JS / 'app-hostconfig.js').read_text()
        # strip comments first — the explanation of this very bug quotes both
        # strings, and matching prose instead of code is the mistake that put
        # a "// handles the unsupported case" comment above code that did not
        js = re.sub(r'//[^\n]*', '', js)
        self.assertRegex(js, r'r\.supported\s*===\s*false',
                         'the host-config save no longer checks `supported`, so '
                         'a Windows/macOS host is told enforcement is ON')
        # the success sentence must be unreachable for an unsupported host
        i_check = js.index('r.supported === false')
        i_toast = js.index('enforcement ON')
        self.assertLess(i_check, i_toast,
                        'the success toast fires before the platform check')

    def test_backup_save_surfaces_the_note(self):
        js = (_JS / 'app-backups.js').read_text()
        self.assertRegex(js, r'if\s*\(\s*d\.note\s*\)',
                         'the backup-job save discards `note`, so hosts dropped '
                         'from a file job are never mentioned')


if __name__ == '__main__':
    unittest.main()
