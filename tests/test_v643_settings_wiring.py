#!/usr/bin/env python3
"""Every Settings control must be wired to something. 191 of them.

Settings is the product's largest config surface — 191 `cfg-` ids across ~20
panes, loaded and saved by functions 550 lines apart. The failure it invites is
a control that renders, accepts input, and is connected to nothing: the operator
ticks a box, saves, and the value is discarded. That is the same
looks-wired-but-is-dead class as the module kill switches and the RAG save
whitelist, on the surface most likely to hide it.

WHAT THIS IS NOT. The backlog proposed table-driving loadSettings/saveSettings —
two hand-maintained lists into one registry, ~8 commits. Measured first, with an
instrument covering every accessor shape, the surface turned out to be
CONSISTENT: all 191 ids are wired, and the backlog's own note admitted no live
instance of the bug was ever found. An 8-commit rewrite of 133 fields whose
blank-means-keep and blank-means-zero semantics differ per field, carrying real
regression risk in the SAVE direction, is not the proportionate answer to a
defect that does not exist. The guard is: it catches the class at a fraction of
the risk, and would fail the moment a 192nd control shipped unwired.

A NOTE ON THE INSTRUMENT, because it was wrong twice before it was right. A
first pass compared `getElementById` calls inside loadSettings against those
inside saveSettings and reported 38 asymmetries. Every one was a false positive:
values also flow through the `_setv()` helper, several fields are saved by
DEDICATED savers rather than saveSettings, and the `cfg-mod-*` switches are
driven by the MODULE_SETTINGS table with no literal getElementById at all. An
instrument that knows one access shape manufactures findings — the same mistake
the heartbeat parity gate made with `.get()` versus subscript access. Hence the
deliberately broad match below.
"""
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text()
_JS = '\n'.join(p.read_text() for p in
                sorted((_ROOT / 'server' / 'html' / 'static' / 'js').glob('app*.js')))


def _markup_ids():
    return set(re.findall(r'id="(cfg-[a-z0-9_-]+)"', _HTML))


def _js_referenced(cfg_id):
    """Deliberately broad: a bare quoted literal anywhere in the client JS.

    Narrower matching is what produced 38 false findings on the first attempt.
    The registries (MODULE_SETTINGS, _ALERT_PARAM_FIELDS, _RETENTION_FIELDS)
    carry their ids as plain literals in a table, never as a getElementById
    call, and they are the CORRECT pattern — the thing this surface is slowly
    converging on."""
    return bool(re.search(r"['\"]%s['\"]" % re.escape(cfg_id), _JS))


class TestNoDeadSettingsControl(unittest.TestCase):
    def test_the_extraction_found_the_surface(self):
        """Positive control: an empty id set makes the assertion below
        vacuous, and this file would pass while checking nothing."""
        self.assertGreater(len(_markup_ids()), 150)

    def test_every_settings_control_is_referenced_by_the_client(self):
        """The load-bearing one. A control in the markup that no JS mentions
        renders, accepts input, and silently discards it."""
        orphans = sorted(i for i in _markup_ids() if not _js_referenced(i))
        self.assertEqual(orphans, [], '\n'.join([
            'These Settings controls exist in index.html and are referenced by '
            'no client JS at all — they render, accept input and go nowhere:',
            *('  ' + o for o in orphans),
            '',
            'Wire the id into its pane loader and saver, or add it to a '
            'table-driven registry (MODULE_SETTINGS / _ALERT_PARAM_FIELDS / '
            '_RETENTION_FIELDS). If it is a pure display element, it does not '
            'need an id at all.']))

    def test_no_js_reads_a_settings_id_that_does_not_exist(self):
        """The other direction: a read that always returns null. Silent in JS,
        so it survives review — the exact reason test_ui_wiring exists."""
        ids = _markup_ids()
        # ids built at runtime by an innerHTML template are legitimate
        runtime_built = set(re.findall(r'id="(cfg-[a-z0-9_-]+)"', _JS))
        read = set(re.findall(r"getElementById\('(cfg-[a-z0-9_-]+)'\)", _JS))
        ghosts = sorted(read - ids - runtime_built)
        self.assertEqual(ghosts, [], '\n'.join([
            'client JS reads these ids and no element declares them:',
            *('  ' + g for g in ghosts)]))


class TestTheRegistriesStayTheConvergencePoint(unittest.TestCase):
    """Three registries already replaced hand-maintained pairs on this surface.
    They are the pattern; a new group of related fields belongs in one."""

    REGISTRIES = ('MODULE_SETTINGS', '_ALERT_PARAM_FIELDS', '_RETENTION_FIELDS')

    def test_each_registry_still_exists(self):
        for name in self.REGISTRIES:
            with self.subTest(registry=name):
                self.assertRegex(_JS, r'\b%s\s*=' % name)

    def test_each_registry_drives_real_controls(self):
        """A registry whose ids are not in the markup is a table nobody
        renders — coverage on paper only."""
        ids = _markup_ids()
        for name in self.REGISTRIES:
            # Array OR object literal: MODULE_SETTINGS is `[...]`,
            # _RETENTION_FIELDS is `{...}`. Assuming one shape is how the
            # first version of this test reported a healthy registry as gone.
            m = (re.search(r'\b%s\s*=\s*\[(.*?)\n\]' % name, _JS, re.S)
                 or re.search(r'\b%s\s*=\s*\{(.*?)\n\}' % name, _JS, re.S))
            self.assertIsNotNone(m, f'{name} is no longer a literal table')
            listed = set(re.findall(r"'(cfg-[a-z0-9_-]+)'", m.group(1)))
            listed |= set(re.findall(r"'(ap-[a-z0-9_-]+)'", m.group(1)))
            listed |= set(re.findall(r"'(ret-[a-z0-9_-]+)'", m.group(1)))
            with self.subTest(registry=name):
                self.assertTrue(listed, f'{name} lists no element ids')
                present = {x for x in listed
                           if f'id="{x}"' in _HTML or f"'{x}'" in _JS}
                self.assertEqual(
                    sorted(listed - present), [],
                    f'{name} names ids that exist nowhere')


if __name__ == '__main__':
    unittest.main()
