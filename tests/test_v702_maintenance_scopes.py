#!/usr/bin/env python3
"""Maintenance windows could only target a device, a group, or the whole fleet.

Every other targeting surface in the product takes site and tag as well —
service baselines, auto-patch, rollouts, alert routing, reports, RBAC scopes.
Maintenance windows were the exception.

An MSP patching one customer's SITE on Saturday could not say so. Sites
routinely span groups, so the choice was one window per device — hundreds of
rows for a single customer — or silencing the entire fleet.

site and tag read fields already on the device record. smart-group costs a store
read, but `_smart_group_match` is a pure predicate over the device record and
its embedded sysinfo (its docstring says it exists to drive membership tests
cheaply) and the read goes through `_load_ro`, which is memoised per request and
skips the deepcopy. `_window_applies` runs per device per heartbeat, so that
mattered.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-mw-'))
_spec = importlib.util.spec_from_file_location('api_maint_scopes', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_WEB = {'name': 'web01', 'site': 'acme-hq', 'tags': ['web', 'prod'],
        'group': 'servers', 'os': 'Ubuntu 22.04'}
_DB = {'name': 'db01', 'site': 'globex-dc', 'tags': ['db'],
       'group': 'servers', 'os': 'Debian 12'}


class _Base(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='rp-mw-run-'))
        self._saved = {n: getattr(api, n) for n in
                       ('DATA_DIR', 'SMART_GROUPS_FILE')}
        api.DATA_DIR = self.dir
        api.SMART_GROUPS_FILE = self.dir / 'smart_groups.json'
        api.save(api.SMART_GROUPS_FILE, {
            'sg1': {'name': 'ubuntu hosts', 'rules': {'os_contains': 'Ubuntu'}},
            'sgbad': {'name': 'malformed', 'rules': 'not-a-dict'},
        })

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)

    def applies(self, scope, target, dev):
        api._invalidate_load_cache(api.SMART_GROUPS_FILE)
        return api._window_applies({'scope': scope, 'target': target},
                                   'd1', dev=dev, dev_group=dev.get('group'))


class TestTheNewScopesMatch(_Base):

    def test_site(self):
        self.assertTrue(self.applies('site', 'acme-hq', _WEB))
        self.assertFalse(self.applies('site', 'acme-hq', _DB))

    def test_tag(self):
        self.assertTrue(self.applies('tag', 'prod', _WEB))
        self.assertFalse(self.applies('tag', 'prod', _DB))

    def test_tag_matches_any_of_the_devices_tags(self):
        self.assertTrue(self.applies('tag', 'web', _WEB))

    def test_smart_group(self):
        self.assertTrue(self.applies('smart', 'sg1', _WEB))
        self.assertFalse(self.applies('smart', 'sg1', _DB))

    def test_the_old_scopes_still_work(self):
        """The control. A matcher that returned True for everything would pass
        half the assertions above, and one that returned False for everything
        would pass the other half."""
        self.assertTrue(self.applies('group', 'servers', _WEB))
        self.assertTrue(self.applies('global', '', _DB))
        self.assertFalse(self.applies('group', 'other', _WEB))


class TestItFailsClosed(_Base):
    """A maintenance window SUPPRESSES alerting and gates command execution, so
    every uncertain case has to cover nothing rather than everything."""

    def test_a_deleted_smart_group_covers_nothing(self):
        self.assertFalse(self.applies('smart', 'nosuchgroup', _WEB))

    def test_a_malformed_rule_set_covers_nothing(self):
        self.assertFalse(self.applies('smart', 'sgbad', _WEB))

    def test_a_blank_target_covers_nothing(self):
        for scope in ('site', 'tag', 'smart', 'group'):
            with self.subTest(scope=scope):
                self.assertFalse(self.applies(scope, '', _WEB))

    def test_a_device_with_no_site_or_tags_is_not_swept_up(self):
        bare = {'name': 'bare', 'group': 'servers'}
        self.assertFalse(self.applies('site', 'acme-hq', bare))
        self.assertFalse(self.applies('tag', 'prod', bare))

    def test_an_unknown_scope_covers_nothing(self):
        self.assertFalse(self.applies('nonsense', 'x', _WEB))


class TestHostileShapesCannotRaiseOrWiden(_Base):
    """`_window_applies` runs from the heartbeat and the scheduler, and
    `in_maintenance()` has no try around it — so an exception here breaks
    alerting for the WHOLE fleet, not just for the malformed window.

    Found by fuzzing this release's own new code an hour after writing it: a
    smart-scoped window whose target was a dict raised TypeError, because a
    dict is unhashable and went straight into `.get()`. The API validator
    rejects a non-string target; a hand-edited store and a declarative import
    do not go through it.

    Two properties: nothing raises, and nothing MATCHES that should not — a
    window suppresses alerting and gates commands, so widening is the direction
    that hurts.
    """

    _DEVICES = [None, {}, {'tags': None}, {'tags': 'notalist'}, {'tags': [None]},
                {'tags': [{'a': 1}]}, {'site': None}, {'site': 0},
                {'site': {'x': 1}}, {'tenant': None}, {'group': 0}]
    _TARGETS = [None, 0, {'a': 1}, [1], '', b'x', 'nomatch']
    _SCOPES = ['tag', 'site', 'smart', 'group', 'device', None, 'TAG', 'nonsense']

    def test_nothing_raises_and_nothing_matches(self):
        raised, matched = [], []
        n = 0
        for scope in self._SCOPES:
            for target in self._TARGETS:
                for dev in self._DEVICES:
                    n += 1
                    w = {'scope': scope, 'target': target}
                    try:
                        r = api._window_applies(w, 'd1', dev=dev, dev_group=None)
                    except Exception as e:
                        raised.append((w, dev, type(e).__name__))
                        continue
                    if r:
                        matched.append((w, dev))
        self.assertGreater(n, 400, 'the matrix collapsed — nothing was tested')
        self.assertEqual([], raised[:5], f'{len(raised)} raised, e.g. {raised[:3]}')
        self.assertEqual([], matched[:5],
                         f'{len(matched)} matched a device that matches nothing: '
                         f'{matched[:3]}')

    def test_the_matrix_can_still_produce_a_match(self):
        """Positive control. If none of these inputs could ever match, the
        assertion above would pass against a matcher that always returns
        False — which is the other way to break it."""
        self.assertTrue(api._window_applies(
            {'scope': 'tag', 'target': 'nomatch'}, 'd1',
            dev={'tags': ['nomatch']}, dev_group=None))

    def test_an_empty_target_never_matches(self):
        """`''` is the shape a blank form field produces, and it must not
        become a wildcard."""
        for scope in ('tag', 'site', 'smart', 'group'):
            with self.subTest(scope=scope):
                self.assertFalse(api._window_applies(
                    {'scope': scope, 'target': ''}, 'd1',
                    dev={'tags': [''], 'site': '', 'group': ''}, dev_group=''))


class TestValidation(unittest.TestCase):

    def setUp(self):
        self.cap = {}
        self._resp = api.respond

        def _r(s, b=None):
            self.cap['s'], self.cap['b'] = s, b
            raise api.HTTPError(s, b)
        api.respond = _r

    def tearDown(self):
        api.respond = self._resp

    def _validate(self, **body):
        body.setdefault('start', '2030-01-01T00:00')
        body.setdefault('end', '2030-01-01T04:00')
        self.cap.clear()
        try:
            return api._validate_maintenance_body(body), None
        except (api.HTTPError, SystemExit):
            return None, self.cap.get('b')

    def test_the_new_scopes_are_accepted(self):
        for scope, target in (('site', 'acme-hq'), ('tag', 'prod'),
                              ('smart', 'sg1')):
            with self.subTest(scope=scope):
                ok, err = self._validate(scope=scope, target=target)
                self.assertIsNone(err, err)

    def test_a_scope_with_no_target_is_rejected(self):
        """A blank target matches no device rather than all of them, so it is a
        window that silently does nothing — worse than an error."""
        for scope in ('site', 'tag', 'smart', 'group'):
            with self.subTest(scope=scope):
                ok, err = self._validate(scope=scope, target='')
                self.assertIsNotNone(err, f'{scope} accepted a blank target')

    def test_global_still_needs_no_target(self):
        ok, err = self._validate(scope='global', target='')
        self.assertIsNone(err, err)

    def test_an_unknown_scope_is_still_rejected(self):
        ok, err = self._validate(scope='everything', target='x')
        self.assertIsNotNone(err)

    def test_the_error_names_the_scopes(self):
        ok, err = self._validate(scope='everything', target='x')
        for s in api._MAINTENANCE_SCOPES:
            self.assertIn(s, str(err))


class TestTheUiOffersThem(unittest.TestCase):

    def test_every_scope_has_an_option(self):
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        i = html.index('id="maint-scope"')
        block = html[i:html.index('</select>', i)]
        for s in api._MAINTENANCE_SCOPES:
            with self.subTest(scope=s):
                self.assertIn(f'value="{s}"', block,
                              f'the server accepts {s} and the form cannot '
                              f'produce it')

    def test_the_target_field_says_which_target(self):
        """site, tag and smart share one text input. It said "group name" for
        all of them."""
        js = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        i = js.index('function onMaintScopeChange')
        body = js[i:js.index('\n}', i)]
        for word in ('site name', 'tag', 'smart group id'):
            self.assertIn(word, body)


if __name__ == '__main__':
    unittest.main()
