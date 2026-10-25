#!/usr/bin/env python3
"""v7.4.1, issue #32: one poll-interval range, wherever a cadence is set.

Settings took a default poll interval of 10 s and a new host got it, but an
enrolled host's own interval was refused below 30 s. Three validators and four
places in the dashboard said 30; the default, the PATCH route, the OpenAPI
document and all three agents said 10. The only way to move an enrolled host to
10 s was to delete it and enrol it again.

The agent is the authority: it runs max(10, min(3600, n)) of whatever it is
sent, so a range the server enforces that differs from that is a promise the
agent does not keep. This file reads the range out of the three agents' source
and then drives every entry point that sets a cadence with the edge values.
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Set before api.py is exec'd: its import writes the default user to DATA_DIR.
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v741-poll-'))

import srcpin  # noqa: E402

AGENTS = ('client/remotepower-agent.py',
          'client/remotepower-agent-win.py',
          'client/remotepower-agent-mac.py')

_CLAMP = re.compile(r'max\((\d+),\s*min\((\d+),\s*\w+\)\)')


def _fresh_api():
    d = tempfile.mkdtemp(prefix='rp-v741-poll-')
    os.environ['RP_DATA_DIR'] = d
    spec = importlib.util.spec_from_file_location(
        'api_v741_poll', _ROOT / 'server' / 'cgi-bin' / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def agent_clamps():
    """[(file, lo, hi)] for every clamp the agents put on a poll interval."""
    found = []
    for rel in AGENTS:
        for line in (_ROOT / rel).read_text().splitlines():
            if 'interval' not in line and '_srv_iv' not in line:
                continue
            m = _CLAMP.search(line)
            if m:
                found.append((rel, int(m.group(1)), int(m.group(2))))
    return found


def agent_range():
    ranges = {(lo, hi) for _f, lo, hi in agent_clamps()}
    assert len(ranges) == 1, f'the agents disagree among themselves: {agent_clamps()}'
    return ranges.pop()


class TestTheAgentsAreTheAuthority(unittest.TestCase):

    def test_the_population_is_not_empty(self):
        """Linux clamps twice (server push and the command), Windows and macOS
        once each. A parser that found nothing would make every test below
        compare against an empty set."""
        files = [f for f, _lo, _hi in agent_clamps()]
        self.assertGreaterEqual(len(files), 4, agent_clamps())
        self.assertEqual({f for f in files}, set(AGENTS))

    def test_the_agents_agree_with_each_other(self):
        self.assertEqual(len({(lo, hi) for _f, lo, hi in agent_clamps()}), 1,
                         agent_clamps())


class _Case(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.api = _fresh_api()
        cls.lo, cls.hi = agent_range()

    def setUp(self):
        api = self.api
        self.cap = {}

        def _respond(status, data=None):
            self.cap['status'] = status
            self.cap['data'] = data
            raise api.HTTPError(status, data)
        api.respond = _respond
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None
        api.log_command = lambda *a, **k: None
        for gate in ('require_auth', 'require_admin_auth', 'require_write_role',
                     'require_perm'):
            setattr(api, gate, lambda *a, **k: 'admin')
        api.save(api.DEVICES_FILE, {'d1': {'name': 'one', 'token': 't', 'group': 'g',
                                           'poll_interval': 60}})
        api.save(api.CONFIG_FILE, {})
        api.save(api.DEVICE_PROFILES_FILE, {})
        api._LOAD_CACHE.clear()

    def body(self, method, obj):
        self.api.method = lambda: method
        self.api.get_json_obj = lambda: obj
        self.api.get_json_body = lambda: obj

    def call(self, fn, *a):
        self.cap.clear()
        try:
            fn(*a)
        except self.api.HTTPError as e:
            return e.status, e.body
        except SystemExit:
            return self.cap.get('status'), self.cap.get('data')
        return 200, None

    def stored(self):
        self.api._LOAD_CACHE.clear()
        return self.api.load(self.api.DEVICES_FILE)['d1'].get('poll_interval')


# Every way a cadence can be set, as (name, "reject" | "clamp", function).
# "reject" answers 400 outside the range; "clamp" stores the nearest edge.
class TestEveryEntryPointTakesTheAgentsRange(_Case):

    def _device_save(self, v):
        self.body('POST', {'poll_interval': v})
        st, out = self.call(self.api.handle_device_save_bulk, 'd1')
        return ('stored', self.stored()) if st == 200 else ('rejected', out)

    def _bulk_attrs(self, v):
        self.body('POST', {'device_ids': ['d1'], 'poll_interval': v})
        st, out = self.call(self.api.handle_devices_bulk_attrs)
        return ('stored', self.stored()) if st == 200 else ('rejected', out)

    def _profile(self, v):
        self.body('POST', {'name': 'p', 'poll_interval': v})
        st, out = self.call(self.api.handle_device_profiles)
        if st != 201:
            return ('rejected', out)
        prof = self.api.load(self.api.DEVICE_PROFILES_FILE)[out['id']]
        self.api.save(self.api.DEVICE_PROFILES_FILE, {})
        return ('stored', prof['poll_interval'])

    def _patch_route(self, v):
        self.body('PATCH', {'poll_interval': v})
        st, out = self.call(self.api.handle_device_poll_interval, 'd1')
        return ('stored', self.stored()) if st == 200 else ('rejected', out)

    def _fleet_default(self, v):
        self.body('POST', {'default_poll_interval': v})
        st, out = self.call(self.api.handle_config_save)
        if st != 200:
            return ('rejected', out)
        self.api._LOAD_CACHE.clear()
        return ('stored', self.api.load(self.api.CONFIG_FILE)['default_poll_interval'])

    def _new_host_default(self, v):
        """What an enrolling host is given: the default, clamped on the way out."""
        self.api.save(self.api.CONFIG_FILE, {'default_poll_interval': v})
        self.api._LOAD_CACHE.clear()
        return ('stored', self.api.get_default_poll_interval())

    def entry_points(self):
        return (
            ('POST /api/devices/{id}', 'reject', self._device_save),
            ('POST /api/devices/bulk-attrs', 'reject', self._bulk_attrs),
            ('POST /api/device-profiles', 'reject', self._profile),
            ('PATCH /api/devices/{id}/poll_interval', 'clamp', self._patch_route),
            ('POST /api/config default_poll_interval', 'reject', self._fleet_default),
            ('the default an enrolling host is given', 'clamp', self._new_host_default),
        )

    def test_every_entry_point_matches_the_agents(self):
        lo, hi = self.lo, self.hi
        wrong = []
        in_range_stored = 0
        entry_points = self.entry_points()
        for name, mode, fn in entry_points:
            for v in (lo - 1, lo, hi, hi + 1):
                kind, got = fn(v)
                inside = lo <= v <= hi
                if inside:
                    ok = kind == 'stored' and got == v
                    in_range_stored += ok
                elif mode == 'reject':
                    ok = kind == 'rejected'
                else:
                    ok = kind == 'stored' and got == (lo if v < lo else hi)
                if not ok:
                    wrong.append(f'{name}: {v} -> {kind} {got!r}')
        agree = len(entry_points) - len({w.split(':')[0] for w in wrong})
        self.assertEqual(
            wrong, [],
            f'{agree} of {len(entry_points)} entry points take the agents\' '
            f'{lo}-{hi}; the others disagree:\n  ' + '\n  '.join(wrong))
        # The control: the in-range values really were stored, so a harness that
        # rejected everything cannot pass by agreeing about the outside.
        self.assertEqual(in_range_stored, 2 * len(entry_points))

    def test_a_refusal_names_the_range_the_agents_run(self):
        lo, hi = self.lo, self.hi
        for name, mode, fn in self.entry_points():
            if mode != 'reject':
                continue
            kind, got = fn(lo - 1)
            self.assertEqual(kind, 'rejected', name)
            text = got['error']
            self.assertIn(f'{lo}–{hi}', text.replace('..', '–'),
                          f'{name} says {text!r}')

    def test_the_server_constants_are_the_agents_range(self):
        self.assertEqual((self.api.POLL_INTERVAL_MIN, self.api.POLL_INTERVAL_MAX),
                         (self.lo, self.hi))


class TestEveryDocumentedSurfaceSaysTheSame(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.lo, cls.hi = agent_range()
        cls.html = (_ROOT / 'server/html/index.html').read_text()
        cls.js = (_ROOT / 'server/html/static/js/app.js').read_text()

    def test_openapi_documents_the_agents_range(self):
        src = (_ROOT / 'server/cgi-bin/openapi_spec.py').read_text()
        m = re.search(r'"poll_interval":\s*\{"type": "integer", "minimum": (\d+), '
                      r'"maximum": (\d+)\}', src)
        self.assertTrue(m, 'the poll_interval schema is gone from openapi_spec.py')
        self.assertEqual((int(m.group(1)), int(m.group(2))), (self.lo, self.hi))

    def test_every_poll_input_carries_the_range(self):
        pop = []
        for where, src in (('index.html', self.html), ('app.js', self.js)):
            for m in re.finditer(r'<input\b[^>]*\bid="([^"]*poll[^"]*)"[^>]*>', src):
                tag = m.group(0)
                # ap-offline-polls is a missed-poll multiplier (1-100), not an interval.
                if 'type="number"' not in tag or not re.search(
                        r'(?:^|-)poll$|^poll-input$', m.group(1)):
                    continue
                mn = re.search(r'\bmin="(\d+)"', tag)
                mx = re.search(r'\bmax="(\d+)"', tag)
                pop.append((where, m.group(1),
                            int(mn.group(1)) if mn else None,
                            int(mx.group(1)) if mx else None))
        names = {n for _w, n, _a, _b in pop}
        # The five inputs that exist today; a rename must update this list.
        self.assertEqual(names, {'ds-poll', 'ba-poll', 'dp-poll', 'poll-input',
                                 'cfg-default-poll'}, pop)
        wrong = [p for p in pop if (p[2], p[3]) != (self.lo, self.hi)]
        self.assertEqual(wrong, [], 'inputs whose min/max differ from the agents')

    def test_the_drawer_prompt_and_the_bulk_form_check_the_same_numbers(self):
        lo, hi = self.lo, self.hi
        fn = srcpin.js_function(self.js, '_drawerAdjustPoll')
        self.assertNotRegex(fn, r'\b30\b')
        self.assertRegex(fn, rf'n < {lo}\b')
        self.assertIn(f'min {lo}', fn)
        self.assertIn(f'≥ {lo} seconds', fn)
        m = re.search(r'p < (\d+) \|\| p > (\d+)', self.js)
        self.assertTrue(m, 'the bulk-edit range check is gone')
        self.assertEqual((int(m.group(1)), int(m.group(2))), (lo, hi))
        self.assertIn(f"Poll interval must be {lo}–{hi} seconds", self.js)

    def test_saving_the_drawer_does_not_raise_the_floor(self):
        m = re.search(r'poll_interval: Math\.max\((\d+), poll\)', self.js)
        self.assertTrue(m, 'the drawer save no longer clamps poll_interval')
        self.assertEqual(int(m.group(1)), self.lo)


if __name__ == '__main__':
    unittest.main()
