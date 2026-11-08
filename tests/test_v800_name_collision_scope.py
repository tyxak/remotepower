#!/usr/bin/env python3
"""8.0.0: a row is matched to the caller's hosts by id, not by display name.

A host name is free text and two tenants can each have a host called web01. The compliance evidence matched fleet events to the caller's hosts by id OR by name, so another
tenant's event of a host with the same name as one of the caller's was counted as the caller's, and its port and event kind went into the caller's evidence. The image
auto-update page matched its last run by name in the same way (test_v800_image_autoupdate holds that one). The population here is read from the code: every membership test of
a name-like field against a collection of names.
"""

import ast
import glob
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-namecoll-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

from test_ip_intel import _fresh_api  # noqa: E402

CGI = _TESTS.parent / 'server' / 'cgi-bin'

# a membership test of a name-like field that is not a visibility test, with the reason
EXEMPT = {
    ('api.py', "g.get('name') in c_names"): 'compares the names of the groups of two lists (a diff of one document), not hosts',
    ('time_periods.py', "per['name'].lower() in names"): 'checks that a time period name is not already taken',
    ('api.py', "(e.get('payload') or {}).get('name') in _visible_names"): 'the fallback of _compliance_facts for a fleet event that carries no host id: reached only when the event has none',
}


def name_keyed_tests(sources):
    """[(file, line, left, right)] for each `X in Y` whose X reads a name-like field and whose Y is a name-like collection and not a literal."""
    out = []
    for name, src in sources.items():
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for n in ast.walk(tree):
            if isinstance(n, ast.Compare) and len(n.ops) == 1 and isinstance(n.ops[0], (ast.In, ast.NotIn)):
                left, right = ast.unparse(n.left), ast.unparse(n.comparators[0])
                if re.search(r"get\('(name|hostname|device|host)'\)|\['(name|hostname|device|host)'\]", left) and re.search(r'name|visible|vis\b|_vis|confin|mine', right, re.I) \
                        and not re.search(r'^[\(\[\{]?[\'"]', right):
                    out.append((name, n.lineno, left, right))
    return out


class TestThePopulation(unittest.TestCase):

    def test_the_scan_sees_a_planted_name_match_and_passes_an_id_match(self):
        planted = "def f(rows, names, ids):\n    return [r for r in rows if r.get('name') in names]\n"
        by_id = "def f(rows, names, ids):\n    return [r for r in rows if r.get('device_id') in ids]\n"
        self.assertEqual(len(name_keyed_tests({'x.py': planted})), 1)
        self.assertEqual(name_keyed_tests({'x.py': by_id}), [], 'control: an id match is not listed')

    def test_every_name_match_is_listed_with_a_reason(self):
        sources = {Path(p).name: Path(p).read_text() for p in sorted(glob.glob(str(CGI / '*.py')))}
        self.assertGreater(sum(s.count('.get(') for s in sources.values()), 10000, 'control: the sources were read')
        found = name_keyed_tests(sources)
        left = [f for f in found if (f[0], '%s in %s' % (f[2], f[3])) not in EXEMPT]
        self.assertEqual(left, [], '%d name-keyed tests found, %d listed with a reason; these are not: %s' % (len(found), len(found) - len(left), left))


class TestComplianceEvidence(unittest.TestCase):

    def setUp(self):
        self.api = _fresh_api()
        now = int(time.time())
        self.devs = {
            'dA': {'id': 'dA', 'name': 'web01', 'tenant': 'tenantA', 'os': 'Ubuntu', 'last_seen': now, 'token': 'ta'},
            'dB': {'id': 'dB', 'name': 'web01', 'tenant': 'tenantB', 'os': 'Ubuntu', 'last_seen': now, 'token': 'tb'},
        }
        self.api.save(self.api.DEVICES_FILE, self.devs)
        self.api.save(self.api.CONFIG_FILE, {})
        self.api.save(self.api.FLEET_EVENTS_FILE, {'events': [
            {'event': 'new_port_detected', 'ts': now, 'payload': {'device_id': 'dA', 'name': 'web01', 'port': 8080}},
            {'event': 'new_port_detected', 'ts': now, 'payload': {'device_id': 'dB', 'name': 'web01', 'port': 2222}},
            {'event': 'brute_force_detected', 'ts': now, 'payload': {'name': 'web01'}},
        ]})
        self.api._LOAD_CACHE.clear()

    def test_another_tenants_event_of_a_host_with_the_same_name_is_not_the_callers(self):
        facts = self.api._compliance_facts({'dA': self.devs['dA']})
        self.assertEqual(facts['new_ports'], ['web01:8080'], 'tenant B\'s port 2222 is not tenant A\'s evidence')

    def test_the_other_tenant_sees_its_own_event_and_not_the_first(self):
        facts = self.api._compliance_facts({'dB': self.devs['dB']})
        self.assertEqual(facts['new_ports'], ['web01:2222'])

    def test_the_whole_fleet_is_still_the_whole_fleet(self):
        facts = self.api._compliance_facts()
        self.assertEqual(sorted(facts['new_ports']), ['web01:2222', 'web01:8080'], 'control: the system path reads every event')

    def test_an_event_with_no_id_is_still_matched_by_its_name(self):
        facts = self.api._compliance_facts({'dA': self.devs['dA']})
        self.assertEqual(facts['brute_force'], ['web01'], 'the one case with nothing but a name to go by')

    def test_a_damaged_id_is_read_as_no_id(self):
        now = int(time.time())
        self.api.save(self.api.FLEET_EVENTS_FILE, {'events': [{'event': 'new_port_detected', 'ts': now, 'payload': {'device_id': ['dB'], 'name': 'web01', 'port': 1}}]})
        self.api._LOAD_CACHE.clear()
        facts = self.api._compliance_facts({'dA': self.devs['dA']})
        self.assertEqual(facts['new_ports'], ['web01:1'], 'not an id, so the name decides, and nothing is raised')


if __name__ == '__main__':
    unittest.main()
