#!/usr/bin/env python3
"""The SBOM of a host that lists 10,000 packages of one source does not take 18 seconds.

`sbom._affected_refs` finds the components a vulnerability is about. It walked the whole package list for each finding and tested
`c not in picked` and `c['ref'] not in refs` on lists that grow to the number of packages of the source, so it cost 0.36 s a finding at
10,000 packages and four times that for each doubling. A host sends its own list (up to 10,000 rows, 1 MB of the 2 MiB body limit), so
a host that says every package was built from `linux`, with fifty findings stored against that source, made `GET /api/devices/<id>/sbom`
cost 18 seconds of CPU for any signed-in user who can see the host (a tenant's viewer), and the fleet archive the same. Four such
requests at once held every thread of a worker, and the whole installation answered 50 to 600 times slower while they ran.

What this holds:

* the answer is the one the old walk gave, in the same order, cut at the same number, for random lists and findings: names that are
  cut at thirty, two versions of one name, a source that the list names and a binary that it does not, lists with a repeated name;
* it is found from indexes: 40,000 components of one source take a fraction of a second where the walk took seconds;
* a whole document, 10,000 packages of one source and fifty findings, is built in seconds and not in tens of them, and the number
  of components a vulnerability points at stays at the ceiling.
"""
import os
import random
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v802-sb-"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server" / "cgi-bin"))
import sbom  # noqa: E402


def _walk(f, installed):
    """The lookup as it was before 8.0.2, kept here as the reference the indexed one is held to."""
    package = f.get('package') if isinstance(f.get('package'), str) else ''
    version = sbom._no_epoch(f.get('version'))
    names = [n for n in (f.get('binaries') if isinstance(f.get('binaries'), list) else []) if isinstance(n, str) and n]
    more = f.get('binaries_more')
    cut = isinstance(more, int) and not isinstance(more, bool) and more > 0
    if not names and package:
        names = [package]
    wanted = set(names)
    named = [c for c in installed if c['name'] in wanted]
    at_version = [c for c in named if version and version in (c['version'], c['source_version'])]
    held = {c['name'] for c in at_version}
    picked = at_version + [c for c in named if c['name'] not in held]
    if cut or not picked:
        picked += [c for c in installed
                   if c['source'] == package and version and version in (c['source_version'], c['version'])
                   and c not in picked]
    refs = []
    for c in picked:
        if c['ref'] not in refs:
            refs.append(c['ref'])
    return refs[:sbom.MAX_AFFECTS]


def _component(i, name, version, source=None, source_version=None):
    return {'ref': 'comp-%d' % i, 'name': name, 'version': version, 'source': source or name,
            'source_version': source_version or version}


class TestTheAnswerIsTheOldOne(unittest.TestCase):

    def test_random_lists_and_findings_get_the_answer_the_walk_gave(self):
        rng = random.Random(8021)
        checked = filled = capped = 0
        for case in range(400):
            n = rng.choice([0, 1, 5, 30, 120, 400])
            names = ['pkg%d' % rng.randrange(max(1, n // 2 + 1)) for _ in range(n)]       # repeated names: two versions of one name
            sources = ['src%d' % rng.randrange(5) for _ in range(n)]
            installed = []
            for i in range(n):
                v = rng.choice(['1.0', '1.1', '2:3.0-1', '3.0-1'])
                installed.append(_component(i, names[i], sbom._no_epoch(v), sources[i], sbom._no_epoch(rng.choice(['1.0', '1.1', '3.0-1']))))
            f = {'package': rng.choice(['src%d' % rng.randrange(6), 'pkg%d' % rng.randrange(max(1, n // 2 + 1)), '', None, 5]),
                 'version': rng.choice(['1.0', '1.1', '2:3.0-1', '3.0-1', '', None, 9])}
            if rng.random() < 0.6:
                f['binaries'] = [rng.choice(['pkg%d' % rng.randrange(max(1, n // 2 + 1)), 'nothing', '', 7]) for _ in range(rng.randrange(0, 31))]
            if rng.random() < 0.4:
                f['binaries_more'] = rng.choice([0, 3, 9970, True, 'x', None])
            want = _walk(f, installed)
            got = sbom._affected_refs(f, installed)
            checked += 1
            filled += bool(want)
            capped += len(want) >= sbom.MAX_AFFECTS
            self.assertEqual(got, want, 'case %d: %r' % (case, f))
        self.assertGreater(filled, 100, 'control: the cases found components often enough to mean something')
        self.assertEqual(checked, 400)

    def test_a_list_that_was_cut_at_the_ceiling_gets_the_same_first_components(self):
        installed = [_component(i, 'libx%d' % i, '1.0', 'linux', '5.10.1-1') for i in range(1000)]
        f = {'package': 'linux', 'version': '5.10.1-1', 'binaries': ['libx%d' % j for j in range(30)], 'binaries_more': 970}
        got = sbom._affected_refs(f, installed)
        self.assertEqual(got, _walk(f, installed))
        self.assertEqual(len(got), sbom.MAX_AFFECTS)
        self.assertEqual(got[:3], ['comp-0', 'comp-1', 'comp-2'])

    def test_an_index_built_once_gives_the_same_answers_as_the_list(self):
        installed = [_component(i, 'a%d' % (i % 7), '1.0', 'src%d' % (i % 3), '1.0') for i in range(60)]
        index = sbom._Installed(installed)
        for f in ({'package': 'a1', 'version': '1.0'}, {'package': 'src2', 'version': '1.0', 'binaries_more': 5}, {'package': 'zzz', 'version': '1'}):
            self.assertEqual(sbom._affected_refs(f, index), sbom._affected_refs(f, installed))


class TestTheCost(unittest.TestCase):

    def test_forty_thousand_components_of_one_source_are_found_from_the_index(self):
        installed = [_component(i, 'libx%d' % i, '1.0', 'linux', '5.10.1-1') for i in range(40000)]
        f = {'package': 'linux', 'version': '5.10.1-1', 'binaries': ['libx%d' % j for j in range(30)], 'binaries_more': 39970}
        t = time.process_time()
        refs = sbom._affected_refs(f, installed)
        took = time.process_time() - t
        self.assertEqual(len(refs), sbom.MAX_AFFECTS)
        self.assertLess(took, 0.5, "the walk took %.1f s for this and four times as long for each doubling" % took)

    def test_a_document_of_ten_thousand_packages_of_one_source_and_fifty_findings(self):
        n = 10000
        packages = [{'name': 'libx%d' % i, 'version': '1.0', 'arch': 'amd64', 'source': 'linux', 'source_version': '5.10.1-1'} for i in range(n)]
        findings = [{'package': 'linux', 'version': '5.10.1-1', 'vuln_id': 'DEBIAN-CVE-2024-%d' % (1000 + i), 'severity': 'critical',
                     'fix_status': 'fixed', 'fixed_version': '6.1.99-1', 'aliases': [], 'binaries': ['libx%d' % j for j in range(30)],
                     'binaries_more': n - 30} for i in range(50)]
        entry = {'packages': packages, 'pkg_manager': 'apt', 'ecosystem': 'Debian:12', 'os_id': 'debian'}
        t = time.process_time()
        doc = sbom.build_cyclonedx({'id': 'd1', 'name': 'h', 'hostname': 'h'}, entry, findings)
        took = time.process_time() - t
        self.assertEqual(len(doc['vulnerabilities']), 50)
        self.assertTrue(all(len(v['affects']) == sbom.MAX_AFFECTS for v in doc['vulnerabilities']))
        self.assertEqual(len(doc['components']), n)
        self.assertLess(took, 3.0, "this took 18 s of CPU before 8.0.2; %.1f s now" % took)

    def test_the_control_host_with_a_source_of_its_own_per_package_is_not_slower(self):
        n = 10000
        packages = [{'name': 'libx%d' % i, 'version': '1.0', 'arch': 'amd64', 'source': 'src%d' % i, 'source_version': '1.0'} for i in range(n)]
        findings = [{'package': 'src%d' % i, 'version': '1.0', 'vuln_id': 'DEBIAN-CVE-2024-%d' % i, 'severity': 'high', 'aliases': []}
                    for i in range(50)]
        entry = {'packages': packages, 'pkg_manager': 'apt', 'ecosystem': 'Debian:12', 'os_id': 'debian'}
        t = time.process_time()
        doc = sbom.build_cyclonedx({'id': 'd1'}, entry, findings)
        self.assertLess(time.process_time() - t, 3.0)
        self.assertEqual([len(v['affects']) for v in doc['vulnerabilities']][:3], [1, 1, 1])


if __name__ == '__main__':
    unittest.main()
