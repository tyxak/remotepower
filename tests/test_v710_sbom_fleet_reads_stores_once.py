"""GET /api/sbom reads the four SBOM stores once for the whole fleet, not once per host.

The fleet ZIP builds one SBOM per host, and `_build_sbom_doc` called load() on the packages, CVE-findings,
CVE-ignore and containers stores for every host. Each load() deep-copies a store that holds a row per
host, so the cost grew with the square of the fleet: on a 2,000-host synthetic fleet the request did not
answer within 60 s, and it takes 1.9 s now. The fleet handler reads the four stores once and passes them in.

This runs the real handler, counts load() calls per store, and reads the ZIP it returns, so the
documents are checked as well as the cost: a host with a finding carries its vulnerability, a host with a
container carries the container component, and the stores come out of the request unchanged.
"""
import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))

_STORES = ('packages.json', 'cve_findings.json', 'cve_ignore.json', 'containers.json')


def _fresh_api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v710-sbom-')
    spec = importlib.util.spec_from_file_location('api_v710_sbom', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Base(unittest.TestCase):

    def setUp(self):
        self.api = _fresh_api()
        api = self.api
        api.audit_log = lambda *a, **k: None
        api.get_token_from_request = lambda: 'x'
        api.verify_token = lambda tok=None: ('alice', 'admin')
        api.require_auth = lambda *a, **k: ('alice', 'admin')
        api._caller_scope = lambda: None
        api._env = lambda k, d='': d

    def seed(self, n):
        api = self.api
        devices, packages, findings, containers = {}, {}, {}, {}
        for i in range(n):
            did = 'd%03d' % i
            devices[did] = {'name': 'host-%03d' % i, 'os': 'ubuntu-22.04', 'token': 't'}
            packages[did] = {'packages': [{'name': 'pkg%d' % j, 'version': '1.%d' % j, 'arch': 'amd64'} for j in range(5)],
                             'pkg_manager': 'apt', 'os_id': 'ubuntu', 'collected_at': 1700000000}
        findings['d000'] = {'findings': [{'vuln_id': 'CVE-2024-0001', 'package': 'pkg0', 'version': '1.0',
                                          'severity': 'high', 'fixed_version': '1.1'}]}
        containers['d001'] = {'items': [{'image': 'nginx', 'tag': '1.25', 'name': 'web', 'runtime': 'docker'}]}
        api.save(api.DEVICES_FILE, devices)
        api.save(api.PACKAGES_FILE, packages)
        api.save(api.CVE_FINDINGS_FILE, findings)
        api.save(api.CVE_IGNORE_FILE, {})
        api.save(api.CONTAINERS_FILE, containers)
        api._LOAD_CACHE.clear()

    def download(self):
        """(zip, {store file name: load() calls}) for one real GET /api/sbom."""
        api = self.api
        api._LOAD_CACHE.clear()
        calls = {}
        real = api.load

        def counting(path, *a, **k):
            name = Path(str(path)).name
            calls[name] = calls.get(name, 0) + 1
            return real(path, *a, **k)

        api.load = counting
        out = io.TextIOWrapper(io.BytesIO(), encoding='utf-8', write_through=True)
        try:
            with contextlib.redirect_stdout(out):
                try:
                    api.handle_sbom_fleet()
                except SystemExit:
                    pass
        finally:
            api.load = real
        head, _, body = out.buffer.getvalue().partition(b'\n\n')
        self.assertIn(b'application/zip', head, head[:200])
        return zipfile.ZipFile(io.BytesIO(body)), calls


class TestTheFleetZipReadsEachStoreOnce(_Base):

    def test_store_loads_do_not_grow_with_the_number_of_hosts(self):
        self.seed(5)
        small_zip, small = self.download()
        self.seed(40)
        big_zip, big = self.download()
        self.assertEqual(5, len(small_zip.namelist()))
        self.assertEqual(40, len(big_zip.namelist()), 'control: every host should have a document')
        for store in _STORES:
            self.assertLessEqual(big.get(store, 0), 1, '%s was loaded %r times for 40 hosts' % (store, big.get(store)))
        self.assertEqual(small, big, 'load() calls grew with the host count: %r -> %r' % (small, big))


class TestTheDocumentsAreUnchanged(_Base):

    def docs(self, n=6):
        self.seed(n)
        z, _ = self.download()
        return {name: json.loads(z.read(name)) for name in z.namelist()}

    def test_each_host_gets_its_own_packages(self):
        docs = self.docs()
        self.assertEqual(6, len(docs))
        for name, doc in docs.items():
            self.assertEqual('CycloneDX', doc['bomFormat'], name)
            libs = [c for c in doc['components'] if c['type'] == 'library']
            self.assertEqual(5, len(libs), name)

    def test_a_host_with_a_finding_carries_its_vulnerability_and_others_do_not(self):
        docs = self.docs()
        with_vulns = {name for name, doc in docs.items() if doc.get('vulnerabilities')}
        self.assertEqual(1, len(with_vulns), with_vulns)
        only = next(iter(with_vulns))
        self.assertEqual('CVE-2024-0001', docs[only]['vulnerabilities'][0]['id'])
        self.assertIn('host-000', only)

    def test_a_host_with_a_container_carries_the_container_component(self):
        docs = self.docs()
        with_ctr = {name for name, doc in docs.items() if any(c['type'] == 'container' for c in doc['components'])}
        self.assertEqual(1, len(with_ctr), with_ctr)
        self.assertIn('host-001', next(iter(with_ctr)))

    def test_every_document_equals_the_one_built_from_private_copies(self):
        """Rebuild each host's SBOM from deep copies of the stores, the way the per-host path used to, and
        compare: passing shared views in must change nothing in what is written."""
        self.seed(6)
        self.api.save(self.api.CVE_IGNORE_FILE, {'CVE-2024-0001': {'reason': 'accepted', 'scope': 'global'}})
        self.api._LOAD_CACHE.clear()
        api = self.api
        import cve_scanner
        import sbom as sbom_mod
        z, _ = self.download()
        got = {name: json.loads(z.read(name)) for name in z.namelist()}
        devices, packages = api.load(api.DEVICES_FILE), api.load(api.PACKAGES_FILE)
        findings, ignore, containers = api.load(api.CVE_FINDINGS_FILE), api.load(api.CVE_IGNORE_FILE), api.load(api.CONTAINERS_FILE)
        want = {}
        for did, dev in devices.items():
            dev = dict(dev)
            dev['id'] = did
            fl = cve_scanner.apply_ignore_list((findings.get(did) or {}).get('findings') or [], ignore, did)
            doc = sbom_mod.build_cyclonedx(dev, packages.get(did) or {}, fl, server_version=api.SERVER_VERSION,
                                           containers=(containers.get(did) or {}).get('items') or [])
            want[sbom_mod.filename_for(dev, 'cyclonedx')] = json.loads(json.dumps(doc))
        self.assertEqual(sorted(want), sorted(got))
        for name in want:
            for doc in (want[name], got[name]):
                doc.get('metadata', {}).pop('timestamp', None)
            self.assertEqual(want[name], got[name], name)

    def test_the_stores_come_out_of_the_request_unchanged(self):
        self.seed(4)
        api = self.api
        before = [json.dumps(api.load(f), sort_keys=True) for f in (api.PACKAGES_FILE, api.CVE_FINDINGS_FILE, api.CVE_IGNORE_FILE, api.CONTAINERS_FILE)]
        self.download()
        after = [json.dumps(api.load(f), sort_keys=True) for f in (api.PACKAGES_FILE, api.CVE_FINDINGS_FILE, api.CVE_IGNORE_FILE, api.CONTAINERS_FILE)]
        self.assertEqual(before, after)


if __name__ == '__main__':
    unittest.main()
