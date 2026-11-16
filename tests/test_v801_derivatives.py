"""A derivative of Ubuntu or Debian is scanned under the release it is built on (8.0.1).

The security data is kept per release of Ubuntu and of Debian. A derivative numbers its own releases, and that
number was taken for the base's:

  * Linux Mint 21.3, Zorin OS 17 and elementary OS 7 are Ubuntu 22.04 underneath. Their release was "not known", so
    they stayed matched by installed name and every finding carried the fixed version of whichever release its
    advisory listed last: on a Mint host of the recordings 86 of 92 findings named another release's fix, one of
    them a FIPS build;
  * Devuan 5 was asked for as Debian 5 and LMDE 6 as Debian 6, releases of 2009 and 2011 that the advisory database
    holds nothing for, so the host read as scanned and clean;
  * Kali (2025.3) was asked for as Debian 2025, the same way.

What a derivative does say is the codename of its base (UBUNTU_CODENAME=jammy, DEBIAN_CODENAME=bookworm) or its own
(Devuan: VERSION_CODENAME=daedalus). The agent sends the three fields from 8.0.1, the server keeps them, and the
release comes from a table of the names the distributions published.

The os-release samples below are written from the files the distributions ship. None was read from a host: there
is no such host here.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v801-deriv-'))
_spec = importlib.util.spec_from_file_location('api_v801_deriv', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
cve_scanner = api.cve_scanner
cve_fixes = api.cve_fixes

from osv_recording import UBU, Database  # noqa: E402
from test_docker_agent import load_agent  # noqa: E402

AGENT = load_agent()
HOST = 'v801derivhost'

# /etc/os-release, the fields that matter, as each distribution ships it
OS_RELEASE = {
    'ubuntu 22.04': 'NAME="Ubuntu"\nVERSION_ID="22.04"\nID=ubuntu\nID_LIKE=debian\nVERSION_CODENAME=jammy\nUBUNTU_CODENAME=jammy\n',
    'pop 22.04': 'NAME="Pop!_OS"\nVERSION_ID="22.04"\nID=pop\nID_LIKE="ubuntu debian"\nVERSION_CODENAME=jammy\nUBUNTU_CODENAME=jammy\n',
    'mint 21.3': 'NAME="Linux Mint"\nVERSION_ID="21.3"\nID=linuxmint\nID_LIKE="ubuntu debian"\nVERSION_CODENAME=virginia\nUBUNTU_CODENAME=jammy\n',
    'mint 22': 'NAME="Linux Mint"\nVERSION_ID="22"\nID=linuxmint\nID_LIKE="ubuntu debian"\nVERSION_CODENAME=wilma\nUBUNTU_CODENAME=noble\n',
    'zorin 17': 'NAME="Zorin OS"\nVERSION_ID="17"\nID=zorin\nID_LIKE="ubuntu debian"\nVERSION_CODENAME=jammy\nUBUNTU_CODENAME=jammy\n',
    'elementary 7.1': 'NAME="elementary OS"\nVERSION_ID="7.1"\nID=elementary\nID_LIKE="ubuntu debian"\nVERSION_CODENAME=horus\nUBUNTU_CODENAME=jammy\n',
    'neon 24.04': 'NAME="KDE neon"\nVERSION_ID="24.04"\nID=neon\nID_LIKE="ubuntu debian"\nVERSION_CODENAME=noble\nUBUNTU_CODENAME=noble\n',
    'lmde 6': 'NAME="LMDE"\nVERSION_ID="6"\nID=linuxmint\nID_LIKE=debian\nVERSION_CODENAME=faye\nDEBIAN_CODENAME=bookworm\n',
    'devuan 5': 'NAME="Devuan GNU/Linux"\nVERSION_ID="5"\nID=devuan\nID_LIKE=debian\nVERSION_CODENAME="daedalus"\n',
    'raspbian 12': 'NAME="Raspbian GNU/Linux"\nVERSION_ID="12"\nID=raspbian\nID_LIKE=debian\nVERSION_CODENAME=bookworm\n',
    'debian 12': 'NAME="Debian GNU/Linux"\nVERSION_ID="12"\nID=debian\nVERSION_CODENAME=bookworm\n',
    'debian testing': 'NAME="Debian GNU/Linux"\nID=debian\nVERSION_CODENAME=forky\n',
    'debian unstable': 'NAME="Debian GNU/Linux"\nID=debian\n',
    'kali': 'NAME="Kali GNU/Linux"\nVERSION_ID="2025.3"\nID=kali\nID_LIKE=debian\nVERSION_CODENAME=kali-rolling\n',
    'deepin 23': 'NAME="Deepin"\nVERSION_ID="23"\nID=deepin\nID_LIKE=debian\nVERSION_CODENAME=beige\n',
}
# (the name it is scanned under, the release its fixes are read for), with an agent from 8.0.1
EXPECTED = {
    'ubuntu 22.04': ('Ubuntu', 'Ubuntu:22.04:LTS'), 'pop 22.04': ('Ubuntu', 'Ubuntu:22.04:LTS'),
    'mint 21.3': ('Ubuntu', 'Ubuntu:22.04:LTS'), 'mint 22': ('Ubuntu', 'Ubuntu:24.04:LTS'),
    'zorin 17': ('Ubuntu', 'Ubuntu:22.04:LTS'), 'elementary 7.1': ('Ubuntu', 'Ubuntu:22.04:LTS'),
    'neon 24.04': ('Ubuntu', 'Ubuntu:24.04:LTS'),
    'lmde 6': ('Debian:12', 'Debian:12'), 'devuan 5': ('Debian:12', 'Debian:12'),
    'raspbian 12': ('Debian:12', 'Debian:12'), 'debian 12': ('Debian:12', 'Debian:12'),
    'debian testing': ('Debian:14', 'Debian:14'), 'debian unstable': ('', ''), 'kali': ('', ''), 'deepin 23': ('', ''),
}
# the same hosts with an agent that sends ID, VERSION_ID and ID_LIKE only
WITHOUT_CODENAMES = dict(EXPECTED, **{
    'mint 21.3': ('Ubuntu', ''), 'mint 22': ('Ubuntu', ''), 'zorin 17': ('Ubuntu', ''), 'elementary 7.1': ('Ubuntu', ''),
    'debian testing': ('', ''),
})


class _Captured(Exception):
    def __init__(self, status, body):
        super().__init__(status)
        self.status, self.body = status, body


_READ_OS_RELEASE = AGENT.get_os_release


def parse(text):
    """The agent's own reader of /etc/os-release, on a sample."""
    path = Path(tempfile.mkdtemp(prefix='rp-v801-osr-')) / 'os-release'
    path.write_text(text)
    with mock.patch.object(AGENT, 'host_path', lambda p: str(path)):
        return _READ_OS_RELEASE()


class _Server(unittest.TestCase):
    def setUp(self):
        self._saved = (api.respond, api.method, api.get_json_obj, api._eval_software_policy)

        def respond(status, data):
            raise _Captured(status, data)
        api.respond = respond
        api.method = lambda: 'POST'
        api._eval_software_policy = lambda *a, **k: None
        api.save(api.DEVICES_FILE, {HOST: {'id': HOST, 'name': 'box', 'token': 'tok', 'monitored': True}})
        api.save(api.PACKAGES_FILE, {})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        (api.respond, api.method, api.get_json_obj, api._eval_software_policy) = self._saved
        for store in (api.DEVICES_FILE, api.PACKAGES_FILE):
            api.save(store, {})
        api._LOAD_CACHE.clear()

    def submit(self, body):
        api.get_json_obj = lambda: dict({'device_id': HOST, 'token': 'tok'}, **body)
        api._LOAD_CACHE.clear()
        try:
            api.handle_packages_submit()
        except _Captured as c:
            self.assertEqual(c.status, 200, c.body)
            api._LOAD_CACHE.clear()
            return c.body, (api.load(api.PACKAGES_FILE) or {}).get(HOST) or {}
        self.fail('the handler did not answer')

    def what_the_agent_sends(self, name):
        """The payload of the agent's own send, for a host with this os-release."""
        sent = []
        with mock.patch.object(AGENT, 'get_os_release', lambda: parse(OS_RELEASE[name])), \
                mock.patch.object(AGENT, 'get_package_list_ex',
                                  lambda: ('apt', [{'name': 'libc6', 'version': '2.35-0ubuntu3.6', 'arch': 'amd64',
                                                    'source': 'glibc'}], True)), \
                mock.patch.object(AGENT, 'http_post', lambda url, payload, timeout=30: sent.append(payload) or {}), \
                mock.patch.object(AGENT, '_load_last_pkg_hash', lambda: ''), \
                mock.patch.object(AGENT, '_save_last_pkg_hash', lambda h: None):
            self.assertTrue(AGENT.send_package_list({'device_id': HOST, 'token': 'tok', 'server_url': 'https://rp.example'}))
        (payload,) = sent
        return payload


class TestFromTheAgentToTheRelease(_Server):
    """The agent's payload for each os-release, through the real handler, to the release a scan reads."""

    def through(self, name, strip_codenames=False):
        payload = self.what_the_agent_sends(name)
        if strip_codenames:
            payload = dict(payload, ecosystem_hint={k: v for k, v in payload['ecosystem_hint'].items()
                                                    if k in ('ID', 'VERSION_ID', 'ID_LIKE')})
        answer, stored = self.submit({k: v for k, v in payload.items() if k not in ('device_id', 'token')})
        return answer, stored

    def test_the_agent_sends_the_three_codenames(self):
        hint = self.what_the_agent_sends('mint 21.3')['ecosystem_hint']
        self.assertEqual(hint, {'ID': 'linuxmint', 'VERSION_ID': '21.3', 'ID_LIKE': 'ubuntu debian',
                                'UBUNTU_CODENAME': 'jammy', 'DEBIAN_CODENAME': '', 'VERSION_CODENAME': 'virginia'})
        self.assertEqual(self.what_the_agent_sends('lmde 6')['ecosystem_hint']['DEBIAN_CODENAME'], 'bookworm')
        self.assertEqual(self.what_the_agent_sends('devuan 5')['ecosystem_hint']['VERSION_CODENAME'], 'daedalus')

    def test_every_sample_with_an_agent_from_8_0_1(self):
        self.assertEqual(sorted(OS_RELEASE), sorted(EXPECTED))
        for name, (ecosystem, release) in EXPECTED.items():
            answer, stored = self.through(name)
            self.assertEqual(answer['ecosystem'], ecosystem or 'unsupported', name)
            self.assertEqual((cve_scanner.entry_ecosystem(stored), cve_scanner.entry_release(stored)), (ecosystem, release), name)
            self.assertEqual(cve_scanner.by_source(ecosystem, release), bool(release), name)

    def test_every_sample_with_an_older_agent(self):
        """Without the codenames a derivative that numbers its own releases is as it was: release not known.
        Devuan and LMDE are told apart by their name and number, so they are right with any agent."""
        for name, (ecosystem, release) in WITHOUT_CODENAMES.items():
            answer, stored = self.through(name, strip_codenames=True)
            self.assertEqual(answer['ecosystem'], ecosystem or 'unsupported', name)
            self.assertEqual((cve_scanner.entry_ecosystem(stored), cve_scanner.entry_release(stored)), (ecosystem, release), name)
            for key in ('ubuntu_codename', 'debian_codename', 'version_codename'):
                self.assertNotIn(key, stored, name)

    def test_what_is_kept_of_a_codename(self):
        _answer, stored = self.through('mint 21.3')
        self.assertEqual((stored['ubuntu_codename'], stored['version_codename']), ('jammy', 'virginia'))
        self.assertNotIn('debian_codename', stored)
        keep = cve_scanner.codename
        self.assertEqual([keep(v) for v in ('jammy', ' Jammy ', 'kali-rolling', 'a')], ['jammy', 'jammy', 'kali-rolling', 'a'])
        for odd in ('', None, 7, True, ['jammy'], {'a': 1}, '<script>', 'two words', '9lives', '-x', 'a' * 33, 'jammy\nx', 'ja/mmy'):
            self.assertEqual(keep(odd), '', odd)           # `True` is not the codename "true"
        for hostile in ('<img src=x onerror=1>', 'x' * 300, ['jammy'], {'a': 1}, 7):
            body = {'pkg_manager': 'apt', 'packages': [{'name': 'a', 'version': '1'}],
                    'ecosystem_hint': {'ID': 'linuxmint', 'VERSION_ID': '21.3', 'ID_LIKE': 'ubuntu debian',
                                       'UBUNTU_CODENAME': hostile, 'DEBIAN_CODENAME': hostile, 'VERSION_CODENAME': hostile}}
            _answer, kept = self.submit(body)
            self.assertNotIn('ubuntu_codename', kept, hostile)
            self.assertEqual(cve_scanner.entry_release(kept), '', hostile)
        # a hint that is no object is refused before any of this
        api.get_json_obj = lambda: {'device_id': HOST, 'token': 'tok', 'pkg_manager': 'apt',
                                    'packages': [{'name': 'a', 'version': '1'}], 'ecosystem_hint': 'ubuntu'}
        with self.assertRaises(_Captured) as refused:
            api.handle_packages_submit()
        self.assertEqual(refused.exception.status, 400)


class TestTheNames(unittest.TestCase):
    def test_the_codename_wins_over_a_version_that_looks_like_ubuntus(self):
        release = cve_scanner.entry_release
        base = {'ecosystem': 'Ubuntu', 'os_id': 'neon', 'version_id': '24.04'}
        self.assertEqual(release(base), 'Ubuntu:24.04:LTS')
        self.assertEqual(release(dict(base, ubuntu_codename='jammy')), 'Ubuntu:22.04:LTS')
        # a codename this version does not know says nothing; the version is read as before
        self.assertEqual(release(dict(base, ubuntu_codename='zesty')), 'Ubuntu:24.04:LTS')
        self.assertEqual(release({'ecosystem': 'Ubuntu', 'os_id': 'linuxmint', 'version_id': '23', 'ubuntu_codename': 'zesty'}), '')
        # Ubuntu itself and Pop!_OS say their release in the version, whatever else the entry holds
        self.assertEqual(release({'ecosystem': 'Ubuntu', 'os_id': 'ubuntu', 'version_id': '22.04', 'ubuntu_codename': 'noble'}),
                         'Ubuntu:22.04:LTS')

    def test_every_ubuntu_codename_names_a_release_the_records_can_hold(self):
        for name, version in cve_scanner._UBUNTU_BY_CODENAME.items():
            self.assertTrue(cve_fixes.ubuntu_release_name(version), name)
            self.assertIsNotNone(cve_fixes.release_of(cve_fixes.ubuntu_release_name(version)), name)
            self.assertEqual(cve_scanner.codename(name), name)
        self.assertEqual(cve_scanner._UBUNTU_BY_CODENAME['jammy'], '22.04')
        for name, major in cve_scanner._DEBIAN_BY_CODENAME.items():
            self.assertIsNotNone(cve_fixes.release_of(f'Debian:{major}'), name)
        self.assertEqual((cve_scanner._DEBIAN_BY_CODENAME['bookworm'], cve_scanner._DEBIAN_BY_CODENAME['daedalus']), (12, 12))

    def test_a_number_no_debian_release_has_is_the_derivatives_own(self):
        detect = lambda **osr: cve_scanner.detect_ecosystem(dict(osr, ID_LIKE='debian'), 'apt')      # noqa: E731
        newest = max(cve_scanner._DEBIAN_BY_CODENAME.values())
        self.assertEqual(detect(ID='raspbian', VERSION_ID=str(newest + 1)), f'Debian:{newest + 1}')      # the next release
        self.assertIsNone(detect(ID='deepin', VERSION_ID=str(newest + 9)))
        self.assertIsNone(detect(ID='kali', VERSION_ID='2025.3'))
        self.assertIsNone(detect(ID='old', VERSION_ID='5'))
        self.assertIsNone(detect(ID='x', VERSION_ID='rolling'))
        self.assertIsNone(detect(ID='x', VERSION_ID=''))
        self.assertIsNone(detect(ID='devuan', VERSION_ID='9'))                     # a Devuan this version does not know
        self.assertEqual(detect(ID='devuan', VERSION_ID='9', VERSION_CODENAME='excalibur'), 'Debian:13')
        self.assertEqual(detect(ID='x', VERSION_ID='2', DEBIAN_CODENAME='trixie'), 'Debian:13')
        # the other package managers are as they were
        self.assertEqual(cve_scanner.detect_ecosystem({'ID': 'rocky', 'VERSION_ID': '9.4'}, 'dnf'), 'Rocky Linux:9')
        self.assertEqual(cve_scanner.detect_ecosystem({'ID': 'alpine', 'VERSION_ID': '3.19.1'}, 'apk'), 'Alpine:v3.19')

    def test_a_list_stored_before_the_upgrade_is_read_under_the_right_release(self):
        """It says "Debian:5" for Devuan 5. The name is worked out again from what the entry holds."""
        read = cve_scanner.entry_ecosystem
        self.assertEqual(read({'ecosystem': 'Debian:5', 'os_id': 'devuan', 'version_id': '5'}), 'Debian:12')
        self.assertEqual(read({'ecosystem': 'Debian:6', 'os_id': 'linuxmint', 'version_id': '6'}), 'Debian:12')
        self.assertEqual(read({'ecosystem': 'Debian:2025', 'os_id': 'kali', 'version_id': '2025.3'}), '')
        self.assertEqual(read({'ecosystem': 'Debian:12', 'os_id': 'raspbian', 'version_id': '12'}), 'Debian:12')
        self.assertEqual(read({'ecosystem': 'Debian:12', 'os_id': 'debian', 'version_id': '12'}), 'Debian:12')
        self.assertEqual(read({'ecosystem': 'Debian:12'}), 'Debian:12')            # stored before the host's name was kept
        self.assertEqual(read({'ecosystem': 'Debian:5', 'os_id': 'devuan', 'version_id': 5}), 'Debian:12')
        self.assertEqual(read({'ecosystem': 'Ubuntu', 'os_id': 'linuxmint', 'version_id': '21.3'}), 'Ubuntu')

    def test_what_the_host_view_says_is_left_out(self):
        coverage = cve_scanner.coverage
        # an older agent on a derivative: updating it is what helps, and the note says so
        self.assertEqual(coverage('Ubuntu', False, ''), 'needs_agent')
        self.assertEqual(coverage('Ubuntu', False, 'Ubuntu:22.04:LTS'), 'needs_agent')
        self.assertEqual(coverage('Debian:12', False, 'Debian:12'), 'needs_agent')
        # an agent from 8.0.1 that names a base this version does not know
        self.assertEqual(coverage('Ubuntu', True, ''), 'no_release')
        self.assertEqual(coverage('Ubuntu', True, 'Ubuntu:22.04:LTS'), '')
        self.assertEqual(coverage('Debian:12', True, 'Debian:12'), '')


class TestAMintHostIsScannedAsTheUbuntuItIs(unittest.TestCase):
    JAMMY = [{'name': 'libc6', 'version': '2.35-0ubuntu3.6', 'arch': 'amd64', 'source': 'glibc'},
             {'name': 'openssh-server', 'version': '1:8.9p1-3ubuntu0.6', 'arch': 'amd64', 'source': 'openssh'},
             {'name': 'sudo', 'version': '1.9.9-1ubuntu2.4', 'arch': 'amd64'}]

    def scan(self, entry):
        db = Database(UBU)
        with mock.patch.object(cve_scanner, '_osv_querybatch', db.querybatch), \
                mock.patch.object(cve_scanner, '_osv_vuln_details', db.details):
            result = cve_scanner.scan_device(HOST, entry['packages'], cve_scanner.entry_ecosystem(entry),
                                             Path(tempfile.mkdtemp(prefix='rp-v801-mint-')), has_meta=entry.get('sources') is True,
                                             release=cve_scanner.entry_release(entry))
        self.assertNotIn('error', result, result.get('error'))
        return db, result

    def test_with_the_codename_it_is_asked_by_source_and_reads_the_fixes_of_22_04(self):
        mint = {'ecosystem': 'Ubuntu', 'os_id': 'linuxmint', 'version_id': '21.3', 'ubuntu_codename': 'jammy', 'sources': True,
                'packages': self.JAMMY}
        ubuntu = dict(mint, os_id='ubuntu', version_id='22.04')
        ubuntu.pop('ubuntu_codename')
        db, result = self.scan(mint)
        _db, as_ubuntu = self.scan(ubuntu)
        self.assertEqual([k[1] for k in db.asked], ['glibc', 'openssh', 'sudo'])
        self.assertIs(result['ruled'], True)
        self.assertEqual({f['fix_status'] for f in result['findings']}, {'fixed'})
        strip = lambda r: [(f['vuln_id'], f['fix_status'], f['fixed_version']) for f in r['findings']]     # noqa: E731
        self.assertEqual(strip(result), strip(as_ubuntu))
        self.assertEqual(result.get('rollup'), as_ubuntu.get('rollup'))
        glibc = next(f for f in result['findings'] if f['vuln_id'] == 'UBUNTU-CVE-2024-2961')
        self.assertEqual(glibc['fixed_version'], '2.35-0ubuntu3.7')               # the fix of 22.04

    def test_without_it_the_host_is_as_it_was(self):
        """The control: by installed name, nothing for the libraries, every status "not checked"."""
        mint = {'ecosystem': 'Ubuntu', 'os_id': 'linuxmint', 'version_id': '21.3', 'sources': True, 'packages': self.JAMMY}
        db, result = self.scan(mint)
        self.assertEqual([k[1] for k in db.asked], ['libc6', 'openssh-server', 'sudo'])
        self.assertNotIn('ruled', result)
        self.assertEqual({f['package'] for f in result['findings']}, {'sudo'})
        self.assertEqual({f['fix_status'] for f in result['findings']}, {'unknown'})


class TestTheAgentCopiesAndTheStoredShape(unittest.TestCase):
    def test_both_agent_files_send_the_same(self):
        a = (ROOT / 'client' / 'remotepower-agent.py').read_text()
        self.assertEqual(a, (ROOT / 'client' / 'remotepower-agent').read_text())
        for key in ('UBUNTU_CODENAME', 'DEBIAN_CODENAME', 'VERSION_CODENAME'):
            self.assertIn(f"'{key}':", a)

    def test_the_three_fields_are_text_when_read(self):
        import store_shapes
        damaged = {HOST: {'ecosystem': 'Ubuntu', 'ubuntu_codename': ['jammy'], 'debian_codename': {'a': 1},
                          'version_codename': 'virginia', 'packages': []}}
        entry = store_shapes.normalize('packages.json', damaged)[HOST]
        for key in ('ubuntu_codename', 'debian_codename'):
            self.assertIn(type(entry.get(key)), (str, type(None)), key)
        self.assertEqual(entry['version_codename'], 'virginia')
        self.assertEqual(cve_scanner.entry_release(dict(entry, os_id='linuxmint', version_id='21.3')), '')


if __name__ == '__main__':
    unittest.main()
