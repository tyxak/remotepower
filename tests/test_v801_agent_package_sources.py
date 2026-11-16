"""The package list the Linux agent sends names source packages and epochs (8.0.1).

A distribution's security data is kept by source package ("glibc", "openssl"), and an RPM version is not
complete without its epoch. The agent reported the installed name, the version and the architecture, so the
server could not ask the advisory database the right question. It now adds, per package and only where it
says something: `source` (the source package, when its name differs), `source_version` (when it differs from
the package's own version) and `epoch` (when there is one). The list says `sources: true` when it was read in
a way that knows them.

Three things were wrong on the way and are held here too:

  * `dpkg-query -W` prints a package that was removed and still has its configuration files ("rc" in dpkg -l),
    so removed software was reported as installed and checked for vulnerabilities;
  * an Alpine host monitored from the agent container had no reader, fell through to the tools of the agent's
    own Debian image and was reported with the image's packages;
  * the agent decides whether to send by a hash of names and versions, so the new fields alone would never
    have been sent.

The readers are driven with the text the real tools print. That text is written here from the tools'
documented formats: this machine has neither dpkg nor rpm nor apk, so none of it was captured from a run.
"""
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import cve_scanner  # noqa: E402
from test_docker_agent import load_agent  # noqa: E402

AGENT = load_agent()

DPKG_QUERY = '\n'.join([
    'ii \tlibc6\t2.36-9+deb12u7\tamd64\tglibc\t2.36-9+deb12u7',
    'ii \tlibc6\t2.36-9+deb12u7\ti386\tglibc\t2.36-9+deb12u7',
    'ii \topenssl\t3.0.15-1~deb12u1\tamd64\topenssl\t3.0.15-1~deb12u1',
    'ii \tlibgcc-s1\t12.2.0-14\tamd64\tgcc-12\t12.2.0-14',
    'ii \tlinux-image-6.1.0-18-amd64\t6.1.76-1\tamd64\tlinux-signed-amd64\t6.1.76+1',
    'rc \tnginx-common\t1.22.1-9\tall\tnginx\t1.22.1-9',
    'un \tghost\t\t\tghost\t',
    'hi \theld\t1.0-1\tall\theld\t1.0-1',
    'iU \tunpacked\t2.0-1\tall\tsrc-of-unpacked\t2.0-1',
    'pn \tpurged\t1.0\tall\tpurged\t1.0',
    'garbage line',
    '',
])

DPKG_STATUS = '''Package: libc6
Status: install ok installed
Architecture: amd64
Source: glibc
Version: 2.36-9+deb12u7
Description: GNU C Library: Shared libraries
 Contains the standard libraries that are used by nearly all programs on
 the system.

Package: libgcc-s1
Status: install ok installed
Architecture: amd64
Source: gcc-12 (12.2.0-14)
Version: 12.2.0-14+b1

Package: openssl
Status: install ok installed
Architecture: amd64
Version: 3.0.15-1~deb12u1

Package: nginx-common
Status: deinstall ok config-files
Architecture: all
Source: nginx
Version: 1.22.1-9

Package: half
Status: install ok unpacked
Architecture: all
Version: 1.0-1

Package: noversion
Status: install ok installed
'''

RPM_QUERY = '\n'.join([
    'openssl-libs\t3.0.7-28.el9_4\tx86_64\t1\topenssl-3.0.7-28.el9_4.src.rpm',
    'openssl\t3.0.7-28.el9_4\tx86_64\t1\topenssl-3.0.7-28.el9_4.src.rpm',
    'bash\t5.1.8-9.el9\tx86_64\t(none)\tbash-5.1.8-9.el9.src.rpm',
    'python3-libs\t3.9.18-3.el9_4.6\tx86_64\t(none)\tpython3.9-3.9.18-3.el9_4.6.src.rpm',
    'perl-Errno\t1.30-481.el9\tx86_64\t0\tperl-5.32.1-481.el9.src.rpm',
    'gpg-pubkey\tb86b3716-61e69f29\t(none)\t(none)\t(none)',
    'kmod-thing\t1.0-1.el9\tx86_64\t(none)\tthing-kmod-1.0-1.el9.nosrc.rpm',
    'odd\t1.0-1\tnoarch\t(none)\tnot-a-source-name',
    'short\t1.0-1',
    '',
])

APK_DB = '''C:Q1abcdefghijklmnopqrstuvwxyz0123=
P:libcrypto3
V:3.1.4-r5
A:x86_64
S:1700000
I:4300000
T:Crypto library from openssl
U:https://www.openssl.org/
L:Apache-2.0
o:openssl
m:Someone <someone@example.org>
t:1700000000
c:0123456789abcdef
D:so:libc.musl-x86_64.so.1
F:lib
R:libcrypto.so.3

P:openssl
V:3.1.4-r5
A:x86_64
o:openssl

P:musl-utils
V:1.2.4-r2
A:x86_64
o:musl

P:broken
A:x86_64
'''


def by_name(pkgs):
    out = {}
    for p in pkgs:
        out.setdefault(p['name'], []).append(p)
    return out


class TestDpkgQuery(unittest.TestCase):
    def setUp(self):
        self.pkgs, self.has_sources = AGENT._parse_dpkg_query(DPKG_QUERY)
        self.named = by_name(self.pkgs)

    def test_what_is_installed_is_listed(self):
        self.assertEqual(sorted(self.named), ['held', 'libc6', 'libgcc-s1', 'linux-image-6.1.0-18-amd64', 'openssl',
                                              'unpacked'])
        self.assertEqual(len(self.named['libc6']), 2)                    # both architectures
        self.assertTrue(self.has_sources)

    def test_a_removed_package_with_its_configuration_left_is_not(self):
        self.assertNotIn('nginx-common', self.named)
        self.assertNotIn('purged', self.named)
        self.assertNotIn('ghost', self.named)

    def test_the_source_is_named_where_it_differs(self):
        self.assertEqual(self.named['libc6'][0], {'name': 'libc6', 'version': '2.36-9+deb12u7', 'arch': 'amd64',
                                                  'source': 'glibc'})
        self.assertEqual(self.named['openssl'][0], {'name': 'openssl', 'version': '3.0.15-1~deb12u1',
                                                    'arch': 'amd64'})
        self.assertEqual(self.named['libgcc-s1'][0]['source'], 'gcc-12')
        self.assertNotIn('source_version', self.named['libgcc-s1'][0])

    def test_the_source_version_is_named_where_it_differs(self):
        kernel = self.named['linux-image-6.1.0-18-amd64'][0]
        self.assertEqual((kernel['source'], kernel['source_version']), ('linux-signed-amd64', '6.1.76+1'))

    def test_a_dpkg_without_the_source_fields_says_so(self):
        old = 'ii \tbash\t5.2-1\tamd64\t\t\nii \tsed\t4.9-1\tamd64\t\t\n'
        pkgs, has_sources = AGENT._parse_dpkg_query(old)
        self.assertEqual([p['name'] for p in pkgs], ['bash', 'sed'])
        self.assertFalse(has_sources)
        self.assertEqual(pkgs[0], {'name': 'bash', 'version': '5.2-1', 'arch': 'amd64'})

    def test_the_format_asks_for_what_the_reader_reads(self):
        fields = AGENT._DPKG_QUERY_FORMAT.replace('\\t', '\t').replace('\\n', '').split('\t')
        self.assertEqual(fields, ['${db:Status-Abbrev}', '${Package}', '${Version}', '${Architecture}',
                                  '${source:Package}', '${source:Version}', '${Built-Using}'])


class TestASignedPackageNamesWhatItWasBuiltFrom(unittest.TestCase):
    """The kernel image, grub and shim are signed packages: a source of their own that holds a signature. OSV
    answers nothing for "linux-signed-amd64" and 1,000 advisories for "linux" (asked 2026-11-15). Built-Using
    names the source the code came from."""

    LINES = '\n'.join([
        'ii \tlinux-image-6.1.0-18-amd64\t6.1.76-1\tamd64\tlinux-signed-amd64\t6.1.76+1\tlinux (= 6.1.76-1)',
        'ii \tgrub-efi-amd64-signed\t1+2.06+13+deb12u1\tamd64\tgrub-efi-amd64-signed\t1+2.06+13+deb12u1\tgrub2 (= 2.06-13+deb12u1)',
        'ii \tshim-signed\t1.39+15.7-1\tamd64\tshim-signed\t1.39\tshim (= 15.7-1)',
        'ii \tlinux-image-5.15.0-25-generic\t5.15.0-25.25\tamd64\tlinux-signed\t5.15.0-25.25\tlinux (= 5.15.0-25.25)',
        'ii \tbusybox-static\t1:1.35.0-4+b3\tamd64\tbusybox\t1:1.35.0-4\tglibc (= 2.36-9)',
        'ii \tdocker.io\t20.10.24+dfsg1-1+b3\tamd64\tdocker.io\t20.10.24+dfsg1-1\tgolang-1.19 (= 1.19.8-2), golang-x (= 1.0-1)',
        'ii \tunsigned-thing\t1.0-1\tamd64\tthing-signed\t1.0\tone (= 1), two (= 2)',
        'ii \tdesigned\t1.0-1\tamd64\tdesigned\t1.0-1\tother (= 9)',
        'ii \tno-field\t1.0-1\tamd64\tx-signed\t1.0-1',
    ])

    def setUp(self):
        self.named = {p['name']: p for p in AGENT._parse_dpkg_query(self.LINES)[0]}

    def test_the_kernel_image_is_filed_under_the_kernel_source(self):
        self.assertEqual(self.named['linux-image-6.1.0-18-amd64'],
                         {'name': 'linux-image-6.1.0-18-amd64', 'version': '6.1.76-1', 'arch': 'amd64', 'source': 'linux'})
        self.assertEqual(self.named['linux-image-5.15.0-25-generic']['source'], 'linux')

    def test_grub_and_shim_too_with_the_version_they_were_built_from(self):
        self.assertEqual((self.named['grub-efi-amd64-signed']['source'], self.named['grub-efi-amd64-signed']['source_version']),
                         ('grub2', '2.06-13+deb12u1'))
        self.assertEqual((self.named['shim-signed']['source'], self.named['shim-signed']['source_version']),
                         ('shim', '15.7-1'))

    def test_what_a_program_embeds_is_not_what_it_is(self):
        # a statically linked program lists what it embeds in the same field
        self.assertEqual(self.named['busybox-static']['source'], 'busybox')
        self.assertNotIn('source', self.named['docker.io'])

    def test_only_one_named_source_and_only_for_a_signed_one(self):
        self.assertEqual(self.named['unsigned-thing']['source'], 'thing-signed')      # two sources named: left alone
        self.assertNotIn('source', self.named['designed'])                            # "designed" is not "signed"
        self.assertEqual(self.named['no-field']['source'], 'x-signed')                # a dpkg without the field

    def test_the_status_file_says_the_same(self):
        text = ('Package: linux-image-6.1.0-18-amd64\nStatus: install ok installed\nArchitecture: amd64\n'
                'Source: linux-signed-amd64 (6.1.76+1)\nVersion: 6.1.76-1\nBuilt-Using: linux (= 6.1.76-1)\n')
        (pkg,) = AGENT._parse_dpkg_status(text)[0]
        self.assertEqual(pkg, {'name': 'linux-image-6.1.0-18-amd64', 'version': '6.1.76-1', 'arch': 'amd64',
                               'source': 'linux'})


class TestDpkgStatus(unittest.TestCase):
    def setUp(self):
        self.pkgs, self.has_sources = AGENT._parse_dpkg_status(DPKG_STATUS)
        self.named = by_name(self.pkgs)

    def test_what_is_installed_is_listed(self):
        self.assertEqual(sorted(self.named), ['half', 'libc6', 'libgcc-s1', 'openssl'])
        self.assertTrue(self.has_sources)

    def test_the_source_and_its_version_in_brackets(self):
        self.assertEqual(self.named['libc6'][0], {'name': 'libc6', 'version': '2.36-9+deb12u7', 'arch': 'amd64',
                                                  'source': 'glibc'})
        self.assertEqual(self.named['libgcc-s1'][0], {'name': 'libgcc-s1', 'version': '12.2.0-14+b1',
                                                      'arch': 'amd64', 'source': 'gcc-12',
                                                      'source_version': '12.2.0-14'})
        self.assertEqual(self.named['openssl'][0], {'name': 'openssl', 'version': '3.0.15-1~deb12u1',
                                                    'arch': 'amd64'})

    def test_both_readers_agree_on_what_installed_means(self):
        """The same host through the tool and through the file gives the same set of names."""
        status_from_query = '\n\n'.join(
            f'Package: {name}\nStatus: {state}\nVersion: 1.0\nArchitecture: all' for name, state in (
                ('a', 'install ok installed'), ('b', 'deinstall ok config-files'), ('c', 'install ok unpacked'),
                ('d', 'install ok half-configured'), ('e', 'purge ok not-installed'), ('f', 'hold ok installed'),
                ('g', 'install ok triggers-pending'), ('h', 'install reinstreq half-installed')))
        query = '\n'.join(f'{abbrev}\t{name}\t1.0\tall\t{name}\t1.0' for name, abbrev in (
            ('a', 'ii '), ('b', 'rc '), ('c', 'iU '), ('d', 'iF '), ('e', 'pn '), ('f', 'hi '), ('g', 'it '),
            ('h', 'iHR')))
        from_file = sorted(p['name'] for p in AGENT._parse_dpkg_status(status_from_query)[0])
        from_tool = sorted(p['name'] for p in AGENT._parse_dpkg_query(query)[0])
        self.assertEqual(from_file, ['a', 'c', 'd', 'f', 'g', 'h'])
        self.assertEqual(from_tool, from_file)


class TestRpmQuery(unittest.TestCase):
    def setUp(self):
        self.pkgs, self.has_sources = AGENT._parse_rpm_query(RPM_QUERY)
        self.named = {p['name']: p for p in self.pkgs}

    def test_what_is_installed_is_listed(self):
        self.assertEqual(sorted(self.named), ['bash', 'gpg-pubkey', 'kmod-thing', 'odd', 'openssl', 'openssl-libs',
                                              'perl-Errno', 'python3-libs'])
        self.assertTrue(self.has_sources)

    def test_the_epoch_is_its_own_field_and_the_version_is_as_it_was(self):
        self.assertEqual(self.named['openssl-libs'], {'name': 'openssl-libs', 'version': '3.0.7-28.el9_4',
                                                      'arch': 'x86_64', 'epoch': '1', 'source': 'openssl'})
        self.assertEqual(self.named['openssl'], {'name': 'openssl', 'version': '3.0.7-28.el9_4', 'arch': 'x86_64',
                                                 'epoch': '1'})
        for name in ('bash', 'perl-Errno', 'gpg-pubkey'):                 # none, and 0, are no epoch
            self.assertNotIn('epoch', self.named[name], name)

    def test_the_source_comes_out_of_the_source_package_file_name(self):
        self.assertEqual(self.named['python3-libs']['source'], 'python3.9')
        self.assertNotIn('source_version', self.named['python3-libs'])
        self.assertEqual((self.named['perl-Errno']['source'], self.named['perl-Errno']['source_version']),
                         ('perl', '5.32.1-481.el9'))
        self.assertEqual(self.named['kmod-thing']['source'], 'thing-kmod')     # a source without sources shipped
        self.assertNotIn('source', self.named['bash'])                    # built from a source of its own name
        for name in ('gpg-pubkey', 'odd'):
            self.assertEqual(set(self.named[name]), {'name', 'version', 'arch'}, name)

    def test_the_format_asks_for_what_the_reader_reads(self):
        fields = AGENT._RPM_QUERY_FORMAT.replace('\\t', '\t').replace('\\n', '').split('\t')
        self.assertEqual(fields, ['%{NAME}', '%{VERSION}-%{RELEASE}', '%{ARCH}', '%{EPOCH}', '%{SOURCERPM}'])


class TestApkDatabase(unittest.TestCase):
    def test_the_origin_is_the_source(self):
        pkgs, has_sources = AGENT._parse_apk_db(APK_DB)
        self.assertTrue(has_sources)
        self.assertEqual(pkgs, [
            {'name': 'libcrypto3', 'version': '3.1.4-r5', 'arch': 'x86_64', 'source': 'openssl'},
            {'name': 'openssl', 'version': '3.1.4-r5', 'arch': 'x86_64'},
            {'name': 'musl-utils', 'version': '1.2.4-r2', 'arch': 'x86_64', 'source': 'musl'},
        ])

    def test_an_empty_database_is_an_empty_list(self):
        self.assertEqual(AGENT._parse_apk_db('')[0], [])
        self.assertEqual(AGENT._parse_apk_db('\n\n\n')[0], [])


class TestAnAlpineHostFromTheAgentContainer(unittest.TestCase):
    def test_the_host_database_is_read_not_the_image(self):
        root = tempfile.mkdtemp(prefix='rp-v801-alpine-')
        os.makedirs(root + '/lib/apk/db')
        Path(root + '/lib/apk/db/installed').write_text(APK_DB)
        agent = load_agent(host_root=root)
        with mock.patch.object(agent.subprocess, 'check_output',
                               side_effect=AssertionError('no tool of the image may be run')):
            mgr, pkgs, has_sources = agent.get_package_list_ex()
        self.assertEqual(mgr, 'apk')
        self.assertTrue(has_sources)
        self.assertEqual([p['name'] for p in pkgs], ['libcrypto3', 'openssl', 'musl-utils'])
        self.assertEqual(agent.get_package_list(), (mgr, pkgs))           # the two-value form is the same list

    def test_the_merged_usr_path_is_read_too(self):
        root = tempfile.mkdtemp(prefix='rp-v801-alpine-usr-')
        os.makedirs(root + '/usr/lib/apk/db')
        Path(root + '/usr/lib/apk/db/installed').write_text(APK_DB)
        self.assertEqual(load_agent(host_root=root)._host_pkglist_from_db()[0], 'apk')

    def test_a_host_with_no_database_at_all_is_still_unknown(self):
        root = tempfile.mkdtemp(prefix='rp-v801-nodb-')
        self.assertEqual(load_agent(host_root=root)._host_pkglist_from_db_ex(), (None, None, False))

    def test_a_debian_host_from_the_container_names_sources(self):
        root = tempfile.mkdtemp(prefix='rp-v801-deb-')
        os.makedirs(root + '/var/lib/dpkg')
        Path(root + '/var/lib/dpkg/status').write_text(DPKG_STATUS)
        mgr, pkgs, has_sources = load_agent(host_root=root).get_package_list_ex()
        self.assertEqual((mgr, has_sources), ('apt', True))
        self.assertEqual(by_name(pkgs)['libc6'][0]['source'], 'glibc')


class TestAToolThatDoesNotTakeTheNewFormat(unittest.TestCase):
    """The list still goes out, as it was collected before 8.0.1, and does not claim to name sources."""

    def run_with(self, tool, outputs):
        agent = load_agent()
        calls = []

        def check_output(argv, **_kw):
            calls.append(list(argv))
            out = outputs[len(calls) - 1]
            if isinstance(out, Exception):
                raise out
            return out
        real_exists = Path.exists

        def exists(path):
            if str(path) in ('/usr/bin/dpkg-query', '/usr/bin/rpm'):
                return str(path) == tool
            return real_exists(path)
        with mock.patch.object(Path, 'exists', exists), mock.patch.object(agent.subprocess, 'check_output', check_output):
            return agent.get_package_list_ex(), calls

    def test_dpkg_refuses_the_format(self):
        (mgr, pkgs, has_sources), calls = self.run_with(
            '/usr/bin/dpkg-query', [OSError('unknown field'), 'bash\t5.2-1\tamd64\nsed\t4.9-1\tamd64\n'])
        self.assertEqual((mgr, has_sources), ('apt', False))
        self.assertEqual(pkgs, [{'name': 'bash', 'version': '5.2-1', 'arch': 'amd64'},
                                {'name': 'sed', 'version': '4.9-1', 'arch': 'amd64'}])
        self.assertEqual(len(calls), 2)
        self.assertNotIn('source', calls[1][-1])

    def test_dpkg_prints_nothing_for_the_format(self):
        (mgr, pkgs, has_sources), calls = self.run_with('/usr/bin/dpkg-query', ['', 'bash\t5.2-1\tamd64\n'])
        self.assertEqual((mgr, [p['name'] for p in pkgs], has_sources, len(calls)), ('apt', ['bash'], False, 2))

    def test_dpkg_takes_it_and_is_asked_once(self):
        (mgr, pkgs, has_sources), calls = self.run_with('/usr/bin/dpkg-query', [DPKG_QUERY])
        self.assertEqual((mgr, has_sources, len(calls)), ('apt', True, 1))
        self.assertIn('libc6', by_name(pkgs))

    def test_rpm_refuses_the_format(self):
        (mgr, pkgs, has_sources), calls = self.run_with(
            '/usr/bin/rpm', [OSError('bad format'), 'bash\t5.1.8-9.el9\tx86_64\n'])
        self.assertEqual((mgr, has_sources, len(calls)), ('dnf', False, 2))
        self.assertEqual(pkgs, [{'name': 'bash', 'version': '5.1.8-9.el9', 'arch': 'x86_64'}])

    def test_rpm_takes_it_and_is_asked_once(self):
        (mgr, pkgs, has_sources), calls = self.run_with('/usr/bin/rpm', [RPM_QUERY])
        self.assertEqual((mgr, has_sources, len(calls)), ('dnf', True, 1))

    def test_a_tool_that_fails_both_ways_gives_an_empty_list(self):
        (mgr, pkgs, has_sources), calls = self.run_with('/usr/bin/rpm', [OSError('a'), OSError('b')])
        self.assertEqual((mgr, pkgs, has_sources, len(calls)), ('dnf', [], False, 2))

    def test_an_epoch_that_is_not_a_plain_number_is_no_epoch(self):
        for odd in ('²', '١', '1e3', '-1', ' ', 'x'):
            pkgs, _ = AGENT._parse_rpm_query(f'a\t1-1\tnoarch\t{odd}\ta-1-1.src.rpm\n')
            self.assertEqual(pkgs, [{'name': 'a', 'version': '1-1', 'arch': 'noarch'}], odd)


class TestTheListIsSentOnceWithItsNewFields(unittest.TestCase):
    PLAIN = [{'name': 'openssl-libs', 'version': '3.0.7-28.el9_4', 'arch': 'x86_64'},
             {'name': 'bash', 'version': '5.1.8-9.el9', 'arch': 'x86_64'}]
    RICH = [{'name': 'openssl-libs', 'version': '3.0.7-28.el9_4', 'arch': 'x86_64', 'epoch': '1', 'source': 'openssl'},
            {'name': 'bash', 'version': '5.1.8-9.el9', 'arch': 'x86_64'}]

    def setUp(self):
        self.agent = load_agent()
        self.sent = []
        self.hash_file = Path(tempfile.mkdtemp(prefix='rp-v801-hash-')) / 'pkg_hash'
        patches = [
            mock.patch.object(self.agent, 'PKG_HASH_FILE', self.hash_file),
            mock.patch.object(self.agent, 'http_post', self.post),
            mock.patch.object(self.agent, 'get_os_release',
                              lambda: {'ID': 'almalinux', 'VERSION_ID': '9.4', 'ID_LIKE': 'rhel'}),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.creds = {'device_id': 'd', 'token': 't', 'server_url': 'https://server.invalid'}

    def post(self, url, payload, timeout=30):
        self.sent.append((url, payload))
        return {'ecosystem': 'AlmaLinux:9', 'changed': True}

    def send(self, pkgs, has_sources, manager='dnf'):
        with mock.patch.object(self.agent, 'get_package_list_ex', lambda: (manager, pkgs, has_sources)):
            return self.agent.send_package_list(self.creds)

    def test_the_hash_is_the_servers_hash(self):
        for pkgs in (self.PLAIN, self.RICH, list(reversed(self.RICH)), [],
                     [{'name': 'a', 'version': '1', 'source_version': '2'}]):
            self.assertEqual(self.agent._compute_pkg_hash(pkgs), cve_scanner.packages_hash(pkgs), pkgs)

    def test_a_list_without_the_new_fields_hashes_as_it_always_did(self):
        old = hashlib.sha256(json.dumps(sorted((p['name'], p['version']) for p in self.PLAIN),
                                        separators=(',', ':')).encode()).hexdigest()[:16]
        self.assertEqual(self.agent._compute_pkg_hash(self.PLAIN), old)
        self.assertNotEqual(self.agent._compute_pkg_hash(self.RICH), old)

    def test_the_first_list_with_sources_is_sent_though_no_package_changed(self):
        self.assertTrue(self.send(self.PLAIN, False))                     # what the agent before sent
        self.assertFalse(self.send(self.PLAIN, False))                    # and nothing changed: not sent again
        self.assertTrue(self.send(self.RICH, True))                       # the same packages, now with sources
        self.assertFalse(self.send(self.RICH, True))
        self.assertEqual(len(self.sent), 2)

    def test_the_list_says_whether_it_names_sources(self):
        self.send(self.RICH, True)
        url, payload = self.sent[-1]
        self.assertEqual(url, 'https://server.invalid/api/packages')
        self.assertIs(payload['sources'], True)
        self.assertEqual(payload['packages'], self.RICH)
        self.hash_file.unlink()
        self.send(self.PLAIN, False, manager='pacman')
        self.assertNotIn('sources', self.sent[-1][1])

    def test_the_two_copies_of_the_agent_are_one_file(self):
        client = ROOT / 'client'
        self.assertEqual((client / 'remotepower-agent.py').read_bytes(), (client / 'remotepower-agent').read_bytes())


if __name__ == '__main__':
    unittest.main()
