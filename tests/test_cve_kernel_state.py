"""A finding against the kernel is matched against the kernel the host runs, and says when a reboot is all it needs (8.0.2).

A scan asked about every version of a kernel package a host has, so the findings of a kernel that is installed and does not
run were counted beside the kernel that does, and a fix that sat in an installed kernel the host had not booted into was
offered as an update to install. The agent now reports the release it runs (uname -r) and, for each installed kernel image,
the release that image owns: the file /boot/vmlinuz-<release> (the modules directory on Alpine, whose kernel file is named by
flavour). The server matches the kernel's findings against the one package that owns the running release. When it cannot tell
which that is it does what it always did, and says so and why.

  * the agent: what it reads on each family (a fake host tree, a fake `rpm` that is a real program on the PATH), what it sends,
    and that a host that boots another kernel sends its list again though the list did not change;
  * the scan, against the recordings of api.osv.dev in tests/data and advisory records written for the kernel (the recordings
    hold none): the running kernel's package alone is asked about, an older kernel is not counted, a finding that an installed
    newer kernel clears is `reboot`, and every way of not being able to tell ends in `unknown` with a reason;
  * the rule: `reboot` is stored beside what an update clears, counts as something to do, and a finding that goes from one to
    the other is not one that was cleared (the alert comparison runs here over real scan results, through a reboot).
"""
import importlib.util
import json
import os
import shutil
import stat
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))
_TMP = []


def _tmp(prefix):
    d = tempfile.mkdtemp(prefix=prefix)
    _TMP.append(d)
    return d


os.environ.setdefault('RP_DATA_DIR', _tmp('rp-kern-'))
_spec = importlib.util.spec_from_file_location('api_cve_kernel_state', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
cve_scanner = api.cve_scanner
cve_fixes = api.cve_fixes

import mcp_http  # noqa: E402
import store_shapes  # noqa: E402
from osv_recording import DEB, Database  # noqa: E402
from test_docker_agent import load_agent  # noqa: E402

AGENT = load_agent()
_mcp_spec = importlib.util.spec_from_file_location('rp_mcp_kernel', ROOT / 'mcp' / 'remotepower-mcp.py')
sidecar = importlib.util.module_from_spec(_mcp_spec)
_mcp_spec.loader.exec_module(sidecar)


def tearDownModule():
    for d in _TMP:
        shutil.rmtree(d, ignore_errors=True)


# ── a host and its kernels ────────────────────────────────────────────────────────────────────────────────────────────
OLD, NEW = '6.1.0-40-amd64', '6.1.0-48-amd64'
LIST = [{'name': f'linux-image-{OLD}', 'version': '6.1.158-1', 'arch': 'amd64', 'source': 'linux'},
        {'name': f'linux-image-{NEW}', 'version': '6.1.192-1', 'arch': 'amd64', 'source': 'linux'},
        {'name': 'linux-libc-dev', 'version': '6.1.192-1', 'arch': 'amd64', 'source': 'linux'}]
SUDO = {'name': 'sudo', 'version': '1.9.13p3-1+deb12u1', 'arch': 'amd64'}      # not a kernel; the recording holds its advisories
ONLY_OLD = [LIST[0]]
IMG_OLD = {'name': f'linux-image-{OLD}', 'version': '6.1.158-1', 'release': OLD}
IMG_NEW = {'name': f'linux-image-{NEW}', 'version': '6.1.192-1', 'release': NEW}


def report(running, *images):
    return {'release': running, 'images': list(images)}


def record(vid, fixed, urgency='high', package='linux', ecosystem='Debian:12'):
    """An advisory record of the data source for a kernel: the recordings hold none. The record rates itself, as a
    distribution's record may (`database_specific.severity`), so what a finding is rated is not left to a score."""
    events = [{'introduced': '0'}] + ([{'fixed': fixed}] if fixed else [])
    return {'id': vid, 'details': 'a flaw in the kernel', 'upstream': [vid.replace('DEBIAN-', '')],
            'modified': '2026-11-10T08:00:00.123456789Z', 'database_specific': {'severity': urgency},
            'affected': [{'package': {'ecosystem': ecosystem, 'name': package},
                          'ranges': [{'type': 'ECOSYSTEM', 'events': events}],
                          'ecosystem_specific': {'urgency': urgency}}]}


A, B, C, D, E = ('DEBIAN-CVE-2099-000%d' % i for i in range(1, 6))
RECORDS = {A: record(A, '6.1.192-1'), B: record(B, '6.1.200-1'), C: record(C, ''),
           D: record(D, '6.1.192-1', 'medium'), E: record(E, '', 'medium')}
ANSWERS = {('Debian:12', 'linux', '6.1.158-1'): [A, B, C, D, E],
           ('Debian:12', 'linux', '6.1.192-1'): [B, C, E]}


def database():
    return Database(DEB, extra=ANSWERS, records=RECORDS)


def scan(packages, kernel, db=None, ecosystem='Debian:12', **kw):
    db = db or database()
    with mock.patch.object(cve_scanner, '_osv_querybatch', db.querybatch), \
            mock.patch.object(cve_scanner, '_osv_vuln_details', db.details), \
            mock.patch.object(cve_scanner, '_debian_severity_fallback', lambda cve: None):
        result = cve_scanner.scan_device('h', packages, ecosystem, Path(_tmp('rp-kern-scan-')), has_meta=True,
                                         kernel=kernel, **kw)
    assert 'error' not in result, result.get('error')
    return result, db


def by_id(result):
    return {f['vuln_id']: f for f in result['findings']}


class _Captured(Exception):
    def __init__(self, status, body):
        super().__init__(status)
        self.status, self.body = status, body


# ── the agent ─────────────────────────────────────────────────────────────────────────────────────────────────────────
def uname(release):
    return lambda: types.SimpleNamespace(release=release)


class _Host(unittest.TestCase):
    """A host tree under a temporary HOST_ROOT, read by the agent as a container reads a host."""

    def setUp(self):
        self.root = Path(_tmp('rp-kern-host-'))
        self.agent = load_agent(host_root=str(self.root))
        self._patches = []
        self.addCleanup(self._stop)

    def patch(self, target, name, value):
        p = mock.patch.object(target, name, value)
        p.start()
        self._patches.append(p)

    def _stop(self):
        for p in reversed(self._patches):
            p.stop()

    def put(self, path, text=''):
        p = self.root / path.lstrip('/')
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def running(self, release):
        self.patch(self.agent.os, 'uname', uname(release))


class TestWhatTheAgentReadsOnDebian(_Host):
    PKGS = [{'name': 'linux-image-6.1.0-18-amd64', 'version': '6.1.76-1', 'arch': 'amd64'},
            {'name': 'linux-image-6.1.0-40-amd64', 'version': '6.1.158-1', 'arch': 'amd64'},
            {'name': 'linux-image-amd64', 'version': '6.1.76-1', 'arch': 'amd64'},
            {'name': 'linux-image-6.1.0-18-amd64-dbg', 'version': '6.1.76-1', 'arch': 'amd64'},
            {'name': 'linux-image-unsigned-6.5.0-9-generic', 'version': '6.5.0-9.9', 'arch': 'amd64'},
            {'name': 'bash', 'version': '5.2.15-2', 'arch': 'amd64'}]

    def setUp(self):
        super().setUp()
        self.put('/var/lib/dpkg/info/linux-image-6.1.0-18-amd64.list',
                 '/.\n/boot\n/boot/vmlinuz-6.1.0-18-amd64\n/lib/modules/6.1.0-18-amd64/kernel/fs/ext4/ext4.ko\n')
        self.put('/var/lib/dpkg/info/linux-image-6.1.0-40-amd64.list',
                 '/.\n/lib/modules/6.1.0-40-amd64/kernel\n/boot/vmlinuz-6.1.0-40-amd64\n')
        self.put('/var/lib/dpkg/info/linux-image-6.1.0-18-amd64-dbg.list', '/.\n/usr/lib/debug/boot/vmlinux-6.1.0-18-amd64\n')
        self.put('/var/lib/dpkg/info/linux-image-unsigned-6.5.0-9-generic.list', '/boot/vmlinuz-6.5.0-9-generic\n')

    def test_each_image_is_reported_with_the_release_its_file_list_names(self):
        self.running('6.1.0-18-amd64')
        got = self.agent.get_kernel_report('apt', self.PKGS)
        self.assertEqual(got['release'], '6.1.0-18-amd64')
        self.assertEqual(got['images'], [
            {'name': 'linux-image-6.1.0-18-amd64', 'version': '6.1.76-1', 'release': '6.1.0-18-amd64'},
            {'name': 'linux-image-6.1.0-40-amd64', 'version': '6.1.158-1', 'release': '6.1.0-40-amd64'},
            {'name': 'linux-image-6.1.0-18-amd64-dbg', 'version': '6.1.76-1'},          # owns no kernel file: no release
            {'name': 'linux-image-unsigned-6.5.0-9-generic', 'version': '6.5.0-9.9', 'release': '6.5.0-9-generic'},
        ])

    def test_the_meta_package_is_not_an_image_and_a_name_is_never_taken_for_a_release(self):
        self.running('6.1.0-18-amd64')
        names = [i['name'] for i in self.agent.get_kernel_report('apt', self.PKGS)['images']]
        self.assertNotIn('linux-image-amd64', names)
        # a package whose list cannot be read has no release, whatever its name says
        (self.root / 'var/lib/dpkg/info/linux-image-6.1.0-40-amd64.list').unlink()
        image = [i for i in self.agent.get_kernel_report('apt', self.PKGS)['images'] if i['name'].endswith('40-amd64')][0]
        self.assertNotIn('release', image)

    def test_what_the_agent_reads_is_what_the_server_resolves_to_the_running_package(self):
        self.running('6.1.0-18-amd64')
        sent = self.agent.get_kernel_report('apt', self.PKGS)
        clean = cve_scanner.kernel_report(sent)
        self.assertEqual(clean, sent)                                        # the server keeps what the agent sent
        units = cve_scanner.plan(self.PKGS, 'Debian:12', False)
        block, running, _others = cve_scanner.kernel_state(clean, self.PKGS, units, 'deb')
        self.assertEqual((block['state'], block['package'], block['version']),
                         ('matched', 'linux-image-6.1.0-18-amd64', '6.1.76-1'))
        self.assertEqual(len(running), 1)


class TestWhatTheAgentReadsOnRpm(_Host):
    def setUp(self):
        super().setUp()
        for name in ('vmlinuz-5.14.0-362.8.1.el9_3.x86_64', 'vmlinuz-5.14.0-427.13.1.el9_4.x86_64',
                     'vmlinuz-0-rescue-0c1d2e3f', 'config-5.14.0-362.8.1.el9_3.x86_64'):
            self.put('/boot/' + name)
        # the real program, on a PATH of its own: it answers for the two kernels and says what rpm says of a file no package owns
        self.bin = Path(_tmp('rp-kern-bin-'))
        script = self.bin / 'rpm'
        script.write_text(
            '#!/bin/sh\n'
            'for last; do :; done\n'
            'case "$last" in\n'
            '  /boot/vmlinuz-5.14.0-362.8.1.el9_3.x86_64) printf "kernel-core\\t5.14.0-362.8.1.el9_3\\tx86_64\\n";;\n'
            '  /boot/vmlinuz-5.14.0-427.13.1.el9_4.x86_64) printf "kernel-core\\t5.14.0-427.13.1.el9_4\\tx86_64\\n";;\n'
            '  *) echo "file $last is not owned by any package"; exit 1;;\n'
            'esac\n')
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        env = mock.patch.dict(os.environ, {'PATH': str(self.bin)})
        env.start()
        self.addCleanup(env.stop)

    def test_the_package_that_owns_each_kernel_file_is_the_image_and_a_file_nobody_owns_gives_nothing(self):
        self.running('5.14.0-362.8.1.el9_3.x86_64')
        got = self.agent.get_kernel_report('dnf', [])
        self.assertEqual(got['release'], '5.14.0-362.8.1.el9_3.x86_64')
        self.assertEqual(got['images'], [
            {'name': 'kernel-core', 'version': '5.14.0-362.8.1.el9_3', 'release': '5.14.0-362.8.1.el9_3.x86_64'},
            {'name': 'kernel-core', 'version': '5.14.0-427.13.1.el9_4', 'release': '5.14.0-427.13.1.el9_4.x86_64'}])

    def test_rpm_is_run_against_the_host_root_of_a_container(self):
        seen = []
        real = self.agent._safe_run

        def run(argv, timeout=10):
            seen.append(argv)
            return real(argv, timeout)
        self.patch(self.agent, '_safe_run', run)
        self.running('5.14.0-362.8.1.el9_3.x86_64')
        self.agent.get_kernel_report('dnf', [])
        self.assertTrue(seen)
        for argv in seen:
            self.assertEqual(argv[:3], ['rpm', '--root', str(self.root)])
            self.assertTrue(argv[-1].startswith('/boot/vmlinuz-'), argv)        # a path on the host, not under the root

    def test_an_rpm_that_hangs_holds_the_report_for_the_budget_and_no_longer(self):
        """A broken rpm database makes every question wait out its time limit. The questions share one budget, and the report
        goes out with what was read by then (here nothing: the first question was never answered)."""
        script = self.bin / 'rpm'
        script.write_text('#!/bin/sh\nexec /bin/sleep 60\n')
        self.patch(self.agent, 'KERNEL_READ_SECONDS', 2)
        asked = []
        real = self.agent._safe_run

        def run(argv, timeout=10):
            asked.append(timeout)
            return real(argv, timeout)
        self.patch(self.agent, '_safe_run', run)
        self.running('5.14.0-362.8.1.el9_3.x86_64')
        start = time.monotonic()
        got = self.agent.get_kernel_report('dnf', [])
        took = time.monotonic() - start
        self.assertEqual(got, {'release': '5.14.0-362.8.1.el9_3.x86_64', 'images': []})
        self.assertLess(took, 8, 'the questions did not stop at the budget')
        self.assertEqual(len(asked), 1, 'rpm was asked again after the budget was spent: %r' % asked)
        self.assertLessEqual(asked[0], 2, 'a question was given more time than the budget holds')

    def test_a_host_with_no_rpm_reports_the_release_alone(self):
        self.patch(self.agent, '_safe_run', lambda argv, timeout=10: (-1, '<error: no rpm>'))
        self.running('5.14.0-362.8.1.el9_3.x86_64')
        self.assertEqual(self.agent.get_kernel_report('dnf', []), {'release': '5.14.0-362.8.1.el9_3.x86_64', 'images': []})


class TestWhatTheAgentReadsOnAlpineAndArch(_Host):
    DB = '\n'.join([
        'C:Q1abc=', 'P:linux-lts', 'V:6.6.13-r0', 'A:x86_64', 'o:linux-lts', 'F:boot', 'R:vmlinuz-lts', 'F:lib/modules/6.6.13-0-lts',
        'R:modules.order', 'F:lib/modules/6.6.13-0-lts/kernel/drivers', 'R:x.ko', '',
        'C:Q1def=', 'P:zfs-lts', 'V:2.2.2-r0', 'A:x86_64', 'F:lib/modules/6.6.13-0-lts/extra', 'R:zfs.ko', '',
        'C:Q1ghi=', 'P:busybox', 'V:1.36.1-r2', 'A:x86_64', 'F:bin', 'R:busybox', '',
        'C:Q1jkl=', 'P:linux-virt', 'V:6.6.12-r1', 'A:x86_64', 'F:lib/modules/6.6.12-1-virt', 'R:modules.order', ''])

    def test_the_package_that_lists_the_modules_directory_is_the_kernel_of_that_release(self):
        self.put('/lib/apk/db/installed', self.DB)
        self.running('6.6.13-0-lts')
        got = self.agent.get_kernel_report('apk', [])
        self.assertEqual(got['images'], [{'name': 'linux-lts', 'version': '6.6.13-r0', 'release': '6.6.13-0-lts'},
                                         {'name': 'linux-virt', 'version': '6.6.12-r1', 'release': '6.6.12-1-virt'}])

    def test_a_package_that_only_has_files_below_the_directory_is_not_a_kernel(self):
        self.put('/lib/apk/db/installed', self.DB)
        self.running('6.6.13-0-lts')
        self.assertNotIn('zfs-lts', [i['name'] for i in self.agent.get_kernel_report('apk', [])['images']])

    def test_arch_names_the_package_in_the_file_next_to_the_modules(self):
        self.put('/usr/lib/modules/6.9.7-arch1-1/pkgbase', 'linux\n')
        self.put('/usr/lib/modules/6.6.30-1-lts/pkgbase', 'linux-lts\n')
        self.put('/usr/lib/modules/6.1.0-orphan/other', 'x')
        self.running('6.9.7-arch1-1')
        pkgs = [{'name': 'linux', 'version': '6.9.7.arch1-1'}, {'name': 'linux-lts', 'version': '6.6.30-1'}]
        got = self.agent.get_kernel_report('pacman', pkgs)
        self.assertEqual(got['images'], [{'name': 'linux-lts', 'version': '6.6.30-1', 'release': '6.6.30-1-lts'},
                                         {'name': 'linux', 'version': '6.9.7.arch1-1', 'release': '6.9.7-arch1-1'}])


class TestTheReportIsBoundedAndNeverRaises(_Host):
    def test_a_release_that_is_not_one_gives_no_report(self):
        for odd in ('', 'a b', 'x' * 200, '../etc', '-6.1', 'ok\nline'):
            self.running(odd)
            self.assertEqual(self.agent.get_kernel_report('apt', []), {}, repr(odd))

    def test_at_most_sixteen_images_and_a_name_that_is_not_a_package_is_left_out(self):
        pkgs = [{'name': f'linux-image-6.1.{i}-amd64', 'version': '6.1.1-1', 'arch': 'amd64'} for i in range(40)]
        pkgs.append({'name': 'linux-image-6.1.bad name', 'version': '1', 'arch': 'amd64'})
        self.running('6.1.0-amd64')
        got = self.agent.get_kernel_report('apt', pkgs)
        self.assertEqual(len(got['images']), self.agent.MAX_KERNEL_IMAGES)
        self.assertEqual(self.agent.MAX_KERNEL_IMAGES, 16)

    def test_a_reader_that_fails_still_reports_the_release(self):
        def boom(*a, **k):
            raise RuntimeError('unreadable')
        self.patch(self.agent, '_owned_release_dpkg', boom)
        self.running('6.1.0-18-amd64')
        got = self.agent.get_kernel_report('apt', [{'name': 'linux-image-6.1.0-18-amd64', 'version': '1', 'arch': 'a'}])
        self.assertEqual(got, {'release': '6.1.0-18-amd64', 'images': []})

    def test_an_unknown_manager_reports_the_release_alone(self):
        self.running('6.1.0-18-amd64')
        self.assertEqual(self.agent.get_kernel_report('unknown', []), {'release': '6.1.0-18-amd64', 'images': []})

    def test_nothing_the_server_would_refuse_is_sent(self):
        self.running('6.1.0-18-amd64')
        self.put('/var/lib/dpkg/info/linux-image-6.1.0-18-amd64.list', '/boot/vmlinuz-6.1.0-18-amd64\n')
        sent = self.agent.get_kernel_report('apt', [{'name': 'linux-image-6.1.0-18-amd64', 'version': '6.1.76-1', 'arch': 'amd64'}])
        self.assertEqual(cve_scanner.kernel_report(sent), sent)


class TestTheListIsSentAgainWhenTheKernelChanges(_Host):
    """A host that boots into another kernel changes nothing in its package list, and the list is only sent when it changes."""

    PKGS = [{'name': 'linux-image-6.1.0-40-amd64', 'version': '6.1.158-1', 'arch': 'amd64'},
            {'name': 'linux-image-6.1.0-48-amd64', 'version': '6.1.192-1', 'arch': 'amd64'}]

    def setUp(self):
        super().setUp()
        self.put('/var/lib/dpkg/info/linux-image-6.1.0-40-amd64.list', '/boot/vmlinuz-6.1.0-40-amd64\n')
        self.put('/var/lib/dpkg/info/linux-image-6.1.0-48-amd64.list', '/boot/vmlinuz-6.1.0-48-amd64\n')
        self.sent = []
        self.agent.PKG_HASH_FILE = Path(_tmp('rp-kern-hash-')) / 'pkg_hash'
        self.patch(self.agent, 'get_package_list_ex', lambda: ('apt', [dict(p) for p in self.PKGS], True))
        self.patch(self.agent, 'get_os_release', lambda: {'ID': 'debian', 'VERSION_ID': '12'})
        self.patch(self.agent, 'http_post', lambda url, payload, timeout=30: self.sent.append(payload) or {'ok': True})
        self.creds = {'device_id': 'kern1', 'token': 't', 'server_url': 'https://rp.example.com'}

    def test_the_kernel_goes_with_the_list(self):
        self.running('6.1.0-40-amd64')
        self.assertTrue(self.agent.send_package_list(self.creds))
        (payload,) = self.sent
        self.assertEqual(payload['kernel']['release'], '6.1.0-40-amd64')
        self.assertEqual([i['release'] for i in payload['kernel']['images']], ['6.1.0-40-amd64', '6.1.0-48-amd64'])
        self.assertTrue(payload['sources'])

    def test_an_unchanged_list_on_an_unchanged_kernel_is_not_sent_again(self):
        self.running('6.1.0-40-amd64')
        self.assertTrue(self.agent.send_package_list(self.creds))
        self.assertFalse(self.agent.send_package_list(self.creds))
        self.assertEqual(len(self.sent), 1)

    def test_a_reboot_into_another_kernel_sends_the_same_list_again(self):
        self.running('6.1.0-40-amd64')
        self.agent.send_package_list(self.creds)
        self.patch(self.agent.os, 'uname', uname('6.1.0-48-amd64'))
        self.assertTrue(self.agent.send_package_list(self.creds))
        self.assertEqual([p['kernel']['release'] for p in self.sent], ['6.1.0-40-amd64', '6.1.0-48-amd64'])
        self.assertEqual(self.sent[0]['packages'], self.sent[1]['packages'])           # the list itself did not change
        self.assertFalse(self.agent.send_package_list(self.creds))

    def test_a_kernel_installed_beside_the_running_one_changes_the_list_and_is_sent(self):
        self.running('6.1.0-40-amd64')
        self.agent.send_package_list(self.creds)
        self.PKGS = self.PKGS[:1]
        self.assertTrue(self.agent.send_package_list(self.creds))

    def test_the_gate_of_an_older_agent_sends_the_list_once_with_the_kernel(self):
        self.running('6.1.0-40-amd64')
        self.agent._save_last_pkg_hash(self.agent._compute_pkg_hash(self.PKGS))     # what the agent before this wrote
        self.assertTrue(self.agent.send_package_list(self.creds))
        self.assertFalse(self.agent.send_package_list(self.creds))

    def test_a_host_whose_kernel_cannot_be_read_sends_no_kernel_and_gates_on_the_list_alone(self):
        self.running('not a release')
        self.assertTrue(self.agent.send_package_list(self.creds))
        self.assertNotIn('kernel', self.sent[0])
        self.assertEqual(self.agent._load_last_pkg_hash(), self.agent._compute_pkg_hash(self.PKGS))
        self.assertFalse(self.agent.send_package_list(self.creds))

    def test_force_sends_it_whatever_the_gate_says(self):
        self.running('6.1.0-40-amd64')
        self.agent.send_package_list(self.creds)
        self.assertTrue(self.agent.send_package_list(self.creds, force=True))

    def test_a_failed_send_is_not_remembered(self):
        self.running('6.1.0-40-amd64')
        self.patch(self.agent, 'http_post', lambda *a, **k: (_ for _ in ()).throw(OSError('down')))
        self.assertFalse(self.agent.send_package_list(self.creds))
        self.assertEqual(self.agent._load_last_pkg_hash(), '')

    def test_the_digest_follows_the_release_the_images_and_their_versions(self):
        base = report('r1', {'name': 'a', 'version': '1', 'release': 'r1'})
        digest = self.agent._kernel_digest
        self.assertEqual(digest({}), '')
        self.assertEqual(digest(base), digest(json.loads(json.dumps(base))))
        for other in (report('r2', {'name': 'a', 'version': '1', 'release': 'r1'}),
                      report('r1', {'name': 'a', 'version': '2', 'release': 'r1'}),
                      report('r1', {'name': 'a', 'version': '1'}), report('r1')):
            self.assertNotEqual(digest(other), digest(base), other)

    def test_the_two_copies_of_the_agent_are_the_same_file(self):
        self.assertEqual((ROOT / 'client' / 'remotepower-agent').read_bytes(), (ROOT / 'client' / 'remotepower-agent.py').read_bytes())


# ── the server keeps what it was sent ─────────────────────────────────────────────────────────────────────────────────
class TestWhatTheServerKeepsOfAReport(unittest.TestCase):
    def test_a_good_report_is_kept_as_it_is(self):
        good = report(OLD, IMG_OLD, IMG_NEW)
        self.assertEqual(cve_scanner.kernel_report(json.loads(json.dumps(good))), good)

    def test_a_report_of_another_shape_is_nothing(self):
        for odd in (None, 7, 'x', [], {}, {'release': 7}, {'release': ''}, {'release': 'a b'}, {'release': '<script>'},
                    {'release': 'x' * 100}, {'images': [IMG_OLD]}):
            self.assertEqual(cve_scanner.kernel_report(odd), {}, odd)

    def test_the_images_are_cut_checked_and_capped(self):
        many = [{'name': f'linux-image-6.{i}', 'version': '1', 'release': f'6.{i}'} for i in range(40)]
        junk = [None, 7, 'x', [], {}, {'name': 'a b', 'version': '1'}, {'name': 'a', 'version': ''}, {'name': 'a', 'version': 'x y'},
                {'name': 5, 'version': '1'}, {'name': 'ok', 'version': '1', 'release': 'bad release'}, {'name': 'fine', 'version': '2'}]
        got = cve_scanner.kernel_report({'release': 'r', 'images': junk + many})
        # the cap is on the list as it is received: 11 rows of junk and the first 5 of the others
        self.assertEqual([i['name'] for i in got['images']],
                         ['ok', 'fine'] + [f'linux-image-6.{i}' for i in range(5)])
        self.assertNotIn('release', got['images'][0])
        self.assertEqual(len(cve_scanner.kernel_report({'release': 'r', 'images': many})['images']), cve_scanner.MAX_KERNEL_IMAGES)
        self.assertEqual(cve_scanner.kernel_report({'release': 'r', 'images': 'x'}), {'release': 'r', 'images': []})


# ── the scan ──────────────────────────────────────────────────────────────────────────────────────────────────────────
class TestAHostThatRunsTheOlderKernel(unittest.TestCase):
    """6.1.0-40 runs (6.1.158-1); 6.1.0-48 (6.1.192-1) is installed and has not been booted into."""

    @classmethod
    def setUpClass(cls):
        cls.result, cls.db = scan(LIST, report(OLD, IMG_OLD, IMG_NEW))
        cls.found = by_id(cls.result)

    def test_only_the_running_kernels_package_is_asked_about(self):
        asked = sorted(k for k in self.db.asked if k[1] == 'linux')
        self.assertEqual(asked, [('Debian:12', 'linux', '6.1.158-1')])

    def test_the_block_names_the_running_kernel_the_package_and_the_newer_one_beside_it(self):
        self.assertEqual(self.result['kernel'], {
            'running': OLD, 'state': 'matched', 'package': f'linux-image-{OLD}', 'version': '6.1.158-1',
            'newer': f'linux-image-{NEW} 6.1.192-1', 'left_out': 2})

    def test_what_an_installed_kernel_would_clear_is_reboot_and_names_it(self):
        for vid in (A, D):
            f = self.found[vid]
            self.assertEqual(f['fix_status'], 'reboot', vid)
            self.assertEqual(f['reboot_to'], f'linux-image-{NEW} 6.1.192-1')
            self.assertEqual(f['fixed_version'], '6.1.192-1')          # the version that has the fix is still said

    def test_what_no_installed_kernel_clears_is_what_it_was(self):
        self.assertEqual((self.found[B]['fix_status'], self.found[B]['fixed_version']), ('fixed', '6.1.200-1'))
        self.assertEqual(self.found[C]['fix_status'], 'none')
        for vid in (B, C):
            self.assertNotIn('reboot_to', self.found[vid])

    def test_a_reboot_finding_is_stored_beside_what_an_update_clears_even_when_medium(self):
        self.assertIn(D, self.found)                                      # medium, and not critical or high
        self.assertNotIn(E, self.found)                                   # medium with no fix: counted
        self.assertEqual(self.result['rollup']['fix'], {'none': 1})
        self.assertEqual(self.result['rollup']['total'], 1)

    def test_every_finding_is_the_running_kernels_and_names_its_package(self):
        for f in self.result['findings']:
            if f['package'] == 'linux':
                self.assertEqual(f['version'], '6.1.158-1', f)
                self.assertEqual(f['binaries'], [f'linux-image-{OLD}'])

    def test_the_packages_of_the_kernel_that_does_not_run_are_not_listed_or_counted_as_not_checked(self):
        covered = self.result['covered']
        self.assertEqual((covered['listed'], covered['checked'], covered['not_checked']), (1, 1, 0))

    def test_the_fix_counts_have_a_tile_for_it(self):
        counts = cve_fixes.summarize(self.result['findings'], set())
        self.assertEqual(counts, {'fixable': 1, 'reboot': 2, 'newer_release': 0, 'none': 1, 'pro': 0, 'unchecked': 0})


class TestAHostThatRunsTheNewerKernel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result, cls.db = scan(LIST, report(NEW, IMG_OLD, IMG_NEW))
        cls.found = by_id(cls.result)

    def test_an_older_kernel_that_is_not_running_is_not_counted(self):
        self.assertEqual(sorted(k for k in self.db.asked if k[1] == 'linux'), [('Debian:12', 'linux', '6.1.192-1')])
        self.assertEqual(set(self.found), {B, C})                          # A and D are fixed in what runs
        for f in self.result['findings']:
            self.assertNotEqual(f['version'], '6.1.158-1')

    def test_the_block_says_which_runs_and_that_one_kernel_was_left_out(self):
        self.assertEqual(self.result['kernel'], {
            'running': NEW, 'state': 'matched', 'package': f'linux-image-{NEW}', 'version': '6.1.192-1', 'left_out': 1})

    def test_nothing_is_a_reboot_when_the_installed_kernel_that_does_not_run_is_older(self):
        self.assertFalse([f for f in self.result['findings'] if f['fix_status'] == 'reboot'])
        self.assertNotIn('newer', self.result['kernel'])


class TestWhenTheKernelCannotBeTold(unittest.TestCase):
    """Every way of not knowing ends in today's plan, and the block says why."""

    def say(self, kernel, packages=LIST):
        result, db = scan(packages, kernel)
        return result, db

    def check_as_before(self, result, db):
        self.assertEqual(sorted(k for k in db.asked if k[1] == 'linux'),
                         [('Debian:12', 'linux', '6.1.158-1'), ('Debian:12', 'linux', '6.1.192-1')])
        self.assertFalse([f for f in result['findings'] if f['fix_status'] == 'reboot'])
        self.assertEqual(result['covered']['listed'], 3)

    def test_an_agent_that_reports_nothing(self):
        for kernel in (None, {}, 'x', {'release': 'a b'}):
            result, db = self.say(kernel)
            self.assertEqual(result['kernel'], {'running': '', 'state': 'unknown', 'why': 'not_reported', 'left_out': 0}, kernel)
            self.check_as_before(result, db)

    def test_a_release_no_image_owns(self):
        result, db = self.say(report('6.1.0-99-amd64', IMG_OLD, IMG_NEW))
        self.assertEqual((result['kernel']['state'], result['kernel']['why'], result['kernel']['running']),
                         ('unknown', 'no_owner', '6.1.0-99-amd64'))
        self.check_as_before(result, db)

    def test_an_image_whose_release_was_not_read_is_not_taken_for_the_owner_by_its_name(self):
        nameless = dict(IMG_OLD)
        del nameless['release']
        result, db = self.say(report(OLD, nameless, IMG_NEW))
        self.assertEqual(result['kernel']['why'], 'no_owner')
        self.check_as_before(result, db)

    def test_an_agent_that_found_no_image_on_a_host_that_has_some(self):
        result, db = self.say(report(OLD))
        self.assertEqual(result['kernel']['why'], 'no_images')
        self.check_as_before(result, db)

    def test_two_owners_built_from_different_versions(self):
        both = dict(IMG_NEW, release=OLD)
        result, db = self.say(report(OLD, IMG_OLD, both))
        self.assertEqual(result['kernel']['why'], 'several_owners')
        self.check_as_before(result, db)

    def test_an_owner_that_is_not_in_the_list(self):
        ghost = {'name': 'linux-image-6.1.0-77-amd64', 'version': '6.1.99-1', 'release': '6.1.0-77-amd64'}
        result, db = self.say(report('6.1.0-77-amd64', IMG_OLD, IMG_NEW, ghost))
        self.assertEqual(result['kernel']['why'], 'not_in_list')
        self.check_as_before(result, db)
        wrong_version = dict(IMG_OLD, version='6.1.158-2')
        self.assertEqual(self.say(report(OLD, wrong_version, IMG_NEW))[0]['kernel']['why'], 'not_in_list')

    def test_one_owner_in_the_list_and_another_that_is_not_is_not_told_apart(self):
        """The owner that is in the list is not taken for the one: the other claims the release too, and nothing says which."""
        ghost = {'name': 'linux-image-6.1.0-40-amd64-custom', 'version': '6.1.158-9', 'release': OLD}
        result, db = self.say(report(OLD, IMG_OLD, ghost, IMG_NEW))
        self.assertEqual(result['kernel']['why'], 'not_in_list')
        self.check_as_before(result, db)

    def test_a_signed_package_and_the_unsigned_one_it_holds_are_one_owner(self):
        """Both are built from one source version, so the answer is the same whichever of them owns the file."""
        packages = LIST + [{'name': f'linux-image-{OLD}-unsigned', 'version': '6.1.158-1', 'arch': 'amd64', 'source': 'linux'}]
        unsigned = {'name': f'linux-image-{OLD}-unsigned', 'version': '6.1.158-1', 'release': OLD}
        result, db = self.say(report(OLD, IMG_OLD, unsigned, IMG_NEW), packages)
        self.assertEqual((result['kernel']['state'], result['kernel']['package']), ('matched', f'linux-image-{OLD}'))
        self.assertEqual(sorted(k for k in db.asked if k[1] == 'linux'), [('Debian:12', 'linux', '6.1.158-1')])

    def test_a_host_with_no_kernel_package_and_no_report_has_no_block(self):
        result, _ = scan([SUDO], None)
        self.assertNotIn('kernel', result)
        result, _ = scan([SUDO], {})
        self.assertNotIn('kernel', result)

    def test_a_host_that_reports_images_but_has_no_kernel_package_in_its_list_has_no_block(self):
        result, _ = scan([SUDO], report(OLD))
        self.assertNotIn('kernel', result)

    def test_a_family_nothing_is_matched_against_has_no_block(self):
        """Arch and the rest have no ecosystem, so no scan is made of them and no kernel is matched."""
        for family_name in ('', 'pacman', 'windows', None):
            self.assertEqual(cve_scanner.kernel_state(report(OLD, IMG_OLD), LIST, [], family_name), (None, [], []), family_name)
        for family_name in ('deb', 'rpm', 'apk'):
            self.assertIn(family_name, cve_scanner._KERNEL_PACKAGE)


class TestSeveralKernelsInstalledBesideTheRunningOne(unittest.TestCase):
    MID = {'name': 'linux-image-6.1.0-44-amd64', 'version': '6.1.180-1', 'release': '6.1.0-44-amd64'}
    F = 'DEBIAN-CVE-2099-0006'

    def scan(self, running, report_order):
        packages = LIST + [{'name': self.MID['name'], 'version': self.MID['version'], 'arch': 'amd64', 'source': 'linux'}]
        answers = dict(ANSWERS)
        answers[('Debian:12', 'linux', '6.1.158-1')] = ANSWERS[('Debian:12', 'linux', '6.1.158-1')] + [self.F]
        answers[('Debian:12', 'linux', '6.1.180-1')] = [A, B, C, D, E]        # F is fixed in 6.1.180-1
        records = dict(RECORDS, **{self.F: record(self.F, '6.1.180-1')})
        db = Database(DEB, extra=answers, records=records)
        images = {'old': IMG_OLD, 'mid': self.MID, 'new': IMG_NEW}
        return scan(packages, report(running, *[images[k] for k in report_order]), db=db)

    def test_the_newest_is_the_one_named_whatever_order_the_agent_listed_them_in(self):
        for order in (('old', 'mid', 'new'), ('new', 'mid', 'old'), ('mid', 'old', 'new')):
            result, db = self.scan(OLD, order)
            self.assertEqual(result['kernel']['newer'], f'linux-image-{NEW} 6.1.192-1', order)
            self.assertEqual(result['kernel']['left_out'], 3, order)             # the two other images and the libc-dev
            self.assertEqual(sorted(k[2] for k in db.asked if k[1] == 'linux'), ['6.1.158-1'], order)

    def test_a_fix_that_a_kernel_in_the_middle_already_holds_is_still_a_reboot_and_names_the_newest(self):
        result, _ = self.scan(OLD, ('old', 'mid', 'new'))
        found = by_id(result)
        self.assertEqual((found[self.F]['fix_status'], found[self.F]['reboot_to']), ('reboot', f'linux-image-{NEW} 6.1.192-1'))
        self.assertEqual(found[A]['fix_status'], 'reboot')
        self.assertEqual(found[B]['fix_status'], 'fixed')

    def test_when_the_middle_one_runs_the_older_one_is_not_counted_and_the_newest_is_the_one_a_reboot_starts(self):
        result, db = self.scan('6.1.0-44-amd64', ('old', 'mid', 'new'))
        self.assertEqual(result['kernel']['package'], self.MID['name'])
        self.assertEqual(result['kernel']['newer'], f'linux-image-{NEW} 6.1.192-1')
        found = by_id(result)
        self.assertNotIn(self.F, found)              # the middle kernel has it
        self.assertEqual((found[A]['fix_status'], found[A]['reboot_to']), ('reboot', f'linux-image-{NEW} 6.1.192-1'))
        self.assertEqual(sorted(k[2] for k in db.asked if k[1] == 'linux'), ['6.1.180-1'])


class TestTheListOfAScanThatKnows(unittest.TestCase):
    def test_a_host_that_runs_the_older_kernel_after_it_installed_the_new_one_is_one_that_needs_a_reboot_and_no_update(self):
        before, _ = scan(ONLY_OLD, report(OLD, IMG_OLD))
        after, _ = scan(LIST, report(OLD, IMG_OLD, IMG_NEW))
        self.assertEqual({f['vuln_id']: f['fix_status'] for f in before['findings']},
                         {A: 'fixed', B: 'fixed', C: 'none', D: 'fixed'})
        self.assertEqual({f['vuln_id']: f['fix_status'] for f in after['findings']},
                         {A: 'reboot', B: 'fixed', C: 'none', D: 'reboot'})
        self.assertNotIn('newer', before['kernel'])
        self.assertEqual(after['kernel']['newer'], f'linux-image-{NEW} 6.1.192-1')

    def test_the_fleet_prefetch_asks_for_the_same_questions_as_a_scan(self):
        entry = {'ecosystem': 'Debian:12', 'sources': True, 'pkg_manager': 'apt', 'os_id': 'debian', 'packages': LIST,
                 'kernel': report(OLD, IMG_OLD, IMG_NEW)}
        db = database()
        with mock.patch.object(cve_scanner, '_osv_querybatch', db.querybatch):
            held = cve_scanner.prefetch_osv({'h': entry}, Path(_tmp('rp-kern-pf-')))
        self.assertEqual(sorted(k[1:] for k in held if k[1] == 'linux'), [('linux', '6.1.158-1')])
        # and a scan that is handed the map asks nothing more
        db2 = database()
        with mock.patch.object(cve_scanner, '_osv_querybatch', db2.querybatch), \
                mock.patch.object(cve_scanner, '_osv_vuln_details', db2.details), \
                mock.patch.object(cve_scanner, '_debian_severity_fallback', lambda c: None):
            result = cve_scanner.scan_device('h', LIST, 'Debian:12', Path(_tmp('rp-kern-pf-')), has_meta=True,
                                             osv_prefetch=held, kernel=entry['kernel'])
        self.assertEqual([k for k in db2.asked if k[1] == 'linux'], [])
        self.assertEqual(by_id(result)[A]['fix_status'], 'reboot')

    def test_an_rpm_host_whose_installed_kernel_is_past_the_fix(self):
        """AlmaLinux: the fix is a version, not a release, and the kernel is asked about by its installed name."""
        installed = [{'name': 'kernel-core', 'version': '5.14.0-362.8.1.el9_3', 'arch': 'x86_64', 'source': 'kernel'},
                     {'name': 'kernel-core', 'version': '5.14.0-427.13.1.el9_4', 'arch': 'x86_64', 'source': 'kernel'}]
        records = {'ALSA-2099:1': {'id': 'ALSA-2099:1', 'details': 'x', 'modified': '2026-11-10T08:00:00.123456789Z',
                                   'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}],
                                   'affected': [{'package': {'ecosystem': 'AlmaLinux:9', 'name': 'kernel-core'},
                                                 'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'},
                                                                                             {'fixed': '0:5.14.0-427.13.1.el9_4'}]}]}]}}
        answers = {('AlmaLinux:9', 'kernel-core', '5.14.0-362.8.1.el9_3'): ['ALSA-2099:1'],
                   ('AlmaLinux:9', 'kernel-core', '5.14.0-427.13.1.el9_4'): []}
        kernel = report('5.14.0-362.8.1.el9_3.x86_64',
                        {'name': 'kernel-core', 'version': '5.14.0-362.8.1.el9_3', 'release': '5.14.0-362.8.1.el9_3.x86_64'},
                        {'name': 'kernel-core', 'version': '5.14.0-427.13.1.el9_4', 'release': '5.14.0-427.13.1.el9_4.x86_64'})
        db = Database(DEB, extra=answers, records=records)
        result, _ = scan(installed, kernel, db=db, ecosystem='AlmaLinux:9')
        (finding,) = result['findings']
        self.assertEqual((finding['fix_status'], finding['reboot_to']), ('reboot', 'kernel-core 5.14.0-427.13.1.el9_4'))
        self.assertEqual(result['kernel']['state'], 'matched')
        # the same host running the newer kernel has nothing to say
        db = Database(DEB, extra=answers, records=records)
        newer = report('5.14.0-427.13.1.el9_4.x86_64', *kernel['images'])
        result, _ = scan(installed, newer, db=db, ecosystem='AlmaLinux:9')
        self.assertEqual(result['findings'], [])


# ── the rule ──────────────────────────────────────────────────────────────────────────────────────────────────────────
class TestTheStatusAndTheRulesThatReadIt(unittest.TestCase):
    def test_the_vocabulary(self):
        self.assertEqual(cve_fixes.REBOOT, 'reboot')
        self.assertIn('reboot', cve_fixes.STATUSES)
        self.assertEqual(cve_fixes.FIX_KEYS, ('fixable', 'reboot', 'newer_release', 'none', 'pro', 'unchecked'))
        self.assertEqual(cve_fixes.summarize([], set()), dict.fromkeys(cve_fixes.FIX_KEYS, 0))

    def test_it_is_not_something_an_update_clears_and_it_is_something_to_do(self):
        f = {'vuln_id': 'X', 'severity': 'medium', 'fix_status': 'reboot', 'fixed_version': '9'}
        self.assertFalse(cve_fixes.is_fixable(f))
        self.assertTrue(cve_fixes.is_clearable(f))
        self.assertTrue(cve_fixes.is_clearable({'fix_status': 'fixed'}))
        for status in ('none', 'newer_release', 'pro'):
            self.assertFalse(cve_fixes.is_clearable({'fix_status': status, 'fixed_version': '9'}), status)
        self.assertEqual(cve_fixes.fix_key(f), 'reboot')
        self.assertEqual(cve_fixes.fix_key({'fix_status': 'fixed'}), 'fixable')

    def test_it_counts_where_the_findings_an_update_clears_count_and_is_stored_beside_them(self):
        f = {'vuln_id': 'X', 'severity': 'medium', 'fix_status': 'reboot'}
        none = {'vuln_id': 'Y', 'severity': 'medium', 'fix_status': 'none'}
        self.assertTrue(cve_fixes.counted(f, True))
        self.assertFalse(cve_fixes.counted(none, True))
        self.assertTrue(cve_fixes.counted(none, False))
        self.assertTrue(cve_fixes.alert_candidate(f, True, set()))
        self.assertFalse(cve_fixes.alert_candidate(none, True, set()))
        self.assertTrue(cve_fixes.kept(f))
        self.assertFalse(cve_fixes.kept(none))
        stored, counted_rest = cve_fixes.split([f, none])
        self.assertEqual([x['vuln_id'] for x in stored], ['X'])
        self.assertEqual(counted_rest['fix'], {'none': 1})

    def test_it_takes_the_room_of_a_finding_an_update_clears(self):
        reboot = {'vuln_id': 'DEBIAN-CVE-2024-1', 'severity': 'medium', 'fix_status': 'reboot', 'package': 'linux'}
        fixed = {'vuln_id': 'DEBIAN-CVE-2024-2', 'severity': 'medium', 'fix_status': 'fixed', 'fixed_version': '2', 'package': 'linux'}
        none = {'vuln_id': 'DEBIAN-CVE-2024-3', 'severity': 'high', 'fix_status': 'none', 'package': 'linux'}
        stored, rest = cve_fixes.split([reboot, fixed, none], per_package=2)
        self.assertEqual(sorted(x['vuln_id'] for x in stored), ['DEBIAN-CVE-2024-1', 'DEBIAN-CVE-2024-2'])
        self.assertEqual(rest['total'], 1)
        # a clearable finding is as pressing as the one an update clears, and a high finding with no fix comes after it
        self.assertEqual(cve_fixes._pressing(reboot, None)[0], cve_fixes._pressing(fixed, None)[0])
        self.assertLess(cve_fixes._pressing(reboot, None)[0], cve_fixes._pressing({'severity': 'medium', 'fix_status': 'none'}, None)[0])

    def test_the_words_for_a_count_name_it(self):
        words = cve_fixes.rollup_words({'rollup': {'total': 5, 'fix': {'reboot': 3, 'fixable': 1}, 'severity': {'medium': 5}}})
        self.assertIn('3 fixed by an installed kernel, reboot to apply', words)
        self.assertIn('1 cleared by an update', words)

    def test_the_block_a_page_gets(self):
        view = cve_fixes.kernel_view({'running': OLD, 'state': 'matched', 'package': 'p', 'version': '1', 'newer': 'q 2',
                                      'left_out': 3, 'why': 'ignored', 'extra': 'x'})
        self.assertEqual(view, {'state': 'matched', 'running': OLD, 'package': 'p', 'version': '1', 'newer': 'q 2', 'left_out': 3})
        unknown = cve_fixes.kernel_view({'running': OLD, 'state': 'unknown', 'why': 'no_owner', 'left_out': -4})
        self.assertEqual(unknown, {'state': 'unknown', 'running': OLD, 'why': 'no_owner', 'left_out': 0})
        self.assertEqual(cve_fixes.kernel_view({'state': 'unknown', 'why': 'bogus'})['why'], '')
        for odd in (None, 7, 'x', [], {}, {'state': 'maybe'}):
            self.assertIsNone(cve_fixes.kernel_view(odd), odd)
        self.assertEqual(sorted(cve_fixes.KERNEL_WHY_WORDS), sorted(cve_fixes.KERNEL_WHY))

    def test_the_words_for_a_text_that_is_not_a_page(self):
        matched = cve_fixes.kernel_words({'running': OLD, 'state': 'matched', 'package': f'linux-image-{OLD}', 'version': '6.1.158-1',
                                          'newer': f'linux-image-{NEW} 6.1.192-1'})
        self.assertIn(f'The host runs kernel {OLD}', matched)
        self.assertIn('a reboot starts it', matched)
        unknown = cve_fixes.kernel_words({'running': OLD, 'state': 'unknown', 'why': 'no_owner'})
        self.assertIn('could not be matched to an installed package: no installed kernel package owns', unknown)
        self.assertIn('matched against every installed kernel', unknown)
        self.assertEqual(cve_fixes.kernel_words(None), '')


# ── the alerts, through a reboot ──────────────────────────────────────────────────────────────────────────────────────
class TestACompleteCircuitTheAlertsDoNotMistakeARebootForAClearance(unittest.TestCase):
    """The real comparison over real scan results: the host installs the new kernel (a finding goes from fixed to reboot), and
    then reboots (it is gone)."""

    HOST = 'kerndev1'

    def setUp(self):
        self.events = []
        self._p = [mock.patch.object(api, 'fire_webhook', lambda event, payload=None, *a, **k: self.events.append((event, payload))),
                   mock.patch.object(api, 'audit_log', lambda *a, **k: None)]
        for p in self._p:
            p.start()
            self.addCleanup(p.stop)
        api.save(api.CONFIG_FILE, {})
        api.save(api.CVE_IGNORE_FILE, {})
        api.save(api.KEV_EPSS_FILE, {})
        api._LOAD_CACHE.clear()
        self.addCleanup(lambda: [api.save(f, {}) for f in (api.CONFIG_FILE, api.CVE_IGNORE_FILE, api.KEV_EPSS_FILE)])
        self.devices = {self.HOST: {'id': self.HOST, 'name': 'kern01'}}

    def compare(self, before, after):
        self.events.clear()
        api._detect_new_cve_and_fire_webhook(self.HOST, self.devices, before['findings'], after['findings'], kev=set(),
                                             counted=after.get('rollup'), listed_to=before.get('listed_to'))
        return [e for e, _ in self.events]

    def test_installing_the_kernel_that_has_the_fix_is_neither_a_new_finding_nor_a_cleared_one(self):
        before, _ = scan(ONLY_OLD, report(OLD, IMG_OLD))
        after, _ = scan(LIST, report(OLD, IMG_OLD, IMG_NEW))
        self.assertEqual({f['fix_status'] for f in after['findings']} & {'reboot'}, {'reboot'})
        self.assertEqual(self.compare(before, after), [])

    def test_the_reboot_itself_clears_what_it_applied(self):
        installed, _ = scan(LIST, report(OLD, IMG_OLD, IMG_NEW))
        rebooted, _ = scan(LIST, report(NEW, IMG_OLD, IMG_NEW))
        # B and C are still there: the host is not clean, so nothing is cleared yet
        self.assertEqual(self.compare(installed, rebooted), [])
        # a host whose findings were all of the kernel it left
        only = {'findings': [f for f in installed['findings'] if f['fix_status'] == 'reboot'], 'rollup': None}
        gone = {'findings': [f for f in rebooted['findings'] if f['vuln_id'] not in (B, C)], 'rollup': None}
        self.assertEqual(self.compare(only, gone), ['cve_cleared'])

    def test_a_finding_that_is_only_reboot_pending_is_not_announced_as_cleared(self):
        """The mistake this guards: a status the list did not keep would leave the list and read as cleared."""
        before, _ = scan(ONLY_OLD, report(OLD, IMG_OLD))
        after, _ = scan(LIST, report(OLD, IMG_OLD, IMG_NEW))
        only_before = {'findings': [f for f in before['findings'] if f['vuln_id'] in (A, D)], 'rollup': None}
        only_after = {'findings': [f for f in after['findings'] if f['vuln_id'] in (A, D)], 'rollup': None}
        self.assertEqual({f['fix_status'] for f in only_after['findings']}, {'reboot'})
        self.assertEqual(self.compare(only_before, only_after), [])

    def test_with_the_count_option_on_the_reboot_findings_still_alert_and_count(self):
        api.save(api.CONFIG_FILE, {'cve_alert_fixable_only': True})
        api._LOAD_CACHE.clear()
        before, _ = scan(ONLY_OLD, report(OLD, IMG_OLD))
        after, _ = scan(LIST, report(OLD, IMG_OLD, IMG_NEW))
        self.assertEqual(self.compare(before, after), [])

    def test_a_reboot_finding_that_is_new_is_a_finding_to_act_on(self):
        api.save(api.CONFIG_FILE, {'cve_alert_fixable_only': True})
        api._LOAD_CACHE.clear()
        empty = {'findings': [], 'rollup': None}
        after, _ = scan(LIST, report(OLD, IMG_OLD, IMG_NEW))
        self.assertEqual(self.compare(empty, after), ['cve_found'])
        sample = self.events[0][1]['sample']
        self.assertIn(A, {s['id'] for s in sample})


# ── the whole way: the agent's report, the ingest, the worker, the alerts and the pages ───────────────────────────────────
KERNEL_ONLY = {('Debian:12', 'linux', '6.1.158-1'): [A, D], ('Debian:12', 'linux', '6.1.192-1'): []}


class _Fleet(unittest.TestCase):
    """Two tenants, a Debian host in each; the list of the first goes through the real ingest and the real worker. Only
    verify_token is stubbed when a reader is called, never a gate."""

    HOST, OTHER = 'kernfleet1', 'kernfleet2'

    def setUp(self):
        self._patches = []
        self.addCleanup(self._stop)
        self.events = []
        self.patch(api, 'respond', self._respond)
        self.patch(api, 'audit_log', lambda *a, **k: None)
        self.patch(api, 'fire_webhook', lambda event, payload=None, *a, **k: self.events.append((event, payload)))
        self.patch(api, 'get_token_from_request', lambda: 'x')
        api.save(api.CONFIG_FILE, {})
        api.save(api.TENANTS_FILE, {'tenantA': {'name': 'A', 'status': 'active'}, 'tenantB': {'name': 'B', 'status': 'active'}})
        api.save(api.USERS_FILE, {'alice': {'tenant_id': 'tenantA', 'role': 'admin'},
                                  'bruno': {'tenant_id': 'tenantB', 'role': 'admin'},
                                  'carol': {'tenant_id': 'tenantA', 'role': 'viewer'}})
        api.save(api.DEVICES_FILE, {h: {'id': h, 'name': h, 'tenant': t, 'os': 'Debian 12', 'token': 'tok-' + h, 'monitored': True,
                                        'group': '', 'tags': [], 'last_seen': 2_000_000_000}
                                    for h, t in ((self.HOST, 'tenantA'), (self.OTHER, 'tenantB'))})
        for store in (api.PACKAGES_FILE, api.CVE_FINDINGS_FILE, api.CVE_IGNORE_FILE, api.CVE_CAMPAIGNS_FILE, api.KEV_EPSS_FILE):
            api.save(store, {})
        api._LOAD_CACHE.clear()

    def patch(self, target, name, value):
        p = mock.patch.object(target, name, value)
        p.start()
        self._patches.append(p)

    def _stop(self):
        for p in reversed(self._patches):
            p.stop()
        for store in (api.DEVICES_FILE, api.PACKAGES_FILE, api.CVE_FINDINGS_FILE, api.CVE_IGNORE_FILE, api.CVE_CAMPAIGNS_FILE,
                      api.KEV_EPSS_FILE, api.CONFIG_FILE, api.TENANTS_FILE, api.USERS_FILE):
            api.save(store, {})
        api._LOAD_CACHE.clear()

    @staticmethod
    def _respond(status, data=None, headers=None):
        raise _Captured(status, data)

    def send(self, packages, kernel=None, host=None, manager='apt', **extra):
        host = host or self.HOST
        body = dict({'device_id': host, 'token': 'tok-' + host, 'pkg_manager': manager, 'packages': packages,
                     'ecosystem_hint': {'ID': 'debian', 'VERSION_ID': '12', 'ID_LIKE': ''}, 'sources': True}, **extra)
        if kernel is not None:
            body['kernel'] = kernel
        with mock.patch.object(api, 'method', lambda: 'POST'), mock.patch.object(api, 'get_json_obj', lambda: body):
            api._LOAD_CACHE.clear()
            try:
                api.handle_packages_submit()
            except _Captured as c:
                self.assertEqual(c.status, 200, c.body)
                return
        self.fail('the handler did not answer')

    def stored(self, host=None):
        api._LOAD_CACHE.clear()
        return (api.load(api.PACKAGES_FILE) or {}).get(host or self.HOST) or {}

    def scan_the_fleet(self, answers=None):
        db = Database(DEB, extra=answers or ANSWERS, records=RECORDS)
        with mock.patch.object(cve_scanner, '_osv_querybatch', db.querybatch), \
                mock.patch.object(cve_scanner, '_osv_vuln_details', db.details), \
                mock.patch.object(cve_scanner, '_debian_severity_fallback', lambda cve: None), \
                mock.patch.object(api, 'DATA_DIR', Path(_tmp('rp-kern-cache-'))):
            api._cve_scan_worker('tester', None)
        api._LOAD_CACHE.clear()
        return db

    def record(self, host=None):
        api._LOAD_CACHE.clear()
        return (api.load(api.CVE_FINDINGS_FILE) or {}).get(host or self.HOST) or {}

    def get(self, handler, *args, user=('root', 'admin'), tenancy=False):
        api.save(api.CONFIG_FILE, {'tenancy_enforced': True} if tenancy else {})
        api._LOAD_CACHE.clear()
        env = lambda key, default=None: default  # noqa: E731
        with mock.patch.object(api, '_env', env), mock.patch.object(api, 'method', lambda: 'GET'), \
                mock.patch.object(api, 'verify_token', lambda tok=None: user), \
                mock.patch.object(api, '_kev_epss', lambda: (set(), {})), \
                mock.patch.object(api, 'device_get', lambda dev_id: api.load(api.DEVICES_FILE).get(dev_id)):
            try:
                handler(*args)
            except _Captured as c:
                return c.status, c.body
        self.fail('the handler did not answer')

    def gated(self, user, dev_id):
        """GET /api/devices/<id>/cve as main() serves it: the device gate runs before the handler."""
        def run():
            api._enforce_device_scope()
            api.handle_cve_device(dev_id)
        with mock.patch.object(api, 'path_info', lambda: f'/api/devices/{dev_id}/cve'):
            return self.get(run, user=user, tenancy=True)


class TestTheIngestKeepsTheReport(_Fleet):
    def test_a_good_report_is_stored_with_the_list_and_the_next_list_replaces_it(self):
        good = report(OLD, IMG_OLD, IMG_NEW)
        self.send(LIST, good)
        self.assertEqual(self.stored()['kernel'], good)
        # a list that comes without one (an older agent) leaves none behind: what a host reported before it rebooted is not current
        self.send(LIST)
        self.assertNotIn('kernel', self.stored())

    def test_a_hostile_report_is_cut_to_what_the_server_would_keep(self):
        hostile = {'release': OLD, 'images': [{'name': 'a b', 'version': '1'}, {'name': 'ok', 'version': '1', 'release': '<script>'},
                                              {'name': 'x' * 300, 'version': '1'}, 'str', None] + [IMG_OLD] * 40}
        self.send(LIST, hostile)
        kernel = self.stored()['kernel']
        self.assertEqual(kernel['release'], OLD)
        self.assertLessEqual(len(kernel['images']), cve_scanner.MAX_KERNEL_IMAGES)
        self.assertEqual(kernel['images'][0], {'name': 'ok', 'version': '1'})
        for odd in ('<script>', {'release': '<script>'}, {'release': 7}, [], 'x', {'images': [IMG_OLD]}):
            self.send(LIST, odd)
            self.assertNotIn('kernel', self.stored(), odd)

    def test_the_list_of_a_windows_host_holds_no_kernel(self):
        self.send([{'name': 'Program', 'version': '1', 'manager': 'windows'}], report(OLD, IMG_OLD), manager='windows')
        self.assertNotIn('kernel', self.stored())

    def test_the_stored_shape_is_registered_and_a_wrong_one_is_repaired(self):
        self.send(LIST, report(OLD, IMG_OLD, IMG_NEW))
        store = {'h': dict(self.stored())}
        self.assertEqual(store_shapes.normalize('packages.json', json.loads(json.dumps(store))), store)
        broken = {'h': {'kernel': {'release': 7, 'images': [{'version': '1'}, {'name': 'a', 'version': '1'}, 5]}}}
        got = store_shapes.normalize('packages.json', broken)
        self.assertEqual([i['name'] for i in got['h']['kernel']['images']], ['a'])
        scan_store = {'h': {'findings': [{'vuln_id': 'X', 'fix_status': 'reboot', 'reboot_to': 'p 1'}],
                            'kernel': {'running': OLD, 'state': 'matched', 'left_out': 2}}}
        self.assertEqual(store_shapes.normalize('cve_findings.json', json.loads(json.dumps(scan_store))), scan_store)
        bad = {'h': {'findings': [], 'kernel': 'x'}}
        self.assertEqual(store_shapes.normalize('cve_findings.json', bad)['h']['kernel'], {})


class TestAHostThroughAnInstallAndAReboot(_Fleet):
    """The real ingest, worker and alert comparison, one scan after another, as an operator sees them."""

    def events_of(self, *names):
        return [e for e, _p in self.events if e in names]

    def test_the_circuit(self):
        # 1. the host runs the kernel it has: the advisories A and D wait for an update
        self.send(ONLY_OLD, report(OLD, IMG_OLD))
        self.scan_the_fleet(KERNEL_ONLY)
        first = self.record()
        self.assertEqual({f['vuln_id']: f['fix_status'] for f in first['findings']}, {A: 'fixed', D: 'fixed'})
        self.assertEqual(first['kernel']['state'], 'matched')
        self.assertIn('cve_found', self.events_of('cve_found'))
        # 2. an update installs the newer kernel: nothing is new and nothing is cleared, and what an update cleared a reboot clears
        self.events.clear()
        self.send(LIST, report(OLD, IMG_OLD, IMG_NEW))
        self.scan_the_fleet(KERNEL_ONLY)
        second = self.record()
        self.assertEqual({f['vuln_id']: f['fix_status'] for f in second['findings']}, {A: 'reboot', D: 'reboot'})
        self.assertEqual(second['kernel']['newer'], f'linux-image-{NEW} 6.1.192-1')
        self.assertEqual(self.events_of('cve_found', 'cve_cleared'), [])
        # the host's own page says what is left to do
        status, view = self.get(api.handle_cve_device, self.HOST)
        self.assertEqual(status, 200, view)
        self.assertEqual({f['vuln_id']: f['fix_status'] for f in view['findings']}, {A: 'reboot', D: 'reboot'})
        self.assertEqual((view['kernel']['state'], view['kernel']['running'], view['kernel']['newer']),
                         ('matched', OLD, f'linux-image-{NEW} 6.1.192-1'))
        status, report_all = self.get(api.handle_cve_findings)
        self.assertEqual(report_all['summary']['fix']['reboot'], 2)
        self.assertEqual(report_all['summary']['fix']['fixable'], 0)
        self.assertEqual(report_all['devices'][0]['fix']['reboot'], 2)
        # 3. the host reboots into it: the list is sent again, and now what the reboot applied is cleared, once
        self.events.clear()
        self.send(LIST, report(NEW, IMG_OLD, IMG_NEW))
        self.scan_the_fleet(KERNEL_ONLY)
        third = self.record()
        self.assertEqual(third['findings'], [])
        self.assertEqual(third['kernel']['running'], NEW)
        self.assertEqual(self.events_of('cve_cleared'), ['cve_cleared'])
        self.assertEqual(self.events_of('cve_found'), [])

    def test_a_host_that_reports_no_kernel_is_scanned_as_it_was_and_says_why(self):
        self.send(LIST)
        db = self.scan_the_fleet()
        self.assertEqual(self.record()['kernel'], {'running': '', 'state': 'unknown', 'why': 'not_reported', 'left_out': 0})
        self.assertEqual(sorted(k[2] for k in db.asked if k[1] == 'linux'), ['6.1.158-1', '6.1.192-1'])
        status, view = self.get(api.handle_cve_device, self.HOST)
        self.assertEqual(view['kernel'], {'state': 'unknown', 'running': '', 'why': 'not_reported', 'left_out': 0})


class TestTheReadersOfTheNewStatus(_Fleet):
    def setUp(self):
        super().setUp()
        self.send(LIST, report(OLD, IMG_OLD, IMG_NEW))
        self.scan_the_fleet()
        self.send(LIST, report(OLD, IMG_OLD, IMG_NEW), host=self.OTHER)

    def test_the_host_view_is_gated_to_the_hosts_tenant_and_a_viewer_reads_it(self):
        status, view = self.gated(('alice', 'admin'), self.HOST)
        self.assertEqual((status, view['kernel']['state'], view['kernel']['package']), (200, 'matched', f'linux-image-{OLD}'))
        status, view = self.gated(('carol', 'viewer'), self.HOST)
        self.assertEqual((status, view['kernel']['running']), (200, OLD))
        # the other tenant's administrator is refused before the handler, and learns nothing of the kernel
        for user in (('bruno', 'admin'),):
            status, view = self.gated(user, self.HOST)
            # 8.0.2: a host of another tenant is answered as a host that does not exist (404 "Host not found"), not 403 (tests/test_v802_host_of_another_tenant_is_not_found.py)
            self.assertEqual(status, 404, view)
            self.assertNotIn('kernel', view)
        status, view = self.gated(('alice', 'admin'), self.OTHER)
        # 8.0.2: a host of another tenant is answered as a host that does not exist (404 "Host not found"), not 403 (tests/test_v802_host_of_another_tenant_is_not_found.py)
        self.assertEqual(status, 404, view)

    def test_a_host_never_scanned_has_no_kernel_block_in_its_view(self):
        status, view = self.get(api.handle_cve_device, self.OTHER)
        self.assertEqual(status, 200)
        self.assertIsNone(view['kernel'])

    def test_the_text_of_a_ticket_and_the_assistants_tool_say_reboot_and_not_install(self):
        api._LOAD_CACHE.clear()
        ticket = api._alert_ticket_detail({'event': 'cve_found', 'device_id': self.HOST, 'title': 'New CVEs',
                                           'payload': {'device_id': self.HOST}})
        self.assertIn('(fixed by an installed kernel, reboot to apply)', ticket)
        self.assertNotIn('→ fix in 6.1.192-1', ticket)
        dev = api.load(api.DEVICES_FILE)[self.HOST]
        tool = api._triage_tools(self.HOST, dev)['cves']({})
        self.assertIn('(fixed by an installed kernel, reboot to apply)', tool)
        self.assertNotIn('→ fix in 6.1.192-1', tool)

    def test_the_texts_say_which_kernel_runs_and_when_the_scan_could_not_tell(self):
        """The ticket and the assistant's tool are read without the page: the kernel sentence is what lets a reader see that a
        reboot applies the fix, or that findings against the kernel cover every installed kernel and why."""
        api._LOAD_CACHE.clear()
        dev = api.load(api.DEVICES_FILE)[self.HOST]
        event = {'event': 'cve_found', 'device_id': self.HOST, 'title': 'New CVEs', 'payload': {'device_id': self.HOST}}
        matched = f'The host runs kernel {OLD}, the package linux-image-{OLD} 6.1.158-1.'
        newer = f'A newer kernel is installed and not running (linux-image-{NEW} 6.1.192-1): a reboot starts it.'
        for text in (api._alert_ticket_detail(event), api._triage_tools(self.HOST, dev)['cves']({})):
            self.assertIn(matched, text)
            self.assertIn(newer, text)
        # the same host, its agent no longer reporting a kernel
        self.send(LIST)
        self.scan_the_fleet()
        api._LOAD_CACHE.clear()
        said = ('The running kernel (unknown) could not be matched to an installed package: the agent of this host does not '
                'report its running kernel. Findings against the kernel are matched against every installed kernel.')
        for text in (api._alert_ticket_detail(event), api._triage_tools(self.HOST, dev)['cves']({})):
            self.assertIn(said, text)
            self.assertNotIn('a reboot starts it', text)

    def test_the_mcp_tools_carry_the_block(self):
        def fetch(path, method='GET', body=None):
            if path == '/api/devices':
                return {'devices': [dict(d) for d in api.load(api.DEVICES_FILE).values()]}
            status, answer = self.get(api.handle_cve_device, path.split('/')[3])
            self.assertEqual(status, 200, answer)
            return answer
        hosted = mcp_http.tool_get_cves({'name': self.HOST}, fetch)
        with mock.patch.object(sidecar, '_api', lambda method, path, body=None, mcp_prompt=None: fetch(path)):
            local = sidecar.tool_get_cves({'name': self.HOST})
        for out in (hosted, local):
            self.assertEqual((out['kernel']['state'], out['kernel']['running']), ('matched', OLD))
            self.assertIn(A, {f['vuln_id'] for f in out['findings']})
            self.assertEqual({f['fix_status'] for f in out['findings'] if f['vuln_id'] == A}, {'reboot'})

    def test_a_reboot_finding_is_not_in_the_count_of_what_a_pending_patch_installs(self):
        """The Patches link counts the critical and high findings an update installs the fix of: B, and not A, whose fix is
        already installed."""
        api._LOAD_CACHE.clear()
        self.assertEqual(api._cve_fixable_by_device(), {self.HOST: 1})


if __name__ == '__main__':
    unittest.main()
