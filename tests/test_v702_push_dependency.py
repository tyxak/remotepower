#!/usr/bin/env python3
"""The push daemon is installed and enabled by default, and nothing installed
its one hard dependency.

`server/push/remotepower-push.py` imports `websockets` and exits 2 in `main()`
without it. `install-server.sh` defaults `WITH_PUSH=1` and runs
`systemctl enable --now remotepower-push`.

Nothing installed the package. Not install-server.sh, not install.sh, not
deploy-server.sh, not the Dockerfile's pip line, not docker/entrypoint.sh, not
requirements-server.txt, not the AUR PKGBUILD. The only file in the tree that
did was packaging/install-webterm.sh — an opt-in script install-server.sh never
calls.

The unit is `Type=simple`, so `enable --now` returns 0 whether or not the
process survives. The installer printed "Agent push daemon installed" and the
container entrypoint printed that it had started it, while the unit crash-looped
into its start limit — on every fresh host without the web terminal, and in
every image built from the Dockerfile.

CLAUDE.md already states the rule this broke: a new hard runtime import must
land in ci.yml, the Makefile CI_DEPS, install*.sh, the Dockerfile and the AUR
depends at the same time. This checks the rule for the packages that have one,
so the next daemon added is caught.
"""
import pathlib
import re
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _text(rel):
    p = _ROOT / rel
    return p.read_text() if p.exists() else None


class TestTheDaemonStillNeedsIt(unittest.TestCase):
    """The premise. If the daemon stops importing websockets, everything below
    becomes an assertion about nothing."""

    def test_the_push_daemon_imports_websockets(self):
        src = _text('server/push/remotepower-push.py')
        self.assertIsNotNone(src, 'the push daemon is gone')
        # re.M: the import is inside a try, mid-file. Without it this
        # asserted against the first line of the file and failed on a
        # premise that is true.
        self.assertRegex(src, re.compile(r'^\s*import websockets', re.M))

    def test_it_refuses_to_run_without_it(self):
        src = _text('server/push/remotepower-push.py')
        self.assertIn('_WS_AVAILABLE', src,
                      'the daemon no longer distinguishes the missing package')

    def test_it_is_installed_by_default(self):
        sh = _text('install-server.sh')
        self.assertRegex(sh, re.compile(r'WITH_PUSH="\$\{RP_WITH_PUSH:-1\}"'),
                         'if push became opt-in, the urgency below changes')


class TestEveryInstallPathProvidesIt(unittest.TestCase):

    def test_install_server_installs_it_on_every_package_manager(self):
        """Per branch, not once. The script switches on $PKG_MGR and each arm
        installs separately — checking that the string appears somewhere passes
        while one distro's arm is missing, which is how a gap like this returns."""
        sh = _text('install-server.sh')
        i = sh.index('import websockets')
        seg = sh[i:sh.index('esac', i)]
        for mgr in ('apt)', 'dnf)', 'pacman)'):
            self.assertIn(mgr, seg, f'no {mgr[:-1]} arm at all')
            # Bound the arm at its own ';;'. A fixed character window spills
            # into the NEXT arm, so removing one distro's install line still
            # matched its neighbour's and the demo passed while the gap was real.
            arm = seg[seg.index(mgr):]
            arm = arm[:arm.index(';;') + 2]
            self.assertIn('install websockets', arm,
                          f'the {mgr[:-1]} arm does not install websockets')

    def test_install_server_does_not_enable_a_unit_that_cannot_run(self):
        """Installing the package can still fail — behind a proxy, on an air-
        gapped host. Enabling the unit anyway is what turned a missing package
        into a crash loop reported as success."""
        sh = _text('install-server.sh')
        i = sh.index('import websockets')
        seg = sh[i:i + 1400]
        self.assertIn('WITH_PUSH=0', seg,
                      'a failed dependency install must skip the daemon, not '
                      'enable it')

    def test_the_dockerfile_installs_it(self):
        df = _text('Dockerfile')
        self.assertRegex(df, r'pip install[^\n]*websockets')

    def test_the_requirements_manifest_lists_it(self):
        """This file is the input to the control-plane SBOM, so an omission is
        also a supply-chain blind spot."""
        req = _text('packaging/requirements-server.txt')
        self.assertRegex(req, re.compile(r'^websockets\b', re.M))

    def test_the_aur_package_mentions_it(self):
        pkg = _text('packaging/aur/remotepower-server/PKGBUILD')
        self.assertIn('python-websockets', pkg)


class TestTheRuleGenerally(unittest.TestCase):
    """Every third-party module a SHIPPED DAEMON imports at module scope has to
    come from somewhere. This is the population, not the one instance."""

    _DAEMONS = ('server/push/remotepower-push.py',
                'server/flow/remotepower-flowd.py',
                'server/syslog/remotepower-syslogd.py',
                'server/kmip/remotepower-kmipd.py')
    _STDLIB_OK = {
        'os', 'sys', 're', 'json', 'time', 'socket', 'ssl', 'signal', 'select',
        'struct', 'hashlib', 'hmac', 'base64', 'logging', 'argparse', 'pathlib',
        'threading', 'asyncio', 'datetime', 'subprocess', 'sqlite3', 'secrets',
        'collections', 'contextlib', 'traceback', 'ipaddress', 'binascii',
        'urllib', 'http', 'typing', 'gzip', 'shutil', 'tempfile', 'errno',
        'stat', 'fcntl', 'random', 'string', 'itertools', 'functools', 'math',
        'copy', 'uuid', 'queue', 'enum', 'dataclasses', 'io', 'zlib', 'glob',
        'platform', 'getpass', 'pwd', 'grp', 'textwrap', 'unicodedata',
    }

    def test_every_daemon_import_is_stdlib_or_provisioned(self):
        provisioned = ' '.join(filter(None, (
            _text('install-server.sh'), _text('Dockerfile'),
            _text('packaging/requirements-server.txt'),
            _text('packaging/aur/remotepower-server/PKGBUILD'))))
        missing = []
        for rel in self._DAEMONS:
            src = _text(rel)
            if src is None:
                continue
            for m in re.finditer(r'^\s*(?:import|from)\s+([a-z_][\w]*)', src, re.M):
                mod = m.group(1)
                if mod in self._STDLIB_OK or mod.startswith(('remotepower', 'storage')):
                    continue
                if mod in provisioned:
                    continue
                missing.append(f'{rel}: {mod}')
        self.assertEqual(sorted(set(missing)), [],
                         'a shipped daemon imports a package no install path '
                         'provides — it will exit on a fresh host:\n  '
                         + '\n  '.join(sorted(set(missing))))


if __name__ == '__main__':
    unittest.main()
