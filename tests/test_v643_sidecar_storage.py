#!/usr/bin/env python3
"""Every sidecar daemon must be able to find the app's storage layer.

Three standalone daemons read state the main API owns — the agent push daemon,
the syslog receiver and the NetFlow/IPFIX receiver. Under Postgres and SQLite
(Postgres has been the default since v6.1.0) the `*.json` stores are DB rows
with no file on disk, so a daemon that cannot import `storage` reads `{}` from
every file and silently rejects everything.

This has now happened TWICE.

v6.1.1 fixed it in the push daemon: installed at /usr/local/bin, its
`__file__`-relative search resolved to /usr/local/cgi-bin and found nothing,
so it authenticated every device against `{}` and the push channel was dead —
failed closed, no error, unit reporting active. The fix added RP_CGI_BIN plus
the real install roots.

v6.4.3 found the SAME bug still live in the other two, reported from a
production host:

    remotepower-flowd[...]: WARNING storage backend detection failed
        (No module named 'storage') — flat-file reads
    remotepower-flowd[...]: INFO flow from unmapped exporter 192.168.1.1
        dropped (enrol it + add a kind=flow inbound token)

The second line is a symptom of the first, and its advice is misleading: the
exporter WAS enrolled, but the token map was read from files that do not exist
under Postgres. Meanwhile the Self page showed "Flow receiver · Healthy ·
Running · 0 exporter(s)".

So the fix's own comment sat in one file describing a bug two siblings still
had. These tests make that impossible to repeat: the discovery logic is
verified per daemon, not assumed to have been copied.
"""
import importlib.util
import os
import shutil
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'

DAEMONS = {
    'push':   _ROOT / 'server' / 'push' / 'remotepower-push.py',
    'syslog': _ROOT / 'server' / 'syslog' / 'remotepower-syslogd.py',
    'flow':   _ROOT / 'server' / 'flow' / 'remotepower-flowd.py',
}
UNITS = {
    'syslog': _ROOT / 'packaging' / 'remotepower-syslogd.service',
    'flow':   _ROOT / 'packaging' / 'remotepower-flowd.service',
}
# The layouts the installers actually use. /usr/local/cgi-bin is NOT among them,
# which is the whole point — that is where the old code looked.
INSTALL_ROOTS = (
    '/var/www/remotepower/cgi-bin',
    '/usr/share/webapps/remotepower/cgi-bin',
    '/opt/remotepower/cgi-bin',
)


def _load(path, extra_dir=None):
    """Import a daemon by path. `extra_dir` goes on sys.path first for the
    siblings a daemon imports from its own directory (flow_parse)."""
    import sys
    if extra_dir and str(extra_dir) not in sys.path:
        sys.path.insert(0, str(extra_dir))
    spec = importlib.util.spec_from_file_location(f'sidecar_{path.stem}', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@unittest.skipUnless(all(p.exists() for p in DAEMONS.values()),
                     'excluded from dist tree')
class TestEverySidecarCanFindStorage(unittest.TestCase):
    def test_all_three_honour_rp_cgi_bin(self):
        """The deterministic path: the unit says where the app lives, rather
        than the daemon guessing from where it happens to be installed."""
        missing = [n for n, p in DAEMONS.items()
                   if 'RP_CGI_BIN' not in p.read_text()]
        self.assertEqual(missing, [], f'{missing} do not read RP_CGI_BIN, so an '
                                      'operator has no way to tell them where '
                                      'the storage layer is')

    def test_all_three_probe_the_real_install_roots(self):
        """The fallback, for an install that predates the env var. The bug was
        exactly this list being absent."""
        bad = []
        for name, p in DAEMONS.items():
            src = p.read_text()
            for root in INSTALL_ROOTS:
                if root not in src:
                    bad.append(f'{name}: does not probe {root}')
        self.assertEqual(bad, [], '\n'.join(bad))

    def test_discovery_works_from_an_installed_layout(self):
        """Behavioural, not textual: copy the daemon to a /usr/local/bin-shaped
        path with no cgi-bin anywhere above it, and confirm RP_CGI_BIN still
        resolves. Run against the REAL file, because the failure mode was a
        path calculation that looked perfectly reasonable in the repo."""
        for name, path in DAEMONS.items():
            with self.subTest(daemon=name):
                tmp = Path(tempfile.mkdtemp(prefix='rp-sidecar-'))
                self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
                bindir = tmp / 'usr' / 'local' / 'bin'
                bindir.mkdir(parents=True)
                dst = bindir / f'{path.stem}.py'
                shutil.copy(path, dst)
                for sib in path.parent.glob('*.py'):
                    if sib != path:
                        shutil.copy(sib, bindir / sib.name)

                prev = os.environ.get('RP_CGI_BIN')
                os.environ['RP_CGI_BIN'] = str(_CGI)
                try:
                    mod = _load(dst, extra_dir=bindir)
                    found = mod._find_cgi_bin()
                finally:
                    if prev is None:
                        os.environ.pop('RP_CGI_BIN', None)
                    else:
                        os.environ['RP_CGI_BIN'] = prev
                self.assertIsNotNone(
                    found, f'{name} cannot find cgi-bin from an installed '
                           'layout even with RP_CGI_BIN set — it will fall '
                           'back to flat-file reads and drop everything under '
                           'Postgres')
                self.assertEqual(Path(found).resolve(), _CGI.resolve())

    def test_the_repo_layout_still_resolves_without_the_env_var(self):
        """The positive control. If this broke, the test above could pass
        against a daemon that ONLY works when the env var is set, which would
        silently break every existing install on upgrade."""
        prev = os.environ.pop('RP_CGI_BIN', None)
        try:
            for name, path in DAEMONS.items():
                with self.subTest(daemon=name):
                    mod = _load(path, extra_dir=path.parent)
                    self.assertEqual(Path(mod._find_cgi_bin()).resolve(),
                                     _CGI.resolve())
        finally:
            if prev is not None:
                os.environ['RP_CGI_BIN'] = prev

    def test_a_failed_import_is_logged_not_swallowed(self):
        """The daemon degrades rather than crashing, which is right — but the
        degradation must be visible. This is the line that let the production
        host be diagnosed at all."""
        for name, path in DAEMONS.items():
            with self.subTest(daemon=name):
                src = path.read_text()
                self.assertRegex(
                    src, r'log\.(warning|error)\(',
                    f'{name} has no warning path for a failed storage import')


@unittest.skipUnless(all(p.exists() for p in UNITS.values()),
                     'excluded from dist tree')
class TestTheUnitsPointAtTheAppCode(unittest.TestCase):
    def test_each_optional_receiver_unit_sets_rp_cgi_bin(self):
        for name, p in UNITS.items():
            with self.subTest(unit=name):
                self.assertIn('Environment=RP_CGI_BIN=/var/www/remotepower/cgi-bin',
                              p.read_text(),
                              f'{name}.service does not tell the daemon where '
                              'the storage layer is, so it falls back to '
                              'probing and may find nothing')

    def test_they_can_still_read_the_data_dir(self):
        """RP_CGI_BIN is useless if the sandbox blocks the marker file that
        carries the Postgres DSN."""
        for name, p in UNITS.items():
            with self.subTest(unit=name):
                src = p.read_text()
                self.assertRegex(src, r'(ReadOnlyPaths|ReadWritePaths)=[^\n]*'
                                      r'/var/lib/remotepower')

    def test_no_receiver_runs_as_a_transient_user(self):
        """The SECOND wall, found on the same production host after the import
        was fixed:

            WARNING storage backend detection failed
                ([Errno 13] Permission denied:
                 '/var/lib/remotepower/storage_backend.json') — flat-file reads

        Both units ran `DynamicUser=yes`, which sandboxes a network listener
        beautifully and makes this particular one useless: the installer
        creates /var/lib/remotepower mode 0700 owned by the web user, so a
        transient uid gets EPERM on the very first read and degrades to
        flat-file reads — the exact failure the import fix was meant to end.

        `ReadOnlyPaths=` is a MOUNT NAMESPACE, not a permission. It was in the
        unit, it looked like access, and it granted none. The push daemon runs
        as the web user, which is the whole reason it works."""
        for name, p in UNITS.items():
            with self.subTest(unit=name):
                # DIRECTIVES only — a systemd '#' line is a comment, and the
                # explanation of this very fix names the directive it removed.
                src = '\n'.join(l for l in p.read_text().splitlines()
                                 if not l.lstrip().startswith('#'))
                self.assertNotIn(
                    'DynamicUser=yes', src,
                    f'{name}.service runs as a transient user but must READ '
                    'the 0700 data dir — it will EPERM on the backend marker '
                    'and silently drop everything under Postgres')
                self.assertRegex(
                    src, r'(?m)^User=',
                    f'{name}.service sets no User=, so it cannot be rendered '
                    'to the distro web user that owns the data dir')

    def test_the_installer_renders_the_distro_user_into_them(self):
        """The units ship User=www-data (the Debian name). On RHEL and Arch the
        web user is nginx / http, and an unrendered unit fails 217/USER — the
        same class that took down the app server and scheduler."""
        inst = _ROOT / 'install-server.sh'
        if not inst.exists():
            self.skipTest('excluded from dist tree')
        src = inst.read_text()
        for name in UNITS:
            unit = f'remotepower-{"syslogd" if name == "syslog" else "flowd"}.service'
            with self.subTest(unit=unit):
                self.assertIn(f'render_unit_user /etc/systemd/system/{unit}', src)


if __name__ == '__main__':
    unittest.main()
