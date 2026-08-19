#!/usr/bin/env python3
"""The Secure Boot check is OFF by default, like the other deliberate-choice checks.

It first shipped always-on, with a comment arguing that booting an unsigned
kernel "is not a trade-off anyone makes on purpose". That is wrong on Linux:
out-of-tree kernel modules — ZFS, NVIDIA, VirtualBox, anything through DKMS —
will not load under Secure Boot unless their signing key is enrolled, so turning
it off is a routine decision. Warning by default flags that decision as a
security problem across a whole fleet at once, which is precisely the
guard-fires-on-every-healthy-host failure this codebase has shipped before (the
v6.2.1 initramfs guard, which stopped patching on every Arch host and blamed
systemd for it).

It now sits behind `secure_boot_checks`, next to `disk_encryption_checks` and
`security_hardening_checks` in Settings → Security — the same shelf, for the
same reason: they all report configuration that is often chosen on purpose.

One switch drives BOTH surfaces. Gating the check and leaving the advisory
finding always-on would mean an operator who turned the row off gets told about
it on a different page instead, which is worse than not gating at all.

The drawer pill is NOT gated, and that is the existing precedent rather than an
exception: the Disk encryption row renders whatever the agent reported no matter
what `disk_encryption_checks` says. A fact on a host's own page is not a warning
about the fleet.
"""
import importlib.util
import pathlib
import re
import sys
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


checks = _load('checks_v702sb', _CGI / 'checks.py')
advisory = _load('advisory_v702sb', _CGI / 'advisory.py')

_OFF = {'name': 'web01', 'sysinfo': {'secure_boot': False}}
_ON = {'name': 'web01', 'sysinfo': {'secure_boot': True}}
_ABSENT = {'name': 'web01', 'sysinfo': {}}


def _rows(dev, flag):
    return [r for r in checks._host_checks('d1', dev, secure_boot=flag)
            if r['key'] == 'secure_boot']


def _findings(dev, flag):
    return [f for f in advisory._os_findings('d1', 'web01', dev, None, None,
                                             secure_boot_checks=flag)
            if f['id'] == 'os.secureboot']


class TestItIsSilentUntilAskedFor(unittest.TestCase):

    def test_no_check_row_by_default(self):
        self.assertEqual(_rows(_OFF, False), [])

    def test_no_advisory_finding_by_default(self):
        self.assertEqual(_findings(_OFF, False), [])

    def test_the_default_really_is_off(self):
        """Not just the parameter default — what the config returns on an
        install where nobody has touched the setting."""
        src = (_CGI / 'api.py').read_text()
        self.assertIn("safe.setdefault('secure_boot_checks', False)", src)
        self.assertRegex(
            src, r"'secure_boot':\s*bool\(cfg\.get\('secure_boot_checks',\s*False\)\)")

    def test_the_signature_default_is_off_too(self):
        import inspect
        self.assertIs(
            inspect.signature(checks._host_checks).parameters['secure_boot'].default,
            False)


class TestItWorksWhenTurnedOn(unittest.TestCase):
    """The control. A gate that never fires would pass every test above."""

    def test_the_check_row_appears_and_warns(self):
        rows = _rows(_OFF, True)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['status'], 'warning')

    def test_the_advisory_finding_appears(self):
        f = _findings(_OFF, True)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]['severity'], 'medium')

    def test_a_host_with_it_ON_is_an_ok_row_and_no_finding(self):
        rows = _rows(_ON, True)
        self.assertEqual([r['status'] for r in rows], ['ok'])
        self.assertEqual(_findings(_ON, True), [])

    def test_a_host_with_no_efi_variable_stays_silent_either_way(self):
        """Absent is not off. A BIOS/CSM boot, a container, or a VM without
        UEFI firmware has no answer to give, and inventing one would be the
        absent-vs-negative confusion the encryption collector avoids."""
        for flag in (False, True):
            self.assertEqual(_rows(_ABSENT, flag), [], f'flag={flag}')
            self.assertEqual(_findings(_ABSENT, flag), [], f'flag={flag}')


class TestOneSwitchDrivesBothSurfaces(unittest.TestCase):

    def test_the_advisory_handler_reads_the_same_config_key(self):
        src = (_CGI / 'advisory_handlers.py').read_text()
        self.assertRegex(
            src, r"secure_boot_checks=bool\(A\._config_ro\(\)"
                 r"\.get\('secure_boot_checks',\s*False\)\)",
            'the advisory must read the SAME key as the check, or turning the '
            'check off just moves the message to another page')

    def test_the_config_save_path_persists_it(self):
        """Miss the save whitelist and the toggle silently does not stick —
        the documented failure mode for every config key in this product."""
        src = (_CGI / 'api.py').read_text()
        self.assertIn("if 'secure_boot_checks' in body:", src)
        self.assertIn("cfg['secure_boot_checks'] = bool(body['secure_boot_checks'])", src)


class TestTheSettingIsReachable(unittest.TestCase):

    def test_the_checkbox_exists_in_the_security_pane(self):
        html = (_ROOT / 'server/html/index.html').read_text()
        self.assertIn('id="cfg-secure-boot-checks"', html)
        pane = html[html.index('id="settings-pane-security"'):]
        pane = pane[:pane.index('id="settings-pane-', 10)] if 'id="settings-pane-' in pane[10:] else pane
        self.assertIn('cfg-secure-boot-checks', pane,
                      'the toggle must live beside the other opt-in checks')

    def test_the_frontend_loads_and_saves_it(self):
        js = (_ROOT / 'server/html/static/js/app.js').read_text()
        self.assertIn('data.secure_boot_checks', js, 'the box never reflects '
                                                     'the stored value')
        self.assertIn('payload.secure_boot_checks', js, 'the box never saves')

    def test_the_drawer_pill_is_not_gated(self):
        """A fact on the host's own page, matching how Disk encryption behaves
        regardless of its own opt-in."""
        js = (_ROOT / 'server/html/static/js/app.js').read_text()
        m = re.search(r"\['Secure Boot'.{0,900}", js, re.S)
        self.assertTrue(m)
        self.assertNotIn('secure_boot_checks', m.group(0),
                         'the drawer must show what the agent reported')


if __name__ == '__main__':
    unittest.main()
