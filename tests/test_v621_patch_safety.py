"""v6.2.1: guardrails against sandboxing-induced module-less initrds.

Root cause: the agent unit's ProtectKernelModules=yes hid /usr/lib/modules from
everything the agent executes, so a patch run that triggered update-initramfs
built initrds with NO kernel modules (mkinitramfs warns but exits 0). Such a host
runs fine until its next patch-window reboot, then drops to the initramfs
shell unable to find its LVM root — all kernels affected, so no fallback boot.

Three defenses under test — FUNCTIONALLY (real sh + stubbed binaries in a
controlled PATH), not source greps:
1. the shipped unit file no longer hides kernel modules;
2. _UPGRADE_CMD refuses to run when /lib/modules/$(uname -r) is inaccessible
   while an initramfs toolchain exists;
3. _SCHED_UPGRADE_REBOOT_CMD reboots ONLY after a clean upgrade whose on-disk
   initrds actually contain kernel modules.
"""
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_v621', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestAgentUnitDoesNotHideKernelModules(unittest.TestCase):
    """The unit template ships to every Linux host (install-client.sh + AUR).
    Any of these directives active again re-arms the unbootable-initrd bug."""

    def test_boot_breaking_directives_stay_disabled(self):
        unit = (_ROOT / 'client' / 'remotepower-agent.service').read_text()
        for line in unit.splitlines():
            ls = line.strip()
            for directive in ('ProtectKernelModules', 'NoNewPrivileges',
                              'ProtectSystem'):
                self.assertFalse(
                    ls.startswith(directive),
                    f'{directive} is active in remotepower-agent.service — it '
                    f'breaks package maintenance run through the exec channel '
                    f'(ProtectKernelModules builds module-less initrds → '
                    f'unbootable hosts). Line: {line!r}')


class _ShellHarness(unittest.TestCase):
    """Runs the real command strings under sh with a fully controlled PATH.

    PATH = <stubdir>:<realbin> where realbin holds symlinks to ONLY the real
    utilities the commands legitimately need. Nothing else on the host is
    reachable — critically, the host's own update-initramfs / systemctl /
    reboot can never be found (some distros, e.g. CachyOS, ship an
    update-initramfs shim in /usr/bin, which broke a PATH-prefix approach).
    Stubs append to $CALLS for assertions.
    """

    _REAL_TOOLS = ('cat', 'grep', 'mktemp', 'rm', 'date', 'tail', 'mkdir',
                   'printf', 'sh')

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.bin = self.dir / 'bin'
        self.bin.mkdir()
        self.realbin = self.dir / 'realbin'
        self.realbin.mkdir()
        import shutil
        for tool in self._REAL_TOOLS:
            src = shutil.which(tool)
            if src:
                os.symlink(src, self.realbin / tool)
        self.calls = self.dir / 'calls.log'
        self.calls.write_text('')
        self.env = {
            'PATH': f'{self.bin}:{self.realbin}',
            'CALLS': str(self.calls),
        }
        # A fake running-kernel version that cannot exist under /lib/modules.
        self.stub('uname', 'echo 0.0.0-rpfake')

    def stub(self, name, body):
        p = self.bin / name
        p.write_text('#!/bin/sh\n' + body + '\n')
        p.chmod(0o755)

    def run_sh(self, cmd):
        return subprocess.run(['/bin/sh', '-c', cmd], capture_output=True,
                              text=True, timeout=60, env=self.env)

    def called(self):
        return self.calls.read_text()


class TestUpgradeGuardRefusesWithoutModules(_ShellHarness):

    def test_refuses_when_modules_hidden_and_initramfs_tools_present(self):
        # update-initramfs exists, /lib/modules/0.0.0-rpfake does not →
        # the exact sandboxed-agent situation. apt must never be reached.
        self.stub('update-initramfs', 'echo "UI $*" >> "$CALLS"')
        self.stub('apt-get', 'echo "APT $*" >> "$CALLS"')
        r = self.run_sh(api._UPGRADE_CMD)
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn('not accessible', r.stderr)
        self.assertIn('unbootable', r.stderr)
        self.assertNotIn('APT', self.called())

    def test_proceeds_when_no_initramfs_toolchain(self):
        # No update-initramfs in PATH (WSL / containers / non-initramfs
        # distros): the guard must not block, and the apt chain runs fully.
        self.stub('apt-get', 'echo "APT $*" >> "$CALLS"')
        r = self.run_sh(api._UPGRADE_CMD)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        calls = self.called()
        for verb in ('update', '-y upgrade', '-y autoremove', 'clean'):
            self.assertIn(verb, calls)


class _SchedHarness(_ShellHarness):
    """_SCHED_UPGRADE_REBOOT_CMD with its hardcoded host paths redirected
    into the temp dir (log dir, /boot initrd glob, the absolute /sbin/reboot
    fallback) so the logic runs for real without touching the system."""

    def setUp(self):
        super().setUp()
        self.boot = self.dir / 'boot'
        self.boot.mkdir()
        self.log = self.dir / 'log' / 'remotepower_update.log'
        self.stub('systemctl', 'echo "SYSTEMCTL $*" >> "$CALLS"')
        self.stub('reboot', 'echo "REBOOT $*" >> "$CALLS"')

    def sched_cmd(self):
        cmd = api._SCHED_UPGRADE_REBOOT_CMD
        cmd = cmd.replace('/var/log/remotepower', str(self.log.parent))
        cmd = cmd.replace('/boot/initrd.img-', f'{self.boot}/initrd.img-')
        cmd = cmd.replace('/sbin/reboot', str(self.bin / 'reboot'))
        return cmd

    def log_text(self):
        return self.log.read_text() if self.log.exists() else ''


class TestSchedRebootGates(_SchedHarness):

    def test_clean_upgrade_healthy_initrd_reboots(self):
        self.stub('apt-get', 'echo "APT $*" >> "$CALLS"')
        (self.boot / 'initrd.img-0.0.0-rpfake').write_text('x')
        listing = self.dir / 'lsout'
        listing.write_text('usr/lib/modules/0.0.0-rpfake/kernel/md/dm-mod.ko.zst\n')
        self.stub('lsinitramfs', f'cat "{listing}"')
        r = self.run_sh(self.sched_cmd())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('SYSTEMCTL reboot', self.called())
        self.assertIn('rebooting', self.log_text())

    def test_moduleless_initrd_aborts_reboot(self):
        # The killer shape: upgrade exits 0, but an initrd on disk has no
        # kernel modules. Rebooting would brick the host — must abort.
        self.stub('apt-get', 'echo "APT $*" >> "$CALLS"')
        (self.boot / 'initrd.img-0.0.0-rpfake').write_text('x')
        listing = self.dir / 'lsout'
        listing.write_text('usr/lib/modules/0.0.0-rpfake/modules.dep\n'
                           'usr/bin/lvm\nconf/initramfs.conf\n')
        self.stub('lsinitramfs', f'cat "{listing}"')
        r = self.run_sh(self.sched_cmd())
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertNotIn('SYSTEMCTL', self.called())
        self.assertNotIn('REBOOT', self.called())
        self.assertIn('ABORTED', self.log_text())

    def test_failed_upgrade_skips_reboot(self):
        self.stub('apt-get',
                  'echo "APT $*" >> "$CALLS"\n'
                  'case "$*" in *upgrade*) exit 100;; esac')
        r = self.run_sh(self.sched_cmd())
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn('SYSTEMCTL', self.called())
        self.assertNotIn('REBOOT', self.called())
        self.assertIn('reboot SKIPPED', self.log_text())

    def test_no_lsinitramfs_still_reboots(self):
        # dracut/mkinitcpio hosts have no lsinitramfs — the sanity check must
        # skip (not block every RHEL/Arch patch window forever).
        self.stub('apt-get', 'echo "APT $*" >> "$CALLS"')
        r = self.run_sh(self.sched_cmd())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('SYSTEMCTL reboot', self.called())


if __name__ == '__main__':
    unittest.main()
