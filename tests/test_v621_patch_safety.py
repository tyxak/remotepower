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
                   'printf', 'sh', 'ls', 'sort')   # ls/sort: v6.4.0 kernel-compare

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
    """The guard distinguishes two states that look identical at the running
    kernel's own path, so every case here redirects BOTH module roots into the
    sandbox — otherwise the host's real /usr/lib/modules decides the verdict and
    the result depends on whether the machine running the tests happens to have
    rebooted since its last kernel update.

    Substitution order matters: '/usr/lib/modules' contains '/lib/modules', so
    replacing the short one first mangles the long one into '/usr<tmp>'. The
    longer path goes first. (_SchedHarness below still has them the other way
    round; there it is inert because that command only reads the short path.)
    """

    def setUp(self):
        super().setUp()
        self.libmod = self.dir / 'lib-modules'
        self.usrmod = self.dir / 'usr-lib-modules'

    def guard_cmd(self):
        cmd = api._UPGRADE_CMD
        cmd = cmd.replace('/usr/lib/modules', str(self.usrmod))
        cmd = cmd.replace('/lib/modules', str(self.libmod))
        return cmd

    def test_refuses_when_the_whole_tree_is_hidden(self):
        # update-initramfs exists and NO module tree is visible at all → the
        # v6.2.1 sandboxed-agent situation. apt must never be reached.
        self.stub('update-initramfs', 'echo "UI $*" >> "$CALLS"')
        self.stub('apt-get', 'echo "APT $*" >> "$CALLS"')
        r = self.run_sh(self.guard_cmd())
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn('no kernel module tree is visible', r.stderr)
        self.assertIn('unbootable', r.stderr)
        self.assertNotIn('APT', self.called())

    def test_refuses_when_the_tree_exists_but_is_empty(self):
        """ProtectKernelModules mounts an empty tmpfs rather than removing the
        directory, so 'the path exists' is not evidence the modules are there."""
        self.usrmod.mkdir()
        self.stub('update-initramfs', 'echo "UI $*" >> "$CALLS"')
        self.stub('apt-get', 'echo "APT $*" >> "$CALLS"')
        r = self.run_sh(self.guard_cmd())
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertNotIn('APT', self.called())

    def test_proceeds_when_the_running_kernel_was_replaced_by_an_upgrade(self):
        """THE FIELD-REPORTED BUG (CachyOS, 2026-08-13). Arch-family package
        managers delete the previous kernel's module tree on upgrade, so between
        the upgrade and the next reboot /usr/lib/modules/$(uname -r) is genuinely
        absent — while other kernels sit right beside it. CachyOS also ships
        /usr/bin/update-initramfs, so both of the old guard's conditions were
        true and EVERY package upgrade was refused until somebody rebooted, with
        a message blaming service sandboxing that was not involved.

        An initramfs rebuild here targets an INSTALLED kernel whose modules are
        present, so there is nothing to protect against. Proceed.
        """
        (self.usrmod / '7.1.8-1-cachyos').mkdir(parents=True)
        (self.usrmod / '6.18.42-1-cachyos-lts').mkdir()
        self.stub('update-initramfs', 'echo "UI $*" >> "$CALLS"')
        self.stub('apt-get', 'echo "APT $*" >> "$CALLS"')
        r = self.run_sh(self.guard_cmd())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('not yet rebooted', r.stderr,
                      'proceeding silently hides why the running kernel differs')
        self.assertNotIn('refusing', r.stderr)
        self.assertIn('APT', self.called(), 'the upgrade must actually run')

    def test_the_short_path_alone_is_enough_to_proceed(self):
        """Distros where /lib is not a symlink to /usr/lib."""
        (self.libmod / '9.9.9-other').mkdir(parents=True)
        self.stub('update-initramfs', 'echo "UI $*" >> "$CALLS"')
        self.stub('apt-get', 'echo "APT $*" >> "$CALLS"')
        r = self.run_sh(self.guard_cmd())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('APT', self.called())

    def test_the_normal_case_is_silent(self):
        """Running kernel's modules present: no note, no refusal, no noise in
        every patch report on every healthy host."""
        (self.usrmod / '0.0.0-rpfake').mkdir(parents=True)
        self.stub('update-initramfs', 'echo "UI $*" >> "$CALLS"')
        self.stub('apt-get', 'echo "APT $*" >> "$CALLS"')
        r = self.run_sh(self.guard_cmd())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn('not yet rebooted', r.stderr)
        self.assertNotIn('refusing', r.stderr)

    def test_proceeds_when_no_initramfs_toolchain(self):
        # No update-initramfs in PATH (WSL / containers / non-initramfs
        # distros): the guard must not block even with nothing visible, and the
        # apt chain runs fully.
        self.stub('apt-get', 'echo "APT $*" >> "$CALLS"')
        r = self.run_sh(self.guard_cmd())
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
        # v6.4.0: sandboxed modules dir for the kernel-compare need signal —
        # seeded with the (stubbed) RUNNING kernel only, i.e. "no reboot
        # needed". The harness stubs `uname` to 0.0.0-rpfake.
        self.modules = self.dir / 'modules'
        (self.modules / '0.0.0-rpfake').mkdir(parents=True)

    def sched_cmd(self):
        cmd = api._SCHED_UPGRADE_REBOOT_CMD
        cmd = cmd.replace('/var/log/remotepower', str(self.log.parent))
        cmd = cmd.replace('/boot/initrd.img-', f'{self.boot}/initrd.img-')
        cmd = cmd.replace('/sbin/reboot', str(self.bin / 'reboot'))
        # v6.4.0: the reboot is CONDITIONAL now — redirect the need-check
        # paths into the sandbox so the host's real state can't leak in.
        cmd = cmd.replace('/var/run/reboot-required', str(self.dir / 'reboot-required'))
        cmd = cmd.replace('/lib/modules', str(self.modules))
        cmd = cmd.replace('/usr/lib/modules', str(self.dir / 'usr-lib-modules'))
        return cmd

    def need_reboot(self):
        """Arm the Debian/Ubuntu need signal in the sandbox."""
        (self.dir / 'reboot-required').write_text('')

    def log_text(self):
        return self.log.read_text() if self.log.exists() else ''


class TestSchedRebootGates(_SchedHarness):

    def test_clean_upgrade_healthy_initrd_reboots_when_required(self):
        # v6.4.0: "if required" is real now — this scenario arms the
        # Debian/Ubuntu marker, so the reboot must fire.
        self.stub('apt-get', 'echo "APT $*" >> "$CALLS"')
        (self.boot / 'initrd.img-0.0.0-rpfake').write_text('x')
        listing = self.dir / 'lsout'
        listing.write_text('usr/lib/modules/0.0.0-rpfake/kernel/md/dm-mod.ko.zst\n')
        self.stub('lsinitramfs', f'cat "{listing}"')
        self.need_reboot()
        r = self.run_sh(self.sched_cmd())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('SYSTEMCTL reboot', self.called())
        self.assertIn('rebooting', self.log_text())

    def test_clean_upgrade_without_need_signal_skips_reboot(self):
        # THE field-reported bug: a run that upgraded nothing still bounced
        # the host. No marker, no needs-restarting, running kernel == newest
        # installed → the host must stay up, exit 0.
        self.stub('apt-get', 'echo "APT $*" >> "$CALLS"')
        (self.boot / 'initrd.img-0.0.0-rpfake').write_text('x')
        listing = self.dir / 'lsout'
        listing.write_text('usr/lib/modules/0.0.0-rpfake/kernel/md/dm-mod.ko.zst\n')
        self.stub('lsinitramfs', f'cat "{listing}"')
        r = self.run_sh(self.sched_cmd())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn('SYSTEMCTL', self.called())
        self.assertNotIn('REBOOT', self.called())
        self.assertIn('no reboot required', self.log_text())

    def test_newer_installed_kernel_triggers_the_reboot(self):
        # Arch-style signal: no marker file, but the newest installed kernel
        # differs from the running one.
        self.stub('apt-get', 'echo "APT $*" >> "$CALLS"')
        (self.modules / '999.0.0-newer').mkdir()
        r = self.run_sh(self.sched_cmd())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('SYSTEMCTL reboot', self.called())

    def test_needs_restarting_verdict_triggers_the_reboot(self):
        # RHEL-style signal: needs-restarting -r exits nonzero when a reboot
        # is needed.
        self.stub('apt-get', 'echo "APT $*" >> "$CALLS"')
        self.stub('needs-restarting', 'exit 1')
        r = self.run_sh(self.sched_cmd())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('SYSTEMCTL reboot', self.called())

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
        # skip (not block every RHEL/Arch patch window forever). Need signal
        # armed so the v6.4.0 conditional gate lets it through.
        self.stub('apt-get', 'echo "APT $*" >> "$CALLS"')
        self.need_reboot()
        r = self.run_sh(self.sched_cmd())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('SYSTEMCTL reboot', self.called())


if __name__ == '__main__':
    unittest.main()
