#!/usr/bin/env python3
"""Every installed unit that hardcodes `User=www-data` must be rendered per distro.

The shipped `.service` files carry the Debian web-user name. On RHEL the web
user is `nginx` and on Arch it is `http` — `www-data` does not exist there, so
systemd refuses the unit with `status=217/USER` and the service never starts.
install-server.sh was rewriting exactly one of the three units it installs
(the push daemon), which left `remotepower-wsgi` and `remotepower-scheduler` —
the app server and the maintenance scheduler, i.e. the product — dead on those
distros. The data directory is chowned to the distro user a few lines earlier,
so even hand-creating a `www-data` account would not have fixed it.

This is the same shape as the 2026-07-19 field outage where a packaging unit
template was copied over an installed, host-rendered one. Rendered-vs-shipped
is a distinction the installer has to keep, and a test is the only thing that
notices when a fourth unit is added and the render call is forgotten.

Source-level on purpose: running the installer needs root, systemd and a
package manager. What is being pinned is a pairing between two lines of shell,
which source inspection reads exactly.
"""
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_INSTALLER = _ROOT / 'install-server.sh'
_CONF = _ROOT / 'server' / 'conf'


@unittest.skipUnless(_INSTALLER.exists(), 'excluded from dist tree')
class TestUnitUserIsRenderedForEveryInstalledUnit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sh = _INSTALLER.read_text()

    def test_units_shipping_the_debian_user_are_known(self):
        """The precondition. If a unit stops hardcoding www-data (e.g. moves to
        DynamicUser), it drops out of the requirement below rather than being
        silently exempted."""
        hardcoded = sorted(p.name for p in _CONF.glob('*.service')
                           if re.search(r'^User=www-data$', p.read_text(), re.M))
        self.assertEqual(
            hardcoded,
            ['remotepower-push.service', 'remotepower-scheduler.service',
             'remotepower-wsgi.service'],
            'the set of units carrying User=www-data changed — add or remove '
            'the render_unit_user call in install-server.sh to match')

    def test_the_installer_renders_each_one_it_installs(self):
        missing = []
        for unit in sorted(_CONF.glob('*.service')):
            name = unit.name
            if not re.search(r'^User=www-data$', unit.read_text(), re.M):
                continue
            # only units this installer actually deploys
            if f'/etc/systemd/system/{name}' not in self.sh:
                continue
            if not re.search(r'render_unit_user\s+/etc/systemd/system/%s\b'
                             % re.escape(name), self.sh):
                missing.append(name)
        self.assertEqual(missing, [], '\n'.join([
            'install-server.sh installs these units without rendering the '
            'distro web user into them:', *missing, '',
            'On RHEL/Arch the unit fails with status=217/USER because '
            'www-data does not exist. Add: '
            'render_unit_user /etc/systemd/system/<unit>']))

    def test_the_helper_is_defined_before_its_first_use(self):
        i_def = self.sh.index('render_unit_user() {')
        i_use = self.sh.index('render_unit_user /etc/systemd/system/')
        self.assertLess(i_def, i_use,
                        'render_unit_user is called before it is defined — '
                        'bash would abort the install with "command not found"')

    def test_the_helper_rewrites_both_user_and_group(self):
        blk = self.sh[self.sh.index('render_unit_user() {'):]
        blk = blk[:blk.index('\n}\n') + 3]
        self.assertIn('s/^User=www-data/User=${NGINX_USER}/', blk)
        self.assertIn('s/^Group=www-data/Group=${NGINX_USER}/', blk,
                      'rewriting User but not Group leaves the unit running '
                      'with a group that cannot read the data dir')
        self.assertIn('[[ "$NGINX_USER" == "www-data" ]] && return 0', blk,
                      'the Debian no-op path must stay explicit — a blind sed '
                      'on Debian is harmless but the intent should be readable')


if __name__ == '__main__':
    unittest.main()
