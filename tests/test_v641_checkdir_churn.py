"""v6.4.1: the dir_baseline check ignores Snap's revisioned mount units.

Snap encodes the package revision in the unit filename, so every `snap refresh`
removes `snap-snapd-26865.mount` and adds `snap-snapd-27591.mount` — plus the
enable-symlinks under `multi-user.target.wants/` and
`snapd.mounts.target.wants/`. A `dir_baseline` watch on `/etc/systemd/system`
therefore raised a critical added/removed diff every few days on any Ubuntu
host, for a package manager doing exactly its job. Alert noise that regular
teaches operators to ignore the check.

The security-relevant half of this is the SECOND class of test below: an
exclusion list is a hole by construction, so what matters is that it stays
narrow. A unit dropped by an attacker still has to be named something, and
anything outside these patterns is still compared byte-for-byte.
"""
import fnmatch
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'client'))

AGENT = (ROOT / 'client' / 'remotepower-agent.py').read_text()


def _churn_patterns():
    """The literal tuple out of the agent source (the agent is not importable
    as a module — it runs as a script)."""
    ns = {}
    start = AGENT.index('_CHECKDIR_CHURN = (')
    end = AGENT.index(')', start) + 1
    exec(AGENT[start:end], ns)
    return ns['_CHECKDIR_CHURN']


def _excluded(filename):
    return any(fnmatch.fnmatch(filename, p) for p in _churn_patterns())


class TestSnapChurnIsExcluded(unittest.TestCase):
    def test_revisioned_snap_units(self):
        for fn in ('snap-snapd-26865.mount',
                   'snap-snapd-27591.mount',
                   'snap-core22-1908.mount',
                   'snap-firefox-4173.mount',
                   'snap.certbot.renew.service'):
            self.assertTrue(_excluded(fn), fn)


class TestRealUnitsAreStillWatched(unittest.TestCase):
    """The half that matters. If any of these ever start matching, the
    exclusion has widened into a blind spot."""

    def test_ordinary_units(self):
        for fn in ('sshd.service', 'remotepower-agent.service', 'nginx.service',
                   'snapd.service', 'snapd.socket', 'snapd.seeded.service',
                   'cron.service', 'var-lib-docker.mount', 'home.mount',
                   'backdoor.service', 'evil.mount', 'snapshot.service'):
            self.assertFalse(_excluded(fn), fn)

    def test_a_unit_merely_mentioning_snap_is_not_excluded(self):
        # The patterns are anchored on the `snap-` / `snap.` prefixes; a name
        # that only contains "snap" must not slip through.
        for fn in ('my-snap-thing.service', 'unsnap.mount', 'usr-snap.mount'):
            self.assertFalse(_excluded(fn), fn)

    def test_exclusion_list_stays_small(self):
        # A growing list is how an exclusion becomes a blind spot. If this
        # needs raising, justify each new pattern against the tests above.
        self.assertLessEqual(len(_churn_patterns()), 4)


class TestFilterIsWiredIntoTheWalk(unittest.TestCase):
    def test_applied_in_the_dir_integrity_walk(self):
        self.assertIn('_CHECKDIR_CHURN', AGENT)
        use = AGENT.index('fnmatch.fnmatch(fn, p) for p in _CHECKDIR_CHURN')
        # It must sit inside the dir_baseline check, not somewhere it never runs.
        start = AGENT.index("if ctype == 'dir_baseline':")
        self.assertLess(start, use)
        self.assertLess(use, AGENT.index('def ', start + 100))

    def test_extensionless_copy_is_in_sync(self):
        self.assertEqual(AGENT, (ROOT / 'client' / 'remotepower-agent').read_text())


if __name__ == '__main__':
    unittest.main()
