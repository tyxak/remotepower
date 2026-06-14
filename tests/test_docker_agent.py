#!/usr/bin/env python3
"""Tests for the containerized agent (v4.7.0): HOST_ROOT path indirection,
host-DB package parsing, container-mode scanner gating + self-update disable,
and the Docker artifacts / UI wiring that make binding a host trivial."""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_AGENT_PY = _ROOT / 'client' / 'remotepower-agent.py'


def load_agent(host_root=None, container=None):
    """Load a FRESH agent module instance with HOST_ROOT/RP_CONTAINER set, since
    those are read at import time. Restores the environment afterwards."""
    saved = {k: os.environ.get(k) for k in ('HOST_ROOT', 'RP_CONTAINER')}
    # psutil is a process-global singleton; loading the agent with HOST_ROOT set
    # mutates psutil.PROCFS_PATH. Snapshot + restore it so a container-mode load
    # here can never leak a stale procfs root into another test.
    try:
        import psutil as _ps
        _saved_procfs = getattr(_ps, 'PROCFS_PATH', '/proc')
    except Exception:
        _ps = None
        _saved_procfs = None
    try:
        os.environ.pop('HOST_ROOT', None)
        os.environ.pop('RP_CONTAINER', None)
        if host_root is not None:
            os.environ['HOST_ROOT'] = host_root
        if container is not None:
            os.environ['RP_CONTAINER'] = container
        spec = importlib.util.spec_from_file_location('rpa_test', _AGENT_PY)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        if _ps is not None and _saved_procfs is not None:
            _ps.PROCFS_PATH = _saved_procfs


class TestHostPathNative(unittest.TestCase):
    """Native (no HOST_ROOT): everything is the identity — zero behaviour change."""

    def setUp(self):
        self.m = load_agent()

    def test_flags_off(self):
        self.assertEqual(self.m.HOST_ROOT, '')
        self.assertFalse(self.m.IN_CONTAINER)

    def test_host_path_identity(self):
        self.assertEqual(self.m.host_path('/etc/os-release'), '/etc/os-release')
        self.assertEqual(self.m.host_path(Path('/proc/uptime')), Path('/proc/uptime'))
        self.assertEqual(self.m.unhost_path('/etc/x'), '/etc/x')

    def test_rp_container_forces_mode_without_hostroot(self):
        m = load_agent(container='1')
        self.assertTrue(m.IN_CONTAINER)
        self.assertEqual(m.HOST_ROOT, '')   # still identity for paths


class TestHostPathContainer(unittest.TestCase):
    """Containerized (HOST_ROOT set): host-fact paths are remapped, cleanly."""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.m = load_agent(host_root=self.root)

    def test_flags_on(self):
        self.assertEqual(self.m.HOST_ROOT, self.root)
        self.assertTrue(self.m.IN_CONTAINER)

    def test_host_path_prefixes_absolute(self):
        self.assertEqual(self.m.host_path('/etc/os-release'), self.root + '/etc/os-release')

    def test_host_path_no_double_prefix(self):
        once = self.m.host_path('/etc/x')
        self.assertEqual(self.m.host_path(once), once)

    def test_host_path_leaves_relative(self):
        self.assertEqual(self.m.host_path('etc/x'), 'etc/x')

    def test_unhost_path_strips(self):
        self.assertEqual(self.m.unhost_path(self.root + '/etc/netplan/x.yaml'), '/etc/netplan/x.yaml')

    def test_preserves_path_type(self):
        self.assertIsInstance(self.m.host_path(Path('/etc/x')), Path)
        self.assertIsInstance(self.m.host_path('/etc/x'), str)

    def test_safe_read_reads_host(self):
        os.makedirs(self.root + '/etc', exist_ok=True)
        Path(self.root + '/etc/os-release').write_text('PRETTY_NAME="FakeHost 9000"\n')
        self.assertIn('FakeHost 9000', self.m._safe_read('/etc/os-release'))
        self.m._os_info_cache = None
        self.assertIn('FakeHost 9000', self.m.get_os_info())


class TestHostPackageDB(unittest.TestCase):
    """Container mode parses the HOST's package DB directly (no image binary)."""

    def test_dpkg_status_parsing(self):
        root = tempfile.mkdtemp()
        os.makedirs(root + '/var/lib/dpkg')
        Path(root + '/var/lib/dpkg/status').write_text(
            'Package: bash\nStatus: install ok installed\nVersion: 5.2-1\nArchitecture: amd64\n\n'
            'Package: gone\nStatus: deinstall ok config-files\nVersion: 1.0\nArchitecture: amd64\n\n'
            'Package: openssl\nStatus: install ok installed\nVersion: 3.0.11-1\nArchitecture: amd64\n'
        )
        m = load_agent(host_root=root)
        mgr, pkgs = m.get_package_list()
        names = {p['name']: p['version'] for p in pkgs}
        self.assertEqual(mgr, 'apt')
        self.assertEqual(names, {'bash': '5.2-1', 'openssl': '3.0.11-1'})  # deinstalled excluded

    def test_pacman_db_parsing(self):
        root = tempfile.mkdtemp()
        d = root + '/var/lib/pacman/local/bash-5.2-1'
        os.makedirs(d)
        Path(d + '/desc').write_text('%NAME%\nbash\n\n%VERSION%\n5.2-1\n\n%ARCH%\nx86_64\n')
        m = load_agent(host_root=root)
        mgr, pkgs = m.get_package_list()
        self.assertEqual(mgr, 'pacman')
        self.assertEqual(pkgs[0]['name'], 'bash')
        self.assertEqual(pkgs[0]['version'], '5.2-1')

    def test_patch_info_never_false_zero(self):
        # A host with no apt-get available in the image must not report a false 0.
        root = tempfile.mkdtemp()
        os.makedirs(root + '/var/lib/pacman/local')   # pacman host
        m = load_agent(host_root=root)
        info = m.get_patch_info()
        self.assertEqual(info['manager'], 'pacman')
        self.assertIsNone(info['upgradable'])         # unknown, not a false 0


class TestContainerModeGating(unittest.TestCase):
    """Scanners that would only see the container refuse honestly; self-update off."""

    def test_lynis_skipped_in_container(self):
        m = load_agent(host_root=tempfile.mkdtemp())
        r = m.run_host_scan({'id': 's1', 'tool': 'lynis'})
        self.assertEqual(r['status'], 'skipped')
        self.assertIn('containerized', r['error'])

    def test_lynis_not_skipped_natively(self):
        m = load_agent()
        r = m.run_host_scan({'id': 's1', 'tool': 'lynis'})
        self.assertNotEqual(r['status'], 'skipped')   # runs or "not installed"

    def test_self_update_disabled_in_container(self):
        m = load_agent(host_root=tempfile.mkdtemp())
        # Should short-circuit to False without any network call.
        self.assertFalse(m.check_for_update('https://unused.example', force=True))


class TestDockerArtifacts(unittest.TestCase):
    """The image, entrypoint, compose and ghcr workflow exist and are wired."""

    def test_dockerfile_agent_exists_and_targets_agent(self):
        df = (_ROOT / 'Dockerfile.agent').read_text()
        self.assertIn('remotepower-agent', df)
        self.assertIn('HOST_ROOT=/host', df)
        self.assertIn('agent-entrypoint.sh', df)

    def test_entrypoint_enrolls_from_env(self):
        ep = (_ROOT / 'docker' / 'agent-entrypoint.sh').read_text()
        self.assertIn('RP_SERVER', ep)
        self.assertIn('RP_ENROLL_TOKEN', ep)
        self.assertIn('enroll-token', ep)
        self.assertIn('RP_CA_FINGERPRINT', ep)        # fingerprint pinning path

    def test_compose_standard_caps_no_privileged(self):
        c = (_ROOT / 'docker' / 'docker-compose.agent.yml').read_text()
        self.assertIn('remotepower-agent', c)
        self.assertIn('pid: host', c)
        self.assertIn('network_mode: host', c)
        self.assertIn('rp-agent-creds:/etc/remotepower', c)
        # default profile must NOT be privileged (the active, non-comment lines)
        active = '\n'.join(l for l in c.splitlines() if not l.lstrip().startswith('#'))
        self.assertNotIn('privileged: true', active)

    def test_release_workflow_publishes_agent_image(self):
        wf = (_ROOT / '.github' / 'workflows' / 'release.yml').read_text()
        self.assertIn('docker-agent', wf)
        self.assertIn('Dockerfile.agent', wf)
        self.assertIn('repository }}-agent', wf)


class TestEnrollUI(unittest.TestCase):
    """The one-click Docker enrollment snippet in the Enroll modal is wired + CSP-safe."""

    def setUp(self):
        self.html = (_ROOT / 'server/html/index.html').read_text()
        self.js = (_ROOT / 'server/html/static/js/app.js').read_text()

    def test_modal_has_docker_section(self):
        self.assertIn('id="enroll-docker-result"', self.html)
        self.assertIn('data-action="generateDockerEnroll"', self.html)

    def test_js_functions_present(self):
        self.assertIn('function generateDockerEnroll(', self.js)
        self.assertIn('function copyDockerEnroll(', self.js)
        self.assertIn("'/enrollment-tokens'", self.js)
        self.assertIn('ghcr.io/tyxak/remotepower-agent', self.js)

    def test_snippet_built_without_innerhtml_interpolation(self):
        # The token must be set via textContent/dataset, never interpolated into
        # an innerHTML string — assert the function uses createElement + textContent.
        i = self.js.index('async function generateDockerEnroll(')
        body = self.js[i:i + 2600]
        self.assertIn('createElement', body)
        self.assertIn('textContent', body)
        self.assertNotIn('.innerHTML', body)


if __name__ == '__main__':
    unittest.main()
