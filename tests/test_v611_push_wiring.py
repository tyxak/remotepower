"""v6.1.1 (#1) -- server-side wiring for the opt-in agent push channel:
the heartbeat response only advertises `push_enabled` when the operator has
explicitly turned it on (Settings), and the config get/save round-trip
persists the flag. The daemon itself (server/push/remotepower-push.py) and
the agent-side listener are covered by tests/test_v611_push.py and manual
protocol review respectively -- this file is just the api.py glue that
opts a fleet in, following the exact same pattern already established for
secrets_scan_enabled/image_scan_enabled.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))


class TestHeartbeatAdvertisesPushEnabled(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault('REQUEST_METHOD', 'POST')
        os.environ.setdefault('PATH_INFO', '/api/heartbeat')
        os.environ.setdefault('CONTENT_LENGTH', '0')
        _s = importlib.util.spec_from_file_location("api_v611_push_wiring", _CGI_BIN / "api.py")
        cls.api = importlib.util.module_from_spec(_s)
        _s.loader.exec_module(cls.api)

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        api = self.api
        api.DATA_DIR = self._tmp
        api.DEVICES_FILE = self._tmp / 'devices.json'
        api.CMDS_FILE = self._tmp / 'cmds.json'
        api.CONFIG_FILE = self._tmp / 'config.json'
        api.TOKENS_FILE = self._tmp / 'tokens.json'
        api.save(api.CMDS_FILE, {})
        api.save(api.DEVICES_FILE, {'d1': {
            'id': 'd1', 'name': 'host1', 'token': 'tok',
            'poll_interval': 60,
        }})
        api._invalidate_load_cache(api.CONFIG_FILE)
        api._invalidate_load_cache(api.DEVICES_FILE)

    def _heartbeat(self):
        api = self.api
        cap = {}
        def fake_respond(status, body):
            cap['status'] = status
            cap['body'] = body
            raise SystemExit(0)
        api.respond = fake_respond
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'd1', 'token': 'tok', 'version': '6.1.1'}
        try:
            api.handle_heartbeat()
        except SystemExit:
            pass
        return cap.get('body') or {}

    def test_push_enabled_advertised_when_config_on(self):
        api = self.api
        api.save(api.CONFIG_FILE, {'push_enabled': True})
        api._invalidate_load_cache(api.CONFIG_FILE)
        body = self._heartbeat()
        self.assertTrue(body.get('push_enabled'))

    def test_push_enabled_absent_when_config_off(self):
        api = self.api
        api.save(api.CONFIG_FILE, {'push_enabled': False})
        api._invalidate_load_cache(api.CONFIG_FILE)
        body = self._heartbeat()
        self.assertNotIn('push_enabled', body)

    def test_push_enabled_absent_by_default(self):
        api = self.api
        api.save(api.CONFIG_FILE, {})
        api._invalidate_load_cache(api.CONFIG_FILE)
        body = self._heartbeat()
        self.assertNotIn('push_enabled', body)


class _ConfigHandlerBase(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        _spec = importlib.util.spec_from_file_location(
            "api_v611_push_cfg", _CGI_BIN / "api.py")
        self.api = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(self.api)
        api = self.api
        for attr in ('USERS_FILE', 'CONFIG_FILE'):
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self.cap = {}
        api.require_auth = lambda require_admin=False: 'jakob'
        api.require_admin_auth = lambda: 'jakob'
        api.verify_token = lambda t: ('jakob', 'admin')
        api.get_token_from_request = lambda: 't'
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None

        def _resp(s, b=None):
            self.cap['s'] = s
            self.cap['b'] = b
            raise api.HTTPError(s, b)
        api.respond = _resp

    def call(self, fn, *a):
        try:
            fn(*a)
        except self.api.HTTPError:
            pass
        return self.cap.get('b')


class TestPushEnabledConfigRoundTrip(_ConfigHandlerBase):
    def test_config_save_persists_flag(self):
        api = self.api
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'push_enabled': True}
        self.call(api.handle_config_save)
        self.assertTrue((api.load(api.CONFIG_FILE) or {}).get('push_enabled'))

    def test_config_save_can_turn_it_back_off(self):
        api = self.api
        api.save(api.CONFIG_FILE, {'push_enabled': True})
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'push_enabled': False}
        self.call(api.handle_config_save)
        self.assertFalse((api.load(api.CONFIG_FILE) or {}).get('push_enabled'))

    def test_config_get_defaults_to_false(self):
        api = self.api
        api.save(api.CONFIG_FILE, {})
        api.method = lambda: 'GET'
        out = self.call(api.handle_config_get)
        self.assertFalse(out.get('push_enabled'))


class TestPushChannelTestEndpoint(_ConfigHandlerBase):
    """POST /api/push-daemon/test -- a TCP-reachability smoke test against
    the companion daemon's bind port, surfaced as the "Test daemon
    connection" button next to the Settings toggle."""

    def test_route_registered(self):
        api = self.api
        routes = api._build_exact_routes()
        self.assertIn(('POST', '/api/push-daemon/test'), routes)
        self.assertIs(routes[('POST', '/api/push-daemon/test')], api.handle_push_channel_test)

    def test_reports_reachable_when_port_is_open(self):
        import socket as _socket
        srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        srv.bind(('127.0.0.1', 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        api = self.api
        api.method = lambda: 'POST'
        old_env = os.environ.get('RP_PUSH_PORT')
        os.environ['RP_PUSH_PORT'] = str(port)
        try:
            out = self.call(api.handle_push_channel_test)
        finally:
            srv.close()
            if old_env is None:
                os.environ.pop('RP_PUSH_PORT', None)
            else:
                os.environ['RP_PUSH_PORT'] = old_env
        self.assertTrue(out.get('ok'))
        self.assertTrue(out.get('reachable'))

    def test_reports_unreachable_when_port_is_closed(self):
        import socket as _socket
        # Find a free port and immediately release it -- nothing listens there.
        probe = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
        probe.close()
        api = self.api
        api.method = lambda: 'POST'
        old_env = os.environ.get('RP_PUSH_PORT')
        os.environ['RP_PUSH_PORT'] = str(port)
        try:
            out = self.call(api.handle_push_channel_test)
        finally:
            if old_env is None:
                os.environ.pop('RP_PUSH_PORT', None)
            else:
                os.environ['RP_PUSH_PORT'] = old_env
        self.assertTrue(out.get('ok'))
        self.assertFalse(out.get('reachable'))

    def test_requires_admin(self):
        api = self.api
        def _deny():
            raise api.HTTPError(403, {'error': 'forbidden'})
        api.require_admin_auth = _deny
        api.method = lambda: 'POST'
        try:
            api.handle_push_channel_test()
            self.fail('expected HTTPError')
        except api.HTTPError as e:
            self.assertEqual(e.status, 403)


class TestPushDaemonPackaging(unittest.TestCase):
    """v6.1.1 follow-up: a live deploy hit both of these -- the unit ran as
    root because User= was never set (the useradd/usermod dance in
    docs/push.md was pointless as shipped), and `cp` (docs/push.md) propagated
    the script's missing +x bit into a `status=203/EXEC` systemd failure.
    """

    def test_script_is_executable(self):
        script = _ROOT / "server" / "push" / "remotepower-push.py"
        self.assertTrue(os.access(script, os.X_OK),
                         f"{script} must be chmod +x -- `cp` (per docs/push.md) "
                         f"propagates this bit into the installed copy, and a "
                         f"non-executable copy fails systemd with status=203/EXEC")

    def test_unit_runs_as_dedicated_user_not_root(self):
        unit = (_ROOT / "packaging" / "remotepower-push.service").read_text()
        self.assertIn("User=rp-push", unit)

    def test_unit_does_not_reference_nonexistent_rp_www_group(self):
        # rp-www is never created by any installer in this repo (same mistake
        # already fixed once for webterm, see CHANGELOG v1.11.11) -- the real
        # group is auto-detected (www-data/nginx/http) from the data dir.
        unit = (_ROOT / "packaging" / "remotepower-push.service").read_text()
        self.assertNotIn("rp-www", unit)

    def test_doc_install_step_does_not_hardcode_rp_www_usermod(self):
        # The doc may still mention "rp-www" in prose explaining what NOT to
        # use -- just make sure the actual command it tells operators to run
        # doesn't hardcode that nonexistent group.
        doc = (_ROOT / "docs" / "push.md").read_text()
        self.assertNotIn("-G rp-www", doc)


class TestPushInstalledByDefault(unittest.TestCase):
    """v6.1.1: the push daemon + its nginx route are installed and started by
    default so the channel is a single Settings toggle. Guard every install
    surface so 'installed by default' can't silently regress."""

    def test_installer_service_unit_exists(self):
        self.assertTrue((_ROOT / "server" / "conf" / "remotepower-push.service").is_file())
        self.assertTrue((_ROOT / "server" / "conf" / "remotepower-ws-map.conf").is_file())

    def test_install_server_installs_and_enables_push(self):
        sh = (_ROOT / "install-server.sh").read_text()
        self.assertIn("WITH_PUSH", sh)
        self.assertIn("--no-push", sh)
        self.assertIn("/usr/local/bin/remotepower-push", sh)
        self.assertIn("enable --now remotepower-push", sh)
        self.assertIn("remotepower-ws-map.conf", sh)

    def test_nginx_locations_route_push_connect_to_daemon(self):
        loc = (_ROOT / "server" / "conf" / "remotepower-locations.conf").read_text()
        self.assertIn("location = /api/push/connect", loc)
        self.assertIn("127.0.0.1:8766", loc)
        self.assertIn("$connection_upgrade", loc)

    def test_docker_installs_and_starts_push(self):
        df = (_ROOT / "Dockerfile").read_text()
        self.assertIn("remotepower-push", df)
        self.assertIn("remotepower-ws-map.conf", df)
        ep = (_ROOT / "docker" / "entrypoint.sh").read_text()
        self.assertIn("remotepower-push", ep)
        dloc = (_ROOT / "docker" / "nginx-docker-locations.conf").read_text()
        self.assertIn("location = /api/push/connect", dloc)
        self.assertIn("127.0.0.1:8766", dloc)


if __name__ == "__main__":
    unittest.main()
