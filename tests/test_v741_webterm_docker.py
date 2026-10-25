#!/usr/bin/env python3
"""v7.4.1, issue #36: the web terminal and the file manager in the Docker image.

The Files page said "WebSocket error" on a Docker install. The browser terminal
and the SFTP file manager are one daemon, remotepower-webterm, and the image
neither shipped it, started it, nor routed /api/webterm/connect to it
(install-webterm.sh is for bare-metal installs). It is opt-in now,
RP_WITH_WEBTERM=1, like the SSH gateway.

Four layers:
  * a census of the sidecar daemons the image carries (push, SSH gateway, web
    terminal): shipped, started and routed. The web terminal was 0 of 3;
  * the secret handoff, run for real: the entrypoint's block, and the app's
    check with the environment fallback;
  * the whole path, run for real: a WebSocket through a real nginx on the
    SHIPPED snippet to the real daemon, which consumes a ticket, speaks SSH to an
    asyncssh server and reports the audit with the shared secret;
  * the control for the last one: the same session through the snippet without
    the route fails, which is what the reporter saw.

The last two need asyncssh and websockets (which CI does not install, so they
skip there, like the other web terminal tests) and an nginx binary.
"""
import asyncio
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nginx_rig  # noqa: E402

try:
    import asyncssh
    import websockets
    _HAVE_LIBS = True
except Exception:                                       # pragma: no cover - env dependent
    _HAVE_LIBS = False

ROOT = nginx_rig.ROOT
DOCKERFILE = (ROOT / "Dockerfile").read_text()
ENTRYPOINT = (ROOT / "docker/entrypoint.sh").read_text()
SNIPPET = (ROOT / "docker/nginx-docker-locations.conf").read_text()
COMPOSE = (ROOT / "docker-compose.yml").read_text()
DAEMON = ROOT / "server" / "webterm" / "remotepower-webterm.py"


class TestEverySidecarTheImageCarriesIsShippedStartedAndRouted(unittest.TestCase):
    """push, the SSH gateway and the web terminal: one rule, three daemons."""

    SIDECARS = {
        # name: (daemon file in the image, route in the nginx snippet, upstream port)
        "push": ("remotepower-push", "/api/push/connect", "8766"),
        "sshgw": ("remotepower-sshgw", "/api/sshgw/tunnel", "8767"),
        "webterm": ("remotepower-webterm", "/api/webterm/connect", "8765"),
    }

    def status(self, name):
        daemon, route, port = self.SIDECARS[name]
        route_block = re.search(r"location = %s \{(.*?)\n\}" % re.escape(route), SNIPPET, re.S)
        return {
            "copied": f"/usr/local/bin/{daemon}" in DOCKERFILE and
                      re.search(rf"COPY server/\w+/{daemon}\.py /usr/local/bin/{daemon}", DOCKERFILE) is not None,
            "executable": DOCKERFILE.count(f"/usr/local/bin/{daemon} ") +
                          DOCKERFILE.count(f"/usr/local/bin/{daemon}\\") >= 1,
            "started": f"python3 /usr/local/bin/{daemon}" in ENTRYPOINT,
            "routed": bool(route_block and f"proxy_pass http://127.0.0.1:{port};" in route_block.group(1)
                           and "proxy_set_header Upgrade $http_upgrade;" in route_block.group(1)),
        }

    def test_each_daemon_is_complete(self):
        got = {n: self.status(n) for n in self.SIDECARS}
        incomplete = {n: [k for k, ok in s.items() if not ok] for n, s in got.items()
                      if not all(s.values())}
        done = len(got) - len(incomplete)
        self.assertEqual(incomplete, {}, f"{done} of {len(got)} sidecars are complete in the image: "
                                         f"missing {incomplete}")

    def test_the_web_terminals_libraries_are_installed(self):
        pip = re.search(r"pip install --no-cache-dir ([^\n]+?)(?: && | \\\n)", DOCKERFILE)
        self.assertTrue(pip)
        self.assertIn("websockets", pip.group(1))
        self.assertIn("asyncssh>=2.14.2", pip.group(1))


class TestTheStartupOrderAndTheSwitch(unittest.TestCase):

    def test_it_is_off_unless_asked_for(self):
        self.assertIn('if [ "${RP_WITH_WEBTERM:-0}" = "1" ] || [ "${RP_WITH_WEBTERM:-0}" = "true" ]; then', ENTRYPOINT)
        start = ENTRYPOINT.index('if [ "$WEBTERM_ON" = "1" ]; then')
        self.assertIn("remotepower-webterm", ENTRYPOINT[start:start + 900])
        self.assertEqual(ENTRYPOINT.count("python3 /usr/local/bin/remotepower-webterm"), 1)
        self.assertRegex(COMPOSE, r'#\s*RP_WITH_WEBTERM: "1"')

    def test_the_secret_is_exported_before_the_app_server_starts(self):
        """The app reads RP_WEBTERM_SECRET from its environment, and gunicorn
        takes its environment when it starts."""
        self.assertLess(ENTRYPOINT.index("export RP_WEBTERM_SECRET"),
                        ENTRYPOINT.index("gunicorn --workers"))

    def test_the_audit_goes_to_the_app_not_through_the_redirecting_http_server(self):
        self.assertIn("--api-base http://127.0.0.1:8090/api", ENTRYPOINT)
        self.assertNotIn("--api-base http://127.0.0.1:8080", ENTRYPOINT)

    def test_it_listens_on_loopback_only(self):
        self.assertIn("--host 127.0.0.1 --port 8765", ENTRYPOINT)


def _entrypoint_block():
    i = ENTRYPOINT.index("WEBTERM_ON=0\n")
    j = ENTRYPOINT.index("# ── Persistent gunicorn/Flask app tier")
    return ENTRYPOINT[i:j]


class TestTheSecretHandoff(unittest.TestCase):

    def run_block(self, env, data_dir, show=""):
        script = f'DATA_DIR="{data_dir}"\n{_entrypoint_block()}\n{show}'
        e = {"PATH": os.environ["PATH"], **env}
        return subprocess.run(["bash", "-c", script], env=e, capture_output=True, text=True)

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="rp-v741-wt-"))
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def test_off_by_default_nothing_is_created(self):
        r = self.run_block({}, self.d, 'echo "ON=$WEBTERM_ON SECRET=${RP_WEBTERM_SECRET:-}"')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ON=0 SECRET=", r.stdout)
        self.assertFalse((self.d / "webterm").exists())

    def test_on_creates_a_private_secret_once_and_exports_it(self):
        show = 'echo "ON=$WEBTERM_ON SECRET=$RP_WEBTERM_SECRET"'
        r = self.run_block({"RP_WITH_WEBTERM": "1"}, self.d, show)
        self.assertEqual(r.returncode, 0, r.stderr)
        m = re.search(r"ON=1 SECRET=([0-9a-f]{64})", r.stdout)
        self.assertTrue(m, r.stdout)
        f = self.d / "webterm" / "secret"
        self.assertEqual(f.read_text().strip(), m.group(1))
        self.assertEqual(f.stat().st_mode & 0o777, 0o600, "the secret must not be readable by others")
        self.assertEqual((self.d / "webterm").stat().st_mode & 0o777, 0o700)
        again = self.run_block({"RP_WITH_WEBTERM": "true"}, self.d, show)
        self.assertIn("SECRET=" + m.group(1), again.stdout, "the secret changed across a restart")

    def test_a_secret_from_the_environment_wins_and_is_written_for_the_daemon(self):
        r = self.run_block({"RP_WITH_WEBTERM": "1", "RP_WEBTERM_SECRET": "chosen-by-the-operator"}, self.d,
                           'echo "SECRET=$RP_WEBTERM_SECRET"')
        self.assertIn("SECRET=chosen-by-the-operator", r.stdout)
        self.assertEqual((self.d / "webterm" / "secret").read_text(), "chosen-by-the-operator")


class TestTheAppAcceptsTheSecretFromTheEnvironment(unittest.TestCase):
    """The daemon sends X-Webterm-Secret on its audit and host-key calls. On a bare-metal
    install the app compares it with config.json; in the image it has RP_WEBTERM_SECRET."""

    @classmethod
    def setUpClass(cls):
        os.environ["RP_DATA_DIR"] = tempfile.mkdtemp(prefix="rp-v741-wtapp-")
        sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
        spec = importlib.util.spec_from_file_location("api_v741_wt", ROOT / "server/cgi-bin/api.py")
        cls.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.api)

    def call(self, fn, header, cfg_secret="", env_secret=None, query=""):
        api = self.api
        cap = {}

        def respond(status, data=None):
            cap["s"], cap["d"] = status, data
            raise api.HTTPError(status, data)
        api.respond = respond
        api.audit_log = lambda *a, **k: None
        api._config_ro = lambda: {"webterm_daemon_secret": cfg_secret} if cfg_secret else {}
        api.method = lambda: "GET" if fn.__name__ == "handle_webterm_hostkeys" else "POST"
        api.get_json_obj = lambda: {"actor": "a", "device_id": "dev1", "reason": "x"}
        real_env = api._env
        api._env = lambda k, d="": header if k == "HTTP_X_WEBTERM_SECRET" else (query if k == "QUERY_STRING" else d)
        old = os.environ.pop("RP_WEBTERM_SECRET", None)
        if env_secret is not None:
            os.environ["RP_WEBTERM_SECRET"] = env_secret
        try:
            fn()
        except api.HTTPError:
            pass
        finally:
            api._env = real_env
            os.environ.pop("RP_WEBTERM_SECRET", None)
            if old is not None:
                os.environ["RP_WEBTERM_SECRET"] = old
        return cap.get("s")

    def both(self, *a, **k):
        hk = self.call(self.api.handle_webterm_hostkeys, *a, query="device_id=dev1", **k)
        au = self.call(self.api.handle_webterm_session_audit, *a, **k)
        return hk, au

    def test_the_environment_secret_is_accepted(self):
        self.assertEqual(self.both("s3cret", env_secret="s3cret"), (200, 200))

    def test_the_config_secret_still_is(self):
        self.assertEqual(self.both("s3cret", cfg_secret="s3cret"), (200, 200))

    def test_a_wrong_secret_is_refused_by_both(self):
        self.assertEqual(self.both("nope", env_secret="s3cret"), (403, 403))
        self.assertEqual(self.both("nope", cfg_secret="s3cret"), (403, 403))

    def test_no_secret_configured_anywhere_refuses_even_an_empty_header(self):
        """The trap: an empty expected value must never match an empty header."""
        self.assertEqual(self.both("", env_secret=None), (403, 403))
        self.assertEqual(self.both("anything"), (403, 403))

    def test_one_helper_serves_both_handlers(self):
        src = (ROOT / "server/cgi-bin/webterm_handlers.py").read_text()
        self.assertEqual(src.count("hmac.compare_digest"), 1, "the secret check is copied again")
        self.assertEqual(src.count("if not _daemon_secret_ok():"), 2)


class _Api:
    """Stands in for the app: records what the daemon sends it."""

    def __init__(self, secret):
        self.secret = secret
        self.audits = []
        self.keylookups = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def _reply(self, obj, status=200):
                body = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                ok = self.headers.get("X-Webterm-Secret") == outer.secret
                outer.keylookups.append((self.path, ok))
                self._reply({"fingerprints": [], "known": False} if ok else {"error": "no"}, 200 if ok else 403)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                ok = self.headers.get("X-Webterm-Secret") == outer.secret
                outer.audits.append((self.path, ok, body))
                self._reply({"ok": True} if ok else {"error": "no"}, 200 if ok else 403)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@unittest.skipUnless(_HAVE_LIBS and nginx_rig.available(),
                     "needs asyncssh, websockets and an nginx binary (see nginx_rig.py)")
class TestTheWholePath(unittest.IsolatedAsyncioTestCase):
    """browser (a WebSocket client) -> the shipped nginx snippet -> the real daemon
    -> an SSH server. Nothing in between is mocked."""

    SECRET = "0123456789abcdef" * 4

    async def asyncSetUp(self):
        # Starting nginx and the daemon blocks the loop for a moment; debug mode
        # would report each as a slow callback.
        asyncio.get_running_loop().slow_callback_duration = 30
        self.tmp = Path(tempfile.mkdtemp(prefix="rp-v741-wtfull-"))
        self.addAsyncCleanup(asyncio.to_thread, shutil.rmtree, self.tmp, True)
        (self.tmp / "secret").write_text(self.SECRET)
        self.api = _Api(self.SECRET)
        self.addCleanup(self.api.close)

        async def sshd_session(process):
            process.stdout.write("hello-from-sshd\r\n")
            await process.stdout.drain()
            process.exit(0)

        class _Ssh(asyncssh.SSHServer):
            def begin_auth(self, username):
                return True

            def password_auth_supported(self):
                return True

            def validate_password(self, username, password):
                return password == "pw"

        self.ssh = await asyncssh.create_server(
            _Ssh, "127.0.0.1", 0, server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")],
            process_factory=sshd_session)
        self.addAsyncCleanup(self.ssh.wait_closed)
        self.addCleanup(self.ssh.close)
        self.ssh_port = next(iter(self.ssh.sockets)).getsockname()[1]

        self.daemon_port = nginx_rig.free_port()
        env = dict(os.environ, RP_CGI_BIN=str(ROOT / "server" / "cgi-bin"))
        self.daemon = subprocess.Popen(
            [sys.executable, str(DAEMON), "--host", "127.0.0.1", "--port", str(self.daemon_port),
             "--data-dir", str(self.tmp), "--api-base", f"http://127.0.0.1:{self.api.port}/api",
             "--secret-file", str(self.tmp / "secret"), "--verbose"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.addCleanup(lambda: (self.daemon.terminate(), self.daemon.wait(10)))
        for _ in range(100):
            try:
                (await asyncio.open_connection("127.0.0.1", self.daemon_port))[1].close()
                break
            except OSError:
                await asyncio.sleep(0.1)
        else:
            self.fail("the daemon did not start:\n" + self.daemon.stderr.read().decode(errors="replace")[-800:])

    def rig(self, snippet=None):
        r = nginx_rig.NginxRig({"127.0.0.1:8765": f"127.0.0.1:{self.daemon_port}",
                                "127.0.0.1:8090": f"127.0.0.1:{self.api.port}"}, locations_text=snippet)
        self.addCleanup(r.stop)
        return r

    def ticket(self, name="tkt"):
        now = int(time.time())
        f = self.tmp / "webterm_tickets.json"
        data = json.loads(f.read_text()) if f.exists() else {}
        data[name] = {"actor": "alice", "device_id": "dev1", "created": now, "expires": now + 60, "used": False}
        f.write_text(json.dumps(data))
        return name

    async def session(self, rig, ticket):
        """Open the terminal as the dashboard does and return everything it received."""
        uri = f"ws://127.0.0.1:{rig.port}/api/webterm/connect?ticket={ticket}"
        got = []
        async with websockets.connect(uri) as ws:
            await ws.send(json.dumps({"host": "127.0.0.1", "user": "op", "password": "pw",
                                      "port": self.ssh_port, "cols": 80, "rows": 24}))
            try:
                while "hello-from-sshd" not in "".join(got):
                    got.append(await asyncio.wait_for(ws.recv(), 20))
            except (asyncio.TimeoutError, websockets.ConnectionClosed):
                pass
        return got

    async def test_a_terminal_session_goes_through_nginx_to_ssh_and_is_audited(self):
        rig = self.rig()
        got = await self.session(rig, self.ticket())
        text = "".join(got)
        self.assertIn('"type": "connected"', text)
        self.assertIn("hello-from-sshd", text, "the SSH server's output never reached the browser: " + repr(got))
        for _ in range(60):                                  # the audit follows the close
            if self.api.audits:
                break
            await asyncio.sleep(0.25)
        self.assertTrue(self.api.audits, "the daemon never reported the session")
        path, ok, body = self.api.audits[-1]
        self.assertEqual(path, "/api/webterm/audit")
        self.assertTrue(ok, "the audit POST did not carry the shared secret")
        self.assertEqual((body["actor"], body["device_id"], body["ssh_user"]), ("alice", "dev1", "op"))
        self.assertTrue(any(ok for _p, ok in self.api.keylookups), "the host-key lookup never carried the secret")

    async def test_a_ticket_opens_one_session(self):
        rig = self.rig()
        t = self.ticket()
        first = "".join(await self.session(rig, t))
        self.assertIn("hello-from-sshd", first)
        second = "".join(await self.session(rig, t))
        self.assertIn("Invalid or expired ticket", second)
        self.assertNotIn("hello-from-sshd", second)

    async def test_control_without_the_route_the_handshake_fails(self):
        """The reporter's state: the image had no /api/webterm/connect route, so the
        WebSocket was sent to the app, which is not a WebSocket server."""
        no_route = re.sub(r"location = /api/webterm/connect \{.*?\n\}\n", "", SNIPPET, flags=re.S)
        self.assertNotIn("/api/webterm/connect", no_route)
        rig = self.rig(no_route)
        with self.assertRaises(Exception) as cm:
            await self.session(rig, self.ticket())
        self.assertIn(type(cm.exception).__name__, ("InvalidStatusCode", "InvalidStatus", "InvalidHandshake",
                                                      "InvalidMessage", "ConnectionClosedError"))


if __name__ == "__main__":
    unittest.main()
