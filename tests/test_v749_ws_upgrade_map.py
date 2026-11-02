#!/usr/bin/env python3
"""Only a WebSocket handshake asks a backend to switch protocols (7.4.9).

The nginx map that fills the `Connection:` header of the push, SSH-gateway and web-terminal proxies said `default upgrade;`, so
whatever a client put in its `Upgrade:` header (h2c, for one) reached the backend together with `Connection: upgrade`. All three
backends are WebSocket-only daemons, so there was nothing to smuggle to, which is why this is hardening and not a finding. The
map now upgrades for `websocket` (any case) and says `close` for everything else.

The behaviour is measured through a real nginx running the shipped location snippets (tests/nginx_rig.py; set RP_NGINX_BIN or put
nginx on PATH, RP_NGINX_REQUIRE=1 turns a missing binary into a failure). The text checks run everywhere.
"""
import http.client
import json
import re
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nginx_rig  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
MAP = _ROOT / "server" / "conf" / "remotepower-ws-map.conf"
SNIPPETS = {
    "docker": _ROOT / "docker" / "nginx-docker-locations.conf",
    "bare metal": _ROOT / "server" / "conf" / "remotepower-locations.conf",
}
# Every place the map is written out for a person or a script to copy.
COPIES = [
    _ROOT / "server" / "conf" / "remotepower-ws-map.conf",
    _ROOT / "packaging" / "install-webterm.sh",
    _ROOT / "packaging" / "nginx-webterm.conf",
]
OLD_FORM = re.compile(r"default\s+upgrade\s*;")


def ws_locations(snippet_text):
    """[(path, upstream address)] for every exact-match location that proxies the Upgrade header."""
    out = []
    for m in re.finditer(r"location = (\S+) \{(.*?)\n\}", snippet_text, re.S):
        body = m.group(2)
        up = re.search(r"proxy_pass http://(127\.0\.0\.1:\d+)", body)
        if "$connection_upgrade" in body and up:
            out.append((m.group(1), up.group(1)))
    return out


class TestTheMapText(unittest.TestCase):

    def test_the_shared_map_upgrades_only_for_websocket(self):
        text = MAP.read_text()
        self.assertRegex(text, r"default\s+close\s*;")
        self.assertRegex(text, r'"~\*\^websocket\$"\s+upgrade\s*;')
        self.assertIsNone(OLD_FORM.search(re.sub(r"(?m)^\s*#.*$", "", text)), "the old form is still in the map")

    def test_no_copy_of_the_map_says_default_upgrade(self):
        for f in COPIES:
            with self.subTest(file=f.name):
                code = re.sub(r"(?m)^\s*#.*$", "", f.read_text())
                # a printed copy sits inside a heredoc, not in a comment: look at the whole text, minus pure comment lines
                self.assertIsNone(OLD_FORM.search(code), f"{f.name} still says `default upgrade;`")

    def test_the_control_sees_the_old_form(self):
        old = "map $http_upgrade $connection_upgrade {\n    default upgrade;\n    ''      close;\n}\n"
        self.assertIsNotNone(OLD_FORM.search(old))

    def test_the_installers_replace_our_own_older_file(self):
        for name in ("install-server.sh", "deploy-server.sh"):
            with self.subTest(script=name):
                text = (_ROOT / name).read_text()
                self.assertIn("-f /etc/nginx/conf.d/remotepower-ws-map.conf", text,
                              f"{name} would leave an older copy of the map in place")

    def test_every_snippet_has_websocket_locations(self):
        for label, path in SNIPPETS.items():
            with self.subTest(snippet=label):
                locs = ws_locations(path.read_text())
                self.assertGreaterEqual(len(locs), 2, locs)


class _Echo(BaseHTTPRequestHandler):
    def do_GET(self):                                        # noqa: N802
        body = json.dumps({"upgrade": self.headers.get("Upgrade"), "connection": self.headers.get("Connection")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):                    # noqa: A002  (quiet)
        return None


@unittest.skipUnless(nginx_rig.available(), nginx_rig.SKIP_REASON)
class TestThroughARealNginx(unittest.TestCase):

    CASES = [
        # (what the client sends as Upgrade, what the backend must be told as Connection)
        ("websocket", "upgrade"),
        ("WebSocket", "upgrade"),
        ("WEBSOCKET", "upgrade"),
        ("h2c", "close"),
        ("websocketx", "close"),
        ("xwebsocket", "close"),
        ("websocket, h2c", "close"),
        ("TLS/1.0", "close"),
        (None, "close"),
    ]

    @classmethod
    def setUpClass(cls):
        cls.stub = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
        cls.addr = "127.0.0.1:%d" % cls.stub.server_address[1]
        threading.Thread(target=cls.stub.serve_forever, daemon=True).start()
        cls.rigs = {}
        for label, path in SNIPPETS.items():
            text = path.read_text()
            ups = {addr: cls.addr for _, addr in ws_locations(text)}
            cls.rigs[label] = (nginx_rig.NginxRig(ups, locations_text=text), ws_locations(text))

    @classmethod
    def tearDownClass(cls):
        for rig, _ in cls.rigs.values():
            rig.stop()
        cls.stub.shutdown()

    def ask(self, rig, path, upgrade):
        c = http.client.HTTPConnection("127.0.0.1", rig.port, timeout=10)
        c.putrequest("GET", path)
        if upgrade is not None:
            c.putheader("Upgrade", upgrade)
            c.putheader("Connection", "Upgrade, HTTP2-Settings" if upgrade == "h2c" else "Upgrade")
            if upgrade == "h2c":
                c.putheader("HTTP2-Settings", "AAMAAABkAAQAAP__")
        c.endheaders()
        r = c.getresponse()
        body = r.read()
        c.close()
        self.assertEqual(r.status, 200, body)
        return json.loads(body)

    def test_the_connection_header_the_backend_sees(self):
        n = 0
        for label, (rig, locs) in self.rigs.items():
            for path, _ in locs:
                for sent, want in self.CASES:
                    with self.subTest(snippet=label, path=path, upgrade=sent):
                        seen = self.ask(rig, path, sent)
                        n += 1
                        self.assertEqual((seen["connection"] or "").lower(), want, seen)
        self.assertGreater(n, 40, "the population is the shipped locations times the cases")

    def test_h2c_is_never_offered_to_a_backend_as_an_upgrade(self):
        for label, (rig, locs) in self.rigs.items():
            for path, _ in locs:
                with self.subTest(snippet=label, path=path):
                    seen = self.ask(rig, path, "h2c")
                    self.assertNotIn("upgrade", (seen["connection"] or "").lower(), seen)


if __name__ == "__main__":
    unittest.main()
