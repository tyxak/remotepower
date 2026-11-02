#!/usr/bin/env python3
"""The security headers are the same on every response of both shipped nginx configurations, and none is sent twice (7.4.9).

The web client review measured a real nginx on both configurations. Besides the headers the page needs, it found:

* Cross-Origin-Opener-Policy and Cross-Origin-Resource-Policy missing on the static files, the service worker and the manifest on a
  bare-metal install, and everywhere on Docker. A location that sets its own `add_header` makes nginx drop the server-level ones, so
  each such location re-states the whole set; two lines had never been added to those lists.
* `/sw.js` with two `Cache-Control` values (`expires -1` and the explicit header), `/manifest.json` with two `Content-Type` and two
  `Cache-Control` values, the Docker `/agent/` with two `Content-Type` values, and `/ca.crt` with no header at all.

The text checks run everywhere. The measurement runs both configurations through a real nginx (set RP_NGINX_BIN, or put nginx on PATH;
RP_NGINX_REQUIRE=1 turns a missing binary into a failure): the server block's own headers and the shipped location snippet, with the
upstream, the document root and the CA file moved to scratch paths.
"""
import http.client
import re
import shutil
import socket
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

ROOT = Path(__file__).resolve().parent.parent
FLAVORS = {
    "docker": (ROOT / "docker" / "nginx-docker.conf", ROOT / "docker" / "nginx-docker-locations.conf"),
    "bare metal": (ROOT / "server" / "conf" / "remotepower.conf", ROOT / "server" / "conf" / "remotepower-locations.conf"),
}
FULL_SET = ("X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
            "Content-Security-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy")
ONCE_AT_MOST = ("Content-Type", "Cache-Control", "Content-Disposition")


def header_blocks(text):
    """[(location label, set of header names it adds)] for every `location` that has an add_header."""
    out = []
    for m in re.finditer(r"location\s+([^{]+)\{(.*?)\n\}", text, re.S):
        names = set(re.findall(r"^\s*add_header\s+([A-Za-z-]+)\s", m.group(2), re.M))
        if names:
            out.append((m.group(1).strip(), names))
    return out


class TestTheTextOfTheSnippets(unittest.TestCase):

    def test_a_location_that_sets_a_header_states_the_whole_security_set(self):
        for label, (_server, snippet) in FLAVORS.items():
            for loc, names in header_blocks(snippet.read_text()):
                if names <= {"Content-Disposition", "X-Content-Type-Options"}:
                    continue                  # /ca.crt: a public certificate; nosniff is all it needs
                if "Content-Security-Policy" not in names:
                    continue                  # a location that adds a different kind of header (a proxy hint)
                with self.subTest(flavor=label, location=loc):
                    self.assertEqual(sorted(set(FULL_SET) - names), [], "the set is incomplete")

    def test_no_location_adds_a_header_nginx_already_sends(self):
        for label, (_server, snippet) in FLAVORS.items():
            text = snippet.read_text()
            for loc, names in header_blocks(text):
                with self.subTest(flavor=label, location=loc):
                    block = re.search(r"location\s+" + re.escape(loc) + r"\s*\{(.*?)\n\}", text, re.S).group(1)
                    live = re.sub(r"(?m)^\s*#.*$", "", block)
                    if "Content-Type" in names:
                        self.fail("add_header Content-Type: use default_type or types, or the header goes out twice")
                    if "Cache-Control" in names:
                        self.assertNotRegex(live, r"(?m)^\s*expires\s", "expires and add_header Cache-Control both set one")

    def test_the_server_blocks_carry_the_cross_origin_pair(self):
        for label, (server, _snippet) in FLAVORS.items():
            with self.subTest(flavor=label):
                first = re.sub(r"(?m)^\s*#.*$", "", server.read_text())
                self.assertIn("Cross-Origin-Opener-Policy", first)
                self.assertIn("Cross-Origin-Resource-Policy", first)

    def test_the_template_has_no_live_line_among_its_comments(self):
        text = (ROOT / "server" / "conf" / "remotepower.conf").read_text()
        i = text.index("# server {", text.index("HTTPS"))
        tail = text[i:]
        live = [ln for ln in tail.split("\n") if ln.strip() and not ln.lstrip().startswith("#")]
        self.assertEqual(live, [], "an uncommented line sits inside the commented HTTPS template")


class _Upstream(BaseHTTPRequestHandler):
    def do_GET(self):                                        # noqa: N802
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):                    # noqa: A002
        return None


def _server_headers(conf_text):
    """The add_header lines of the first server block of a shipped server config, as they are written."""
    m = re.search(r"server\s*\{(.*?)\n\s*(?:location|gzip|client_max_body_size)", conf_text, re.S)
    return "\n".join(ln for ln in m.group(1).split("\n") if re.match(r"\s*add_header\s", ln))


@unittest.skipUnless(nginx_rig.available(), nginx_rig.SKIP_REASON)
class TestThroughARealNginx(unittest.TestCase):

    PATHS = ["/", "/sw.js", "/manifest.json", "/static/app.js", "/api/anything", "/portal"]

    @classmethod
    def setUpClass(cls):
        cls.stub = ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
        threading.Thread(target=cls.stub.serve_forever, daemon=True).start()
        cls.up = "127.0.0.1:%d" % cls.stub.server_address[1]
        cls.runs = {}
        for label, (server, snippet) in FLAVORS.items():
            t = Path(tempfile.mkdtemp(prefix="rp-hdr-"))
            (t / "www" / "static").mkdir(parents=True)
            (t / "www" / "agent").mkdir()
            (t / "tls").mkdir()
            for rel in ("index.html", "portal.html", "sw.js", "manifest.json", "static/app.js", "agent/remotepower-agent"):
                (t / "www" / rel).write_text("x")
            (t / "tls" / "ca.crt").write_text("-----BEGIN CERTIFICATE-----\n")
            loc = snippet.read_text()
            for shipped in nginx_rig.NginxRig.SHIPPED:
                loc = loc.replace(shipped, cls.up if shipped == "127.0.0.1:8090" else "127.0.0.1:9")
            loc = loc.replace("/var/www/remotepower", str(t / "www"))
            loc = re.sub(r"alias\s+\S+/ca\.crt;", "alias %s;" % (t / "tls" / "ca.crt"), loc)
            (t / "locations.conf").write_text(loc)
            port = nginx_rig.free_port()
            (t / "nginx.conf").write_text(f"""daemon off;
pid {t}/nginx.pid;
error_log {t}/error.log warn;
events {{ worker_connections 64; }}
http {{
    access_log off;
    include {ROOT}/server/conf/remotepower-ws-map.conf;
    client_body_temp_path {t}/b; proxy_temp_path {t}/p; fastcgi_temp_path {t}/f; uwsgi_temp_path {t}/u; scgi_temp_path {t}/s;
    server {{
        listen 127.0.0.1:{port};
        server_name _;
        root {t}/www;
        index index.html;
{_server_headers(server.read_text())}
        include {t}/locations.conf;
    }}
}}
""")
            args = [nginx_rig.NGINX, "-c", str(t / "nginx.conf"), "-p", str(t), "-e", str(t / "error.log")]
            chk = subprocess.run(args[:1] + ["-t"] + args[1:], capture_output=True, text=True)
            if chk.returncode != 0:
                raise AssertionError(label + ": nginx -t failed:\n" + chk.stderr)
            proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            for _ in range(100):
                try:
                    socket.create_connection(("127.0.0.1", port), 0.2).close()
                    break
                except OSError:
                    time.sleep(0.1)
            cls.runs[label] = (t, proc, port)

    @classmethod
    def tearDownClass(cls):
        for t, proc, _port in cls.runs.values():
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
            shutil.rmtree(t, ignore_errors=True)
        cls.stub.shutdown()

    def get(self, label, path):
        conn = http.client.HTTPConnection("127.0.0.1", self.runs[label][2], timeout=10)
        conn.request("GET", path)
        r = conn.getresponse()
        r.read()
        heads = r.getheaders()
        conn.close()
        return r.status, heads

    def test_every_page_carries_the_full_set_once(self):
        for label in FLAVORS:
            for path in self.PATHS:
                with self.subTest(flavor=label, path=path):
                    status, heads = self.get(label, path)
                    self.assertLess(status, 500, (label, path, status))
                    names = [k for k, _v in heads]
                    for want in FULL_SET:
                        self.assertEqual(sum(1 for n in names if n.lower() == want.lower()), 1, (want, names))

    def test_no_response_repeats_a_header_that_must_be_single(self):
        for label in FLAVORS:
            for path in self.PATHS + ["/ca.crt", "/agent/remotepower-agent"]:
                with self.subTest(flavor=label, path=path):
                    _status, heads = self.get(label, path)
                    names = [k.lower() for k, _v in heads]
                    for single in ONCE_AT_MOST:
                        self.assertLessEqual(names.count(single.lower()), 1, (single, heads))

    def test_the_manifest_and_the_certificate_keep_their_types(self):
        for label in FLAVORS:
            with self.subTest(flavor=label):
                status, heads = self.get(label, "/manifest.json")
                self.assertEqual(status, 200)
                types = [v for k, v in heads if k.lower() == "content-type"]
                if label == "bare metal":
                    self.assertTrue(types[0].startswith("application/manifest+json"), types)
                status, heads = self.get(label, "/ca.crt")
                self.assertEqual(status, 200)
                self.assertEqual([v for k, v in heads if k.lower() == "x-content-type-options"], ["nosniff"])

    def test_the_service_worker_is_not_cached(self):
        for label in FLAVORS:
            with self.subTest(flavor=label):
                _status, heads = self.get(label, "/sw.js")
                cc = [v for k, v in heads if k.lower() == "cache-control"]
                self.assertEqual(len(cc), 1, heads)
                self.assertIn("no-store", cc[0])


if __name__ == "__main__":
    unittest.main()
