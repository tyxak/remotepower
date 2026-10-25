#!/usr/bin/env python3
"""v7.4.1, issue #34: the port a browser used reaches the app.

Every proxy location said `proxy_set_header Host $host;`, and nginx's `$host`
has no port. Behind a published port other than 443 (Docker with 8460:8443) the
app saw a bare hostname, so every URL it derives from the request lost its port:
the agent installer's server address (so its downloads went to 443, the "install
URL drops a remapped port" of the issue), the portal magic link, the passkey
origin, the OIDC and SAML redirect URIs. The HTTP -> HTTPS redirect had the same
fault.

Two layers. The census reads every shipped nginx config and prints the ratio; it
is cheap and always runs. The rig starts a REAL nginx on the shipped location
snippet and the shipped HTTP server block, with a stub standing in for gunicorn
(the stub renders the installer with the Host it received, via the real
renderer), and asks it for the things the issue is about.

The rig needs an nginx binary: RP_NGINX_BIN, or `nginx` on PATH. Without one it
skips, and RP_NGINX_REQUIRE=1 turns the skip into a failure (the way
RP_BROWSER_REQUIRE does for the browser suites), so a gate that wants it cannot
pass by not having it.
"""
import http.client
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import installer_harness as H  # noqa: E402
import nginx_rig  # noqa: E402

ROOT = H.ROOT

SHIPPED_CONFIGS = (
    "docker/nginx-docker-locations.conf",
    "docker/nginx-docker-tls.conf",
    "server/conf/remotepower-locations.conf",
    "packaging/nginx-push.conf",
    "packaging/nginx-webterm.conf",
    "packaging/install-webterm.sh",      # writes an nginx server block
    "docs/https.md",                     # the example an operator copies for their own proxy
    "docs/sshgw.md",
)


class TestNoShippedConfigForwardsAPortlessHost(unittest.TestCase):

    def test_the_population_is_every_shipped_config_and_example_that_proxies(self):
        for rel in SHIPPED_CONFIGS:
            self.assertTrue((ROOT / rel).exists(), rel)
        sites = [m for rel in SHIPPED_CONFIGS
                 for m in re.findall(r"proxy_set_header Host [^;]+;",
                                     (ROOT / rel).read_text())]
        self.assertGreaterEqual(len(sites), 19, sites)

    def test_every_proxy_site_forwards_host_with_its_port(self):
        bad = {}
        total = 0
        for rel in SHIPPED_CONFIGS:
            for m in re.finditer(r"proxy_set_header Host ([^;]+);", (ROOT / rel).read_text()):
                total += 1
                if m.group(1).replace("\\", "") != "$http_host":
                    bad.setdefault(rel, []).append(m.group(1))
        self.assertEqual(bad, {}, f"{total - sum(map(len, bad.values()))} of {total} proxy "
                                  f"sites forward Host with its port; these do not")

    def test_the_https_redirect_names_the_published_port(self):
        tls = (ROOT / "docker/nginx-docker-tls.conf").read_text()
        self.assertIn("return 301 https://$host$rp_https_suffix$request_uri;", tls)
        self.assertNotRegex(tls, r"return 301 https://\$host\$request_uri")
        self.assertTrue((ROOT / "docker/nginx-docker-https-port.conf").exists())
        self.assertIn("nginx-docker-https-port.conf", (ROOT / "Dockerfile").read_text())
        compose = (ROOT / "docker-compose.yml").read_text()
        self.assertIn('RP_PUBLIC_HTTPS_PORT: "${RP_HTTPS_PORT:-443}"', compose)


class _Upstream:
    """Stands in for gunicorn: renders the installer from the headers nginx sent."""

    def __init__(self):
        self.seen = []
        outer = self

        class H_(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def do_POST(self):
                self.do_GET()

            def do_GET(self):
                host = self.headers.get("Host", "")
                outer.seen.append((self.path, host))
                if self.path.startswith("/api/agent/install"):
                    q = self.path.partition("?")[2]
                    env = {"HTTP_HOST": host, "QUERY_STRING": q,
                           "HTTP_X_FORWARDED_PROTO": self.headers.get("X-Forwarded-Proto", "")}
                    body = H.load_api()._render_agent_install(env).encode()
                else:
                    body = host.encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H_)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def _entrypoint_port_block():
    """The `case ... esac` the entrypoint uses to write the redirect's port map."""
    src = (ROOT / "docker/entrypoint.sh").read_text()
    i = src.index('case "${RP_PUBLIC_HTTPS_PORT:-443}" in')
    return src[i:src.index("esac", i) + len("esac")]


@unittest.skipUnless(nginx_rig.available(), nginx_rig.SKIP_REASON)
class TestARealNginx(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.up = _Upstream()
        cls.rig = nginx_rig.NginxRig({"127.0.0.1:8090": f"127.0.0.1:{cls.up.port}"})
        cls.port = cls.rig.port
        cls.http_port = cls.rig.http_port
        cls.tmp = cls.rig.tmp
        cls.proc = cls.rig.proc

    @classmethod
    def tearDownClass(cls):
        cls.rig.stop()
        cls.up.close()

    def get(self, port, path, host, method="GET"):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        c.request(method, path, headers={"Host": host})
        r = c.getresponse()
        return r.status, dict(r.getheaders()), r.read().decode()

    # ── the issue: the installer's built-in server address ──

    def test_the_installer_keeps_the_port_the_browser_used(self):
        st, _h, body = self.get(self.port, "/install?t=tok", "rp.example:8460")
        self.assertEqual(st, 200)
        self.assertIn('RP_SERVER="http://rp.example:8460"', body,
                      "the installer's server address lost the port")

    def test_control_without_a_port_there_is_none_to_keep(self):
        st, _h, body = self.get(self.port, "/install?t=tok", "rp.example")
        self.assertIn('RP_SERVER="http://rp.example"', body)

    def test_the_windows_installer_is_served_the_same_way(self):
        # /install.ps1 is proxied by the same rule as /install (a different location)
        self.get(self.port, "/install.ps1?t=tok", "rp.example:8460")
        self.assertIn(("/api/agent/win/install?t=tok", "rp.example:8460"), self.up.seen)

    def test_every_api_request_reaches_the_app_with_its_port(self):
        _s, _h, body = self.get(self.port, "/api/anything", "rp.example:8460")
        self.assertEqual(body, "rp.example:8460")
        # /api/login is its own location, and POST only
        self.up.seen.clear()
        self.get(self.port, "/api/login", "rp.example:8460", method="POST")
        self.assertEqual(self.up.seen[-1][1], "rp.example:8460")

    # ── the redirect ──

    def test_the_http_redirect_has_no_port_when_https_is_on_443(self):
        st, h, _b = self.get(self.http_port, "/some/page?x=1", "rp.example")
        self.assertEqual(st, 301)
        self.assertEqual(h["Location"], "https://rp.example/some/page?x=1")

    def test_the_http_redirect_names_the_published_https_port(self):
        # What the entrypoint writes for RP_PUBLIC_HTTPS_PORT=8460, run for real.
        out = self.tmp / "written.conf"
        block = _entrypoint_port_block().replace("/etc/nginx/conf.d/remotepower-https-port.conf", str(out))
        r = subprocess.run(["bash", "-c", block], env={"RP_PUBLIC_HTTPS_PORT": "8460", "PATH": os.environ["PATH"]},
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.rig.write_https_port_conf(out.read_text())
        try:
            self.rig.reload()
            st, h, _b = self.get(self.http_port, "/some/page", "rp.example:8081")
            self.assertEqual(st, 301)
            self.assertEqual(h["Location"], "https://rp.example:8460/some/page",
                             "the redirect sent a browser on 8081 to a dead port")
        finally:
            self.rig.write_https_port_conf((ROOT / "docker/nginx-docker-https-port.conf").read_text())
            self.rig.reload()


class TestTheEntrypointPortBlock(unittest.TestCase):
    """The case statement that writes the redirect's port map, run for real."""

    def run_block(self, value):
        d = Path(tempfile.mkdtemp(prefix="rp-v741-port-"))
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        out = d / "map.conf"
        block = _entrypoint_port_block().replace("/etc/nginx/conf.d/remotepower-https-port.conf", str(out))
        env = {"PATH": os.environ["PATH"]}
        if value is not None:
            env["RP_PUBLIC_HTTPS_PORT"] = value
        r = subprocess.run(["bash", "-c", block], env=env, capture_output=True, text=True)
        return r, out

    def test_443_unset_and_empty_write_nothing(self):
        for v in (None, "", "443"):
            with self.subTest(v=v):
                r, out = self.run_block(v)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertFalse(out.exists(), "wrote a suffix where none is wanted")

    def test_another_port_writes_the_map(self):
        r, out = self.run_block("8460")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(out.read_text(), 'map $host $rp_https_suffix { default ":8460"; }\n')

    def test_a_value_that_is_not_a_port_is_refused_and_nothing_is_written(self):
        for v in ("8460; return 200", "abc", "84 60", '8460"; }'):
            with self.subTest(v=v):
                r, out = self.run_block(v)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertFalse(out.exists(), f"wrote the map for {v!r}")
                self.assertIn("is not a port number", r.stderr)


if __name__ == "__main__":
    unittest.main()
