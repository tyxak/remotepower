"""A real nginx on the SHIPPED Docker location snippet and HTTP server block.

Shared by test_v741_nginx_host_port.py and test_v741_webterm_docker.py. The rig
starts an unprivileged nginx on free loopback ports, includes the shipped
snippet with its upstream addresses rewritten to wherever the test put them, and
the real HTTP server block of docker/nginx-docker-tls.conf (the redirect).

The binary: RP_NGINX_BIN, or `nginx` on PATH. RP_NGINX_LOCATIONS points the rig
at another snippet (an older release, to watch a test fail on it).
"""
import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NGINX = os.environ.get("RP_NGINX_BIN") or shutil.which("nginx")
LOCATIONS = Path(os.environ.get("RP_NGINX_LOCATIONS") or ROOT / "docker" / "nginx-docker-locations.conf")
SKIP_REASON = "no nginx binary (set RP_NGINX_BIN); RP_NGINX_REQUIRE=1 makes this a failure"


def available():
    return bool(NGINX) or os.environ.get("RP_NGINX_REQUIRE") == "1"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class NginxRig:
    """upstreams: {shipped_address: real_address}, e.g. {"127.0.0.1:8090": "127.0.0.1:41233"}.
    An address the snippet names that is not listed goes to a dead port."""

    SHIPPED = ("127.0.0.1:8090", "127.0.0.1:8765", "127.0.0.1:8766", "127.0.0.1:8767")

    def __init__(self, upstreams, locations_text=None):
        if not NGINX:
            raise AssertionError("RP_NGINX_REQUIRE=1 but no nginx binary was found")
        self.tmp = Path(tempfile.mkdtemp(prefix="rp-nginx-rig-"))
        self.port = free_port()
        self.http_port = free_port()
        t = self.tmp
        (t / "www").mkdir()
        loc = locations_text if locations_text is not None else LOCATIONS.read_text()
        for shipped in self.SHIPPED:
            loc = loc.replace(shipped, upstreams.get(shipped, "127.0.0.1:9"))
        (t / "locations.conf").write_text(loc)
        # The shipped HTTP server block (the first `server {` of the TLS file), on a free port.
        tls = (ROOT / "docker/nginx-docker-tls.conf").read_text()
        first = tls[:tls.index("server {", tls.index("server {") + 1)]
        first = first.replace("listen 8080;", f"listen 127.0.0.1:{self.http_port};")
        first = first.replace(self.SHIPPED[0], upstreams.get(self.SHIPPED[0], "127.0.0.1:9"))
        (t / "http_server.conf").write_text(first)
        self.write_https_port_conf((ROOT / "docker/nginx-docker-https-port.conf").read_text())
        (t / "app_server.conf").write_text(
            f"server {{ listen 127.0.0.1:{self.port}; server_name _; root {t}/www;\n"
            f"  include {t}/locations.conf; }}\n")
        (t / "nginx.conf").write_text(f"""daemon off;
pid {t}/nginx.pid;
error_log {t}/error.log warn;
events {{ worker_connections 64; }}
http {{
    access_log off;
    client_body_temp_path {t}/b; proxy_temp_path {t}/p; fastcgi_temp_path {t}/f;
    uwsgi_temp_path {t}/u; scgi_temp_path {t}/s;
    include {ROOT}/server/conf/remotepower-ws-map.conf;
    include {t}/https-port.conf;
    include {t}/http_server.conf;
    include {t}/app_server.conf;
}}
""")
        args = [NGINX, "-c", str(t / "nginx.conf"), "-p", str(t), "-e", str(t / "error.log")]
        chk = subprocess.run(args[:1] + ["-t"] + args[1:], capture_output=True, text=True)
        if chk.returncode != 0:
            raise AssertionError("nginx -t failed:\n" + chk.stderr)
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.port), 0.2).close()
                return
            except OSError:
                time.sleep(0.1)
        raise AssertionError("nginx did not start:\n" + (t / "error.log").read_text())

    def write_https_port_conf(self, text):
        (self.tmp / "https-port.conf").write_text(text)

    def reload(self):
        self.proc.send_signal(1)         # SIGHUP
        time.sleep(1.0)

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        shutil.rmtree(self.tmp, ignore_errors=True)
