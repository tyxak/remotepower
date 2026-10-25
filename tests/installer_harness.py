"""A rig that runs RemotePower's agent installers for real.

Used by test_v741_installer.py. It stands up what the installers talk to and
what they run on, so the tests can say what happened to a host rather than what
the script text contains:

  * an HTTPS server on an ephemeral port whose certificate is signed by a CA
    from tools/gen-ca.sh, so curl and wget make real verification decisions
    (the server is the self-signed Docker case: nothing it presents is in any
    trust store);
  * the real renderer for the served script (api._render_agent_install), fed
    the request's own Host header;
  * a stub agent binary, served as the download, that records what it was
    asked to do and writes credentials derived from the enrolment token;
  * a controlled PATH: stubs for systemctl, systemd-run and sleep, and symlinks
    to only the real tools the scripts need (so a missing tool shows up as a
    failure, and "no curl" or "no wget" is a real state);
  * a `systemctl` that models a running service: `restart` copies the current
    credentials into the "running process", while `enable --now` does nothing
    for a unit that is already active, which is the trap under test.
"""
import hashlib
import importlib.util
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent

# Real utilities the scripts legitimately use; nothing else is reachable.
REAL_TOOLS = ("sh", "bash", "id", "mkdir", "cp", "chmod", "cat", "sed", "tr", "awk",
              "head", "grep", "mktemp", "rm", "dirname", "sha256sum", "openssl",
              "uname", "touch", "install", "cmp", "basename", "env", "tee", "date")

SYSTEMCTL_STUB = r'''#!/bin/sh
# Stateful stand-in for systemctl. State lives in $RP_TEST_STATE:
#   active    present while the unit is running
#   running_creds   the credentials the running process started with
echo "SYSTEMCTL $*" >> "$RP_TEST_LOG"
creds="$RP_INSTALL_ROOT/etc/remotepower/credentials"
start() {
  touch "$RP_TEST_STATE/active"
  if [ -f "$creds" ]; then cp "$creds" "$RP_TEST_STATE/running_creds"; fi
  echo "$1" >> "$RP_TEST_STATE/starts"
}
case "$1" in
  is-active) [ -e "$RP_TEST_STATE/active" ] ;;
  enable)
    [ -n "${RP_TEST_NO_SYSTEMD:-}" ] && exit 1
    touch "$RP_TEST_STATE/enabled"
    for a in "$@"; do
      if [ "$a" = "--now" ] && [ ! -e "$RP_TEST_STATE/active" ]; then start enable-now; fi
    done ;;
  restart|start) start "$1" ;;
  daemon-reload|disable|stop) ;;
esac
exit 0
'''

SYSTEMD_RUN_STUB = r'''#!/bin/sh
echo "SYSTEMD-RUN $*" >> "$RP_TEST_LOG"
exit 0
'''

AGENT_STUB = r'''#!/bin/sh
# Stand-in for remotepower-agent: logs what it was asked and, for enroll-token,
# writes credentials derived from the token.
echo "AGENT $*" >> "$RP_TEST_LOG"
echo "AGENT-ENV RP_CA_BUNDLE=${RP_CA_BUNDLE:-}" >> "$RP_TEST_LOG"
case "$1" in
  enroll-token|enroll)
    tok=""
    while [ $# -gt 0 ]; do
      case "$1" in --token|--pin) tok="$2" ;; esac
      shift
    done
    mkdir -p "$RP_INSTALL_ROOT/etc/remotepower"
    printf '%s-credentials\n' "$tok" > "$RP_INSTALL_ROOT/etc/remotepower/credentials" ;;
esac
exit 0
'''

_api = None


def load_api():
    """api.py exec'd once against a private data dir (importing it writes there)."""
    global _api
    if _api is None:
        os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-installer-api-"))
        # RP_INSTALLER_API points the rig at another api.py (a copy of an older
        # release, to watch these tests fail on it).
        path = Path(os.environ.get("RP_INSTALLER_API") or ROOT / "server" / "cgi-bin" / "api.py")
        sys.path.insert(0, str(path.parent))
        spec = importlib.util.spec_from_file_location("api_installer_rig", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _api = mod
    return _api


def make_ca(tmp, host="127.0.0.1"):
    """Run the shipped generator; returns (dir, CA SHA-256 fingerprint as printed)."""
    out = Path(tmp) / "tls"
    r = subprocess.run(["bash", str(ROOT / "tools" / "gen-ca.sh"), "--host", host,
                        "--dir", str(out)], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError("gen-ca.sh failed: " + r.stdout + r.stderr)
    fp = subprocess.run(["openssl", "x509", "-in", str(out / "ca.crt"), "-noout",
                         "-fingerprint", "-sha256"], capture_output=True, text=True,
                        check=True).stdout.strip().split("=", 1)[1]
    return out, fp


class Server:
    """HTTPS server for the install flow. `requests` records (path, Host header)."""

    def __init__(self, tls_dir):
        self.requests = []
        self.heartbeats = []         # (device_id, token) of every POST /api/heartbeat
        self.agent = AGENT_STUB.encode()
        self.tls_dir = Path(tls_dir)
        self.ca_body = None          # serve this instead of ca.crt
        self.published_sha = None    # advertise this instead of the binary's hash
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def _send(self, status, body, ctype="text/plain"):
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                u = urlsplit(self.path)
                outer.requests.append((u.path, self.headers.get("Host", "")))
                if u.path == "/install":
                    env = {"HTTP_HOST": self.headers.get("Host", ""),
                           "HTTP_X_FORWARDED_PROTO": "https", "QUERY_STRING": u.query}
                    self._send(200, load_api()._render_agent_install(env).encode(),
                               "text/x-shellscript")
                elif u.path == "/ca.crt":
                    body = (outer.ca_body if outer.ca_body is not None
                            else (outer.tls_dir / "ca.crt").read_bytes())
                    self._send(200, body, "application/x-x509-ca-cert")
                elif u.path == "/api/agent/download":
                    self._send(200, outer.agent, "application/octet-stream")
                elif u.path == "/api/agent/version":
                    sha = outer.published_sha or hashlib.sha256(outer.agent).hexdigest()
                    self._send(200, ('{"version": "9.9.9", "sha256": "%s"}' % sha).encode(),
                               "application/json")
                else:
                    self._send(404, b"not found")

        def do_POST(self):
            import json
            u = urlsplit(self.path)
            outer.requests.append((u.path, self.headers.get("Host", "")))
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            if u.path == "/api/heartbeat":
                try:
                    b = json.loads(raw)
                    outer.heartbeats.append((b.get("device_id"), b.get("token")))
                except ValueError:
                    pass
                self._send(200, b'{"ok": true}', "application/json")
            else:
                self._send(404, b"not found")

        H.do_POST = do_POST

        class Quiet(ThreadingHTTPServer):
            def handle_error(self, request, client_address):
                pass        # a client that gives up mid-handshake is not news

        self.httpd = Quiet(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(self.tls_dir / "server.crt"), str(self.tls_dir / "server.key"))
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.url = f"https://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class Sandbox:
    """A scratch root, a controlled PATH and a place to run a script."""

    def __init__(self, tmp, tools=REAL_TOOLS, with_curl=True, with_wget=True):
        self.tmp = Path(tmp)
        self.root = self.tmp / "root"
        self.state = self.tmp / "state"
        self.log = self.tmp / "calls.log"
        self.stub = self.tmp / "stub"
        self.realbin = self.tmp / "realbin"
        for d in (self.root, self.state, self.stub, self.realbin):
            d.mkdir(parents=True, exist_ok=True)
        wanted = list(tools) + (["curl"] if with_curl else []) + (["wget"] if with_wget else [])
        for tool in wanted:
            real = shutil.which(tool)
            if real and not (self.realbin / tool).exists():
                (self.realbin / tool).symlink_to(real)
        for name, body in (("systemctl", SYSTEMCTL_STUB), ("systemd-run", SYSTEMD_RUN_STUB),
                           ("sleep", "#!/bin/sh\nexit 0\n"),
                           ("sudo", '#!/bin/sh\nexec "$@"\n')):
            f = self.stub / name
            f.write_text(body)
            f.chmod(0o755)

    def calls(self):
        return self.log.read_text() if self.log.exists() else ""

    def set_running(self, creds="OLD-credentials"):
        """A service that is already up, holding `creds` in memory."""
        (self.state / "active").touch()
        (self.state / "running_creds").write_text(creds + "\n")
        (self.root / "etc/remotepower").mkdir(parents=True, exist_ok=True)
        (self.root / "etc/remotepower/credentials").write_text(creds + "\n")

    def running_creds(self):
        f = self.state / "running_creds"
        return f.read_text().strip() if f.exists() else None

    def _env(self, env):
        e = {"PATH": f"{self.stub}:{self.realbin}", "HOME": str(self.tmp),
             "RP_INSTALL_ROOT": str(self.root), "RP_TEST_LOG": str(self.log),
             "RP_TEST_STATE": str(self.state), "LC_ALL": "C"}
        e.update(env or {})
        return e

    def run(self, shell, script_path, args=(), env=None, timeout=60):
        """Run a script file: `shell script args...`."""
        return subprocess.run([shell, str(script_path), *args], env=self._env(env),
                              capture_output=True, text=True, timeout=timeout)

    def run_piped(self, shell, script_text, args=(), env=None, timeout=60):
        """Run a script the way the Quick-install line does: piped into `sh -s -- args`."""
        return subprocess.run([shell, "-s", "--", *args], env=self._env(env), input=script_text,
                              capture_output=True, text=True, timeout=timeout)
