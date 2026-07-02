#!/usr/bin/env python3
"""RemotePower persistent API worker — SCGI prefork front for api.py.

WHY THIS EXISTS (v4.3.0 perf): under the classic fcgiwrap/CGI deployment,
every /api/* request forks a *fresh* Python interpreter that re-parses the
whole ~2 MB api.py source before a single handler line runs — typically
hundreds of milliseconds of pure startup tax, paid on every dashboard poll
and every agent heartbeat. This worker imports api.py ONCE at service start
and then forks per request.

WHY FORK-PER-REQUEST (not threads, not a long-lived handler loop): api.py
was written for CGI — it freely mutates module globals (_LOAD_CACHE,
os.environ, sys.stdin/sys.stdout) and assumes the process dies with the
request. fork() + copy-on-write preserves exactly those semantics: each
request runs in a pristine copy of the freshly-imported module, crashes are
isolated, and nothing leaks across requests — while the expensive
interpreter-start + parse + import work is paid once, in the parent.

PROTOCOL: SCGI over a unix socket (or TCP). nginx speaks it natively:

    location ^~ /api/ {
        include scgi_params;
        scgi_pass  unix:/run/remotepower/api.sock;
        scgi_param PATH_INFO $uri;
        scgi_param RP_DATA_DIR /var/lib/remotepower;
        scgi_read_timeout 600s;
    }

The CGI-style response api.py prints ("Status: NNN" + headers + body) is
passed through verbatim — nginx's scgi module understands it, exactly like
fcgiwrap did. See server/conf/remotepower-api.service for the unit and
server/conf/remotepower.conf for the ready-to-uncomment location block.

FORK-HYGIENE RULES (load-bearing, don't relax):
  * storage.close_connection() runs in the parent right after import —
    SQLite connections must never be carried across fork() (shared file
    descriptors + WAL state corrupt the database).
  * api._LOAD_CACHE is cleared post-import and again per child — it has no
    mtime validation; it is only correct because it normally dies with the
    CGI process.
  * The child resets SIGCHLD to SIG_DFL before running the handler —
    the parent's reaper would otherwise steal subprocess.run() waits
    inside api.py (ChildProcessError races).

Config (environment):
  RP_SCGI_SOCKET   unix socket path (default /run/remotepower/api.sock),
                   or host:port for TCP (e.g. 127.0.0.1:9008)
  RP_WORKER_MAX    max concurrent request children (default 32)
  RP_WORKER_TIMEOUT  per-request kill timer, seconds (default 900 — above
                   nginx's scgi_read_timeout so nginx gives up first)
  RP_DATA_DIR      data directory, read by api.py at import time
"""

import io
import os
import signal
import socket
import sys
import time
import traceback

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

REQUEST_TIMEOUT = int(os.environ.get("RP_WORKER_TIMEOUT", "900"))
MAX_CHILDREN = int(os.environ.get("RP_WORKER_MAX", "32"))

_active = 0


# ── SCGI parsing ─────────────────────────────────────────────────────────────


class SCGIProtocolError(Exception):
    pass


# SCGI headers are nginx-generated CGI vars — a few KB. The cap exists so a
# rogue local process with socket access can't make the child allocate
# gigabytes with a fabricated netstring length (v4.3.0 security review).
MAX_HEADER_BYTES = 1024 * 1024


def read_netstring(rfile):
    """Read one netstring ("<len>:<payload>,") and return the payload bytes."""
    length = b""
    while True:
        ch = rfile.read(1)
        if not ch:
            raise SCGIProtocolError("EOF while reading netstring length")
        if ch == b":":
            break
        if not ch.isdigit() or len(length) > 8:
            raise SCGIProtocolError("malformed netstring length")
        length += ch
    if not length:
        raise SCGIProtocolError("empty netstring length")
    n = int(length)
    if n > MAX_HEADER_BYTES:
        raise SCGIProtocolError("netstring header block too large")
    payload = rfile.read(n)
    if len(payload) != n:
        raise SCGIProtocolError("short netstring payload")
    if rfile.read(1) != b",":
        raise SCGIProtocolError("netstring missing trailing comma")
    return payload


def parse_scgi_headers(blob):
    """NUL-separated key/value pairs → dict (decoded like os.environ would)."""
    parts = blob.split(b"\x00")
    # trailing NUL leaves one empty element at the end
    if parts and parts[-1] == b"":
        parts.pop()
    if len(parts) % 2:
        raise SCGIProtocolError("odd number of SCGI header parts")
    env = {}
    for i in range(0, len(parts), 2):
        env[parts[i].decode("utf-8", "surrogateescape")] = parts[i + 1].decode(
            "utf-8", "surrogateescape"
        )
    return env


# ── per-request child ────────────────────────────────────────────────────────


def run_request(api_mod, conn):
    """Run exactly one CGI-style request in this (forked) process and exit.

    Mirrors api.py's `if __name__ == '__main__'` block: HTTPError renders the
    planned response, SystemExit is honoured (some handlers sys.exit(0) after
    streaming binary), anything else renders a generic 500.
    """
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.alarm(REQUEST_TIMEOUT)  # hung-handler backstop
    rfile = conn.makefile("rb")
    wfile = conn.makefile("wb")
    exit_code = 0
    try:
        env = parse_scgi_headers(read_netstring(rfile))
        os.environ.update(env)
        # The request body (CONTENT_LENGTH bytes) follows the headers on the
        # same stream — hand it to the handler as stdin, CGI-style.
        sys.stdin = io.TextIOWrapper(rfile, encoding="utf-8", errors="replace", newline="")
        sys.stdout = io.TextIOWrapper(wfile, encoding="utf-8", newline="\n", write_through=True)
        # Fresh per-request state, exactly like a new CGI process.
        api_mod._LOAD_CACHE.clear()
        import random

        random.seed()  # never share the parent's PRNG state
        try:
            api_mod.main()
        except api_mod.HTTPError as e:
            api_mod._render_response(e.status, e.body)
        except SystemExit:
            pass
        except Exception:
            traceback.print_exc(file=sys.stderr)
            try:
                api_mod._render_response(500, {"error": "Internal server error"})
            except Exception:
                pass
    except SCGIProtocolError as exc:
        sys.stderr.write(f"[rp-worker] bad SCGI request: {exc}\n")
        exit_code = 1
    except Exception:
        traceback.print_exc(file=sys.stderr)
        exit_code = 1
    finally:
        for f in (sys.stdout, wfile):
            try:
                f.flush()
            except Exception:
                pass
        try:
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        os._exit(exit_code)  # skip atexit — that's the parent's


# ── parent ───────────────────────────────────────────────────────────────────


def _reap(signum, frame):
    global _active
    while True:
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return
        _active = max(0, _active - 1)


def make_listen_socket(spec):
    """Bind the listening socket: 'host:port' → TCP, anything else → unix."""
    if ":" in spec and not spec.startswith("/"):
        host, port = spec.rsplit(":", 1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, int(port)))
    else:
        try:
            os.unlink(spec)
        except FileNotFoundError:
            pass
        os.makedirs(os.path.dirname(spec) or ".", exist_ok=True)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(spec)
        os.chmod(spec, 0o660)  # nginx (same group) connects; others don't
    sock.listen(64)
    return sock


def serve():
    global _active
    spec = os.environ.get("RP_SCGI_SOCKET", "/run/remotepower/api.sock")

    # Pay the expensive part exactly once.
    t0 = time.monotonic()
    import storage

    import api as api_mod  # noqa: E402 — deliberate late import

    # v5.6.x: mark the request tier so /api/self/status can report what's serving.
    api_mod._SERVER_TIER = "scgi"

    # Fork hygiene (see module docstring): no inherited SQLite connections,
    # no import-time load() snapshots surviving into children.
    storage.close_connection()
    api_mod._LOAD_CACHE.clear()
    sys.stderr.write(
        f"[rp-worker] api.py v{api_mod.SERVER_VERSION} imported in "
        f"{time.monotonic() - t0:.2f}s; serving SCGI on {spec} "
        f"(max {MAX_CHILDREN} children)\n"
    )

    listen = make_listen_socket(spec)
    signal.signal(signal.SIGCHLD, _reap)

    def _shutdown(signum, frame):
        try:
            listen.close()
        finally:
            if not (":" in spec and not spec.startswith("/")):
                try:
                    os.unlink(spec)
                except OSError:
                    pass
            os._exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    while True:
        # Soft concurrency cap — let the kernel backlog queue the rest.
        while _active >= MAX_CHILDREN:
            time.sleep(0.02)
        try:
            conn, _addr = listen.accept()
        except OSError:
            continue
        # Block SIGCHLD around fork + increment so a fast-exiting child's
        # reap can't interleave with the read-modify-write and drift the
        # counter (a lost decrement would eventually wedge the soft cap).
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGCHLD})
        try:
            pid = os.fork()
            if pid == 0:
                signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGCHLD})
                listen.close()
                run_request(api_mod, conn)  # never returns
            _active += 1
        finally:
            signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGCHLD})
        conn.close()


if __name__ == "__main__":
    serve()
