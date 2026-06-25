"""PR #7: the CGI entry point is the api_cgi.py shim, which runs api.py from its
cached bytecode (runpy.run_module under run_name='__main__') instead of letting
fcgiwrap recompile the ~50k-line main script on every request.

These are static contract checks: the shim exists and keeps its shape, api.py is
left directly runnable (so it stays importable by the SCGI worker / cve runner),
and every nginx SCRIPT_FILENAME the repo ships points at the shim, not api.py.
Files absent from the `make dist` staged tree are skipped (a hard read would
error the release build)."""
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"


def _maybe(p):
    p = _ROOT / p
    return p.read_text() if p.exists() else None


class TestCgiShim(unittest.TestCase):
    def test_shim_exists_and_runs_api_as_main(self):
        shim = _CGI / "api_cgi.py"
        if not shim.exists():
            self.skipTest("api_cgi.py absent (excluded tree)")
        src = shim.read_text()
        # Must run api AS __main__ from cached bytecode — a plain `import api;
        # api.main()` would skip the __main__ HTTPError->render block.
        self.assertIn("runpy.run_module(", src)
        self.assertIn("run_name='__main__'", src)
        self.assertIn("'api'", src)

    def test_api_py_still_directly_executable(self):
        # The shim relies on api.py staying importable as a module (it imports it)
        # AND api.py must keep its __main__ entry block.
        api = _CGI / "api.py"
        if not api.exists():
            self.skipTest("api.py absent (excluded tree)")
        self.assertIn("if __name__ == '__main__':", api.read_text())

    def test_nginx_script_filename_points_at_shim(self):
        # Every shipped nginx config must route the CGI to the shim, not api.py.
        for rel in ("server/conf/remotepower-locations.conf",
                    "docker/nginx-docker-locations.conf",
                    "docker/nginx-docker-tls.conf",
                    "packaging/install-demo.sh"):
            conf = _maybe(rel)
            if conf is None:
                continue
            if "SCRIPT_FILENAME" not in conf:
                continue
            self.assertNotIn(
                "cgi-bin/api.py;", conf,
                f"{rel}: SCRIPT_FILENAME still points at api.py — repoint to api_cgi.py")
            self.assertIn("cgi-bin/api_cgi.py", conf, rel)

    def test_installers_compile_and_chmod_the_shim(self):
        # Each installer/deploy path must mark api_cgi.py executable and precompile
        # cgi-bin so the shim has a .pyc to load (root-owned dir; http user can't
        # build it). The AUR package compiles in its .install hook instead.
        for rel in ("install-server.sh", "install.sh", "deploy-server.sh", "Dockerfile"):
            txt = _maybe(rel)
            if txt is None:
                continue
            self.assertIn("api_cgi.py", txt, f"{rel}: shim not installed +x")
            self.assertIn("compileall", txt, f"{rel}: missing precompile step")

    def test_aur_package_compiles_in_install_hook(self):
        inst = _maybe("packaging/aur/remotepower-server/remotepower-server.install")
        pkgb = _maybe("packaging/aur/remotepower-server/PKGBUILD")
        if inst is not None:
            self.assertIn("compileall", inst)
        if pkgb is not None:
            self.assertIn("api_cgi.py", pkgb)


if __name__ == "__main__":
    unittest.main()
