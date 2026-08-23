#!/usr/bin/env python3
"""v7.0.2: guardrails for four fixes that shipped without one.

These landed while a fix agent was interrupted mid-run, so the code was
recovered and verified by hand but the test file it had been asked to write
never existed. Two of the four are security fixes, which is why this is not
left as a note in a report:

  1. A data-protection erasure request naming `*` deleted every avatar on the
     instance. `who` came from the query string and went into a glob PATTERN.
  2. The web-terminal daemon did not check the scheme of its own base URL,
     while its three sibling sidecars all do. urllib honours `file://`.
  3. That same daemon called `sys.exit(2)` at MODULE scope for two optional
     dependencies, so importing it killed the interpreter. Under
     `unittest discover` that ends the whole run with no verdict at all.
  4. A cadence sweep took its write lock BEFORE deciding whether it was due,
     so every read-only request rewrote the store.

Each test below was demonstrated to fail with its fix reverted.
"""
import importlib.abc
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-scat-"))

_spec = importlib.util.spec_from_file_location("api_scat", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
sys.modules["api_scat"] = api
sys.modules.setdefault("api", api)
_spec.loader.exec_module(api)


def _load_bound(name):
    """exec a bound *_handlers module the way api.py does."""
    spec = importlib.util.spec_from_file_location(f"{name}_scat", _CGI / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.bind(vars(api))
    return mod


# ── 1. the avatar glob ───────────────────────────────────────────────────────
class TestASubjectNameIsANameNotAPattern(unittest.TestCase):
    """`who` reaches this from the query string. _sanitize_str trims and
    truncates; it removes no glob metacharacter and no separator."""

    @classmethod
    def setUpClass(cls):
        cls.ah = _load_bound("attention_handlers")

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rp-avatars-"))
        (self.tmp / "avatars").mkdir()
        self._saved = api.AVATARS_DIR
        api.AVATARS_DIR = self.tmp / "avatars"
        for who in ("alice", "bob", "carol"):
            (api.AVATARS_DIR / f"{who}.img").write_bytes(b"png")
        # A file one level up, to catch a traversal.
        (self.tmp / "keep-me.img").write_bytes(b"do not touch")

    def tearDown(self):
        api.AVATARS_DIR = self._saved

    def test_the_control_finds_a_real_subjects_avatar(self):
        """Positive control. Every assertion below is 'this returns nothing',
        which a broken lookup satisfies for the wrong reason."""
        files, err = self.ah._subject_avatar_files("alice")
        self.assertEqual("", err)
        self.assertEqual(["alice.img"], [f.name for f in files])

    def test_a_wildcard_matches_no_one(self):
        files, _ = self.ah._subject_avatar_files("*")
        self.assertEqual(
            [], files,
            "`who=*` was read as a glob, so it matched every avatar on the "
            "instance and the erase handler unlinked all of them while "
            "reporting a single erasure")

    def test_a_traversal_stays_inside_the_avatar_directory(self):
        for probe in ("../keep-me", "../../keep-me", "..%2Fkeep-me"):
            with self.subTest(who=probe):
                files, _ = self.ah._subject_avatar_files(probe)
                self.assertEqual([], files)
        self.assertTrue((self.tmp / "keep-me.img").exists(),
                        "a file outside the avatar directory was reachable")

    def test_an_absolute_path_does_not_raise(self):
        """Path.glob raises NotImplementedError on a non-relative pattern, and
        the caller only catches OSError — a 500 an auditor could trigger from
        the read-only Article 15 report."""
        try:
            files, err = self.ah._subject_avatar_files("/etc/passwd")
        except Exception as exc:                       # noqa: BLE001
            self.fail(f"raised {type(exc).__name__} instead of returning: {exc}")
        self.assertEqual([], files)

    def test_the_reader_uses_the_writers_own_rule(self):
        """_avatar_path folds a username through the same character class
        before storing. Reader and writer must agree, or a legitimate subject
        with a space or an accent in their name silently has no avatar."""
        for who in ("Ann Smith", "renée", "o'brien"):
            with self.subTest(who=who):
                written = api._avatar_path(who)
                written.parent.mkdir(parents=True, exist_ok=True)
                written.write_bytes(b"png")
                files, _ = self.ah._subject_avatar_files(who)
                self.assertIn(written.name, [f.name for f in files])


# ── 2 & 3. the web terminal daemon ───────────────────────────────────────────
_WT = _ROOT / "server" / "webterm" / "remotepower-webterm.py"


class _Block(importlib.abc.MetaPathFinder):
    def __init__(self, names):
        self.names = set(names)

    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in self.names:
            raise ImportError(f"blocked: {name} (simulating the CI dep list)")
        return None


class TestImportingTheDaemonIsSafe(unittest.TestCase):
    """websockets and asyncssh are optional dependencies of an opt-in sidecar,
    and neither is in the ci.yml dep list. The daemon used to sys.exit(2) at
    module scope when they were absent, which propagates SystemExit through the
    importer — `unittest discover` then ends with no verdict at all, which
    reads as a crashed suite rather than a missing optional package."""

    def _import_without(self, *blocked):
        finder = _Block(blocked)
        sys.meta_path.insert(0, finder)
        saved = {k: v for k, v in sys.modules.items()
                 if k.split(".")[0] in set(blocked)}
        for k in saved:
            del sys.modules[k]
        try:
            spec = importlib.util.spec_from_file_location("wt_probe", _WT)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
        finally:
            sys.meta_path.remove(finder)
            sys.modules.update(saved)

    def test_it_imports_with_websockets_absent(self):
        mod = self._import_without("websockets")
        self.assertFalse(mod._WS_AVAILABLE)

    def test_it_imports_with_asyncssh_absent(self):
        mod = self._import_without("asyncssh")
        self.assertFalse(mod._SSH_AVAILABLE)

    def test_it_imports_with_both_absent_and_the_pure_parts_still_work(self):
        mod = self._import_without("websockets", "asyncssh")
        self.assertFalse(mod._WS_AVAILABLE)
        self.assertFalse(mod._SSH_AVAILABLE)
        self.assertTrue(hasattr(mod, "TicketStore"),
                        "the pure parts must be testable without an SSH library")

    def test_no_exit_survives_at_module_scope(self):
        """Source-level backstop for the class, since the import tests above
        only cover the two packages that exist today."""
        src = _WT.read_text()
        head = src[:src.index("def main():")]
        offenders = [ln.strip() for ln in head.splitlines()
                     if "sys.exit(" in ln and not ln.lstrip().startswith("#")]
        self.assertEqual(
            [], offenders,
            "a sys.exit at module scope takes down anything that imports this "
            "file; report it from main() instead")


class TestTheDaemonChecksItsOwnBaseUrl(unittest.TestCase):
    """Its three sibling sidecars (flowd, kmipd, syslogd) all enforce the
    scheme of their systemd-supplied base URL. This one did not, and urllib
    honours file:// — a base set to one turns the audit POST into a local read."""

    def test_a_non_http_base_is_refused_at_startup(self):
        src = _WT.read_text()
        main = src[src.index("def main():"):]
        self.assertIn("startswith(('http://', 'https://'))", main,
                      "main() does not check the scheme of --api-base")

    def test_the_check_runs_before_the_url_is_used(self):
        src = _WT.read_text()
        main = src[src.index("def main():"):]
        guard = main.index("startswith(('http://', 'https://'))")
        self.assertIn("SystemExit", main[guard:guard + 400],
                      "the scheme check must refuse to start, not warn")


# ── 4. the cadence sweep that wrote on every request ─────────────────────────
class TestACadenceGateComesBeforeTheLock(unittest.TestCase):
    """A plain `return` from inside a `with _LockedUpdate(...)` still calls
    __exit__(None, None, None), which SAVES. Gating inside the lock therefore
    rewrote the whole store on every request that was not due — which is
    essentially all of them at a 900s interval, and on the DB backends took a
    write transaction that serialises against every heartbeat."""

    @staticmethod
    def _body(name):
        """The function's CODE, with its docstring and comments removed.

        Both of these functions discuss _LockedUpdate in their docstring, so a
        plain .index() finds the prose and reports the lock ~400 chars before
        the real one — which made the first version of this test pass on one
        function and fail on the other for the same reason.
        """
        src = (_CGI / "flow_handlers.py").read_text()
        i = src.index("def " + name)
        nxt = src.find("\ndef ", i + 5)
        body = src[i:nxt if nxt > 0 else len(src)]
        # drop the docstring
        if '"""' in body:
            a = body.index('"""')
            b = body.index('"""', a + 3) + 3
            body = body[:a] + body[b:]
        return "\n".join(ln for ln in body.splitlines()
                          if not ln.lstrip().startswith("#"))

    def _assert_gated_before_locking(self, name):
        body = self._body(name)
        self.assertIn("_LockedUpdate", body, f"{name}: no lock found — "
                      "this test is measuring the wrong function")
        head = body[:body.index("_LockedUpdate")]
        self.assertRegex(
            head, r"(?m)^\s+return\s*$",
            f"{name}: the cadence gate must return BEFORE the write lock is "
            "taken. Returning from inside the `with` still saves the store, so "
            "every not-due request rewrites it.")
        self.assertTrue(
            "_load_ro" in head or "A.load" in head or "_config_ro" in head,
            f"{name}: nothing is read before the lock, so the gate cannot "
            "know whether it is due")

    def test_the_export_sweep_gates_before_it_locks(self):
        self._assert_gated_before_locking("run_flow_export_check_if_due")

    def test_the_sibling_that_was_already_right_still_is(self):
        """Positive control: the rule holds over BOTH sweeps on this store, so
        a future third one cannot be the only correct example."""
        self._assert_gated_before_locking("run_flow_dep_check_if_due")


if __name__ == "__main__":
    unittest.main()
