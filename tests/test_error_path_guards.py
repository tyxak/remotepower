"""AST error-path guards — three recurring server bug classes, made structural.

Each check below encodes a rule that previously lived only in CLAUDE.md as
"remember to grep", and each has shipped as a real bug at least once:

1. respond(2xx) inside a try whose `except Exception` arm also responds.
   respond() raises HTTPError (an Exception), so the success gets CAUGHT and
   rewritten as the error response. Shipped in handle_server_self_update
   (v5.0.0-v6.1.2), and this gate's first run found two more live ones:
   handle_posture_digest_test (successful test send returned 500) and
   handle_ticket_imap_test (folder-select failure message mangled).

2. <NAME>_FILE.exists() on a logical storage key. Under the SQLite/Postgres
   backends storage keys live in DB tables — there is no file, .exists() is
   False forever, and any gate on it is silently defeated (the v5.0.0
   scheduled-backup runaway). backend_exists() is the storage-aware check.

3. A handle_* that mutates state gated only by bare require_auth() — admits
   the read-only roles (viewer/mcp/auditor/finance). The current set below
   was REVIEWED (2026-07-24): every entry is a self-scoped write (own user
   record / own TOTP / own sessions), an internally owner-or-admin-guarded
   mutation, a cache/watermark write, or the documented handle_monitor_run
   borderline. A NEW name failing this test needs require_write_role — or a
   review that concludes it belongs on this list, with the reason.
"""

import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"


def _py_files():
    return [_CGI / "api.py"] + sorted(_CGI.glob("*_handlers.py"))


def _resp_status(call):
    f = call.func
    name = getattr(f, "id", None) or getattr(f, "attr", None)
    if name != "respond" or not call.args:
        return None
    a = call.args[0]
    return a.value if isinstance(a, ast.Constant) and isinstance(a.value, int) \
        else None


class TestSuccessRespondNotSwallowed(unittest.TestCase):
    ALLOWLIST = set()   # empty on purpose — fix the handler, don't list it

    def test_no_2xx_respond_inside_exception_swallowing_try(self):
        offenders = []
        for p in _py_files():
            tree = ast.parse(p.read_text())
            for fn in [n for n in ast.walk(tree)
                       if isinstance(n, ast.FunctionDef)]:
                if fn.name in self.ALLOWLIST:
                    continue
                for t in [n for n in ast.walk(fn) if isinstance(n, ast.Try)]:
                    swallows = False
                    for h in t.handlers:
                        catches = h.type is None \
                            or (isinstance(h.type, ast.Name)
                                and h.type.id == "Exception") \
                            or (isinstance(h.type, ast.Attribute)
                                and h.type.attr == "Exception")
                        if catches and any(
                                isinstance(c, ast.Call)
                                and _resp_status(c) is not None
                                for c in ast.walk(h)):
                            swallows = True
                    if not swallows:
                        continue
                    for node in t.body:
                        for c in ast.walk(node):
                            if isinstance(c, ast.Call):
                                st = _resp_status(c)
                                if st is not None and 200 <= st < 300:
                                    offenders.append(
                                        f"{p.name}:{c.lineno} {fn.name}")
        self.assertEqual(offenders, [],
                         "respond(2xx) inside a try whose except Exception "
                         "also responds — the success gets rewritten as the "
                         "error (respond() raises HTTPError). Move the "
                         "success respond AFTER the try:\n  "
                         + "\n  ".join(offenders))


class TestNoPathExistsOnStorageKeys(unittest.TestCase):
    # Real files, not logical storage keys — reviewed:
    #   STORAGE_MARKER_FILE — read before the backend is even chosen.
    #   DEBUG_LOG_FILE — a .log stream on disk (only *.json paths are keys).
    ALLOWLIST = {"STORAGE_MARKER_FILE", "DEBUG_LOG_FILE"}

    def test_storage_keys_use_backend_exists(self):
        offenders = []
        for p in _py_files() + [_CGI / "scheduler.py"]:
            for i, ln in enumerate(p.read_text().splitlines(), 1):
                for m in re.finditer(r"(\w+_FILE)\.exists\(\)", ln):
                    if m.group(1) not in self.ALLOWLIST:
                        offenders.append(f"{p.name}:{i} {m.group(1)}")
        self.assertEqual(offenders, [],
                         "Path.exists() on a storage key is always False "
                         "under the DB backends — use backend_exists():\n  "
                         + "\n  ".join(offenders))


class TestBareRequireAuthMutations(unittest.TestCase):
    """Pinned review set — see the module docstring. Adding a handler here
    requires the same review; the default answer is require_write_role."""

    REVIEWED = {
        # self-scoped account/prefs/session writes (caller's own record)
        "handle_step_up_verify", "handle_push_subscribe",
        "handle_push_unsubscribe", "handle_user_passwd",
        "handle_ui_prefs_set", "handle_ui_prefs_clear",
        "handle_activity_clear", "handle_favorites_set", "handle_me_lang",
        "handle_totp_setup", "handle_totp_confirm",
        "handle_totp_regenerate_codes", "handle_totp_disable",
        "handle_webauthn_register_complete",
        "handle_webauthn_credential_delete", "handle_me_avatar",
        "handle_me_session_revoke", "handle_me_sessions_revoke_others",
        "handle_my_notify_prefs",
        # owner-or-admin guarded inside the handler
        "handle_query_template_create", "handle_query_template_delete",
        "handle_time_entry_update",
        # cache / watermark / prune-on-read writes (no shared-state authority)
        "handle_nav_counts", "handle_version_check",
        "handle_exec_batch_status", "handle_batch_jobs_list",
        "handle_maintenance_list", "handle_device_host_config_get",
        "handle_device_host_config_current",
        # write-gated internally (_caller_can_write read receipt)
        "handle_ticket_get",
        # documented LOW borderline (forces a bounded synchronous run)
        "handle_monitor_run",
    }

    def test_new_bare_auth_mutating_handlers_get_reviewed(self):
        offenders = []
        for p in _py_files():
            tree = ast.parse(p.read_text())
            for fn in [n for n in ast.walk(tree)
                       if isinstance(n, ast.FunctionDef)
                       and n.name.startswith("handle_")]:
                names = set()
                for c in ast.walk(fn):
                    if isinstance(c, ast.Call):
                        nm = getattr(c.func, "id", None) \
                            or getattr(c.func, "attr", None)
                        if nm:
                            names.add(nm)
                if "require_auth" not in names:
                    continue
                if names & {"require_admin_auth", "require_write_role",
                            "require_perm", "require_admin"}:
                    continue
                if not names & {"save", "_LockedUpdate", "_DeviceUpdate",
                                "_locked_update"}:
                    continue
                if fn.name not in self.REVIEWED:
                    offenders.append(f"{p.name}: {fn.name}")
        self.assertEqual(offenders, [],
                         "state-mutating handler gated by bare require_auth() "
                         "— read-only roles (viewer/mcp/auditor/finance) can "
                         "reach it. Use require_write_role(), or review and "
                         "add to REVIEWED with the reason:\n  "
                         + "\n  ".join(offenders))

    def test_reviewed_set_stays_pruned(self):
        """A handler that no longer trips the detector must leave the list —
        a stale entry would mask a future regression of the same name."""
        current = set()
        for p in _py_files():
            tree = ast.parse(p.read_text())
            for fn in [n for n in ast.walk(tree)
                       if isinstance(n, ast.FunctionDef)
                       and n.name.startswith("handle_")]:
                names = set()
                for c in ast.walk(fn):
                    if isinstance(c, ast.Call):
                        nm = getattr(c.func, "id", None) \
                            or getattr(c.func, "attr", None)
                        if nm:
                            names.add(nm)
                if "require_auth" in names \
                        and not names & {"require_admin_auth",
                                         "require_write_role",
                                         "require_perm", "require_admin"} \
                        and names & {"save", "_LockedUpdate", "_DeviceUpdate",
                                     "_locked_update"}:
                    current.add(fn.name)
        stale = sorted(self.REVIEWED - current)
        self.assertEqual(stale, [],
                         "REVIEWED entries that no longer trip the detector — "
                         "remove them:\n  " + "\n  ".join(stale))


if __name__ == "__main__":
    unittest.main()
