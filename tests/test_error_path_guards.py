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
   v7.0.2: the detector now follows ONE level of call depth. It used to
   require a literal save/_LockedUpdate in the handler BODY, which
   inspected 31 of 273 candidates — POST /api/time-entries let a
   read-only viewer write the shared billing ledger because its lock
   sits one frame down in `_te_store`, while its own sibling
   handle_time_entry_update had been on the reviewed list all along.
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
    #   KMIP_MASTER_KEY_FILE — deliberately a real 0600 file rather than a
    #     storage key, so it can be excluded from backups (the archive then
    #     holds only ciphertext). Written with os.open/read_text, never
    #     through save()/load(), so backend_exists() would be the wrong check.
    ALLOWLIST = {"STORAGE_MARKER_FILE", "DEBUG_LOG_FILE",
                 "KMIP_MASTER_KEY_FILE"}

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


_MUTATORS = {"save", "_LockedUpdate", "_DeviceUpdate", "_locked_update"}
_STRONGER_GATES = {"require_admin_auth", "require_write_role",
                   "require_perm", "require_admin"}


def _called_names(fn):
    out = set()
    for c in ast.walk(fn):
        if isinstance(c, ast.Call):
            nm = getattr(c.func, "id", None) or getattr(c.func, "attr", None)
            if nm:
                out.add(nm)
    return out


def _callee_map():
    """name -> the set of names IT calls, over api.py + every bound module.

    Handlers reach the storage layer through helpers as often as they touch it
    directly, so a detector that only sees a literal `save(...)`/`_LockedUpdate`
    in the handler body inspects the wrong population.
    """
    out = {}
    for p in _py_files():
        for fn in [n for n in ast.walk(ast.parse(p.read_text()))
                   if isinstance(n, ast.FunctionDef)]:
            out.setdefault(fn.name, set()).update(_called_names(fn))
    return out


def _bare_auth_mutating_handlers():
    """Every handle_* gated ONLY by bare require_auth() that mutates state —
    directly, or through a helper ONE frame down.

    WHY THE DEPTH. The first version of this guard looked for a literal
    save/_LockedUpdate/_DeviceUpdate/_locked_update call inside the handler
    body. 273 handlers call bare require_auth(); only 31 mutate where that
    detector could see it, so the rule was enforced over 11% of its own
    candidates. `handle_time_entries` escaped review purely because the lock
    sits one frame down in `_te_store` — its own sibling
    `handle_time_entry_update` was on the reviewed list the whole time.
    One level of call depth yields 54. Two levels would pull in the whole
    transitive closure (`require_auth` itself reaches storage), which is why
    the walk stops here.
    """
    callees = _callee_map()
    found = set()
    for p in _py_files():
        for fn in [n for n in ast.walk(ast.parse(p.read_text()))
                   if isinstance(n, ast.FunctionDef)
                   and n.name.startswith("handle_")]:
            names = _called_names(fn)
            if "require_auth" not in names:
                continue
            if names & _STRONGER_GATES:
                continue
            wide = set(names)
            for nm in names:
                # Don't follow handler->handler calls: a delegating handler
                # would inherit its target's classification instead of its own.
                if nm in callees and not nm.startswith("handle_"):
                    wide |= callees[nm]
            if wide & _MUTATORS:
                found.add((p.name, fn.name))
    return found


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

        # ---- v7.0.2: newly VISIBLE when the detector grew one level of call
        # depth. Each mutates through a helper rather than in the handler body,
        # which is why none of them had ever been reviewed. Reasons, by what the
        # helper actually writes:
        #
        # session watermark inside verify_token() — the write is the auth
        # mechanism itself, not authority the handler is exercising.
        "handle_me", "handle_me_sessions", "handle_config_get",
        "handle_integrations_list", "handle_query_templates",
        "handle_device_sudo_log", "handle_sudo_search", "handle_gitops_get",
        # audit_log() only — recording that a read happened is not a
        # state-mutating action by the caller.
        "handle_cmdb_vault_unlock", "handle_ticket_attachment",
        "handle_scoped_credentials_reveal",
        # read-through caches / derived rollups recomputed on read
        "handle_fleet_checks", "handle_reliability_overview",
        "handle_risk_overview", "handle_ai_rag_search",
        "handle_proxmox_list", "handle_proxmox_backups_get",
        # self-scoped or rate-limit bookkeeping keyed to the caller
        "handle_webauthn_register_begin", "handle_ai_chat",
        # one-time VAPID keypair generated on first read (_webpush_cfg)
        "handle_push_vapid", "handle_push_test",
        # documented LOW borderline, same shape as handle_monitor_run: the GET
        # advances the rollout sweep that main()'s cadence runs anyway
        # (_rollout_tick_if_due), and the caller supplies no input to it.
        "handle_rollouts_list",
    }

    def test_new_bare_auth_mutating_handlers_get_reviewed(self):
        population = _bare_auth_mutating_handlers()
        # Non-emptiness control. The detector is a name match over an AST; a
        # rename of require_auth or of the storage helpers would empty it and
        # this test would pass having inspected nothing.
        self.assertGreater(
            len(population), 40,
            "the bare-require_auth mutating population collapsed to %d — the "
            "detector is measuring almost nothing." % len(population))
        offenders = sorted(f"{fname}: {name}" for fname, name in population
                           if name not in self.REVIEWED)
        self.assertEqual(offenders, [],
                         "state-mutating handler gated by bare require_auth() "
                         "— read-only roles (viewer/mcp/auditor/finance) can "
                         "reach it. Use require_write_role(), or review and "
                         "add to REVIEWED with the reason:\n  "
                         + "\n  ".join(offenders))

    def test_reviewed_set_stays_pruned(self):
        """A handler that no longer trips the detector must leave the list —
        a stale entry would mask a future regression of the same name."""
        current = {name for _fname, name in _bare_auth_mutating_handlers()}
        stale = sorted(self.REVIEWED - current)
        self.assertEqual(stale, [],
                         "REVIEWED entries that no longer trip the detector — "
                         "remove them:\n  " + "\n  ".join(stale))


if __name__ == "__main__":
    unittest.main()
