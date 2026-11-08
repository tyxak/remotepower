#!/usr/bin/env python3
"""8.0.0: an AI assistant that is switched off answers 409, not 500 or 502.

The authorization matrix found four handlers that answered a 5xx for a setting that says no: the executor's propose, the alert triage, the log-sweep diagnosis and
the mitigation analysis. A setting is not a fault: the status told a monitor that the server had failed, and (for triage) read as the AI provider being down.
`AINotEnabled` (a RuntimeError, so a caller that does not know it still treats it as one) is raised where the setting is read and each handler maps it to 409 with
the message the page shows. Held three ways: the real raise, every caller found by syntax tree (a fifth caller that forgets fails the build), and the two handlers
that can be driven without a model.
"""
import ast
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v800-ainot-"))
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v800_ainot", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)             # type: ignore[arg-type]
_spec.loader.exec_module(api)                             # type: ignore[union-attr]

CALLEES = ("_call_ai_with_prompts", "_run_alert_triage")


def _callers():
    """(file, function, call node, the Try nodes around it) for every call of the AI helpers in the server modules."""
    out = []
    for path in sorted(_CGI.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        parents = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
                if name not in CALLEES:
                    continue
                tries, cur, func = [], node, None
                while cur in parents:
                    cur = parents[cur]
                    if isinstance(cur, ast.Try):
                        tries.append(cur)
                    if func is None and isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        func = cur.name
                out.append((path.name, func, node, tries))
    return out


def _handler_names(try_node):
    names = []
    for h in try_node.handlers:
        t = h.type
        names.append(t.attr if isinstance(t, ast.Attribute) else getattr(t, "id", "") if t is not None else "")
    return names


class TestTheSettingIsRaisedAsItsOwnKind(unittest.TestCase):

    def test_the_real_helper_raises_it_when_the_assistant_is_off(self):
        d = Path(tempfile.mkdtemp())
        saved = api.CONFIG_FILE
        api.CONFIG_FILE = d / saved.name
        api.save(api.CONFIG_FILE, {"ai": {"enabled": False}})
        api._invalidate_load_cache(api.CONFIG_FILE)
        try:
            with self.assertRaises(api.AINotEnabled) as cm:
                api._call_ai_with_prompts("system", "user", "alert_triage")
            self.assertIn("AI not enabled", str(cm.exception))
            self.assertIsInstance(cm.exception, RuntimeError)
        finally:
            api._invalidate_load_cache(api.CONFIG_FILE)
            api.CONFIG_FILE = saved


class TestEveryCallerMapsIt(unittest.TestCase):

    def test_the_population_is_not_empty(self):
        """Control: the check below passes over an empty list."""
        self.assertGreaterEqual(len(_callers()), 4, [(f, fn) for f, fn, _n, _t in _callers()])

    EXEMPT = {
        "_run_alert_triage": "it lets the error rise to its handler, which is a caller of its own below",
        "run_ai_triage_if_due": "a sweep answers no request, and it returns before the call when the assistant is off (ai.enabled is read first)",
    }

    def test_each_exemption_is_still_a_caller(self):
        """An exemption whose caller has gone, or no longer calls the helper, is a line that excuses nothing."""
        funcs = {func for _f, func, _n, _t in _callers()}
        self.assertEqual(sorted(set(self.EXEMPT) - funcs), [])

    def test_each_caller_that_catches_names_AINotEnabled_before_any_wider_handler(self):
        bad = []
        for fname, func, node, tries in _callers():
            if func in self.EXEMPT:
                continue
            inner = next((t for t in tries if any(node in ast.walk(s) for s in t.body)), None)
            if inner is None:
                bad.append((fname, func, node.lineno, "no try around the call"))
                continue
            names = _handler_names(inner)
            if "AINotEnabled" not in names:
                bad.append((fname, func, node.lineno, names))
                continue
            wider = [n for n in names[:names.index("AINotEnabled")] if n in ("Exception", "RuntimeError", "")]
            if wider:
                bad.append((fname, func, node.lineno, "a wider handler comes first: %s" % wider))
        self.assertEqual(bad, [])

    def test_every_handler_status_for_it_is_409(self):
        for fname in ("api.py", "ai_triage_handlers.py"):
            text = (_CGI / fname).read_text(encoding="utf-8")
            for chunk in text.split("except ")[1:]:
                if chunk.startswith(("A.AINotEnabled", "AINotEnabled")):
                    self.assertIn("respond(409", chunk.split("except ")[0][:200], fname)


class _Capture(unittest.TestCase):
    def setUp(self):
        self.cap = {}
        self._orig = {}

        def patch(name, value):
            self._orig[name] = getattr(api, name)
            setattr(api, name, value)

        self.patch = patch

        def _resp(s, b=None):
            self.cap["s"], self.cap["b"] = s, b
            raise api.HTTPError(s, b)

        patch("respond", _resp)
        self.addCleanup(self._undo)

    def _undo(self):
        for n, v in self._orig.items():
            setattr(api, n, v)

    def run_handler(self, fn, *args):
        self.cap.clear()
        try:
            fn(*args)
        except api.HTTPError:
            pass
        return self.cap.get("s"), self.cap.get("b")


class TestTheExecutorAnswers409(_Capture):

    def test_propose_with_the_assistant_off_is_a_409_with_the_message(self):
        self.patch("require_write_role", lambda *a, **k: "admin")
        self.patch("_read_valid", lambda model: {"device_id": "d1", "context": "disk full"})
        self.patch("_scope_filter_devices", lambda d: {"d1": {"name": "web01"}})
        self.patch("_ai_exec_catalog", lambda: [{"id": "s1", "label": "Free disk", "description": ""}])

        def off(*a, **k):
            raise api.AINotEnabled("AI not enabled — configure in Settings → AI Assistant")

        self.patch("_call_ai_with_prompts", off)
        status, body = self.run_handler(api.handle_ai_exec_propose)
        self.assertEqual(status, 409)
        self.assertIn("AI not enabled", body["error"])

    def test_any_other_failure_of_the_call_is_still_a_500(self):
        self.patch("require_write_role", lambda *a, **k: "admin")
        self.patch("_read_valid", lambda model: {"device_id": "d1", "context": ""})
        self.patch("_scope_filter_devices", lambda d: {"d1": {"name": "web01"}})
        self.patch("_ai_exec_catalog", lambda: [{"id": "s1", "label": "x", "description": ""}])

        def boom(*a, **k):
            raise RuntimeError("provider exploded")

        self.patch("_call_ai_with_prompts", boom)
        status, _body = self.run_handler(api.handle_ai_exec_propose)
        self.assertEqual(status, 500)


class TestTheTriageAnswers409(_Capture):

    def test_triage_with_the_assistant_off_is_a_409_and_a_provider_failure_is_a_502(self):
        import ai_triage_handlers as T

        T.bind(vars(api))
        alert = {"id": "a1", "device_id": "d1"}
        self.patch("require_write_role", lambda *a, **k: "admin")
        self.patch("load", lambda f, *a, **k: {"alerts": [alert]} if f == api.ALERTS_FILE else {"d1": {"name": "web01"}})
        self.patch("_filter_alerts_for_caller", lambda alerts: alerts)
        self.patch("_ai_rate_limit_check", lambda actor, cfg: (True, 0, 100))
        self.patch("_ai_cfg", lambda: {})

        def off(*a, **k):
            raise api.AINotEnabled("AI not enabled — configure in Settings → AI Assistant")

        self.patch("_run_alert_triage", off)
        self.assertEqual(self.run_handler(T.handle_alert_ai_triage, "a1")[0], 409)

        def down(*a, **k):
            raise RuntimeError("provider returned no text")

        self.patch("_run_alert_triage", down)
        self.assertEqual(self.run_handler(T.handle_alert_ai_triage, "a1")[0], 502)


if __name__ == "__main__":
    unittest.main()
