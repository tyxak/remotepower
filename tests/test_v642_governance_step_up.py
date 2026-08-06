"""v6.4.2 — the four-eyes control stops being switchable by the people it governs.

`_RBAC_PERMS` is eleven device actions; everything administrative sits behind
one indivisible `admin` bit across 284 `require_admin_auth()` call sites. The
audit's own summary of what remains true after checking the softer claims:

    "the approval CONTROL is not protected from the people it governs —
     handle_config_save is a plain require_admin_auth() with no step-up, so any
     admin can toggle change_approval_enabled off, act, and toggle it back."

That is the line an RFP tests: "show us that the person who requests a change
cannot also turn the approval requirement off." They could — and the same one
POST could also unset `audit_worm_path`, drop audit retention to a day, empty
the IP allowlist, or lift the MFA requirement.

`require_step_up()` already existed with exactly two call sites — creating an
admin and promoting to admin — both guarding privilege escalation. Weakening
the control that watches you is the same class of target.

**Not delivered:** the administrative permission namespace itself (a "backup
operator", a "change approver who cannot configure"). That is a redesign across
284 call sites and remains open. This closes the part that fails the audit
without pretending the rest is done.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-gov-"))

_spec = importlib.util.spec_from_file_location("api_gov", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestWhichKeysCount(unittest.TestCase):
    CFG = {"change_approval_enabled": True, "server_name": "Acme",
           "audit_log_retention_days": 90, "temp_alert_threshold_c": 85}

    def touched(self, body):
        return api._governance_keys_touched(body, self.CFG)

    def test_turning_the_approval_control_off_counts(self):
        self.assertEqual(self.touched({"change_approval_enabled": False}),
                         ["change_approval_enabled"])

    def test_resending_the_same_value_does_not(self):
        """The Settings page POSTs the whole form. Gating on PRESENCE would
        demand a re-auth for editing an unrelated field on the same pane, and a
        step-up prompt that fires when nothing sensitive changed is one that
        operators learn to click through."""
        self.assertEqual(self.touched({"change_approval_enabled": True}), [])

    def test_an_unrelated_field_does_not(self):
        self.assertEqual(self.touched({"server_name": "Other"}), [])

    def test_a_whole_form_save_that_flips_one_switch_does(self):
        self.assertEqual(
            self.touched({"server_name": "X", "temp_alert_threshold_c": 80,
                          "change_approval_enabled": False}),
            ["change_approval_enabled"])

    def test_the_evidence_switches_count_too(self):
        """Each of these weakens the thing that would record the change."""
        for k, v in (("audit_worm_path", ""),
                     ("audit_log_retention_days", 1),
                     ("audit_forward_enabled", False),
                     ("mfa_required_roles", []),
                     ("ip_allowlist", ""),
                     ("sso_only", False),
                     ("tenancy_enforced", False),
                     ("read_only_mode", True),
                     ("litigation_hold", {})):
            with self.subTest(key=k):
                self.assertEqual(self.touched({k: v}), [k])

    def test_a_junk_body_does_not_raise(self):
        for bad in ("nope", None, [], 7):
            with self.subTest(body=bad):
                self.assertEqual(api._governance_keys_touched(bad, self.CFG), [])

    def test_the_list_is_not_empty(self):
        self.assertGreaterEqual(len(api._GOVERNANCE_CONFIG_KEYS), 8)


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._cf = api.CONFIG_FILE
        api.CONFIG_FILE = self.d / "config.json"
        api.save(api.CONFIG_FILE, {"change_approval_enabled": True,
                                   "server_name": "Acme"})
        api._invalidate_load_cache(api.CONFIG_FILE)
        self.cap = {}
        self.stepups = []
        self.audits = []
        self._orig = {n: getattr(api, n) for n in
                      ("respond", "method", "get_json_body", "require_admin_auth",
                       "require_step_up", "audit_log")}
        api.require_admin_auth = lambda: "jakob"
        api.require_step_up = lambda: (self.stepups.append(1), "jakob")[1]
        api.audit_log = lambda a, act, detail="", **k: self.audits.append((act, detail))
        api.method = lambda: "POST"

        def _resp(s, b=None):
            self.cap["s"], self.cap["b"] = s, b
            raise api.HTTPError(s, b)
        api.respond = _resp

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        api.CONFIG_FILE = self._cf

    def save(self, body):
        api.get_json_body = lambda: body
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
        except Exception:
            pass       # the handler does far more than this test cares about
        return self.cap.get("b")


class TestTheGate(_Base):
    def test_flipping_the_control_demands_a_re_auth(self):
        self.save({"change_approval_enabled": False})
        self.assertEqual(len(self.stepups), 1)

    def test_an_ordinary_settings_save_does_not(self):
        """If every save prompted, operators would stop reading the prompt."""
        self.save({"server_name": "Other"})
        self.assertEqual(self.stepups, [])

    def test_the_change_is_named_in_the_audit_trail(self):
        """"config_save changed 41 keys" is not an answer to "who turned
        four-eyes off, and when"."""
        self.save({"change_approval_enabled": False})
        acts = dict(self.audits)
        self.assertIn("governance_config_change", acts)
        self.assertIn("change_approval_enabled", acts["governance_config_change"])

    def test_the_step_up_runs_before_anything_is_written(self):
        """A gate that fires after the save has already happened is decoration."""
        from srcpin import py_function
        src = (_CGI / "api.py").read_text()
        body = py_function(src, "handle_config_save")
        # The persist is `with _LockedUpdate(CONFIG_FILE)`, not a bare
        # save() — searching for the wrong write call would make this pass
        # vacuously wherever it happened not to match.
        self.assertLess(body.index("require_step_up()"),
                        body.index("_LockedUpdate(CONFIG_FILE)"))

    def test_a_refused_step_up_leaves_the_config_alone(self):
        def _refuse():
            api.respond(403, {"error": "step-up re-authentication required",
                              "code": "step_up_required"})
        api.require_step_up = _refuse
        self.save({"change_approval_enabled": False})
        self.assertEqual(self.cap["s"], 403)
        api._invalidate_load_cache(api.CONFIG_FILE)
        self.assertTrue(api.load(api.CONFIG_FILE)["change_approval_enabled"])


class TestTheClientRetries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = ROOT / "server" / "html" / "static" / "js" / "app.js"
        if not p.exists():
            raise unittest.SkipTest("excluded from this tree")
        cls.js = p.read_text()

    def test_the_settings_save_goes_through_withStepUp(self):
        """Without it the operator gets a bare 403 and no way to satisfy it."""
        self.assertIn("withStepUp(() => api('POST', '/config', payload))", self.js)

    def test_withStepUp_prompts_and_retries(self):
        body = self.js[self.js.index("async function withStepUp("):]
        body = body[:body.index("\n}\n")]
        self.assertIn("step_up_required", body)
        self.assertIn("_openStepUpModal()", body)
        self.assertIn("data = await callFn()", body)


class TestTheRestIsStillOpen(unittest.TestCase):
    """Said in a test rather than only in a commit message, so the next person
    reading this does not mistake it for the whole finding."""

    def test_administrative_permissions_are_still_one_bit(self):
        self.assertNotIn("users", api._RBAC_PERMS)
        self.assertNotIn("config", api._RBAC_PERMS)

    def test_which_is_why_the_governance_keys_needed_a_different_mechanism(self):
        """Step-up protects the switches without inventing a permission
        namespace across 284 require_admin_auth() call sites."""
        src = (_CGI / "api.py").read_text()
        self.assertGreater(src.count("require_admin_auth()"), 200)


if __name__ == "__main__":
    unittest.main()
