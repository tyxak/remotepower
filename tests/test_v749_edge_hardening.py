#!/usr/bin/env python3
"""The small findings of the 7.4.9 reviews that are not part of a larger fix (authorization matrix F8 and F9, web client W3 to W12).

Each is measured the way it would be abused, and each check names the control that shows it can see the old behaviour:

* F8  a session and the throttle of the CSP report took the proxy's own address (`REMOTE_ADDR`) for every client;
* F9  `DELETE /api/devices/{id}/runbook` and `/drift` were answered by the host-delete route first and could not be reached;
* W3  the delegated click handlers called `window[<attribute>]`, so a name such as `alert`, `open` or `eval` ran with chosen arguments;
* W4  `/#oidc_token=<anyone's token>` signed the browser into that session with no check that this tab started the sign-in;
* W5  the debug log button opened a tab, which cannot send the token;
* W6  Sign out left the AI conversation, the infrastructure-as-code page's host and instructions and two more per-person keys;
* W7  the public status answer named every monitor, and a label is usually a host name;
* W10 `target="_blank"` links without `rel`, and `window.open` of an external address with a handle to this tab;
* W11 the service worker cached `/install?t=<token>` and the status page with its token;
* W12 the portal escaped a name that was then written as text.

JavaScript is run in node (the check skips when node is not installed; RP_NODE_REQUIRE=1 makes that a failure).
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import srcpin  # noqa: E402

NODE = shutil.which("node")
JS = ROOT / "server" / "html" / "static" / "js"
API_SRC = (ROOT / "server" / "cgi-bin" / "api.py").read_text()


def run_node(script):
    r = subprocess.run([NODE, "-e", script], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise AssertionError(r.stderr[-1500:])
    return json.loads(r.stdout.strip().splitlines()[-1])


def _need_node(test):
    return unittest.skipUnless(NODE or os.environ.get("RP_NODE_REQUIRE") == "1", "node is not installed")(test)


class TestSessionsRecordTheClientNotTheProxy(unittest.TestCase):
    """F8"""

    def test_nothing_but_the_helper_reads_remote_addr(self):
        body = srcpin.py_function(API_SRC, "_get_client_ip")
        rest = API_SRC.replace(body, "")
        self.assertEqual(re.findall(r"_env\('REMOTE_ADDR'", rest), [], "a caller reads the proxy's address directly")

    def test_a_session_behind_the_proxy_records_the_forwarded_address(self):
        d = Path(tempfile.mkdtemp(prefix="rp-f8-"))
        os.environ.setdefault("RP_DATA_DIR", str(d))
        import importlib.util
        spec = importlib.util.spec_from_file_location("api_f8", ROOT / "server" / "cgi-bin" / "api.py")
        api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(api)
        saved = (api.TOKENS_FILE, os.environ.get("REMOTE_ADDR"), os.environ.get("HTTP_X_FORWARDED_FOR"))
        api.TOKENS_FILE = d / "tokens.json"
        os.environ["REMOTE_ADDR"] = "127.0.0.1"
        os.environ["HTTP_X_FORWARDED_FOR"] = "198.51.100.7"
        try:
            api._LOAD_CACHE.clear()
            tok = api._mint_session("alice")
            rows = api.load(api.TOKENS_FILE)
            ips = [v.get("ip") for v in rows.values() if isinstance(v, dict)]
            self.assertIn("198.51.100.7", ips, ips)
            self.assertNotIn("127.0.0.1", ips, "the session took nginx's own address")
            self.assertTrue(tok)
        finally:
            api.TOKENS_FILE = saved[0]
            for k, v in (("REMOTE_ADDR", saved[1]), ("HTTP_X_FORWARDED_FOR", saved[2])):
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


class TestTheTwoShadowedDeleteRoutes(unittest.TestCase):
    """F9"""

    def setUp(self):
        import importlib.util
        os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-f9-"))
        spec = importlib.util.spec_from_file_location("api_f9", ROOT / "server" / "cgi-bin" / "api.py")
        self.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.api)

    def test_the_host_delete_route_leaves_runbook_and_drift_alone(self):
        deleted = []
        self.api.handle_device_delete = lambda dev: deleted.append(dev)
        for tail in ("runbook", "drift"):
            with self.subTest(tail=tail):
                self.assertFalse(self.api._route_code_5("/api/devices/ng01/" + tail, "DELETE"))
        self.assertEqual(deleted, [])

    def test_control_the_host_delete_route_still_deletes_a_host(self):
        deleted = []
        self.api.handle_device_delete = lambda dev: deleted.append(dev)
        self.assertTrue(self.api._route_code_5("/api/devices/ng01", "DELETE"))
        self.assertEqual(deleted, ["ng01"])

    def test_both_handlers_have_a_route(self):
        text = API_SRC
        for handler in ("handle_runbook_delete", "handle_device_drift_reset"):
            self.assertRegex(text, r"'%s'," % handler)


class TestThePublicStatusNamesNoMonitor(unittest.TestCase):
    """W7"""

    def setUp(self):
        import importlib.util
        self.d = Path(tempfile.mkdtemp(prefix="rp-w7-"))
        os.environ.setdefault("RP_DATA_DIR", str(self.d))
        spec = importlib.util.spec_from_file_location("api_w7", ROOT / "server" / "cgi-bin" / "api.py")
        self.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.api)
        api = self.api
        self._saved = {a: getattr(api, a) for a in ("CONFIG_FILE", "DEVICES_FILE", "MON_HIST_FILE", "CONTROL_UPTIME_FILE")}
        for a in self._saved:
            setattr(api, a, self.d / Path(getattr(api, a)).name)
        api.save(api.CONFIG_FILE, {"status_token": "tok-w7"})
        api.save(api.DEVICES_FILE, {})
        api.save(api.MON_HIST_FILE, {"Route to Frankfurt DC (truenas.lab)": [{"ts": 1, "ok": True}],
                                      "Critical hosts . proxmox.lab": [{"ts": 1, "ok": False}]})
        self._env, self._respond = api._env, api.respond
        api._env = lambda k, d=None: ("token=tok-w7" if k == "QUERY_STRING" else d)
        self.cap = {}

        def _resp(status, body=None):
            self.cap["b"] = body
            raise api.HTTPError(status, body)
        api.respond = _resp

    def tearDown(self):
        for a, v in self._saved.items():
            setattr(self.api, a, v)
        self.api._env, self.api.respond = self._env, self._respond

    def test_the_list_counts_monitors_and_names_none(self):
        try:
            self.api.handle_public_status()
        except self.api.HTTPError:
            pass
        mon = self.cap["b"]["monitors"]
        text = json.dumps(mon)
        self.assertNotIn("truenas", text)
        self.assertNotIn("proxmox", text)
        self.assertEqual((mon["total"], mon["up"], mon["down"]), (2, 1, 1), "the counts are unchanged")
        self.assertEqual(sorted(m["label"] for m in mon["items"]), ["Monitor 1", "Monitor 2"])
        self.assertEqual([m["up"] for m in mon["items"]], [False, True], "down first, as before")


class TestTheClientHandlersCallOnlyApplicationFunctions(unittest.TestCase):
    """W3"""

    @_need_node
    def test_the_dispatcher_refuses_native_functions_and_odd_names(self):
        js = (JS / "app.js").read_text()
        name = re.search(r"const _DISPATCH_NAME = [^\n]+", js).group(0)
        fn = srcpin.js_function(js, "_dispatchFn")
        script = f"""
        const window = globalThis;
        function openTicket() {{ return 1; }}
        const bound = function() {{}}.bind(null); window.boundHandler = bound;
        // a browser's alert, open and print are native; node has none, so native built-ins stand in under those names
        window.alert = Math.floor; window.open = Math.max; window.print = parseInt;
        {name}
        {fn}
        const names = ['openTicket', 'boundHandler', 'alert', 'open', 'print', 'eval', 'Function', 'isNaN', 'escape',
                       'constructor', '__proto__', 'a.b', 'a b', '', 'openTicket()', 'toString', 'missing'];
        const got = Object.create(null);     // a plain object would take '__proto__' as its prototype, not as a key
        for (const n of names) got[n] = typeof _dispatchFn(n) === 'function';
        got['null'] = _dispatchFn(null) === undefined;
        console.log(JSON.stringify(got));
        """
        got = run_node(script)
        self.assertTrue(got["openTicket"], "a function this application declares is a handler")
        self.assertTrue(got["boundHandler"], "a bound function is let through by name")
        for n in ("alert", "open", "print", "eval", "Function", "isNaN", "escape", "toString"):
            self.assertFalse(got[n], n + " is native code")
        for n in ("constructor", "__proto__", "a.b", "a b", "", "openTicket()", "missing"):
            self.assertFalse(got[n], repr(n))
        self.assertTrue(got["null"])

    def test_every_delegated_handler_goes_through_it(self):
        js = (JS / "app.js").read_text()
        for attr in ("actionBtn", "action", "action2", "change", "input"):
            self.assertNotIn("window[el.dataset.%s]" % attr, js)
            self.assertNotIn("window[btnEl.dataset.%s]" % attr, js)
        self.assertNotIn("window[e.target.getAttribute('data-enter')]", js)
        self.assertGreaterEqual(js.count("_dispatchFn("), 8)

    def test_every_dispatch_name_in_the_markup_is_a_function_the_scripts_declare(self):
        """The dispatcher would silently turn a native name into a dead control, so the population is checked: no data-action
        names a native function."""
        raw = "\n".join(p.read_text(errors="replace") for p in [ROOT / "server/html/index.html"] + sorted(JS.glob("*.js")))
        text = "\n".join(ln for ln in raw.split("\n") if not ln.lstrip().startswith(("//", "*", "/*")))   # prose is not markup
        names = set(re.findall(r"""data-(?:action|action-btn|action2|change|input|enter)=["']([A-Za-z_$][\w$]*)["']""", text))
        declared = set(re.findall(r"(?:^|\n)\s*(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(", text))
        declared |= set(re.findall(r"window\.([A-Za-z_$][\w$]*)\s*=", text))
        declared |= set(re.findall(r"(?:^|\n)\s*(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=", text))
        native = {"alert", "open", "print", "close", "confirm", "prompt", "eval", "fetch", "reload", "focus", "blur", "scroll"}
        self.assertEqual(sorted(n for n in names if n in native and n not in declared), [])
        self.assertGreater(len(names), 800, "the population collapsed: the pattern no longer finds the dispatch names")


class TestSsoSignInBindsToTheTabThatStartedIt(unittest.TestCase):
    """W4"""

    def script(self, scenario):
        js = (JS / "app-calendar.js").read_text()
        started = srcpin.js_function(js, "_ssoStartedHere")
        consume = srcpin.js_function(js, "_consumeOidcHashToken")
        return f"""
        const store = () => {{ const m = new Map(); return {{ getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)),
                                                           removeItem: k => m.delete(k), _m: m }}; }};
        global.sessionStorage = store(); global.localStorage = store();
        const calls = {{ replace: [], reload: 0, state: [] }};
        global.location = {{ hash: '', pathname: '/', replace: u => calls.replace.push(u), reload: () => {{ calls.reload++; }} }};
        global.history = {{ replaceState: (...a) => calls.state.push(a) }};
        {started}
        {consume}
        {scenario}
        console.log(JSON.stringify({{ token: localStorage.getItem('rp_token'), me: localStorage.getItem('rp_me'),
                                      replace: calls.replace, reload: calls.reload, pending: sessionStorage.getItem('rp_sso_pending') }}));
        """

    @_need_node
    def test_a_link_with_a_token_and_no_sign_in_of_this_tab_is_dropped(self):
        got = run_node(self.script("location.hash = '#oidc_token=ATTACKER&username=mallory'; _consumeOidcHashToken();"))
        self.assertIsNone(got["token"])
        self.assertEqual(got["reload"], 0)
        self.assertEqual(len(got["replace"]), 1)
        self.assertIn("oidc_error=", got["replace"][0])

    @_need_node
    def test_the_tab_that_pressed_the_button_is_signed_in_once(self):
        got = run_node(self.script(
            "sessionStorage.setItem('rp_sso_pending', String(Date.now())); location.hash = '#oidc_token=REAL&username=alice'; "
            "_consumeOidcHashToken();"))
        self.assertEqual((got["token"], got["me"], got["reload"]), ("REAL", "alice", 1))
        self.assertIsNone(got["pending"], "the mark is single-use")

    @_need_node
    def test_a_mark_older_than_fifteen_minutes_is_not_good(self):
        got = run_node(self.script(
            "sessionStorage.setItem('rp_sso_pending', String(Date.now() - 16 * 60 * 1000)); location.hash = '#oidc_token=OLD&username=a'; "
            "_consumeOidcHashToken();"))
        self.assertIsNone(got["token"])

    @_need_node
    def test_an_idp_initiated_saml_sign_in_works_only_where_the_server_allows_it(self):
        base = "location.hash = '#saml_token=S&username=bob'; _consumeOidcHashToken();"
        self.assertIsNone(run_node(self.script(base))["token"])
        got = run_node(self.script("localStorage.setItem('rp_saml_unsolicited', '1'); " + base))
        self.assertEqual(got["token"], "S")
        got = run_node(self.script("localStorage.setItem('rp_saml_unsolicited', '1'); location.hash = '#oidc_token=O&username=a'; _consumeOidcHashToken();"))
        self.assertIsNone(got["token"], "the exception is for SAML only")

    def test_the_buttons_mark_the_tab_and_the_login_page_remembers_the_server_setting(self):
        js = (JS / "app-calendar.js").read_text()
        self.assertIn("login-oidc-btn, #login-saml-btn", js)
        self.assertIn("rp_sso_pending", js)
        self.assertIn("rp_saml_unsolicited", js)
        self.assertIn("'saml_unsolicited':", API_SRC)


class TestOtherClientFindings(unittest.TestCase):

    def test_w5_the_debug_log_is_fetched_with_the_token(self):
        body = srcpin.js_function((JS / "app.js").read_text(), "downloadDebugLog")
        self.assertIn("_downloadAuthed('/api/debug-log'", body)
        self.assertNotIn("window.open", body)

    def test_w6_sign_out_clears_every_per_person_key(self):
        body = srcpin.js_function((JS / "app.js").read_text(), "doLogout")
        for key in ("rp.ai.conv", "rp_iac_last_device", "rp_iac_instructions", "rp_metric_explorer_v1", "rp_activity_cleared"):
            self.assertIn(key, body)

    def test_w10_every_new_tab_link_says_noopener(self):
        for page in ("index.html", "swagger.html"):
            text = (ROOT / "server" / "html" / page).read_text()
            for m in re.finditer(r"<a\b[^>]*target=\"_blank\"[^>]*>", text):
                self.assertIn("noopener", m.group(0), (page, m.group(0)[:100]))

    def test_w10_an_external_sidebar_link_gets_no_handle_to_this_tab(self):
        js = (JS / "app.js").read_text()
        self.assertIn("window.open(extBtn.dataset.openHref, '_blank', 'noopener,noreferrer')", js)

    def test_w12_the_portal_does_not_escape_a_name_it_writes_as_text(self):
        text = (JS / "portal.js").read_text()
        self.assertNotRegex(text, r"textContent\s*=\s*[^;\n]*esc\(")

    @_need_node
    def test_w11_the_service_worker_keeps_secrets_out_of_its_cache(self):
        sw = (ROOT / "server" / "html" / "sw.js").read_text()
        fn = srcpin.js_function(sw, "_worthCaching")
        script = f"""
        {fn}
        const R = (status, cc, type) => ({{ status, type: type || 'basic', headers: {{ get: () => cc || '' }} }});
        const Q = u => ({{ url: 'https://rp.example' + u }});
        const out = {{
          shell: _worthCaching(Q('/static/js/app.js'), R(200)),
          versioned: _worthCaching(Q('/static/js/app.js?v=0123abcd'), R(200)),
          install: _worthCaching(Q('/install?t=ENROLL-TOKEN'), R(200)),
          status: _worthCaching(Q('/status.html?token=SHARE'), R(200)),
          noStore: _worthCaching(Q('/'), R(200, 'no-store')),
          missing: _worthCaching(Q('/x'), R(404)),
          none: _worthCaching(Q('/x'), null),
          err: _worthCaching(Q('/x'), R(200, '', 'error')),
        }};
        console.log(JSON.stringify(out));
        """
        got = run_node(script)
        self.assertEqual(got, {"shell": True, "versioned": True, "install": False, "status": False, "noStore": False,
                               "missing": False, "none": False, "err": False})
        self.assertEqual(sw.count("if (_worthCaching(request, response))"), 2, "both caching paths go through it")


if __name__ == "__main__":
    unittest.main()
