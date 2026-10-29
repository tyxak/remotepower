#!/usr/bin/env python3
"""v7.4.5 security review, the parts that need a running server and a browser.

test_v745_security holds the rules in process. This holds what only the real stack shows: that the pre-dispatch
tenant gate and the role check answer as they should over HTTP, that a write from another origin is refused, that
toggles racing heartbeats on one host leave the stored rows and the switch in agreement, and that text planted in
the strings the switch prints is shown as text and runs nothing.

Self-skips without playwright/chromium/gunicorn, like its siblings.
"""
import collections
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
for p in (_HERE, _ROOT / "server" / "cgi-bin"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import browser_required  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

from e2e_harness import SKIP_REASON, browser_available, start_stack  # noqa: E402

_GATE = browser_available() or browser_required.required()
PW = "Probe-Passw0rd-1"

# What the setup writes: the users, the tenants, the roles and a host in each tenant, through the product's own
# storage, in a data directory of its own.
_SETUP = r"""
import os, sys, time
sys.path.insert(0, os.environ["RP_CGI"])
import api
now = int(time.time())
pw = os.environ["RP_PW"]
def user(role, tenant=None):
    u = {"role": role, "password_hash": api.hash_password(pw), "created": now}
    if tenant:
        u["tenant_id"] = tenant
    return u
def ports():
    return [{"proto": "tcp", "port": 443, "process": "nginx", "addr": "0.0.0.0", "scope": "world"},
            {"proto": "tcp", "port": 22, "process": "sshd", "addr": "::", "scope": "world"},
            {"proto": "tcp", "port": 5432, "process": "postgres", "addr": "127.0.0.1", "scope": "local"}]
def host(i, tenant, addrs):
    return {"id": i, "name": i, "hostname": i, "tenant": tenant, "token": "tok-" + i, "last_seen": now, "enrolled": now,
            "tags": [], "group": "", "monitored": True, "sysinfo": {"listening_ports": ports(), "host_addresses": addrs}}
api.save(api.CONFIG_FILE, {"tenancy_enforced": True, "port_audit_enabled": True})
api.save(api.TENANTS_FILE, {"tenantA": {"name": "A", "status": "active", "created": now},
                            "tenantB": {"name": "B", "status": "active", "created": now}})
api.save(api.ROLES_FILE, {"roles": [{"name": "ops", "permissions": sorted(api._RBAC_PERMS), "scope": {"type": "all"}}]})
api.save(api.USERS_FILE, {"alice": user("admin"), "adminA": user("admin", "tenantA"), "adminB": user("admin", "tenantB"),
                          "viewA": user("viewer", "tenantA"), "opsA": user("ops", "tenantA")})
api.save(api.DEVICES_FILE, {"hostA": host("hostA", "tenantA", ["192.168.1.20"]),
                            "hostB": host("hostB", "tenantB", ["10.1.1.5", "203.0.113.9"])})
"""


def ports():
    return [{"proto": "tcp", "port": 443, "process": "nginx", "addr": "0.0.0.0", "scope": "world"},
            {"proto": "tcp", "port": 22, "process": "sshd", "addr": "::", "scope": "world"},
            {"proto": "tcp", "port": 5432, "process": "postgres", "addr": "127.0.0.1", "scope": "local"}]


class _Http:
    def __init__(self, base):
        self.base = base

    def call(self, method, path, token=None, body=None, raw=None, headers=None):
        path = urllib.parse.quote(path, safe="/%'?=&:;@")
        h = {"Content-Type": "application/json"}
        if token:
            h["X-Token"] = token
        h.update(headers or {})
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read()
            finally:
                e.close()

    def login(self, user):
        return json.loads(self.call("POST", "/api/login", body={"username": user, "password": PW})[1])["token"]


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestOverTheRealStack(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
            raise unittest.SkipTest("what is measured is the stack, not the backend")
        cls.dir = tempfile.mkdtemp(prefix="rp-v745sec-")
        r = subprocess.run([sys.executable, "-c", _SETUP], capture_output=True, text=True, timeout=300,
                           env=dict(os.environ, RP_DATA_DIR=cls.dir, RP_CGI=str(_ROOT / "server" / "cgi-bin"), RP_PW=PW))
        if r.returncode != 0:
            raise unittest.SkipTest("setup failed: " + r.stderr[-300:])
        try:
            cls.base, cls.shutdown = start_stack(data_dir=cls.dir)
        except Exception as exc:
            raise unittest.SkipTest(f"app stack not available: {exc}")
        cls.http = _Http(cls.base)
        cls.tok = {u: cls.http.login(u) for u in ("alice", "adminA", "adminB", "viewA", "opsA")}

    @classmethod
    def tearDownClass(cls):
        cls.shutdown()

    def call(self, *a, **k):
        return self.http.call(*a, **k)

    def devices(self):
        return json.loads((Path(self.dir) / "devices.json").read_text())

    def reset(self):
        for h, addrs in (("hostA", ["192.168.1.20"]), ("hostB", ["10.1.1.5", "203.0.113.9"])):
            self.call("PUT", f"/api/devices/{h}/exposure-internal", self.tok["alice"], {"internal": False})
            self.call("POST", "/api/heartbeat", None, {"device_id": h, "token": "tok-" + h,
                                                      "sysinfo": {"listening_ports": ports(), "host_addresses": addrs}})

    def test_who_may_set_it_and_on_which_host(self):
        for who, host, want in (("alice", "hostA", 200), ("alice", "hostB", 200), ("adminA", "hostA", 200), ("adminA", "hostB", 403),
                                ("adminB", "hostA", 403), ("adminB", "hostB", 200), ("viewA", "hostA", 403),
                                ("opsA", "hostA", 403)):
            self.reset()
            got = self.call("PUT", f"/api/devices/{host}/exposure-internal", self.tok[who], {"internal": True})[0]
            self.assertEqual(got, want, f"{who} on {host}")
            self.assertEqual(self.devices()[host].get("exposure_internal") is True, want == 200, f"{who} on {host}")

    def test_the_exposure_answer_shows_each_tenant_its_own_hosts(self):
        self.reset()
        for h in ("hostA", "hostB"):
            self.call("PUT", f"/api/devices/{h}/exposure-internal", self.tok["alice"], {"internal": True})
        seen = {}
        for who in ("alice", "adminA", "adminB", "viewA", "opsA"):
            j = json.loads(self.call("GET", "/api/exposure", self.tok[who])[1])
            seen[who] = (sorted({r["device_id"] for r in j["ports"]}), sorted(j["hosts"]))
        self.assertEqual(seen["alice"], (["hostA", "hostB"], ["hostA", "hostB"]))
        self.assertEqual(seen["adminA"], (["hostA"], ["hostA"]))
        self.assertEqual(seen["viewA"], (["hostA"], ["hostA"]))
        self.assertEqual(seen["opsA"], (["hostA"], ["hostA"]))
        self.assertEqual(seen["adminB"], (["hostB"], ["hostB"]))
        self.assertNotIn("203.0.113.9", self.call("GET", "/api/exposure", self.tok["adminA"])[1].decode())

    def test_a_write_from_another_origin_is_refused(self):
        self.reset()
        path = "/api/devices/hostA/exposure-internal"
        self.assertEqual(self.call("PUT", path, self.tok["alice"], {"internal": True}, headers={"Origin": self.base})[0], 200)
        self.assertEqual(self.call("PUT", path, self.tok["alice"], {"internal": False}, headers={"Origin": "https://evil.example"})[0], 403)
        self.assertIs(self.devices()["hostA"].get("exposure_internal"), True)

    def test_a_request_that_does_not_say_true_or_false_is_refused_over_http(self):
        self.reset()
        path = "/api/devices/hostA/exposure-internal"
        self.call("PUT", path, self.tok["alice"], {"internal": True})
        for raw in (b"", b"null", b"[]", b"{", b'{"internal": null}', b'{"internal": "true"}', b'{"internal": 1}'):
            for ctype in ("application/json", "text/plain"):
                s = self.call("PUT", path, self.tok["alice"], raw=raw, headers={"Content-Type": ctype})[0]
                self.assertEqual(s, 400, (raw, ctype))
        self.assertIs(self.devices()["hostA"].get("exposure_internal"), True, "none of them changed the switch")
        self.assertEqual(self.call("PUT", path, self.tok["alice"], {"internal": False})[0], 200)

    def test_a_host_token_reaches_nothing_of_another_host(self):
        for method, path, body in (("PUT", "/api/devices/hostB/exposure-internal", {"internal": True}),
                                   ("GET", "/api/devices/hostB/exposure-internal", None)):
            self.assertIn(self.call(method, path, "tok-hostA", body)[0], (401, 403))
        self.assertIn(self.call("POST", "/api/heartbeat", None, {"device_id": "hostB", "token": "tok-hostA", "sysinfo": {}})[0], (401, 403))

    def test_hostile_ids_and_bodies_never_answer_5xx(self):
        bad = []
        for i in ("nope", "../etc/passwd", "..%2f..%2fetc", "a" * 5000, "hostA%00", "host A", "‮", "😀", "hostA/../hostB"):
            for m in ("GET", "PUT", "DELETE", "POST", "PATCH"):
                s = self.call(m, f"/api/devices/{i}/exposure-internal", self.tok["alice"], {"internal": True} if m != "GET" else None)[0]
                if s >= 500:
                    bad.append((m, i[:20], s))
        self.assertEqual(bad, [])
        self.assertEqual(set(self.devices()), {"hostA", "hostB"}, "a DELETE never reached the host")

    def test_toggles_racing_heartbeats_leave_the_rows_and_the_switch_in_agreement(self):
        self.reset()
        path = "/api/devices/hostA/exposure-internal"
        stop = time.time() + 6
        seen = collections.Counter()

        def toggler(n):
            i = 0
            while time.time() < stop:
                seen[("PUT", self.call("PUT", path, self.tok["alice"], {"internal": (i + n) % 2 == 0})[0])] += 1
                i += 1

        def beater(n):
            i = 0
            while time.time() < stop:
                addrs = ["192.168.1.20"] if (i + n) % 3 else ["192.168.1.20", "203.0.113.9"]
                seen[("HB", self.call("POST", "/api/heartbeat", None, {"device_id": "hostA", "token": "tok-hostA",
                                                                       "sysinfo": {"listening_ports": ports(), "host_addresses": addrs}})[0])] += 1
                i += 1
        threads = [threading.Thread(target=toggler, args=(n,)) for n in range(2)] + [threading.Thread(target=beater, args=(n,)) for n in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertGreater(sum(seen.values()), 100, "the race did not run")
        self.assertEqual([k for k in seen if not (isinstance(k[1], int) and k[1] < 500)], [], dict(seen))
        self.call("POST", "/api/heartbeat", None, {"device_id": "hostA", "token": "tok-hostA",
                                                  "sysinfo": {"listening_ports": ports(), "host_addresses": ["192.168.1.20"]}})
        d = self.devices()["hostA"]
        switch = d.get("exposure_internal") is True
        for r in d["sysinfo"]["listening_ports"]:
            wildcard = r["port"] in (443, 22)
            self.assertEqual(bool(r.get("assumed")), switch and wildcard, r)
            self.assertEqual(r["scope"], "lan" if switch and wildcard else ("world" if wildcard else "local"), r)


PAY = '"><img src=x onerror="window.__pwned=(window.__pwned||0)+1">'
PAY2 = "<svg/onload=window.__pwned=(window.__pwned||0)+1>"


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestPlantedTextInABrowser(unittest.TestCase):
    """Markup in the strings the switch prints, put into the stored records past the ingest (which would have refused
    most of it): a host's name, the process and bind address of its sockets, and an entry of its address list that is
    no address. On the Exposure page, in the Ports card of the drawer and in the confirmation of the button."""

    @classmethod
    def setUpClass(cls):
        if sync_playwright is None:
            browser_required.skip_or_fail("playwright not installed")
        if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
            raise unittest.SkipTest("what is measured is the page, not the backend")
        seeder = _ROOT / "packaging" / "seed-demo-data.py"
        if not seeder.is_file():
            raise unittest.SkipTest("demo seeder not in this tree")
        cls.dir = tempfile.mkdtemp(prefix="rp-v745plant-")
        r = subprocess.run([sys.executable, str(seeder), "--data-dir", cls.dir, "--apply"], capture_output=True, cwd=str(_ROOT), timeout=900)
        if r.returncode != 0:
            raise unittest.SkipTest("demo seeder failed")
        path = Path(cls.dir) / "devices.json"
        devs = json.loads(path.read_text())
        devs["nc01"]["name"] = "nextcloud" + PAY
        devs["nc01"]["sysinfo"]["host_addresses"] = ["203.0.113.40", PAY2]
        for row in devs["nc01"]["sysinfo"]["listening_ports"]:
            row["process"] = "proc" + PAY
            row["addr"] = "0.0.0.0" + PAY2
        for row in devs["jf01"]["sysinfo"]["listening_ports"]:
            row["process"] = "jf" + PAY2
        devs["ng01"]["name"] = "nginx" + PAY          # a name that breaks out of an attribute, on a host nobody marked
        devs["ng01"]["sysinfo"]["listening_ports"][-1]["scope"] = PAY2      # a scope that is no word, on the last row only
        path.write_text(json.dumps(devs))
        cls.pw = sync_playwright().start()
        try:
            cls.browser = cls.pw.chromium.launch()
        except Exception as exc:
            cls.pw.stop()
            browser_required.skip_or_fail(f"chromium not available: {exc}")
        try:
            cls.base, cls.shutdown = start_stack(data_dir=cls.dir)
        except Exception as exc:
            cls.browser.close()
            cls.pw.stop()
            raise unittest.SkipTest(f"app stack not available: {exc}")
        ctx = cls.browser.new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        cls.page = ctx.new_page()
        cls.page.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); } catch (e) {}")
        cls.errors, cls.dialogs = [], []
        cls.page.on("pageerror", lambda e: cls.errors.append(str(e)))
        cls.page.on("dialog", lambda d: (cls.dialogs.append(d.message), d.dismiss()) and None)
        cls.page.goto(cls.base + "/index.html")
        cls.page.fill("#login-user", "alice")
        cls.page.fill("#login-pass", "demo")
        cls.page.click('#login-form button[type="submit"]')
        cls.page.wait_for_selector("#app", state="visible", timeout=90000)
        cls.page.wait_for_timeout(6000)

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.pw.stop()
        cls.shutdown()

    def seen(self):
        """(ran, elements, planted text occurrences): nothing may run, nothing may become an element, and the text has to
        be on the page, or 'nothing ran' would only mean 'nothing was shown'."""
        self.page.wait_for_timeout(1500)
        ran = self.page.evaluate("() => window.__pwned || 0")
        elements = self.page.evaluate("""() => document.querySelectorAll('img[src="x"], svg[onload], [onerror]').length""")
        text = self.page.evaluate("""() => (document.body.innerText.match(/<img src=x onerror|<svg\\/onload/g) || []).length""")
        return ran, elements, text

    def open_exposure(self):
        self.page.evaluate("showPage('exposure')")
        self.page.wait_for_function("() => document.querySelectorAll('#exposure-tbody tr td').length > 6", timeout=60000)

    def test_the_exposure_page_shows_planted_text_as_text(self):
        self.open_exposure()
        ran, elements, text = self.seen()
        self.assertEqual((ran, elements), (0, 0))
        self.assertGreater(text, 20, "the planted text reached the page")
        reason = self.page.evaluate("() => [...document.querySelectorAll('#exposure-tbody .hint code')].map(c => c.textContent)")
        self.assertTrue(any(PAY2 in r for r in reason), reason)
        self.assertEqual(self.page.evaluate("() => document.querySelectorAll('#exposure-tbody .hint code *').length"), 0)

    def test_the_confirmation_prints_a_hostile_name_as_text(self):
        self.open_exposure()
        opened = self.page.evaluate("""() => { for (const tr of document.querySelectorAll('#exposure-tbody tr')) {
            const b = tr.querySelector('button[data-action="setHostInternal"][data-arg3="1"]');
            if (b && tr.querySelector('[data-dev-hover="ng01"]')) { b.click(); return true; } } return false; }""")
        self.assertTrue(opened, "the hostile-named host has a button")
        self.page.wait_for_function("() => document.getElementById('ui-prompt-message').textContent.includes('nginx')", timeout=15000)
        self.assertIn(PAY, self.page.evaluate("() => document.getElementById('ui-prompt-message').textContent"))
        self.assertEqual(self.page.evaluate("() => document.getElementById('ui-prompt-message').children.length"), 0)
        self.page.evaluate("() => { const b = document.querySelector('#ui-prompt-modal .btn-secondary'); if (b) b.click(); }")
        self.assertEqual(self.seen()[:2], (0, 0))

    def test_the_ports_card_shows_planted_text_as_text(self):
        for dev_id, name in (("nc01", "nextcloud"), ("jf01", "jellyfin.lab"), ("ng01", "nginx")):
            self.page.evaluate("([i, n]) => openDeviceDrawer(i, n, 'audit')", [dev_id, name])
            self.page.wait_for_selector("#audit-body-ports", state="attached", timeout=30000)
            self.page.evaluate("() => _loadAuditSection('ports')")
            self.page.wait_for_function("() => { const b = document.getElementById('audit-body-ports'); return b && b.querySelector('table.ports-table'); }", timeout=30000)
            ran, elements, text = self.seen()
            self.assertEqual((ran, elements), (0, 0), dev_id)
            self.assertGreater(text, 0, dev_id)
            self.page.evaluate("closeDeviceDrawer()")
        self.assertEqual((self.errors, self.dialogs), ([], []))


if __name__ == "__main__":
    unittest.main()
