#!/usr/bin/env python3
"""8.0.0: the wizards of the agent push channel and the SSH gateway, in a browser on the demo seed.

Both are sidecars: a daemon that is installed with the server (or by a flag) and does nothing until it is switched on and told where it is. The push wizard checks that its daemon answers, switches the
channel on and waits for the first agent that uses it; the SSH gateway wizard switches the module on with the address users reach it by, checks that the gateway service is connected to this server,
opts hosts in, reads how many keys you have and ends with the block for ~/.ssh/config. The daemons' answer is a TCP connect to the port the server was started with (RP_PUSH_PORT,
RP_SSHGW_WS_PORT), so a listening socket on that port is a real answer; the shared secret is the server's own setting. Everything else is the real server: what is stored is read from the data
directory afterwards, and an agent "using the channel" is a host record with a fresh `push_seen`, which the roster turns into the flag the wizard waits for.

Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import browser_required  # noqa: E402
from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_GATE = browser_available() or browser_required.required()

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover
    sync_playwright = None

_STATE = {}
LANGS = ("zh", "hi", "es", "ar", "de", "fr")


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("the settings are backend-agnostic: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-wizards-push-gw-e2e-")
    proc = subprocess.run([sys.executable, str(seeder), "--data-dir", data_dir, "--apply"], capture_output=True, cwd=str(_ROOT), timeout=900)
    if proc.returncode != 0:
        raise unittest.SkipTest("demo seeder failed: " + proc.stderr.decode(errors="replace")[-300:])
    from e2e_harness import start_stack

    ports = {"RP_PUSH_PORT": _free_port(), "RP_SSHGW_WS_PORT": _free_port()}
    saved = {k: os.environ.get(k) for k in list(ports) + ["RP_SSHGW_SECRET"]}
    os.environ.pop("RP_SSHGW_SECRET", None)           # the gateway service is not connected until the test says so
    for k, v in ports.items():
        os.environ[k] = str(v)                        # the server inherits them: the daemons' ports are the test's
    pw = sync_playwright().start()
    try:
        browser = pw.chromium.launch()
    except Exception as exc:
        pw.stop()
        browser_required.skip_or_fail("chromium not available: %s" % exc)
        return
    try:
        base, shutdown = start_stack(data_dir=data_dir)
    except Exception as exc:
        browser.close()
        pw.stop()
        raise unittest.SkipTest("app stack not available: %s" % exc)
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    _STATE.update(pw=pw, browser=browser, base=base, shutdown=shutdown, data_dir=data_dir, ports=ports)


def tearDownModule():
    try:
        _STATE["browser"].close()
        _STATE["pw"].stop()
    finally:
        if _STATE.get("shutdown"):
            _STATE["shutdown"]()


def _path(name):
    return Path(_STATE["data_dir"]) / name


def read(name):
    return json.loads(_path(name).read_text())


def write(name, doc):
    # a file of the data directory that is written twice in the same second can be read by the server as the first version (its cache looks at the modification time),
    # so every write is given a modification time two seconds after the one it replaces
    tmp = _path(name).with_suffix(".tmp")
    tmp.write_text(json.dumps(doc))
    before = _path(name).stat().st_mtime if _path(name).exists() else 0
    stamp = max(before + 2, time.time())
    os.utime(tmp, (stamp, stamp))
    os.replace(tmp, _path(name))


class _Listener:
    """A socket that accepts connections on a port: what a daemon that is up looks like to a TCP connect."""

    def __init__(self, port):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(8)
        self.stop = False
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        self.sock.settimeout(0.3)
        while not self.stop:
            try:
                c, _ = self.sock.accept()
                c.close()
            except OSError:
                continue

    def close(self):
        self.stop = True
        try:
            self.sock.close()
        except OSError:
            pass


@unittest.skipUnless(_GATE, SKIP_REASON)
class _Wizards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
        cls.ctx, cls.page, cls.errors = ctx, ctx.new_page(), []
        cls.page.set_default_timeout(20000)
        cls.page.on("pageerror", lambda e: cls.errors.append(str(e)))
        cls.page.goto(_STATE["base"] + "/index.html")
        cls.page.fill("#login-user", "alice")
        cls.page.fill("#login-pass", "demo")
        cls.page.click('#login-form button[type="submit"]')
        cls.page.wait_for_selector("#app", state="visible", timeout=90000)
        cls.page.wait_for_timeout(3500)
        cls.files0 = {n: read(n) for n in ("config.json", "devices.json", "users.json")}

    @classmethod
    def tearDownClass(cls):
        try:
            for name, doc in cls.files0.items():
                write(name, doc)
        finally:
            cls.ctx.close()

    def setUp(self):
        for name, doc in self.files0.items():
            write(name, doc)
        self.listeners = []
        self.addCleanup(lambda: [x.close() for x in self.listeners])
        self.baseline()
        self.page.reload()
        self.page.wait_for_selector("#app", state="visible", timeout=90000)
        self.page.wait_for_timeout(2000)

    def tearDown(self):
        self.page.unroute_all(behavior="ignoreErrors")
        self.page.evaluate("() => { document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id)); }")

    def baseline(self):
        """What a test starts from, on disk, before the page is loaded."""

    def listen(self, which):
        x = _Listener(_STATE["ports"][which])
        self.listeners.append(x)
        return x

    def open(self, name):
        self.page.evaluate("(n) => wizOpen(n)", name)
        self.page.wait_for_selector("#wizard-modal.active", timeout=30000)
        self.page.wait_for_selector(".wiz-q", timeout=30000)

    def steps(self):
        return self.page.eval_on_selector_all("#wiz-steps .wiz-lbl", "els => els.map(e => e.textContent)")

    def text(self):
        return self.page.inner_text("#wizard-modal")

    def press_next(self):
        self.page.click("#wiz-next")

    def config(self):
        return read("config.json")

    def says(self, text, timeout=15000):
        self.page.wait_for_function("(t) => document.getElementById('wizard-modal').innerText.includes(t)", arg=text, timeout=timeout)


class TestThePushWizard(_Wizards):
    def baseline(self):
        """The demo has the channel on and most of its Linux agents using it, to show the bolt; the wizard is for an install where no agent does yet."""
        cfg = read("config.json")
        cfg.pop("push_enabled", None)
        write("config.json", cfg)
        devices = read("devices.json")
        for d in devices.values():
            d.pop("push_seen", None)
        write("devices.json", devices)

    def test_it_waits_for_the_daemon_turns_the_channel_on_and_sees_the_first_agent(self):
        self.open("push")
        self.assertEqual(self.steps(), ["Daemon", "Agents", "Done"])
        self.says("The push daemon does not answer")
        self.press_next()
        self.says("The push daemon does not answer yet. Start it, then check again.")
        self.assertFalse(self.config().get("push_enabled"), "nothing is switched on while the daemon is not there")
        self.listen("RP_PUSH_PORT")
        self.page.click('[data-action="wizPushCheck"]')
        self.says("The push daemon answers")
        self.press_next()
        self.says("The channel is on")
        self.assertTrue(self.config().get("push_enabled"))
        self.says("Waiting for an agent to connect…")
        self.page.wait_for_timeout(7000)                               # two looks at the roster: no host uses the channel yet, so nothing is claimed
        self.assertNotIn("Connected", self.text())
        now = int(time.time())
        devices = read("devices.json")
        devices["ng01"].update(last_seen=now, push_seen=now)          # what an agent's heartbeat says when its channel is open
        write("devices.json", devices)
        self.says("Connected", timeout=30000)
        self.press_next()
        self.says("Agents are using it")
        self.assertIn("Hosts using it", self.text())

    def test_an_agent_that_does_not_arrive_gets_what_to_look_at(self):
        self.listen("RP_PUSH_PORT")
        self.open("push")
        self.says("The push daemon answers")
        self.press_next()
        self.says("Waiting for an agent to connect…")
        self.page.evaluate("() => { _wiz.st.watchFrom = Date.now() - 301000; }")
        self.says("No agent has connected after 5 minutes", timeout=15000)
        self.assertIn("python3-websockets", self.text())
        self.press_next()
        self.says("No agent is using it yet")

    def test_a_channel_that_is_already_on_stays_on(self):
        cfg = self.config()
        cfg["push_enabled"] = True
        write("config.json", cfg)
        self.listen("RP_PUSH_PORT")
        self.open("push")
        self.says("The push daemon answers")
        self.press_next()
        self.says("The channel is on")
        self.assertTrue(self.config().get("push_enabled"))

    def test_a_refusal_when_turning_it_on_is_said_and_the_wizard_stays_on_its_step(self):
        self.listen("RP_PUSH_PORT")
        self.open("push")
        self.says("The push daemon answers")
        self.page.route("**/api/config", lambda route: route.fulfill(status=403, content_type="application/json", body=json.dumps({"error": "step-up required"}))
                        if route.request.method == "POST" else route.continue_())
        self.press_next()
        self.says("step-up required")
        self.assertEqual(self.page.inner_text("#wiz-title").strip(), "Turn on the agent push channel")
        self.assertNotIn("The channel is on", self.text())
        self.assertFalse(self.config().get("push_enabled"))

    def test_the_title_and_the_first_step_are_translated_in_all_six_languages(self):
        self.open("push")
        self.page.evaluate("async () => { await _ensureI18n(); }")
        pick = "() => [document.getElementById('wiz-title').textContent, document.querySelector('.wiz-q').textContent]"
        english = self.page.evaluate(pick)
        bad = []
        try:
            for lang in LANGS:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(300)
                now = self.page.evaluate(pick)
                if now[0] == english[0] or now[1] == english[1]:
                    bad.append((lang, now))
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
        self.assertEqual(bad, [])

    def test_the_start_button_is_on_the_settings_page(self):
        self.page.evaluate("() => { showPage('settings'); }")
        self.page.wait_for_function("() => !!document.querySelector('[data-action=\"wizOpen\"][data-arg=\"push\"]')", timeout=30000)
        self.assertEqual(self.page.locator('[data-action="wizOpen"][data-arg="push"]').count(), 1)


class TestTheSshGatewayWizard(_Wizards):
    def baseline(self):
        """The demo has the module on, hosts opted in and keys on its accounts to show the page filled; the wizard is for an install that has none of that yet."""
        cfg = read("config.json")
        for k in ("sshgw_enabled", "sshgw_daemon_secret", "sshgw_public_host", "sshgw_public_port"):
            cfg.pop(k, None)
        write("config.json", cfg)
        devices = read("devices.json")
        for d in devices.values():
            d.pop("sshgw_enabled", None)
        write("devices.json", devices)
        users = read("users.json")
        for u in users.values():
            u.pop("sshgw_keys", None)
        write("users.json", users)

    def fill_address(self, host="gw.example.com", port="2222"):
        self.page.fill("#wiz-gw-host", host)
        self.page.fill("#wiz-gw-port", port)

    def test_the_whole_way_through(self):
        self.open("sshgw")
        self.assertEqual(self.steps(), ["Address", "Service", "Access", "Done"])
        self.fill_address("gw.example.com", "2200")
        self.press_next()
        self.says("Is the gateway service here?")
        cfg = self.config()
        self.assertEqual((cfg.get("sshgw_enabled"), cfg.get("sshgw_public_host"), cfg.get("sshgw_public_port")), (True, "gw.example.com", 2200))
        self.says("The gateway service is not connected to RemotePower yet")
        self.press_next()
        self.says("The gateway service is not connected yet. Install it, then check again.")
        cfg["sshgw_daemon_secret"] = "e2e-shared-secret"
        write("config.json", cfg)
        self.page.click('[data-action="wizGwCheck"]')
        self.says("The gateway service is connected to RemotePower")
        self.says("It does not answer on this server")
        self.listen("RP_SSHGW_WS_PORT")
        self.page.click('[data-action="wizGwCheck"]')
        self.says("It answers on this server")
        self.press_next()
        self.says("Which hosts may be reached through it?")
        self.page.wait_for_selector("input[data-wiz-host]", timeout=20000)
        linux = self.page.evaluate("async () => (await api('GET', '/sshgw/devices')).devices.filter(d => d.linux).map(d => d.device_id)")
        shown = self.page.eval_on_selector_all("input[data-wiz-host]", "els => els.map(e => e.getAttribute('data-wiz-host'))")
        self.assertEqual(sorted(shown), sorted(linux))
        self.assertGreaterEqual(len(shown), 1, "the demo has Linux agent hosts")
        pick = shown[0]
        self.page.check(f'input[data-wiz-host="{pick}"]')
        self.press_next()
        self.says("The gateway is ready")
        self.assertTrue(read("devices.json")[pick].get("sshgw_enabled"), "the ticked host is opted in")
        others = [d for d in shown if d != pick]
        self.assertTrue(all(not read("devices.json")[d].get("sshgw_enabled") for d in others), "and no other")
        text = self.text()
        self.assertIn("gw.example.com:2200", text)
        config_block = self.page.inner_text("#wiz-gw-config") if self.page.locator("#wiz-gw-config").count() else text
        self.assertIn("HostName gw.example.com", config_block)
        self.assertIn("Port 2200", config_block)
        self.assertIn("ProxyJump rp-gateway", config_block)

    def test_the_address_is_checked_before_anything_is_switched_on(self):
        self.open("sshgw")
        self.fill_address("   ", "2222")
        self.press_next()
        self.says("Enter the name your users reach this server by")
        self.fill_address("gw.example.com", "70000")
        self.press_next()
        self.says("Enter a port from 1 to 65535")
        self.assertFalse(self.config().get("sshgw_enabled"))

    def test_a_refusal_when_turning_it_on_is_said_and_the_wizard_stays_on_its_step(self):
        self.open("sshgw")
        self.fill_address()
        self.page.route("**/api/config", lambda route: route.fulfill(status=403, content_type="application/json", body=json.dumps({"error": "step-up required"}))
                        if route.request.method == "POST" else route.continue_())
        self.press_next()
        self.says("step-up required")
        self.assertNotIn("Is the gateway service here?", self.text())
        self.assertFalse(self.config().get("sshgw_enabled"))

    def test_a_host_that_is_already_in_is_ticked_and_cannot_be_cleared_here(self):
        devices = read("devices.json")
        devices["ng01"]["sshgw_enabled"] = True
        write("devices.json", devices)
        cfg = self.config()
        cfg.update(sshgw_enabled=True, sshgw_daemon_secret="e2e-shared-secret")
        write("config.json", cfg)
        self.page.reload()
        self.page.wait_for_selector("#app", state="visible", timeout=90000)
        self.page.wait_for_timeout(2000)
        self.open("sshgw")
        self.press_next()
        self.says("The gateway service is connected to RemotePower")
        self.press_next()
        self.says("Which hosts may be reached through it?")
        self.page.wait_for_selector('input[data-wiz-host="ng01"]', timeout=20000)
        box = self.page.locator('input[data-wiz-host="ng01"]')
        self.assertTrue(box.is_checked())
        self.assertTrue(box.is_disabled())

    def test_with_no_key_the_wizard_says_so_and_opens_the_page_that_adds_one(self):
        cfg = self.config()
        cfg.update(sshgw_enabled=True, sshgw_daemon_secret="e2e-shared-secret")
        write("config.json", cfg)
        self.page.reload()
        self.page.wait_for_selector("#app", state="visible", timeout=90000)
        self.page.wait_for_timeout(2000)
        self.open("sshgw")
        self.press_next()
        self.says("The gateway service is connected to RemotePower")
        self.press_next()
        self.says("Keys on your account")
        self.page.wait_for_selector('[data-action="wizGwOpenPage"]', timeout=20000)
        self.assertIn("asks for your password", self.text())
        self.page.click('[data-action="wizGwOpenPage"]')
        # the dialog is taken out of the page when it closes, so it is gone or inactive
        self.page.wait_for_function("() => { const m = document.getElementById('wizard-modal'); return !m || !m.classList.contains('active'); }", timeout=10000)
        self.page.wait_for_function("() => { const p = document.getElementById('page-sshgw'); return !!p && p.classList.contains('active'); }", timeout=15000)

    def test_the_title_and_the_first_step_are_translated_in_all_six_languages(self):
        self.open("sshgw")
        self.page.evaluate("async () => { await _ensureI18n(); }")
        pick = "() => [document.getElementById('wiz-title').textContent, document.querySelector('.wiz-q').textContent]"
        english = self.page.evaluate(pick)
        bad = []
        try:
            for lang in LANGS:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(300)
                now = self.page.evaluate(pick)
                if now[0] == english[0] or now[1] == english[1]:
                    bad.append((lang, now))
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
        self.assertEqual(bad, [])

    def test_the_start_buttons_are_on_the_gateway_page_and_beside_its_switch(self):
        for page in ("settings", "sshgw"):
            self.page.evaluate("(p) => { showPage(p); }", page)
            self.page.wait_for_timeout(1500)
        self.assertEqual(self.page.locator('[data-action="wizOpen"][data-arg="sshgw"]').count(), 2)

    def test_nothing_in_the_page_broke_on_the_way(self):
        self.open("sshgw")
        self.fill_address()
        self.press_next()
        self.says("Is the gateway service here?")
        self.assertEqual([e for e in self.errors if "Failed to load resource" not in e], [])


if __name__ == "__main__":
    unittest.main()
