#!/usr/bin/env python3
"""8.0.0: the wizards of the sidecars, in a browser on the demo seed, against the real sidecars where this machine can run them.

What each wizard has to do, and what this file runs to see it:

  Receive logs   a new host is made from a name and an IPv4 address, a syslog token is pinned to it (one, however often the step is gone back to), the receiver's state is
                 read from Server Status, the sender's settings are shown with this server's address and the port, and the wizard waits for the first line and says when it came.
                 It runs against the REAL syslog receiver (server/syslog/remotepower-syslogd.py, started as a program on a loopback port, mapping the source address 127.0.0.1 to the
                 host it was told about) and a real UDP datagram: the line goes receiver, API, token, and the wizard reads the token's count.
  Receive flows  the same for the flow receiver. The flow receiver is not run (it would need NetFlow packets): the count of the token is raised in the store the way a forwarded
                 rollup raises it.
  Relay satellite the satellite is made, its command carries the token and this server's address, and the wizard waits for it to connect. The REAL satellite
                 (client/remotepower-satellite.py) is started from the token the page showed, and the page says it connected.

Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only.
"""
import json
import os
import re
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
except ImportError:                                     # pragma: no cover
    sync_playwright = None

_STATE = {}
LANGS = ("zh", "hi", "es", "ar", "de", "fr")


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("the wizards are backend-agnostic: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-sidecar-wizards-")
    proc = subprocess.run([sys.executable, str(seeder), "--data-dir", data_dir, "--apply"], capture_output=True, cwd=str(_ROOT), timeout=900)
    if proc.returncode != 0:
        raise unittest.SkipTest("demo seeder failed: " + proc.stderr.decode(errors="replace")[-300:])
    from e2e_harness import start_stack
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
    _STATE.update(pw=pw, browser=browser, base=base, shutdown=shutdown, data_dir=data_dir)


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
    return json.loads(_path(name).read_text()) if _path(name).exists() else {}


def write(name, doc):
    tmp = _path(name).with_suffix(".tmp")
    tmp.write_text(json.dumps(doc))
    before = _path(name).stat().st_mtime if _path(name).exists() else 0
    stamp = max(before + 2, time.time())            # a file written twice in a second can be read by the server as the first version
    os.utime(tmp, (stamp, stamp))
    os.replace(tmp, _path(name))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@unittest.skipUnless(_GATE, SKIP_REASON)
class _Wizards(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
        cls.ctx, cls.page, cls.errors = ctx, ctx.new_page(), []
        cls.page.on("pageerror", lambda e: cls.errors.append(str(e)))
        cls.page.goto(_STATE["base"] + "/index.html")
        cls.page.fill("#login-user", "alice")                # the seeder builds its own operator accounts: there is no 'admin'
        cls.page.fill("#login-pass", "demo")
        cls.page.click('#login-form button[type="submit"]')
        cls.page.wait_for_selector("#app", state="visible", timeout=90000)
        cls.page.wait_for_timeout(3500)
        cls.files0 = {n: read(n) for n in ("devices.json", "inbound_webhooks.json", "satellites.json")}

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
        self.procs = []
        self.addCleanup(self.stop_all)

    def tearDown(self):
        self.page.evaluate("() => { document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id)); }")

    def stop_all(self):
        for p in self.procs:
            try:
                p.terminate()
                p.wait(timeout=10)
            except Exception:
                p.kill()

    def open(self, name, first):
        self.page.evaluate("(n) => wizOpen(n)", name)
        self.page.wait_for_selector("#wizard-modal.active", timeout=30000)
        self.page.wait_for_selector(first, timeout=30000)

    def steps(self):
        return self.page.eval_on_selector_all("#wiz-steps .wiz-lbl", "els => els.map(e => e.textContent)")

    def next(self, wait_for):
        self.page.click("#wiz-next")
        self.page.wait_for_selector(wait_for, timeout=30000)

    def text(self, sel):
        return self.page.inner_text(sel)

    def watch(self):
        return self.page.inner_text("#wiz-watch")


class TestTheSyslogWizardWithTheRealReceiver(_Wizards):

    def start_receiver(self):
        port = free_port()
        log = open(Path(tempfile.mkdtemp(prefix="rp-syslogd-")) / "syslogd.log", "w")
        proc = subprocess.Popen([sys.executable, str(_ROOT / "server" / "syslog" / "remotepower-syslogd.py")], stdout=log, stderr=log, stdin=subprocess.DEVNULL,
                                env=dict(os.environ, RP_DATA_DIR=_STATE["data_dir"], RP_SYSLOG_BIND="127.0.0.1:%d" % port, RP_SYSLOG_SERVER_URL=_STATE["base"]))
        self.procs.append(proc)
        return port

    def keep_sending(self, port):
        """A syslog line from 127.0.0.1 every half second until stopped: the receiver reloads the map of sources on a timer of its own, so the first lines may be dropped."""
        stop = threading.Event()

        def run():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            while not stop.is_set():
                s.sendto(b"<14>Nov  8 12:00:00 e2e-firewall test: hello from the wizard test", ("127.0.0.1", port))
                stop.wait(0.5)
            s.close()
        t = threading.Thread(target=run, daemon=True)
        t.start()
        self.addCleanup(lambda: (stop.set(), t.join(5)))

    def make_host_step(self, name="e2e-firewall", ip="127.0.0.1"):
        self.open("syslog", "#wiz-rx-sender")
        self.assertEqual(self.steps(), ["Sender", "Receiver", "Send", "Done"])
        self.page.check('input[name="wiz-rx-mode"][value="new"]')
        self.page.fill("#wiz-rx-name", name)
        self.page.fill("#wiz-rx-ip", ip)

    def test_a_line_from_a_new_host_reaches_the_real_receiver_and_the_wizard_says_so(self):
        port = self.start_receiver()
        self.make_host_step()
        self.next("#wiz-rx-state")
        hosts = [(i, d) for i, d in read("devices.json").items() if d.get("name") == "e2e-firewall"]
        self.assertEqual(len(hosts), 1, "the new host is made when the step is left")
        host_id, host = hosts[0]
        self.assertEqual((host["ip"], host.get("agentless"), host.get("device_type")), ("127.0.0.1", True, "firewall"))
        self.page.wait_for_function("() => document.getElementById('wiz-rx-state').textContent.trim() !== 'Loading…' && document.getElementById('wiz-rx-state').textContent.trim() !== ''", timeout=20000)
        self.assertIn("Not detected on this server", self.text("#wiz-rx-state"), "there is no systemd unit of the receiver here: it was started as a program")
        self.assertEqual(self.page.evaluate("() => document.getElementById('wiz-rx-install').dataset.rawText"), "sudo ./install-server.sh --with-syslogd")
        self.assertIn("UDP", self.text("#wizard-modal"))
        self.next("#wiz-watch")
        self.assertEqual(self.steps()[2], "Send")
        body = self.text("#wiz-body")
        self.assertIn("Point the sender at this server", body)
        self.assertIn("Open the guide", body)
        self.assertEqual(self.page.get_attribute("#wiz-body a", "href"), "docs/opnsense.md#send-the-firewalls-logs")
        self.assertIn("127.0.0.1", body)
        self.assertIn("UDP 5514", body)
        tokens = [t for t in read("inbound_webhooks.json").get("tokens", []) if t.get("scope_device_id") == host_id]
        self.assertEqual([(t["kind"], t["enabled"]) for t in tokens], [("syslog", True)], "one syslog token, pinned to the host")
        self.assertIn("Waiting for the first line", self.watch())
        self.keep_sending(port)
        self.page.wait_for_function("() => /Arriving/.test(document.getElementById('wiz-watch').textContent)", timeout=90000)
        self.next("text=It is arriving")
        self.assertIn("Lines received", self.text("#wiz-body"))
        hits = int(read("inbound_webhooks.json")["tokens"][-1]["hit_count"])
        self.assertGreaterEqual(hits, 1, "the receiver forwarded the line to the API and the token counted it")
        self.assertTrue(self.page.locator('#wiz-body [data-action="wizRxOpenHost"]').count() == 1)

    def test_going_back_does_not_make_a_second_host_or_a_second_token(self):
        self.make_host_step("e2e-twice")
        self.next("#wiz-rx-state")
        self.next("#wiz-watch")
        self.page.click("#wiz-back")
        self.page.wait_for_selector("#wiz-rx-state", timeout=20000)
        self.page.click("#wiz-back")
        self.page.wait_for_selector("#wiz-rx-sender", timeout=20000)
        self.assertTrue(self.page.is_checked('input[name="wiz-rx-mode"][value="existing"]'), "the host that was made is now the one that is picked")
        self.page.wait_for_selector("#wiz-rx-host", timeout=20000)
        self.assertEqual(self.page.eval_on_selector("#wiz-rx-host", "s => s.options[s.selectedIndex].textContent"), "e2e-twice · 127.0.0.1")
        self.next("#wiz-rx-state")
        self.next("#wiz-watch")
        self.assertEqual(len([d for d in read("devices.json").values() if d.get("name") == "e2e-twice"]), 1)
        self.assertEqual(len([t for t in read("inbound_webhooks.json").get("tokens", []) if t.get("kind") == "syslog" and "e2e-twice" in t.get("label", "")]), 1)

    def test_each_refusal_says_what_to_change_and_goes_no_further(self):
        self.open("syslog", "#wiz-rx-sender")
        self.page.click("#wiz-next")
        self.assertEqual(self.page.inner_text("#wiz-msg"), "Choose a host")
        self.page.check('input[name="wiz-rx-mode"][value="new"]')
        self.page.click("#wiz-next")
        self.assertEqual(self.page.inner_text("#wiz-msg"), "Name required")
        self.page.fill("#wiz-rx-name", "x")
        for bad in ("", "10.0.0", "300.1.1.1", "10.0.0.1.5", "host.lan", "::1", "10.0.0.1/24"):
            self.page.fill("#wiz-rx-ip", bad)
            self.page.click("#wiz-next")
            self.assertEqual(self.page.inner_text("#wiz-msg"), "Enter an IPv4 address such as 192.0.2.10", bad)
        self.assertEqual(self.steps()[0], "Sender")
        self.assertEqual([d for d in read("devices.json").values() if d.get("name") == "x"], [])

    def test_a_host_without_an_address_is_refused_in_words(self):
        devices = json.loads(json.dumps(self.files0["devices.json"]))
        devices["fw01"]["ip"] = ""
        write("devices.json", devices)
        self.open("syslog", "#wiz-rx-sender")
        self.page.wait_for_selector("#wiz-rx-host", timeout=20000)
        self.page.select_option("#wiz-rx-host", "fw01")
        self.page.click("#wiz-next")
        self.assertEqual(self.page.inner_text("#wiz-msg"), "That host has no address. Give it one on its page, or add a new host here.")

    def test_a_sender_that_is_set_up_with_commands_gets_them_with_this_servers_address(self):
        self.make_host_step("e2e-mikrotik")
        self.page.select_option("#wiz-rx-sender", "mikrotik")
        self.next("#wiz-rx-state")
        self.page.fill("#wiz-rx-server", "192.0.2.10")
        self.next("#wiz-watch")
        cmd = self.page.evaluate("() => document.getElementById('wiz-rx-cmd').dataset.rawText")
        self.assertIn("/system logging action add name=remotepower target=remote remote=192.0.2.10 remote-port=5514", cmd)
        self.assertEqual(cmd.count("/system logging add topics="), 4)
        self.assertEqual(self.page.locator("#wiz-rx-test").count(), 0, "no test line for a router that has no logger")

    def test_the_title_and_the_first_step_are_translated_in_all_six_languages(self):
        self.open("syslog", "#wiz-rx-sender")
        self.page.evaluate("async () => { await _ensureI18n(); }")
        english = self.page.evaluate("() => [document.getElementById('wiz-title').textContent, document.querySelector('.wiz-q').textContent]")
        bad = []
        try:
            for lang in LANGS:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(200)
                now = self.page.evaluate("() => [document.getElementById('wiz-title').textContent, document.querySelector('.wiz-q').textContent]")
                if now[0] == english[0] or now[1] == english[1]:
                    bad.append((lang, now))
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
        self.assertEqual(bad, [])


class TestTheFlowWizard(_Wizards):

    def pick(self, host_id, sender):
        self.open("flow", "#wiz-rx-sender")
        self.page.wait_for_selector("#wiz-rx-host", timeout=20000)
        self.page.select_option("#wiz-rx-host", host_id)
        self.page.select_option("#wiz-rx-sender", sender)

    def test_an_existing_host_gets_a_flow_token_and_the_senders_commands_and_the_wizard_waits_for_a_record(self):
        self.pick("fw01", "mikrotik")
        self.assertEqual(self.page.eval_on_selector_all("#wiz-rx-sender option", "els => els.map(e => e.textContent)"), ["OPNsense", "pfSense", "MikroTik RouterOS", "Cisco IOS", "Something else"])
        self.next("#wiz-rx-state")
        self.page.wait_for_function("() => /Not detected|Running/.test(document.getElementById('wiz-rx-state').textContent)", timeout=20000)
        self.assertEqual(self.page.evaluate("() => document.getElementById('wiz-rx-install').dataset.rawText"), "sudo ./install-server.sh --with-flowd")
        self.next("#wiz-watch")
        cmd = self.page.evaluate("() => document.getElementById('wiz-rx-cmd').dataset.rawText")
        self.assertEqual(cmd, "/ip traffic-flow set enabled=yes\n/ip traffic-flow target add dst-address=127.0.0.1 port=2055 version=9")
        tokens = [t for t in read("inbound_webhooks.json").get("tokens", []) if t.get("scope_device_id") == "fw01" and t.get("kind") == "flow"]
        self.assertEqual(len(tokens), 1)
        self.assertIn("Waiting for the first record", self.watch())
        self.page.wait_for_timeout(4500)                           # longer than a poll: nothing arrived, so it still waits
        self.assertIn("Waiting for the first record", self.watch())
        doc = read("inbound_webhooks.json")
        for t in doc["tokens"]:
            if t["id"] == tokens[0]["id"]:
                t["hit_count"] = int(t.get("hit_count") or 0) + 3                    # what the flow receiver's forwarded rollups do
        write("inbound_webhooks.json", doc)
        self.page.wait_for_function("() => /Arriving/.test(document.getElementById('wiz-watch').textContent)", timeout=60000)
        self.next("text=It is arriving")
        self.assertIn("Records received", self.text("#wiz-body"))
        self.assertIn("3", self.text("#wiz-body"))

    def test_a_token_that_is_there_is_used_and_not_made_again(self):
        self.pick("fw01", "opnsense")
        self.next("#wiz-rx-state")
        self.next("#wiz-watch")
        self.page.evaluate("() => closeModal('wizard-modal')")
        self.pick("fw01", "cisco")
        self.next("#wiz-rx-state")
        self.next("#wiz-watch")
        self.assertEqual(len([t for t in read("inbound_webhooks.json").get("tokens", []) if t.get("scope_device_id") == "fw01" and t.get("kind") == "flow"]), 1)
        self.assertEqual(self.page.evaluate("() => document.getElementById('wiz-rx-cmd').dataset.rawText"), "ip flow-export version 9\nip flow-export destination 127.0.0.1 2055")

    def test_an_opnsense_sender_gets_the_guide_for_its_page(self):
        self.pick("fw01", "opnsense")
        self.next("#wiz-rx-state")
        self.next("#wiz-watch")
        self.assertEqual(self.page.get_attribute("#wiz-body a", "href"), "docs/opnsense.md#send-traffic-records-netflow")
        self.assertIn("flow export settings", self.text("#wiz-body"))
        self.assertIn("UDP 2055", self.text("#wiz-body"))


class TestTheSatelliteWizard(_Wizards):

    def make(self, name, scanner=False):
        self.open("satellite", "#wiz-sat-name")
        self.assertEqual(self.steps(), ["Satellite", "Install", "Done"])
        self.page.fill("#wiz-sat-name", name)
        if scanner:
            self.page.check('input[name="wiz-sat-kind"][value="scanner"]')
        self.next("#wiz-sat-cmd")
        return self.page.evaluate("() => document.getElementById('wiz-sat-cmd').dataset.rawText")

    def test_the_command_carries_the_token_and_the_address_and_a_real_satellite_started_from_it_connects(self):
        cmd = self.make("e2e-relay")
        origin = self.page.evaluate("() => location.origin")
        m = re.fullmatch(r"sudo RP_UPSTREAM=(\S+) RP_SATELLITE_TOKEN='([A-Za-z0-9_\-]+)' bash packaging/satellite-setup.sh", cmd)
        self.assertIsNotNone(m, cmd)
        self.assertEqual(m.group(1), origin)
        token = m.group(2)
        sats = read("satellites.json")
        self.assertEqual([s["name"] for s in sats.values() if s["name"] == "e2e-relay"], ["e2e-relay"])
        sid = [k for k, s in sats.items() if s["name"] == "e2e-relay"][0]
        import hashlib
        self.assertEqual(sats[sid]["token_hash"], hashlib.sha256(token.encode()).hexdigest(), "the token on screen is the one the server keeps the hash of")
        self.assertFalse(sats[sid]["scanner"])
        self.assertIn("not on https", self.text("#wiz-body"), "the test stack is http: the page says a satellite needs https")
        self.assertTrue(self.page.eval_on_selector("#wiz-back", "b => b.classList.contains('wiz-off')"), "the token is shown once: there is no way back to make another")
        self.assertIn("Waiting for the satellite to connect", self.watch())
        self.page.wait_for_timeout(4500)                           # longer than a poll: nothing has connected, so it still waits
        self.assertIn("Waiting for the satellite to connect", self.watch())
        proc = subprocess.Popen([sys.executable, str(_ROOT / "client" / "remotepower-satellite.py")], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                env=dict(os.environ, RP_UPSTREAM=_STATE["base"], RP_SATELLITE_TOKEN=token, RP_LISTEN="127.0.0.1:%d" % free_port()))
        self.procs.append(proc)
        self.page.wait_for_function("() => /Connected/.test(document.getElementById('wiz-watch').textContent)", timeout=90000)
        self.assertIn("127.0.0.1", self.watch())
        self.next("text=The satellite has connected")
        self.assertIn("e2e-relay", self.text("#wiz-body"))
        self.assertIn("Relay", self.text("#wiz-body"))

    def test_a_scan_worker_gets_the_scanners_installer_and_the_servers_address_under_its_own_name(self):
        cmd = self.make("e2e-scanner", scanner=True)
        origin = self.page.evaluate("() => location.origin")
        self.assertRegex(cmd, r"^sudo RP_SERVER_URL=%s RP_SATELLITE_TOKEN='[A-Za-z0-9_\-]+' bash packaging/scanner-setup.sh$" % re.escape(origin))
        sats = [s for s in read("satellites.json").values() if s["name"] == "e2e-scanner"]
        self.assertEqual([s["scanner"] for s in sats], [True])

    def test_an_empty_name_is_refused_and_nothing_is_made(self):
        self.open("satellite", "#wiz-sat-name")
        before = len(read("satellites.json"))
        self.page.click("#wiz-next")
        self.assertEqual(self.page.inner_text("#wiz-msg"), "Name required")
        self.assertEqual(len(read("satellites.json")), before)

    def test_nothing_in_the_page_broke_on_the_way(self):
        self.open("satellite", "#wiz-sat-name")
        self.open_again = None
        self.assertEqual([e for e in self.errors if "Failed to load resource" not in e], [])


if __name__ == "__main__":
    unittest.main()
