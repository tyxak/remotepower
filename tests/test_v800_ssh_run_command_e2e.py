#!/usr/bin/env python3
"""8.0.0: Run command on an agentless host that is reached over SSH, in a browser on the demo seed, against a real sshd.

POST /api/devices/<id>/ssh-exec existed, was documented, and the drawer's own hint says an SSH host "runs commands over SSH", but the Actions grid hid Run command for every
agentless host. It shows for a host whose reachability is SSH now, opens the same dialog without the agent queue's wait and timeout rows, runs the command at once and shows the
output and the exit code. The server half is held by tests/test_v800_direct_exec_gates.py; this file holds what a person presses and reads.

An unprivileged OpenSSH sshd (the ordinary user, 127.0.0.1, a free port, a key made here, no password login) answers for the host, so what comes back is what a real ssh client and
a real sshd said. The key is the server's agentless key (Settings, Security); the run adds the server's address to this user's known_hosts, and the module removes it again.
Self-skips without playwright / Chromium / gunicorn / sshd / ssh-keygen, and runs under the default storage backend only.
"""
import getpass
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
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


_SSHD = shutil.which("sshd") or "/usr/bin/sshd"
_STATE_SSH = {}


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _start_sshd():
    """An sshd of the ordinary user on a free loopback port that accepts one key. Returns (port, private key text)."""
    work = Path(tempfile.mkdtemp(prefix="rp-ssh-run-sshd-"))
    key = work / "id_ed25519"
    host = work / "host_ed25519"
    for target in (key, host):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(target)], check=True, capture_output=True)
    (work / "authorized_keys").write_text((key.with_suffix(".pub")).read_text())
    os.chmod(work / "authorized_keys", 0o600)
    port = _free_port()
    (work / "sshd_config").write_text("\n".join([
        "Port %d" % port, "ListenAddress 127.0.0.1", "HostKey %s" % host, "PidFile %s" % (work / "sshd.pid"), "AuthorizedKeysFile %s" % (work / "authorized_keys"),
        "UsePAM no", "PasswordAuthentication no", "KbdInteractiveAuthentication no", "PubkeyAuthentication yes", "StrictModes no", "LogLevel ERROR", ""]))
    proc = subprocess.Popen([_SSHD, "-f", str(work / "sshd_config"), "-D", "-e"], stdout=subprocess.DEVNULL, stderr=open(work / "sshd.log", "wb"))
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
            break
        except OSError:
            if proc.poll() is not None:
                raise unittest.SkipTest("sshd did not start: %s" % (work / "sshd.log").read_text()[-300:])
            time.sleep(0.1)
    else:
        proc.terminate()
        raise unittest.SkipTest("sshd did not answer on port %d" % port)
    _STATE_SSH.update(proc=proc, port=port, work=work)
    return port, key.read_text()


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("the lists are backend-agnostic: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    if not (os.path.exists(_SSHD) and shutil.which("ssh") and shutil.which("ssh-keygen")):
        raise unittest.SkipTest("no OpenSSH client and server on this machine")
    data_dir = tempfile.mkdtemp(prefix="rp-ssh-run-e2e-")
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
    try:
        _start_sshd()
    except BaseException:
        tearDownModule()
        raise


def tearDownModule():
    try:
        _STATE["browser"].close()
        _STATE["pw"].stop()
    finally:
        if _STATE.get("shutdown"):
            _STATE["shutdown"]()
        proc = _STATE_SSH.get("proc")
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            # the runs added the loopback sshd's host key to this user's known_hosts: take that entry out again
            subprocess.run(["ssh-keygen", "-q", "-R", "[127.0.0.1]:%d" % _STATE_SSH["port"]], capture_output=True)
            shutil.rmtree(_STATE_SSH["work"], ignore_errors=True)


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



SSH_HOST = "sw01"        # the demo's switch-core: an agentless host
ICMP_HOST = "sw02"       # another one, left on ICMP
AGENT_HOST = "gt01"      # a host with the agent
SUBTITLE_SSH = "Runs over SSH as the SSH user set for this host, with the key from Settings → Security. The output comes back here."


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestRunCommandOverSsh(unittest.TestCase):

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
        cls.config0 = read("config.json")
        cls.devices0 = read("devices.json")

    @classmethod
    def tearDownClass(cls):
        try:
            write("config.json", cls.config0)
            write("devices.json", cls.devices0)
        finally:
            cls.ctx.close()

    def setUp(self):
        cfg = json.loads(json.dumps(self.config0))
        cfg.update(agentless_ssh_enabled=True, agentless_ssh_key=_key())
        cfg.pop("maintenance_mode", None)
        write("config.json", cfg)
        devices = json.loads(json.dumps(self.devices0))
        devices[SSH_HOST].update(reachability="ssh", ssh_host="127.0.0.1", ssh_user=getpass.getuser(), ssh_port=_STATE_SSH["port"])
        for d in devices.values():
            d.pop("quarantined", None)
        write("devices.json", devices)
        self.marker = Path(_STATE_SSH["work"]) / "marker"
        if self.marker.exists():
            self.marker.unlink()

    def tearDown(self):
        self.page.evaluate("""() => {
          document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id));
          if (typeof closeDeviceDrawer === 'function') closeDeviceDrawer();
        }""")

    def open_drawer(self, dev_id):
        name = read("devices.json")[dev_id]["name"]
        self.page.evaluate("([id, name]) => openDeviceDrawer(id, name)", [dev_id, name])
        self.page.wait_for_function("() => document.querySelectorAll('#drawer-actions-grid .drawer-action-btn').length > 0", timeout=30000)

    def actions(self):
        return self.page.eval_on_selector_all("#drawer-actions-grid .drawer-action-btn", "els => els.map(e => e.dataset.actLabel)")

    def open_run(self, dev_id=SSH_HOST):
        self.open_drawer(dev_id)
        self.page.click('#drawer-actions-grid .drawer-action-btn[data-act-label="run command"]')
        self.page.wait_for_selector("#exec-modal.active", timeout=20000)

    def run_command(self, command):     # not `run`: that is the name unittest calls a test case by
        self.page.fill("#exec-cmd", command)
        self.page.click("#exec-run-btn")
        self.page.wait_for_function("() => { const r = document.getElementById('exec-result'); return r && !r.classList.contains('d-none') && !/Running/.test(r.textContent); }", timeout=40000)
        return self.page.inner_text("#exec-result")

    def test_run_command_is_there_for_a_host_reached_over_ssh_and_not_for_the_others(self):
        self.open_drawer(SSH_HOST)
        self.assertIn("run command", self.actions())
        self.page.evaluate("() => closeDeviceDrawer()")
        self.open_drawer(ICMP_HOST)
        self.assertNotIn("run command", self.actions(), "an agentless host on ICMP has no way to run a command")
        self.page.evaluate("() => closeDeviceDrawer()")
        self.open_drawer(AGENT_HOST)
        self.assertIn("run command", self.actions())

    def test_the_dialog_for_an_ssh_host_says_what_it_does_and_drops_the_agent_queues_rows(self):
        self.open_run()
        self.assertEqual(self.page.inner_text("#exec-subtitle").strip(), SUBTITLE_SSH)
        self.assertTrue(self.page.eval_on_selector("#exec-timeout", "e => e.closest('.form-group').classList.contains('d-none')"))
        self.assertTrue(self.page.eval_on_selector("#exec-wait", "e => e.closest('.form-group').classList.contains('d-none')"))
        self.assertIn("switch-core", self.page.inner_text("#exec-modal-title"))

    def test_the_dialog_for_an_agent_host_is_the_one_it_always_was(self):
        self.open_run(AGENT_HOST)
        self.assertIn("Output returned on next heartbeat", self.page.inner_text("#exec-subtitle"))
        self.assertFalse(self.page.eval_on_selector("#exec-timeout", "e => e.closest('.form-group').classList.contains('d-none')"))
        self.assertFalse(self.page.eval_on_selector("#exec-wait", "e => e.closest('.form-group').classList.contains('d-none')"))

    def test_a_command_runs_on_the_real_sshd_and_its_output_and_exit_code_are_on_screen(self):
        self.open_run()
        text = self.run_command("echo hello-from-ssh; id -un")
        self.assertIn("Output", text)
        self.assertIn("(exit 0)", text)
        self.assertIn("hello-from-ssh", text)
        self.assertIn(getpass.getuser(), text)
        audit = json.dumps(read("audit_log.json"))
        self.assertIn("ssh_exec", audit)
        self.assertIn("hello-from-ssh", audit, "the command is in the audit trail")

    def test_a_command_that_fails_shows_its_exit_code(self):
        self.open_run()
        text = self.run_command("echo oops >&2; exit 3")
        self.assertIn("(exit 3)", text)
        self.assertIn("oops", text)

    def test_the_output_is_text_and_never_markup(self):
        self.open_run()
        self.run_command("echo '<img src=x onerror=\"window.__pwned=1\">'")
        self.assertEqual(self.page.eval_on_selector_all("#exec-result img", "els => els.length"), 0)
        self.assertEqual(self.page.evaluate("() => window.__pwned || 0"), 0)

    def test_a_quarantined_host_is_refused_in_words_and_nothing_runs(self):
        devices = read("devices.json")
        devices[SSH_HOST]["quarantined"] = True
        write("devices.json", devices)
        self.open_run()
        text = self.run_command("touch %s" % self.marker)
        self.assertIn("quarantined", text)
        self.assertFalse(self.marker.exists(), "the command did not run")

    def test_maintenance_mode_refuses_in_words_and_nothing_runs(self):
        cfg = read("config.json")
        cfg.update(maintenance_mode=True, maintenance_reason="controller upgrade")
        write("config.json", cfg)
        self.open_run()
        text = self.run_command("touch %s" % self.marker)
        self.assertIn("maintenance mode", text)
        self.assertFalse(self.marker.exists())

    def test_a_host_with_an_allowlist_refuses_a_command_that_is_not_on_it(self):
        devices = read("devices.json")
        devices[SSH_HOST]["allowed_commands"] = ["uptime"]
        write("devices.json", devices)
        self.open_run()
        text = self.run_command("touch %s" % self.marker)
        self.assertIn("not in allowed_commands", text)
        self.assertFalse(self.marker.exists())

    def test_agentless_ssh_switched_off_says_where_to_switch_it_on(self):
        cfg = read("config.json")
        cfg["agentless_ssh_enabled"] = False
        write("config.json", cfg)
        self.open_run()
        self.assertIn("Settings → Security", self.run_command("uptime"))

    def test_the_words_are_translated_in_all_six_languages(self):
        self.open_run()
        self.page.evaluate("async () => { await _ensureI18n(); }")
        english = self.page.inner_text("#exec-subtitle").strip()
        bad = []
        try:
            for lang in LANGS:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(300)
                if self.page.inner_text("#exec-subtitle").strip() == english:
                    bad.append(lang)
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
        self.assertEqual(bad, [])

    def test_nothing_in_the_page_broke_on_the_way(self):
        self.open_run()
        self.run_command("uptime")
        self.assertEqual([e for e in self.errors if "Failed to load resource" not in e], [])


def _key():
    return Path(_STATE_SSH["work"], "id_ed25519").read_text()


if __name__ == "__main__":
    unittest.main()
