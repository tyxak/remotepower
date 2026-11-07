#!/usr/bin/env python3
"""8.0.0: the Automatic updates card on Containers, Image updates, in a browser on the demo seed.

tests/test_v800_image_autoupdate.py holds the rules, the sweep and the routes against the real handlers. This file holds the card a person uses: it shows the
policy and says what the policy would do now, saving off or shadow goes through, switching it on asks for the password first and stores nothing without it,
a refusal of the server is read on the card, the receipts of what ran are listed with their state, and every word has a translation.

Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only.
"""
import json
import os
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
REG = "sha256:" + "b" * 64
OLD = "sha256:" + "a" * 64
# (English text, language) pairs where the right translation is the same word
SAME = {("Images", "de"), ("Images", "fr"), ("Shadow", "de"), ("Hosts per run", "de"), ("Host", "de"), ("Host", "es"), ("State", "de"), ("Detail", "de"), ("Mode", "fr")}


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("the card is backend-agnostic: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-image-autoupdate-")
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
    return json.loads(_path(name).read_text())


def write(name, doc):
    tmp = _path(name).with_suffix(".tmp")
    tmp.write_text(json.dumps(doc))
    os.replace(tmp, _path(name))


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheAutomaticUpdatesCard(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); "
                            "localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
        cls.ctx, cls.page, cls.errors = ctx, ctx.new_page(), []
        cls.page.on("pageerror", lambda e: cls.errors.append(str(e)))
        cls.page.goto(_STATE["base"] + "/index.html")
        cls.page.fill("#login-user", "alice")                # the seeder builds its own operator accounts: there is no 'admin'
        cls.page.fill("#login-pass", "demo")
        cls.page.click('#login-form button[type="submit"]')
        cls.page.wait_for_selector("#app", state="visible", timeout=90000)
        cls.page.wait_for_timeout(3500)
        cls.config0 = read("config.json")
        cls.periods0 = cls.config0.get("time_periods")
        cls.images0 = read("image_updates.json") if _path("image_updates.json").exists() else {}
        cls.containers0 = read("containers.json") if _path("containers.json").exists() else {}

    @classmethod
    def tearDownClass(cls):
        try:
            cfg = read("config.json")
            cfg.pop("image_autoupdate", None)
            write("config.json", cfg)
            write("image_updates.json", cls.images0)
            write("containers.json", cls.containers0)
        finally:
            cls.ctx.close()

    def setUp(self):
        cfg = read("config.json")
        cfg.pop("image_autoupdate", None)
        cfg.pop("time_periods", None)
        if self.periods0 is not None:
            cfg["time_periods"] = self.periods0
        cfg["last_image_autoupdate"] = int(time.time())          # the sweep is not what this file measures
        write("config.json", cfg)
        write("image_updates.json", self.images0)
        write("containers.json", self.containers0)

    def tearDown(self):
        self.page.evaluate("""() => {
          document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id));
          window.__hold = false;
          if (window.__realApi) { window.api = window.__realApi; window.__realApi = null; }
          (window.__held || []).splice(0).forEach(release => release());
        }""")

    def open_card(self):
        """Enter the page and wait until the card shows what the server says now. Entering starts a load of its own, but only after the page's other data
        has come, and the test before may still have a load on its way. So: wait for the entering load to start, then ask once more and wait for that
        one. It is the newest of them, so it is the one that paints, and nothing is left in flight that could land later."""
        self.release_holds()
        self.page.evaluate("async () => { await _loadPageJs('containers'); window.__seq0 = _iauSeq; showPage('containers'); }")
        self.page.wait_for_function("() => _iauSeq > window.__seq0", timeout=30000)
        self.page.evaluate("async () => { await window.__within(loadImageAutoupdate(true)); }")
        self.page.wait_for_selector("#image-autoupdate-card", state="visible")
        self.page.wait_for_function("() => !document.getElementById('iau-save').disabled", timeout=20000)

    def release_holds(self):
        """Let what is held go and stop holding. A failed assertion skips the lines after it, so the next step cannot count on them: the first version
        left the hold on after a failed subtest and the next open_card waited for ever on an answer it was holding itself."""
        self.page.evaluate("""() => {
          window.__hold = false;
          (window.__held || []).splice(0).forEach(release => release());
          window.__within = p => Promise.race([p, new Promise((_, no) => setTimeout(() => no(new Error('the load did not finish in 20 s')), 20000))]);
        }""")

    def hold_answers(self):
        """From now on the answer of GET /api/image-updates/auto reaches the card only when the test lets it, so a test can type while it is on its way."""
        self.page.evaluate("""() => {
          window.__held = [];
          window.__hold = true;
          if (window.__realApi) return;
          window.__realApi = window.api;
          window.api = function (m, p, ...rest) {
            const out = window.__realApi.call(this, m, p, ...rest);
            if (m !== 'GET' || p !== '/image-updates/auto' || !window.__hold) return out;
            return out.then(v => new Promise(r => window.__held.push(() => r(v))));
          };
        }""")

    def wait_held(self, n):
        self.page.wait_for_function("(n) => window.__held.length >= n", arg=n, timeout=20000)

    def wait_policy(self):
        for _ in range(80):
            got = self.policy()
            if got:
                return got
            self.page.wait_for_timeout(250)
        return None

    def policy(self):
        return read("config.json").get("image_autoupdate")

    def fill_card(self, mode=None, include=None, exclude=None, maxh=None, verify=None):
        if mode is not None:
            self.page.select_option("#iau-mode", mode)
        if include is not None:
            self.page.fill("#iau-include", include)
        if exclude is not None:
            self.page.fill("#iau-exclude", exclude)
        if maxh is not None:
            self.page.fill("#iau-max", str(maxh))
        if verify is not None:
            self.page.fill("#iau-verify", str(verify))

    def message(self):
        return self.page.inner_text("#iau-result").strip()

    # ── the card ────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_it_is_on_the_image_updates_tab_off_with_its_words_and_the_subtitle_no_longer_says_notify_only_alone(self):
        self.open_card()
        self.assertEqual(self.page.inner_text("#image-autoupdate-card .section-title").strip(), "Automatic updates")
        self.assertEqual(self.page.input_value("#iau-mode"), "off")
        self.assertEqual(self.page.input_value("#iau-include"), "")
        self.assertEqual((self.page.input_value("#iau-max"), self.page.input_value("#iau-verify")), ("2", "10"))
        text = self.page.inner_text("#image-autoupdate-card")
        self.assertIn("Off by default.", text)
        self.assertIn("It does not roll back.", text)
        self.assertIn("so maintenance mode, quarantine and change approval apply to it", text)
        self.assertIn("unless you switch on automatic updates below", self.page.inner_text("#page-containers"))
        self.assertNotIn("Notify-only", self.page.content())
        options = self.page.eval_on_selector_all("#iau-mode option", "els => els.map(e => e.value)")
        self.assertEqual(options, ["off", "shadow", "on"])
        self.assertEqual(self.page.inner_text("#iau-preview").strip(), "Switch it to shadow or on to see what it would do.")

    def test_shadow_saves_without_the_password_and_the_card_shows_what_was_saved_after_a_reload(self):
        self.open_card()
        self.fill_card(mode="shadow", include="ghcr.io/your-org/*\nLinuxServer/*\n", exclude="*:latest", maxh=3, verify=15)
        self.page.click("#iau-save")
        self.page.wait_for_function("() => document.getElementById('iau-preview').textContent.indexOf('Switch it') < 0", timeout=20000)
        got = self.policy()
        self.assertEqual((got["mode"], got["include"], got["exclude"], got["max_hosts_per_run"], got["verify_after_min"]),
                         ("shadow", ["ghcr.io/your-org/*", "linuxserver/*"], ["*:latest"], 3, 15))
        self.assertIsNone(self.page.query_selector("#step-up-modal.active"), "shadow asked for no password")
        self.page.wait_for_function("() => document.getElementById('iau-include').value === 'ghcr.io/your-org/*\\nlinuxserver/*'", timeout=20000)   # the saved form, written back by the card itself
        self.assertEqual(self.page.input_value("#iau-mode"), "shadow")
        self.assertEqual(self.page.input_value("#iau-include"), "ghcr.io/your-org/*\nlinuxserver/*")
        self.assertEqual(self.page.input_value("#iau-max"), "3")

    def test_on_asks_for_the_password_first_and_stores_nothing_if_it_is_not_given(self):
        self.open_card()
        self.fill_card(mode="on", include="ghcr.io/your-org/*")
        self.page.click("#iau-save")
        self.page.wait_for_selector("#step-up-modal.active", timeout=20000)
        self.assertIsNone(self.policy(), "nothing was stored while the question was open")
        self.page.keyboard.press("Escape")
        self.page.wait_for_function("() => !document.querySelector('#step-up-modal.active')", timeout=10000)
        self.assertIsNone(self.policy(), "and nothing after the question was dismissed")
        self.assertEqual((self.page.input_value("#iau-mode"), self.page.input_value("#iau-include")), ("on", "ghcr.io/your-org/*"), "what was typed is still there")
        self.assertIsNone(self.page.get_attribute("#iau-save", "aria-busy"), "the button is free again after the question was dismissed")
        self.page.click("#iau-save")
        self.page.wait_for_selector("#step-up-modal.active", timeout=20000)
        self.page.fill("#step-up-password", "demo")
        self.page.press("#step-up-password", "Enter")
        self.page.wait_for_function("() => !document.querySelector('#step-up-modal.active')", timeout=20000)
        got = self.wait_policy()
        self.assertEqual((got["mode"], got["include"]), ("on", ["ghcr.io/your-org/*"]))

    def test_the_servers_refusal_is_read_on_the_card_in_its_own_words(self):
        self.open_card()
        self.fill_card(mode="shadow", include="not a pattern")
        self.page.click("#iau-save")
        self.page.wait_for_function("() => document.getElementById('iau-result').textContent.length > 0", timeout=20000)
        self.assertIn("is not an image pattern", self.message())
        self.assertIsNone(self.policy())
        self.fill_card(mode="shadow", include="a/*", maxh=99)
        self.page.click("#iau-save")
        self.page.wait_for_function("() => document.getElementById('iau-result').textContent.indexOf('whole number') >= 0", timeout=20000)
        self.assertIn("whole number from 1 to 10", self.message())
        self.assertIsNone(self.policy())

    def test_a_save_clears_the_last_refusal(self):
        self.open_card()
        self.fill_card(mode="shadow", include="not a pattern")
        self.page.click("#iau-save")
        self.page.wait_for_function("() => document.getElementById('iau-result').textContent.length > 0", timeout=20000)
        self.fill_card(mode="shadow", include="a/*", maxh=2)
        self.page.click("#iau-save")
        self.page.wait_for_function("() => document.getElementById('iau-result').textContent.length === 0", timeout=20000)
        self.assertEqual((self.wait_policy() or {}).get("include"), ["a/*"])
        self.assertEqual(self.message(), "")

    # ── overlapping loads ───────────────────────────────────────────────────────────────────────────────────────────────────
    def form(self):
        return self.page.evaluate("() => Object.fromEntries(['mode', 'period', 'include', 'exclude', 'max', 'verify'].map(k => [k, document.getElementById('iau-' + k).value]))")

    def test_a_slow_answer_does_not_overwrite_what_is_being_typed(self):
        """The first answer can land after the operator began to type: on a big fleet the plan takes a while. It used to refill the form with the stored
        policy, so a Save a second later sent 'off' and an empty list, and said it had worked."""
        self.open_card()
        self.hold_answers()
        self.page.evaluate("() => { window.__load = loadImageAutoupdate(true); }")
        self.wait_held(1)
        self.fill_card(mode="shadow", include="ghcr.io/acme/*", exclude="*:latest", maxh=4)
        self.page.evaluate("async () => { window.__held.shift()(); await window.__within(window.__load); }")
        self.assertEqual(self.form(), {"mode": "shadow", "period": "", "include": "ghcr.io/acme/*", "exclude": "*:latest", "max": "4", "verify": "10"}, "the typed form was kept")
        self.assertEqual(self.page.evaluate("() => _iau.policy.mode"), "off", "the answer itself was still taken")
        self.assertEqual(self.page.inner_text("#iau-preview").strip(), "Switch it to shadow or on to see what it would do.", "and what is not editable was painted")
        self.page.evaluate("() => { window.__hold = false; }")
        self.page.click("#iau-save")
        got = self.wait_policy()
        self.assertEqual((got["mode"], got["include"], got["exclude"], got["max_hosts_per_run"]), ("shadow", ["ghcr.io/acme/*"], ["*:latest"], 4), "Save sent what was typed")

    def test_every_field_of_the_form_is_kept_when_a_slow_answer_lands(self):
        """The guard is one flag set by what the operator types, so each field has to set it: a field that was left out would be overwritten alone."""
        stored = {"mode": "shadow", "period": "night", "include": "stored/*", "exclude": "stored:1", "max": "3", "verify": "20"}
        typed = {"mode": ("off", lambda s: s.page.select_option("#iau-mode", "off")),
                 "period": ("", lambda s: s.page.select_option("#iau-period", "")),
                 "include": ("typed/*", lambda s: s.page.fill("#iau-include", "typed/*")),
                 "exclude": ("typed:1", lambda s: s.page.fill("#iau-exclude", "typed:1")),
                 "max": ("8", lambda s: s.page.fill("#iau-max", "8")),
                 "verify": ("60", lambda s: s.page.fill("#iau-verify", "60"))}
        for field, (value, act) in typed.items():
            with self.subTest(field=field):
                cfg = read("config.json")
                cfg["time_periods"] = [{"id": "night", "name": "Night", "weekly": {}}]
                cfg["image_autoupdate"] = {"mode": "shadow", "include": ["stored/*"], "exclude": ["stored:1"], "period": "night", "max_hosts_per_run": 3, "verify_after_min": 20}
                write("config.json", cfg)
                self.open_card()
                self.assertEqual(self.form(), stored)
                self.hold_answers()
                self.page.evaluate("() => { window.__load = loadImageAutoupdate(true); }")
                self.wait_held(1)
                act(self)
                self.page.evaluate("async () => { window.__held.shift()(); await window.__within(window.__load); }")
                self.assertEqual(self.form(), dict(stored, **{field: value}), "the field that was typed in kept its text, and the rest did not move")
                self.page.evaluate("() => { window.__hold = false; }")

    def test_a_form_nobody_touched_is_filled_by_a_slow_answer(self):
        """The other direction: the guard must not leave an untouched form on the earlier answer."""
        self.open_card()
        cfg = read("config.json")
        cfg["image_autoupdate"] = {"mode": "shadow", "include": ["b/*"], "exclude": [], "period": "", "max_hosts_per_run": 5, "verify_after_min": 30}
        write("config.json", cfg)
        self.hold_answers()
        self.page.evaluate("() => { window.__load = loadImageAutoupdate(true); }")
        self.wait_held(1)
        self.assertEqual(self.form()["mode"], "off", "while the answer is on its way the form still shows the earlier one")
        self.page.evaluate("async () => { window.__held.shift()(); await window.__within(window.__load); }")
        self.assertEqual(self.form(), {"mode": "shadow", "period": "", "include": "b/*", "exclude": "", "max": "5", "verify": "30"})

    def test_entering_the_page_again_shows_what_is_stored_and_not_an_edit_that_was_left(self):
        self.open_card()
        self.fill_card(mode="shadow", include="left/*")
        self.assertEqual(self.form()["include"], "left/*")
        self.open_card()
        self.assertEqual((self.form()["mode"], self.form()["include"]), ("off", ""), "the edit was not saved, so the page shows the stored policy")

    def test_an_older_answer_that_lands_after_a_newer_one_is_dropped(self):
        self.open_card()
        self.hold_answers()
        self.page.evaluate("() => { window.__a = loadImageAutoupdate(true); }")          # asked while the policy is off
        self.wait_held(1)
        cfg = read("config.json")
        cfg["image_autoupdate"] = {"mode": "shadow", "include": ["a/*"], "exclude": [], "period": "", "max_hosts_per_run": 2, "verify_after_min": 10}
        write("config.json", cfg)
        self.page.evaluate("() => { window.__b = loadImageAutoupdate(true); }")          # asked after it was switched to shadow
        self.wait_held(2)
        self.page.evaluate("async () => { window.__held[1](); await window.__within(window.__b); }")
        self.assertEqual(self.form()["mode"], "shadow")
        self.page.evaluate("async () => { window.__held[0](); await window.__within(window.__a); }")
        self.assertEqual(self.form()["mode"], "shadow", "the older answer, which says off, did not replace the newer one")
        self.assertEqual(self.page.evaluate("() => _iau.policy.mode"), "shadow")

    # ── what it would do, and what it did ───────────────────────────────────────────────────────────────────────────────────
    def stale_project(self, ref_image="ghcr.io/acme/web", tag="1", other=None):
        """One host with a compose project whose image is behind the registry, written into the stores the page reads."""
        devices = read("devices.json")
        dev_id = sorted(d for d in devices if not devices[d].get("agentless"))[0]          # an agentless host is held back, and the preview says so
        items = [{"name": "web", "image": ref_image, "tag": tag, "status": "Up 2 hours", "repo_digest": OLD, "compose_dir": "/srv/web", "restart_count": 0}]
        cache = {"%s:%s" % (ref_image, tag): {"registry_digest": REG, "last_checked": int(time.time()), "registry": "ghcr.io"}}
        if other:
            items.append({"name": "cache", "image": other, "tag": "7", "status": "Up 2 hours", "repo_digest": OLD, "compose_dir": "/srv/web", "restart_count": 0})
            cache["%s:7" % other] = {"registry_digest": REG, "last_checked": int(time.time()), "registry": "docker.io"}
        containers = read("containers.json")
        containers[dev_id] = {"reported_at": int(time.time()), "items": items}
        write("containers.json", containers)
        images = read("image_updates.json") if _path("image_updates.json").exists() else {}
        images.setdefault("images", {}).update(cache)
        write("image_updates.json", images)
        return dev_id, devices[dev_id].get("name") or dev_id

    def test_the_preview_says_what_would_be_updated_and_why_a_project_is_held_back(self):
        dev_id, name = self.stale_project()
        self.open_card()
        self.fill_card(mode="shadow", include="ghcr.io/acme/*")
        self.page.click("#iau-save")
        self.page.wait_for_function("(n) => document.getElementById('iau-preview').textContent.indexOf(n) >= 0", arg=name, timeout=20000)
        text = self.page.inner_text("#iau-preview")
        self.assertIn(name, text)
        self.assertIn("/srv/web", text)
        self.assertIn("ghcr.io/acme/web:1", text)
        self.assertIn("Would update", text)
        self.stale_project(other="docker.io/other/cache")
        self.page.evaluate("async () => { await loadImageAutoupdate(true); }")
        held = self.page.inner_text("#iau-preview")
        self.assertIn("not on the list: docker.io/other/cache:7", held)
        self.assertNotIn("Would update", held, "a project with an image that is not on the list is not updated at all")

    def test_the_receipts_are_listed_with_their_state_and_the_last_run_is_told(self):
        dev_id, name = self.stale_project()
        images = read("image_updates.json")
        now = int(time.time())
        images["autoupdate"] = {"receipts": [
            {"id": "r1", "ts": now - 3000, "device_id": dev_id, "device_name": name, "dir": "/srv/web", "refs": ["ghcr.io/acme/web:1"], "state": "ok", "detail": ""},
            {"id": "r2", "ts": now - 2000, "device_id": dev_id, "device_name": name, "dir": "/srv/web", "refs": ["ghcr.io/acme/api:2"], "state": "not_updated",
             "detail": "api still runs the old image of ghcr.io/acme/api:2"},
            {"id": "r3", "ts": now - 1000, "device_id": dev_id, "device_name": name, "dir": "/srv/db", "refs": ["ghcr.io/acme/db:9"], "state": "awaiting_approval", "detail": "waiting for a second admin to approve it"},
            {"id": "r4", "ts": now - 500, "device_id": dev_id, "device_name": name, "dir": "/srv/x", "refs": ["ghcr.io/acme/x:1"], "state": "shadow", "detail": "shadow mode: nothing was queued"}],
            "last_run": {"ts": now - 60, "mode": "shadow", "made": 1, "held": [{"device": name, "dir": "/srv/web", "refs": ["a"], "reason": "host offline"}]}}
        write("image_updates.json", images)
        self.open_card()
        rows = self.page.eval_on_selector_all("#iau-receipts-tbody tr", "els => els.map(e => [...e.children].map(c => c.textContent.trim()))")
        self.assertEqual(len(rows), 4)
        states = {r[2]: r[3] for r in rows}
        self.assertEqual(states, {"ghcr.io/acme/web:1": "Updated", "ghcr.io/acme/api:2": "Not updated", "ghcr.io/acme/db:9": "Waiting for approval", "ghcr.io/acme/x:1": "Shadow"})
        self.assertEqual(rows[0][2], "ghcr.io/acme/x:1", "newest first")
        failed = [r for r in rows if r[3] == "Not updated"][0]
        self.assertIn("still runs the old image", failed[4])
        badge = self.page.eval_on_selector("#iau-receipts-tbody tr:has(td:text-is('ghcr.io/acme/api:2')) .patch-badge", "e => e.className")
        self.assertIn("crit", badge)
        self.assertIn("ok", self.page.eval_on_selector("#iau-receipts-tbody tr:has(td:text-is('ghcr.io/acme/web:1')) .patch-badge", "e => e.className"))
        last = self.page.inner_text("#iau-lastrun")
        self.assertIn("Last run", last)
        self.assertIn("1 queued", last)
        self.assertIn("1 held back", last)
        self.assertGreaterEqual(self.page.eval_on_selector_all("#iau-receipts-thead th[data-col]", "els => els.length"), 5)

    def test_a_deleted_time_period_stays_visible_in_the_list_so_a_save_does_not_drop_it_unseen(self):
        cfg = read("config.json")
        cfg["image_autoupdate"] = {"mode": "shadow", "include": ["a/*"], "exclude": [], "period": "gone", "max_hosts_per_run": 2, "verify_after_min": 10}
        cfg["time_periods"] = [{"id": "night", "name": "Night", "weekly": {}}]
        write("config.json", cfg)
        self.open_card()
        options = self.page.eval_on_selector_all("#iau-period option", "els => els.map(e => [e.value, e.textContent])")
        self.assertEqual(options, [["", "Any time"], ["night", "Night"], ["gone", "gone"]])
        self.assertEqual(self.page.input_value("#iau-period"), "gone")

    def test_a_user_who_is_not_an_administrator_cannot_press_save(self):
        self.open_card()
        self.page.evaluate("async () => { _meCache = Object.assign({}, _meCache, { admin: false }); await loadImageAutoupdate(true); }")
        self.assertTrue(self.page.is_disabled("#iau-save"))
        self.page.evaluate("async () => { _meCache = Object.assign({}, _meCache, { admin: true }); await loadImageAutoupdate(true); }")
        self.assertFalse(self.page.is_disabled("#iau-save"))

    # ── words ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_every_word_of_the_card_has_a_translation_in_all_six_languages(self):
        dev_id, name = self.stale_project(other="docker.io/other/cache")
        images = read("image_updates.json")
        now = int(time.time())
        images["autoupdate"] = {"receipts": [{"id": "r%d" % i, "ts": now - i, "device_id": dev_id, "device_name": name, "dir": "/srv/web", "refs": ["x/y:%d" % i], "state": st, "detail": ""}
                                             for i, st in enumerate(("shadow", "queued", "awaiting_approval", "ok", "not_updated", "unhealthy", "unverified", "declined"))],
                                "last_run": {"ts": now - 60, "made": 1, "held": []}}
        write("image_updates.json", images)
        self.open_card()
        self.fill_card(mode="shadow", include="ghcr.io/acme/*")
        self.page.click("#iau-save")
        self.page.wait_for_function("(n) => document.getElementById('iau-preview').textContent.indexOf(n) >= 0", arg=name, timeout=20000)
        self.assertTrue(self.page.evaluate("async () => { await _ensureI18n(); return !!window.RPi18n; }"), "i18n.js did not load")
        texts = self.page.evaluate("""() => {
          const out = new Set();
          document.querySelectorAll('#image-autoupdate-card *').forEach(e => {
            if (e.matches('script, style, input, textarea, .mono-12, strong, #iau-lastrun, #iau-preview, #iau-period option + option, [data-i18n-park]')) return;   // data and glue: the own text of the two boxes (their spans are the phrases) and the names of the time periods
            if (e.closest('#iau-receipts-tbody td.hint-nowrap, #iau-receipts-tbody td.fw-500')) return;
            const own = [...e.childNodes].filter(n => n.nodeType === 3).map(n => n.textContent).join('').trim();
            if (own) out.add(own);
          });
          return [...out];
        }""")
        texts = {t for t in texts if not (t.startswith(("·", "/", "ghcr", "docker", ":")) or t.replace(" ", "").replace("·", "").isdigit() or "—" == t)}
        # the pieces of a line built from a number and a word are translated as the word
        texts = {t.lstrip("·— ").strip() for t in texts}
        texts = {t for t in texts if t and not t.replace(" ", "").isdigit() and not t.startswith(("/", "ghcr", "docker", "x/y")) and any(c.isalpha() for c in t)}   # a glyph such as the sort arrow is not a word
        self.assertGreater(len(texts), 25, "the population is not empty: %r" % sorted(texts)[:5])
        langs = self.page.evaluate("() => RPi18n.langs.filter(l => l !== 'en')")
        self.assertEqual(sorted(langs), ["ar", "de", "es", "fr", "hi", "zh"])
        options = self.page.eval_on_selector_all("#iau-mode option, #iau-period option[value='']", "els => els.map(e => e.textContent.trim())")
        texts |= set(options)
        missing = []
        try:
            for lang in langs:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                for t in sorted(texts):
                    got = self.page.evaluate("(k) => RPi18n.t(k)", t)
                    if not got:
                        missing.append((lang, t, "empty"))
                    elif got == t and (t, lang) not in SAME:
                        missing.append((lang, t, "the same as the English"))
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
        self.assertEqual(missing, [], "every word, in every language (all gaps listed at once)")

    def test_no_script_error_was_raised(self):
        self.open_card()
        self.assertEqual([e for e in self.errors if "Failed to load resource" not in e], [])


if __name__ == "__main__":
    unittest.main()
