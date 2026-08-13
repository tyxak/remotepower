#!/usr/bin/env python3
"""docs/master-improvement-scoping-internal.md #63 — automated accessibility
regression checks (axe-core), added to the local test gate the same way the
browser smoke suite (test_v430_e2e.py) was: reuses the shared e2e_harness
(real gunicorn+wsgi.py stack, real Chromium), self-skips when the optional
deps aren't installed.

Bar: zero axe 'critical'/'serious' violations on the login page and the
post-login dashboard, with EVERY rule enforced — no disabled rules.

color-contrast is FULLY ENFORCED (#62's contrast fix landed in the same
session that added this gate): every theme's --accent got a computed
--accent-contrast (black text clears 4.5:1 against every current accent
except the `paper` theme, which keeps white), --muted was retuned per-theme
where it fell short against --surface, and two remaining hardcoded-color
outliers (.sev-pill.sev-low, .isl-751) got dedicated colors sized for their
actual composited background. See CHANGELOG / the #62 tracker row for the
full per-theme numbers.

nested-interactive is ALSO fully enforced as of v6.1.1 (#62's other half):
the sidebar favorite-star toggle (.nav-star, role="button" tabindex="0")
used to be injected as a DESCENDANT of the <button class="nav-btn">, which
is invalid (two independently-focusable/activatable controls, nested).
Fixed by restructuring the star out to a SIBLING of .nav-btn — both wrapped
in a new `.nav-item` flex row (app.js's `_initFavorites`/`_renderFavorites`,
CSS in styles.css near `.nav-item`). Verified with a real Playwright pass:
star click still pins/unpins, the pinned clone under "Main" keeps its own
un-pin star, keyboard Enter still activates it, regular nav-btn clicks are
unaffected, the collapsed-sidebar state still hides the star, and the
sidebar search index doesn't double-count a pinned clone. Two click-delegate
handlers in app.js used `star.closest('.nav-btn')` (an ANCESTOR search) to
find the button from a star click — that broke once the star became a
SIBLING instead of a descendant (`closest()` can't walk sideways) and had
to be changed to a same-parent lookup; a `:not(.nav-fav-clone)` selector in
`_buildSidebarIdx` had the same class-moved-to-the-wrapper issue.

Install to run:
    pip install playwright gunicorn axe-core-python
    python -m playwright install chromium
Run directly via `make e2e` (bundled with the rest of the browser suite) or
`python3 -m pytest tests/test_a11y_axe.py`.
"""
import json
import unittest

try:
    from playwright.sync_api import sync_playwright
    _HAVE_PLAYWRIGHT = True
except ImportError:
    _HAVE_PLAYWRIGHT = False

try:
    from axe_core_python.sync_playwright import Axe
    _HAVE_AXE = True
except ImportError:
    _HAVE_AXE = False

_SERIOUS_IMPACTS = ('critical', 'serious')

# v6.1.1: no rules disabled -- nested-interactive's fix (see module
# docstring) closed the last named exemption. Pass {} (every default rule
# enforced) rather than deleting this constant, so a future exemption has an
# obvious place to land with the same "named reason, not a blanket ignore"
# discipline.
_AXE_OPTIONS = {}


def _run_axe(page, axe, options=None):
    """axe_core_python 0.1.0's Axe.run() str()-formats the options dict for
    the injected JS call, which emits Python's `False`/`True`/`None` instead
    of JS `false`/`true`/`null` -- a ReferenceError for any options dict with
    a boolean (i.e. every realistic one, including ours). Reuses the
    package's vendored axe.min.js (no need to vendor our own copy) but does
    the injection + evaluate ourselves with json.dumps, which IS valid JS."""
    page.evaluate(axe.axe_script)
    return page.evaluate(
        "axe.run(%s).then(r => r)" % json.dumps(options or {}))


@unittest.skipUnless(_HAVE_PLAYWRIGHT and _HAVE_AXE,
                     'playwright + axe-core-python not installed (pip install '
                     'playwright gunicorn axe-core-python && '
                     'python -m playwright install chromium)')
class TestAccessibilityAxe(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import os as _os
        import sys as _sys
        # This suite audits the RENDERED frontend (chrome + pages), which is
        # identical regardless of the storage backend — so running the full
        # ~5-min browser walk a SECOND time under RP_STORAGE_BACKEND=sqlite
        # (via `make test-sqlite`/`test-both`) adds no coverage. Skip it there;
        # the default-backend run in `make test` is authoritative for a11y.
        if _os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest(
                'a11y is backend-agnostic — audited once under the default backend')
        _here = _os.path.dirname(_os.path.abspath(__file__))
        if _here not in _sys.path:
            _sys.path.insert(0, _here)
        from e2e_harness import start_stack
        cls._pw = sync_playwright().start()
        try:
            cls.browser = cls._pw.chromium.launch()
        except Exception as exc:
            cls._pw.stop()
            raise unittest.SkipTest(f'chromium not available: {exc}')
        try:
            cls.base, cls._shutdown = start_stack()
        except Exception as exc:
            cls.browser.close()
            cls._pw.stop()
            raise unittest.SkipTest(f'app stack not available: {exc}')
        cls.axe = Axe()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close()
            cls._pw.stop()
        finally:
            cls._shutdown()

    def setUp(self):
        self.page = self.browser.new_page()

    def tearDown(self):
        self.page.close()

    def _login(self):
        self.page.goto(self.base + '/index.html')
        self.page.fill('#login-user', 'admin')
        self.page.fill('#login-pass', 'remotepower')
        self.page.click('#login-form button[type="submit"]')
        self.page.wait_for_selector('#app', state='visible', timeout=15000)
        self.page.wait_for_selector('#page-home.active', timeout=15000)

    def _assert_no_serious_violations(self, results, page_label):
        violations = results.get('violations') or []
        serious = [v for v in violations if v.get('impact') in _SERIOUS_IMPACTS]
        if serious:
            detail = json.dumps(
                [{'id': v['id'], 'impact': v['impact'], 'help': v['help'],
                  'nodes': len(v.get('nodes') or [])} for v in serious],
                indent=2)
            self.fail(f'{page_label}: {len(serious)} critical/serious a11y '
                     f'violation(s):\n{detail}')

    def test_login_page(self):
        self.page.goto(self.base + '/index.html')
        self.page.wait_for_selector('#login-user', state='visible', timeout=15000)
        results = _run_axe(self.page, self.axe, _AXE_OPTIONS)
        self._assert_no_serious_violations(results, 'login page')

    def test_dashboard_after_login(self):
        self._login()
        results = _run_axe(self.page, self.axe, _AXE_OPTIONS)
        self._assert_no_serious_violations(results, 'dashboard')

    def test_devices_page(self):
        self._login()
        self.page.evaluate(
            "document.body.classList.remove('autohide-sidebar', 'sidebar-collapsed');"
            "document.querySelectorAll('.sidebar-group.collapsed')"
            ".forEach(g => g.classList.remove('collapsed'))")
        self.page.click('.nav-btn[data-page="devices"]')
        self.page.wait_for_selector('#page-devices.active', timeout=15000)
        self.page.wait_for_timeout(500)
        results = _run_axe(self.page, self.axe, _AXE_OPTIONS)
        self._assert_no_serious_violations(results, 'devices page')

    # Concurrency for the two axe walks below. The stack runs gunicorn
    # --workers 2 --threads 8 (16 request slots) and the box has many cores, so
    # a handful of parallel browser contexts each auditing a SLICE of the pages
    # turns a ~4.5-min serial walk into ~40s without overloading the server.
    _AXE_LANES = 8

    def _axe_walk(self, targets, audit_one, settings_first=False):
        """Audit `targets` CONCURRENTLY across _AXE_LANES async browser contexts.

        Each lane opens its own context, logs in and injects axe ONCE, then
        serially audits its round-robin slice via `audit_one(page, target)` (an
        async fn returning that target's axe results). Returns an ordered list of
        (target, results); a per-target exception is captured as {'_error': ...}
        so one bad page can't abort the others (mirrors the old subTest isolation).

        Playwright's SYNC API can't be driven from threads, so the walk uses the
        ASYNC API in its own event loop. The sync setUpClass browser is untouched
        — the smoke tests (login/dashboard/devices) still use it."""
        import asyncio
        import threading
        from playwright.async_api import async_playwright
        n = min(self._AXE_LANES, len(targets)) or 1
        lanes = [targets[i::n] for i in range(n)]   # round-robin slices

        async def _run_lane(browser, slice_):
            ctx = await browser.new_context()
            page = await ctx.new_page()
            out = []
            try:
                # RETRY THE LOGIN. This file now runs three separate browser
                # walks (pages, settings panes, modals), each opening its own
                # lanes against ONE test server. With all three in the same
                # run the third reliably timed out here at 15s — reproducibly,
                # in isolation, so not the documented "e2e flake under load":
                # any two walks passed, all three failed, every time.
                #
                # It is a harness resource limit, not a product defect — the
                # server is simply still working through the previous walk's
                # backlog when the next lane tries to log in. Retrying once
                # with a longer ceiling is the honest fix; shortening the
                # audit to make it fit would be trading coverage for green.
                for _attempt in (1, 2):
                    try:
                        await page.goto(self.base + '/index.html')
                        await page.evaluate(
                            "localStorage.setItem('rp_tour_done', '1')")
                        await page.fill('#login-user', 'admin')
                        await page.fill('#login-pass', 'remotepower')
                        await page.click('#login-form button[type="submit"]')
                        await page.wait_for_selector('#app', state='visible',
                                                     timeout=30000)
                        break
                    except Exception:
                        if _attempt == 2:
                            raise
                        await page.wait_for_timeout(2000)
                if settings_first:
                    await page.evaluate("showPage('settings')")
                    await page.wait_for_selector('#page-settings.active', timeout=15000)
                await page.evaluate(self.axe.axe_script)
                for t in slice_:
                    try:
                        out.append((t, await audit_one(page, t)))
                    except Exception as exc:  # keep auditing the rest of the slice
                        out.append((t, {'_error': repr(exc)}))
            finally:
                await ctx.close()
            return out

        async def _run_all():
            async with async_playwright() as pw:
                browser = await pw.chromium.launch()
                try:
                    lane_results = await asyncio.gather(
                        *(_run_lane(browser, s) for s in lanes))
                finally:
                    await browser.close()
            merged = {}
            for lane in lane_results:
                for t, res in lane:
                    merged[t] = res
            return [(t, merged[t]) for t in targets]

        # setUpClass holds a SYNC-Playwright event loop in this thread, so a bare
        # asyncio.run() here raises "cannot be called from a running event loop".
        # Drive the async walk on a DEDICATED thread with its own fresh loop.
        box = {}

        def _drive():
            try:
                box['result'] = asyncio.run(_run_all())
            except BaseException as exc:  # surface on the caller's thread
                box['error'] = exc

        th = threading.Thread(target=_drive, name='axe-walk')
        th.start()
        th.join()
        if 'error' in box:
            raise box['error']
        return box['result']

    def _check_walk_result(self, target, results, label):
        with self.subTest(target=target):
            if isinstance(results, dict) and results.get('_error'):
                self.fail(f'{label}: axe walk failed to reach the page: '
                          f'{results["_error"]}')
            self._assert_no_serious_violations(results, label)

    def test_every_sidebar_page(self):
        """v6.3.0: axe on ALL sidebar pages (not just two) — axe skips
        non-rendered elements, so each run audits the ACTIVE page plus the shared
        chrome. v6.4.2: the ~50-page walk runs CONCURRENTLY across browser
        contexts (was ~4.5 min serial). Harness lessons: pre-dismiss the first-run
        tour (its backdrop intercepts clicks) and re-expand the accordion before
        every nav."""
        import re as _re
        from pathlib import Path as _P
        html = (_P(__file__).parent.parent / 'server/html/index.html').read_text()
        pages, seen = [], set()
        for m in _re.finditer(r'class="nav-btn[^"]*"[^>]*\sdata-page="([a-z-]+)"', html):
            if m.group(1) not in seen:
                seen.add(m.group(1))
                pages.append(m.group(1))
        # v6.4.3: was `> 50`, which passed at 74 while SIX real pages were
        # being silently excluded by the enumeration regex (tickets,
        # contacts, virtualization, provisioning, billing, kb — all of them
        # row-heavy, and none ever measured). A floor that low cannot tell
        # 'the walk works' from 'the walk lost a tenth of the product', so
        # it pins the real number: raise it deliberately when a page is
        # added, and a silent drop fails here.
        self.assertGreaterEqual(len(pages), 80)

        async def _audit(page, p):
            await page.evaluate(
                "document.body.classList.remove('autohide-sidebar', 'sidebar-collapsed');"
                "document.querySelectorAll('.sidebar-group.collapsed')"
                ".forEach(g => g.classList.remove('collapsed'))")
            await page.click(f'.nav-btn[data-page="{p}"]', timeout=5000)
            await page.wait_for_selector(f'#page-{p}.active', timeout=10000)
            # Under concurrent lanes the page's data-fetch + paint lags behind the
            # 'active' class; auditing a half-rendered page yields false
            # colour-contrast hits. Wait for the network to settle (bounded — some
            # pages poll) plus a small paint buffer before axe runs.
            try:
                await page.wait_for_load_state('networkidle', timeout=4000)
            except Exception:
                pass
            await page.wait_for_timeout(400)
            return await page.evaluate("axe.run(%s).then(r => r)" % json.dumps(_AXE_OPTIONS))

        for p, results in self._axe_walk(pages, _audit):
            self._check_walk_result(p, results, f'page {p!r}')

    def test_every_settings_pane(self):
        """v6.4.2: the sweep above walks PAGES, but Settings is one page whose
        fourteen panes are `display:none` until their tab is clicked — and axe
        does not scan a `display:none` subtree at all.

        So thirteen of fourteen panes had never been audited, and real critical
        failures were living there: 368 unlabelled checkboxes in the
        notifications event matrix, an unnamed button in the AI pane, and two
        colour-contrast failures. The gate was not weak, it was blind. Walks all
        panes CONCURRENTLY (v6.4.2)."""
        import re as _re
        from pathlib import Path as _P
        html = (_P(__file__).parent.parent / 'server/html/index.html').read_text()
        panes = []
        for m in _re.finditer(r'class="settings-tab[^"]*"[^>]*data-tab="([a-z0-9-]+)"', html):
            if m.group(1) not in panes:
                panes.append(m.group(1))
        self.assertGreater(len(panes), 8, 'settings tabs not discovered')

        async def _audit(page, pane):
            await page.evaluate(f"switchSettingsTab({pane!r})")
            await page.wait_for_timeout(300)
            return await page.evaluate(
                "axe.run('#page-settings', %s).then(r => r)" % json.dumps(_AXE_OPTIONS))

        for pane, results in self._axe_walk(panes, _audit, settings_first=True):
            self._check_walk_result(pane, results, f'settings pane {pane!r}')



if __name__ == '__main__':
    unittest.main()


# ── v6.4.3: the same audit, against a POPULATED instance ─────────────────────
#
# Everything above walks a stack booted on an empty temp data dir, so every
# table renders its empty state. That made a whole class of violation
# structurally invisible: anything that only exists once there are rows. A
# seeded run found, on pages the sweep above already "covered":
#
#   * 60 CRITICAL `label` violations — the per-row select checkboxes in the
#     devices and alerts tables are built by JS with no accessible name, so a
#     screen-reader user cannot tell which row a checkbox belongs to (or that
#     bulk select exists). Fixed; this class is pinned at zero below.
#   * 15 `aria-allowed-attr` — `aria-label` on a bare <span> status dot, which
#     is invalid without a role. Fixed (role="img").
#   * 48 `color-contrast` — ALL FIXED, and the diagnosis is worth recording
#     because the first one was wrong. The initial read was "row-level opacity
#     is structurally incompatible with AA": --muted passes at 4.98:1 alone,
#     any dimming pushes it under, and the arithmetic said the minimum alpha
#     preserving AA is 0.94 — no visible dimming at all. The arithmetic was
#     right and the CONCLUSION was wrong, because it never asked which
#     elements were actually failing. Walking each violating node up to its
#     nearest dimmed ancestor gave a completely different answer:
#         33  .isl-451 @0.75      every Containers row, unconditionally
#         12  .isl-598 @0.65      "no results yet" rows, already muted inside
#          2  .cmdb-nat-child @0.85
#          1  .sev-pill.sev-critical   (not opacity — --red as text on its tint)
#     Not five row-state rules and not a design language problem: three stray
#     opacity declarations, the largest of which was not a de-emphasis state at
#     all but a blanket 25% fade on every row of one table. Removing them costs
#     nothing, because in each case the content underneath was ALREADY muted —
#     the opacity was double-dimming text that had done its de-emphasis job.
#     The lesson: measure which nodes fail before theorising about why.
#
# Cost: one extra stack plus the demo seeder, on a focused set of data-heavy
# pages rather than all 74 — the empty-install sweep above already covers
# breadth; this covers depth.
_SEEDED_PAGES = ('devices', 'alerts', 'monitor', 'containers', 'cmdb')

# ZERO, not a baseline. Every violation was a stray opacity declaration and
# they are all gone, so there is nothing to grandfather.
_SEEDED_CONTRAST_CEILING = 0


@unittest.skipUnless(_HAVE_PLAYWRIGHT and _HAVE_AXE,
                     'playwright + axe-core-python not installed')
class TestAccessibilityAxeSeeded(unittest.TestCase):
    """axe over an instance that actually has rows in it."""

    @classmethod
    def setUpClass(cls):
        import os as _os
        import subprocess as _sp
        import sys as _sys
        import tempfile as _tf
        import time as _time
        if _os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest('a11y is backend-agnostic — audited once')
        _here = _os.path.dirname(_os.path.abspath(__file__))
        if _here not in _sys.path:
            _sys.path.insert(0, _here)
        _root = _os.path.dirname(_here)
        seeder = _os.path.join(_root, 'packaging', 'seed-demo-data.py')
        if not _os.path.exists(seeder):
            raise unittest.SkipTest('demo seeder not in this tree')
        data_dir = _tf.mkdtemp(prefix='rp-a11y-seeded-')
        # --apply is required; without it the seeder is a dry run and you get
        # an EMPTY dir, i.e. silently the same blind spot this class exists to
        # remove.
        proc = _sp.run([_sys.executable, seeder, '--data-dir', data_dir, '--apply'],
                       capture_output=True, cwd=_root, timeout=600)
        if proc.returncode != 0:
            raise unittest.SkipTest(
                'demo seeder failed: ' + proc.stderr.decode(errors='replace')[-300:])
        # Force HALF the seeded devices offline, deterministically.
        #
        # Offline rows carry their own styling, and the violation that made
        # this ceiling non-zero lived in one of them — but whether any device
        # is offline depends on how much wall-clock elapsed since the seed.
        # Running this class alone, nothing had aged yet and it saw zero; in
        # the full suite the empty-install sweep runs ~155s first, devices
        # crossed the threshold, and two violations appeared. A gate whose
        # coverage depends on how long the PREVIOUS tests took is exactly the
        # "reports success while measuring nothing" shape this file exists to
        # catch, so pin the state instead of hoping for it. Half, not all, so
        # both the online and offline row treatments are audited.
        import json as _json
        _dev = _os.path.join(data_dir, 'devices.json')
        try:
            with open(_dev) as fh:
                _devices = _json.load(fh)
            _old = int(_time.time()) - 86400
            for _i, _k in enumerate(sorted(_devices)):
                if _i % 2 == 0 and isinstance(_devices[_k], dict):
                    _devices[_k]['last_seen'] = _old
            with open(_dev, 'w') as fh:
                _json.dump(_devices, fh)
        except (OSError, ValueError) as exc:
            raise unittest.SkipTest(f'could not age the seeded devices: {exc}')

        from e2e_harness import start_stack
        cls._pw = sync_playwright().start()
        try:
            cls.browser = cls._pw.chromium.launch()
        except Exception as exc:
            cls._pw.stop()
            raise unittest.SkipTest(f'chromium not available: {exc}')
        try:
            cls.base, cls._shutdown = start_stack(data_dir=data_dir)
        except Exception as exc:
            cls.browser.close()
            cls._pw.stop()
            raise unittest.SkipTest(f'app stack not available: {exc}')
        cls.axe = Axe()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close()
            cls._pw.stop()
        finally:
            cls._shutdown()

    def _walk(self):
        """{rule_id: node_count} for every critical/serious violation across
        the seeded pages."""
        self.detail = []
        page = self.browser.new_page()
        try:
            page.goto(self.base + '/index.html')
            # The seeder builds its own operator accounts; there is no 'admin'.
            page.fill('#login-user', 'alice')
            page.fill('#login-pass', 'demo')
            page.click('#login-form button[type="submit"]')
            page.wait_for_selector('#app', state='visible', timeout=90000)
            page.wait_for_timeout(6000)
            totals = {}
            for name in _SEEDED_PAGES:
                page.evaluate("n => { try { showPage(n) } catch (e) {} }", name)
                page.wait_for_timeout(1500)
                for v in (_run_axe(page, self.axe, _AXE_OPTIONS).get('violations') or []):
                    if v.get('impact') not in _SERIOUS_IMPACTS:
                        continue
                    totals[v['id']] = totals.get(v['id'], 0) + len(v.get('nodes') or [])
                    # Record WHICH nodes. A bare count tells you a number
                    # changed and nothing about what to open — the first run
                    # of this class reported "2" and cost a full re-run to
                    # identify them.
                    for node in (v.get('nodes') or []):
                        self.detail.append(
                            f"{name}: [{v['id']}] "
                            f"{(node.get('target') or ['?'])[0]} :: "
                            f"{node.get('html', '')[:90]} :: "
                            f"{(node.get('failureSummary') or '').splitlines()[-1][:120]}")
            return totals
        finally:
            page.close()

    def test_populated_pages(self):
        totals = self._walk()
        contrast = totals.pop('color-contrast', 0)
        self.assertEqual(
            totals, {},
            'critical/serious a11y violations that only appear once there is '
            f'data on the page: {totals}. The empty-install sweep cannot see '
            'these — a row control with no accessible name has no row to live '
            'in until the table has one.')
        self.assertLessEqual(
            contrast, _SEEDED_CONTRAST_CEILING,
            f'{contrast} color-contrast violation(s) on populated pages '
            f'(ceiling {_SEEDED_CONTRAST_CEILING}). Before theorising about '
            f'the palette, walk each failing node up to its nearest ancestor '
            f'with opacity < 1 — every previous instance of this was a stray '
            f'opacity declaration double-dimming text that was already '
            f'muted.\n' + '\n'.join(self.detail))

    def test_the_device_drawer(self):
        """v6.4.3: the drawer had NEVER been audited by anything.

        The modal walk added earlier in this release discovers its targets by
        regexing `class="…modal-overlay…"` out of index.html — and the drawer's
        class is `device-drawer`, so it matched nothing. It is `display: none`
        until `.open`, and axe does not scan a display:none subtree, so the
        page walks could not see it either. Measured behind that gap: 4-6
        CRITICAL (`label`, `select-name`) and 5-6 SERIOUS `color-contrast`.

        Needs the SEEDED stack — an empty install has no device row to click.
        """
        self.detail = []          # _walk() creates this; these methods do not call it
        page = self.browser.new_page()
        try:
            page.goto(self.base + '/index.html')
            page.evaluate("localStorage.setItem('rp_tour_done', '1')")
            page.fill('#login-user', 'alice')
            page.fill('#login-pass', 'demo')
            page.click('#login-form button[type="submit"]')
            page.wait_for_selector('#app', state='visible', timeout=90000)
            page.wait_for_timeout(4000)
            page.evaluate(self.axe.axe_script)      # axe is NOT global by default
            page.evaluate("() => { try { showPage('devices') } catch (e) {} }")
            page.wait_for_timeout(1500)
            # The real opener is openDeviceDrawer(id, name, tab) — take the id
            # from a rendered row's data-arg, i.e. what a user actually clicks.
            dev_id = page.evaluate(
                "() => { const el = document.querySelector("
                "  '[data-action=\"openDeviceDrawer\"][data-arg]');"
                "  return el ? el.getAttribute('data-arg') : null; }")
            if not dev_id:
                self.skipTest('no rendered device row to open the drawer from')
            page.evaluate(
                "id => { try { openDeviceDrawer(id, 'x', 'actions') } catch (e) {} }",
                dev_id)
            page.wait_for_timeout(1500)
            # A walk where nothing opened measures nothing and reports success —
            # the same guard the modal walk carries.
            self.assertTrue(
                page.evaluate("() => !!document.querySelector('#device-drawer.open')"),
                'the drawer did not open, so this audited an invisible subtree')
            found = {}
            for tab in ('actions', 'audit'):
                page.evaluate("t => { try { switchDrawerTab(t) } catch (e) {} }", tab)
                page.wait_for_timeout(900)
                res = page.evaluate(
                    "axe.run('#device-drawer', %s).then(r => r)"
                    % json.dumps(_AXE_OPTIONS))
                for v in (res.get('violations') or []):
                    if v.get('impact') not in _SERIOUS_IMPACTS:
                        continue
                    found[v['id']] = found.get(v['id'], 0) + len(v.get('nodes') or [])
                    for node in (v.get('nodes') or []):
                        self.detail.append(
                            f"drawer/{tab}: [{v['id']}] "
                            f"{(node.get('target') or ['?'])[0]} :: "
                            f"{node.get('html', '')[:90]}")
            self.assertEqual(found, {}, 'critical/serious a11y violations in the '
                             'device drawer — the product\'s primary device '
                             'surface, unaudited until v6.4.3:\n'
                             + '\n'.join(self.detail))
        finally:
            page.close()

    def test_the_command_palette(self):
        """Also never audited, and for a different reason: the palette has no
        static markup at all — app.js builds `#cmd-palette-overlay` at runtime,
        so no index.html regex could ever have found it.

        It scores ZERO today (it was given dialog/combobox/listbox semantics in
        v6.4.2), so this lands as a clean ratchet rather than a fix. That is
        worth stating: a walk added at zero has never been observed failing,
        which is exactly what this release says is untrustworthy — so the
        assertion below is deliberately the same shape as the drawer's, and the
        first real violation will trip it.
        """
        page = self.browser.new_page()
        try:
            page.goto(self.base + '/index.html')
            page.evaluate("localStorage.setItem('rp_tour_done', '1')")
            page.fill('#login-user', 'alice')
            page.fill('#login-pass', 'demo')
            page.click('#login-form button[type="submit"]')
            page.wait_for_selector('#app', state='visible', timeout=90000)
            page.wait_for_timeout(3000)
            page.evaluate(self.axe.axe_script)      # axe is NOT global by default
            page.evaluate("() => { try { openCommandPalette() } catch (e) {} }")
            page.wait_for_timeout(900)
            if not page.evaluate("() => !!document.querySelector('#cmd-palette-overlay')"):
                self.skipTest('command palette did not open')
            res = page.evaluate("axe.run('#cmd-palette-overlay', %s).then(r => r)"
                                % json.dumps(_AXE_OPTIONS))
            bad = {v['id']: len(v.get('nodes') or [])
                   for v in (res.get('violations') or [])
                   if v.get('impact') in _SERIOUS_IMPACTS}
            self.assertEqual(bad, {}, f'command palette a11y violations: {bad}')
        finally:
            page.close()

    def test_the_seed_actually_produced_rows(self):
        """Guard the guard. If the seeder silently no-ops this whole class
        degrades into a second copy of the empty-install sweep and reports
        success for testing nothing."""
        page = self.browser.new_page()
        try:
            page.goto(self.base + '/index.html')
            page.fill('#login-user', 'alice')
            page.fill('#login-pass', 'demo')
            page.click('#login-form button[type="submit"]')
            page.wait_for_selector('#app', state='visible', timeout=90000)
            page.wait_for_timeout(6000)
            page.evaluate("() => { try { showPage('devices') } catch (e) {} }")
            page.wait_for_timeout(1500)
            rows = page.evaluate(
                "() => document.querySelectorAll('#page-devices tbody tr').length")
            self.assertGreater(rows, 5, 'seeded instance rendered no device rows')
        finally:
            page.close()
