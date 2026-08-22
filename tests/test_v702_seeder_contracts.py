#!/usr/bin/env python3
"""Every store the demo seeder writes, measured against its real reader.

tests/test_v702_seeder_shapes.py covers one store — devices.json — by pushing
its sysinfo through the real heartbeat. Everything else the seeder writes was
covered by nothing, and the v7.0.2 sweep found eight more stores in shapes no
reader knows: log_watch keyed on 'rules'/'recent_alerts' instead of device ids,
query templates with no `entity` (so the Data Explorer printed "(undefined)"
four times and every Run button 400'd), DNSBL listings as bare zone strings
where the checker returns dicts (the table read "undefined, undefined"), the
software policy written to a config key nothing reads (so the page showed four
violations and zero rules), and four subsystems — service baselines, SLO
objects, report definitions, custom checks — with no rows at all.

Reading a builder cannot catch that class, because a wrong shape reads as
plausible. So this file drives the REAL handlers against a freshly seeded data
dir and asserts the collection they return is not empty, plus the specific
joins where two seeded stores have to agree with each other.

Every check has a positive control or is written so that a broken instrument
fails rather than passes: an assertion over an empty set is the failure mode
this whole file exists to close.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_SEEDER = _ROOT / 'packaging' / 'seed-demo-data.py'

# The seeded dir has to exist BEFORE api.py is imported: import-time
# ensure_default_user() writes to DATA_DIR, and every handler below reads the
# module-level *_FILE paths that DATA_DIR fixes at import.
_SEED_DIR = tempfile.mkdtemp(prefix='rp-v702-contracts-')
_SEED_ERR = None
if _SEEDER.exists():
    _r = subprocess.run([sys.executable, str(_SEEDER), '--data-dir', _SEED_DIR,
                         '--apply', '--quiet'], capture_output=True, text=True,
                        timeout=300)
    if _r.returncode != 0:
        _SEED_ERR = f'seeder failed: {_r.stderr[-800:]}'
else:
    _SEED_ERR = 'seeder excluded from dist tree'

os.environ['RP_DATA_DIR'] = _SEED_DIR
sys.path.insert(0, str(_CGI))

api = None
if _SEED_ERR is None:
    _spec = importlib.util.spec_from_file_location('api_v702contracts',
                                                   _CGI / 'api.py')
    api = importlib.util.module_from_spec(_spec)
    sys.modules.setdefault('api', api)
    _spec.loader.exec_module(api)


def _seeder_module():
    spec = importlib.util.spec_from_file_location('seed_v702contracts', _SEEDER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _store(name):
    return json.loads((Path(_SEED_DIR) / name).read_text())


class _SeededBase(unittest.TestCase):
    """Drives real handlers against the seeded dir with auth stubbed out."""

    @classmethod
    def setUpClass(cls):
        if _SEED_ERR:
            raise unittest.SkipTest(_SEED_ERR)

    def setUp(self):
        self._saved = {n: getattr(api, n) for n in
                       ('respond', 'method', 'require_auth', 'require_admin_auth',
                        'require_write_role', 'require_perm', '_env',
                        'get_json_obj', 'get_json_body', '_caller_scope',
                        '_tenant_gate', 'current_username',
                        'get_token_from_request', 'verify_token')}
        self.cap = {}

        def _respond(status, data=None):
            self.cap['status'] = status
            self.cap['body'] = data
            raise api.HTTPError(status, data)

        api.respond = _respond
        api.method = lambda: 'GET'
        api.require_auth = lambda *a, **k: 'alice'
        api.require_admin_auth = lambda *a, **k: 'alice'
        api.require_write_role = lambda *a, **k: 'alice'
        api.require_perm = lambda *a, **k: 'alice'
        api.current_username = lambda *a, **k: 'alice'
        api.get_token_from_request = lambda *a, **k: 'tok'
        api.verify_token = lambda *a, **k: ('alice', 'admin')
        api._caller_scope = lambda *a, **k: None
        api._tenant_gate = lambda *a, **k: None
        api._env = lambda k, dflt='': dflt
        api.get_json_obj = api.get_json_body = lambda: {}
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def call(self, fn, *args):
        """Run a handler, return its response body."""
        self.cap.clear()
        try:
            fn(*args)
        except api.HTTPError as e:
            body = self.cap.get('body')
            return self.cap.get('status'), (body if body is not None else e.body)
        return self.cap.get('status'), self.cap.get('body')


class TestTheSeedIsWorthMeasuring(_SeededBase):
    """A positive control for the whole file. Every assertion below reads a
    seeded store; if the seed did not happen they would all pass over nothing."""

    def test_the_seed_produced_a_fleet_and_a_pile_of_stores(self):
        stores = sorted(p.name for p in Path(_SEED_DIR).glob('*.json'))
        self.assertGreater(len(stores), 100,
                           f'only {len(stores)} stores seeded — the rest of '
                           f'this file would be measuring an empty directory')
        self.assertGreaterEqual(len(_store('devices.json')), 10)


class TestEveryDeviceReferenceIsInTheFleet(_SeededBase):
    """A store naming a host the Devices page does not have reads as
    corruption, not as a demo. The receipts UI, the "what happened last time"
    card and the batch panel all name hosts as plain text, so nothing crashes
    and nothing catches it either."""

    @staticmethod
    def _refs():
        """[(store, key, value)] for every device id any builder wrote."""
        out = []

        def walk(node, store):
            if isinstance(node, dict):
                for k, v in node.items():
                    if k in ('device_id', 'dev_id') and isinstance(v, str) and v:
                        out.append((store, k, v))
                    elif k in ('device_ids', 'targets') and isinstance(v, list):
                        for x in v:
                            if isinstance(x, str) and x:
                                out.append((store, k, x))
                    else:
                        walk(v, store)
            elif isinstance(node, list):
                for x in node:
                    walk(x, store)

        for p in sorted(Path(_SEED_DIR).glob('*.json')):
            try:
                walk(json.loads(p.read_text()), p.name)
            except (ValueError, OSError):
                continue
        return out

    def test_the_walker_finds_references(self):
        """Control: the assertion below is only meaningful over a real set."""
        refs = self._refs()
        self.assertGreater(len(refs), 50,
                           'the reference walker found almost nothing — it is '
                           'the instrument that is broken, not the seed')
        self.assertGreater(len({s for s, _k, _v in refs}), 8,
                           'references came from too few stores')

    def test_no_reference_names_a_host_outside_the_fleet(self):
        fleet = set(_store('devices.json'))
        # A tag/group/'all' target is not a device id; only flag values that
        # LOOK like an id and are not one.
        stray = sorted({(s, k, v) for s, k, v in self._refs()
                        if v not in fleet and v not in ('all', '*')})
        self.assertEqual(
            stray, [],
            'these stores name devices that are not in build_devices():\n  '
            + '\n  '.join(f'{s}: {k}={v!r}' for s, k, v in stray))


class TestCadenceMarkersAreStamped(_SeededBase):
    """An unstamped marker means every sweep is overdue on the first page load,
    and the sweeps then probe the fabricated fleet and overwrite the curated
    results with resolver failures."""

    def test_the_derivation_finds_markers(self):
        markers = _seeder_module()._cadence_markers()
        self.assertGreaterEqual(
            len(markers), 8,
            f'_cadence_markers() derived {len(markers)} markers from '
            f'scheduler.py CADENCE — a broken derivation stamps nothing and '
            f'this file would still pass')

    def test_every_derived_marker_is_in_the_seeded_config(self):
        cfg = _store('config.json')
        missing = [m for m in _seeder_module()._cadence_markers() if m not in cfg]
        self.assertEqual(missing, [],
                         f'build_config did not stamp: {missing}')

    def test_the_integration_poll_is_not_due_at_seed_time(self):
        cfg = _store('config.json')
        interval = int(cfg.get('integrations_interval') or 300)
        age = int(time.time()) - int(cfg.get('last_integrations_run') or 0)
        self.assertLess(age, interval,
                        'the integrations sweep is already due on a fresh '
                        'seed, so the first GET repolls every .lab instance')


class TestTheSeededFleetIsOnlineLongEnoughToReSeed(_SeededBase):
    """The demo was 100% offline about five minutes after every seed, and every
    online-gated surface (patch %, fleet health, SLA, needs-attention) was then
    computed over the two hosts still inside the window."""

    def test_every_agented_host_reads_online(self):
        devices = _store('devices.json')
        now = int(time.time())
        ttl = api.get_online_ttl()
        offline = [d.get('name', k) for k, d in devices.items()
                   if not d.get('agentless')
                   and (now - int(d.get('last_seen') or 0))
                   >= api._offline_thresholds(d, ttl)[0]]
        self.assertEqual(offline, [], f'offline straight after a seed: {offline}')

    def test_the_offline_window_outlives_a_reseed_gap(self):
        """install-demo.sh re-seeds every 2 minutes. The window has to be
        comfortably longer than that or a single missed tick blanks the fleet.
        The 30-minute bar is the cron cadence this seeder's own docstring
        documents, which must also work."""
        devices = _store('devices.json')
        ttl = api.get_online_ttl()
        for dev_id, dev in devices.items():
            if dev.get('agentless'):
                continue
            window = api._offline_thresholds(dev, ttl)[0]
            self.assertGreaterEqual(
                window, 30 * 60,
                f'{dev_id}: offline after {window}s — shorter than the '
                f'documented 30-minute re-seed cron')


class TestLogWatchIsDeviceKeyed(_SeededBase):

    def test_every_key_is_a_device_and_carries_a_units_map(self):
        store = _store('log_watch.json')
        fleet = set(_store('devices.json'))
        self.assertTrue(store, 'log_watch.json is empty')
        for key, rec in store.items():
            self.assertIn(key, fleet,
                          f'log_watch.json key {key!r} is not a device id — on '
                          f'the DB backends it becomes a bogus device row')
            self.assertIsInstance(rec.get('units'), dict,
                                  f'{key}: no units map')
            self.assertTrue(rec['units'], f'{key}: units map is empty')
            for unit, lines in rec['units'].items():
                self.assertIsInstance(lines, list, f'{key}/{unit}')
                for ln in lines:
                    self.assertIsInstance(ln, dict, f'{key}/{unit}')
                    self.assertIn('ts', ln)
                    self.assertIn('line', ln)

    def test_the_services_drawer_reaches_the_buffer(self):
        """handle_device_services reads store[dev_id]['units'][unit] — the
        exact path the old shape made unreachable."""
        store = _store('log_watch.json')
        found = 0
        for dev_id, rec in store.items():
            buf = (api.load(api.LOG_WATCH_FILE) or {}).get(dev_id) or {}
            for unit in rec['units']:
                if (buf.get('units') or {}).get(unit):
                    found += 1
        self.assertGreater(found, 0, 'no unit buffer is reachable by device id')

    def test_the_fleet_log_rules_endpoint_is_not_empty(self):
        """/api/logs/rules is built purely from each DEVICE record's log_watch
        list — global rules do not appear there."""
        status, body = self.call(api.handle_log_rules)
        self.assertEqual(status, 200)
        self.assertTrue(body.get('rules'),
                        'no device carries a log_watch rule, so the Logs '
                        'page\'s per-device table renders empty')


class TestQueryTemplatesMatchTheirOnlyProducer(_SeededBase):

    def test_every_template_carries_a_real_entity_and_a_valid_predicate(self):
        import query_engine
        templates = _store('query_templates.json')
        self.assertTrue(templates)
        for tid, t in templates.items():
            self.assertIn(t.get('entity'), api._QE_ENTITIES,
                          f'{tid}: entity {t.get("entity")!r} is not in '
                          f'_QE_ENTITIES — handle_query_template_create would '
                          f'have refused this record with a 400')
            _loader, fields = api._QE_ENTITIES[t['entity']]
            query_engine.validate_predicate(t.get('where'), fields)
            for key in ('id', 'name', 'kind', 'where', 'params', 'sort',
                        'sort_desc', 'visibility', 'owner', 'created'):
                self.assertIn(key, t, f'{tid}: missing {key}')

    def test_every_template_runs(self):
        """The Run button posts {entity, where, sort} — this is that call."""
        for tid, t in _store('query_templates.json').items():
            status, _payload = api._query_run_one(
                {'entity': t['entity'], 'where': t['where'],
                 'sort': t.get('sort'), 'sort_desc': t.get('sort_desc')})
            self.assertEqual(status, 200, f'{tid} would 400 on Run')

    def test_at_least_one_template_actually_matches_something(self):
        """A template that runs but always returns nothing teaches a visitor
        the same thing an error does."""
        hits = 0
        for t in _store('query_templates.json').values():
            _s, payload = api._query_run_one(
                {'entity': t['entity'], 'where': t['where']})
            hits += len((payload or {}).get('rows') or [])
        self.assertGreater(hits, 0, 'every saved query returns zero rows')


class TestDnsblResultsMatchTheChecker(_SeededBase):

    def test_listed_on_entries_are_the_dicts_check_ip_returns(self):
        import ip_reputation
        zones_by_name = {z['name']: z['zone']
                         for z in ip_reputation.DEFAULT_DNSBLS}
        listed = 0
        for rid, rec in _store('ip_reputation_results.json').items():
            for z in rec.get('listed_on') or []:
                listed += 1
                self.assertIsInstance(
                    z, dict,
                    f'{rid}: listed_on holds {z!r} — check_ip appends '
                    f'{{name, zone, codes, reason}}, and the table renders '
                    f'z.name, so a string renders "undefined"')
                for key in ('name', 'zone', 'codes', 'reason'):
                    self.assertIn(key, z, f'{rid}: listed_on entry has no {key}')
                self.assertEqual(zones_by_name.get(z['name']), z['zone'],
                                 f'{rid}: {z["name"]!r} is not that zone')
            self.assertEqual(rec.get('listed_count'), len(rec.get('listed_on') or []))
        self.assertGreater(listed, 0,
                           'no IP is listed, so the dict shape above was never '
                           'exercised')


class TestSoftwarePolicyRulesBackTheViolations(_SeededBase):

    def test_the_policy_endpoint_returns_rules(self):
        status, body = self.call(api.handle_software_policy)
        self.assertEqual(status, 200)
        self.assertTrue(body.get('rules'),
                        'the Software policy page shows violations with no '
                        'rule that could have produced them')

    def test_every_violation_names_a_seeded_rule(self):
        rules = {(r['type'], r['package'])
                 for r in _store('software_policy.json')['rules']}
        seen = 0
        for dev_id, rec in _store('software_violations.json').items():
            for v in rec.get('violations') or []:
                seen += 1
                self.assertIn((v.get('type'), v.get('package')), rules,
                              f'{dev_id}: violation {v} matches no rule')
        self.assertGreater(seen, 0, 'no violations seeded')


class TestConfigBackedSubsystemsRender(_SeededBase):
    """Four pages whose whole body comes from a config key, all of which were
    unseeded and rendered their empty state."""

    def test_service_baselines(self):
        status, body = self.call(api.handle_service_baselines)
        self.assertEqual(status, 200)
        self.assertTrue(body.get('baselines'))
        for b in body['baselines']:
            self.assertTrue(b.get('units'), f'{b.get("id")}: no units')
            self.assertIn((b.get('scope') or {}).get('type'),
                          ('all', 'groups', 'tags', 'sites'))

    def test_custom_checks(self):
        status, body = self.call(api.handle_custom_checks_list)
        self.assertEqual(status, 200)
        self.assertTrue(body.get('checks'))
        for c in body['checks']:
            self.assertIn(c.get('type'), api.CUSTOM_CHECK_TYPES,
                          f'{c.get("id")}: handle_custom_checks_save would '
                          f'refuse type {c.get("type")!r}')

    def test_every_reported_custom_check_result_names_a_defined_check(self):
        defined = {c['id'] for c in _store('config.json')['custom_checks']}
        reported = 0
        for dev_id, dev in _store('devices.json').items():
            for cid, res in ((dev.get('sysinfo') or {})
                             .get('custom_check_results') or {}).items():
                reported += 1
                self.assertIn(cid, defined,
                              f'{dev_id} reports a result for {cid!r}, which '
                              f'no custom check defines')
                self.assertIn(res.get('status'),
                              ('ok', 'warning', 'critical', 'unknown'))
        self.assertGreater(reported, 0,
                           'no host reports a custom-check result, so the '
                           'agent-side check types render "not yet reported"')

    def test_report_definitions(self):
        reports_handlers = api.reports_handlers_mod
        status, body = self.call(reports_handlers.handle_report_defs_list)
        self.assertEqual(status, 200)
        self.assertTrue(body.get('definitions'))
        allowed = set(reports_handlers._ALL_REPORT_SECTIONS)
        for d in body['definitions']:
            self.assertTrue(set(d.get('sections') or []) <= allowed,
                            f'{d.get("name")}: unknown report section')
            if d.get('cron'):
                self.assertTrue(api._valid_cron(d['cron']),
                                f'{d.get("name")}: invalid cron {d["cron"]!r}')

    def test_slo_objects_have_monitors_attached(self):
        """_compute_slo_objects aggregates purely off monitors naming the
        object in their slo_ids, so an unattached object is a row of zeroes."""
        cfg = _store('config.json')
        objs = cfg.get('slo_objects') or []
        self.assertTrue(objs)
        attached = set()
        for m in cfg.get('monitors') or []:
            attached |= set(m.get('slo_ids') or [])
        for o in objs:
            self.assertIn(o['id'], attached,
                          f'{o["id"]}: no monitor is attached to it')
        status, body = self.call(api.handle_slo)
        self.assertEqual(status, 200)
        rows = body.get('objects') or []
        self.assertEqual(len(rows), len(objs))
        self.assertTrue(any((r.get('checks') or 0) > 0 for r in rows),
                        'every SLO object aggregates zero checks — the '
                        'monitor labels and the history keys disagree')


class TestReportArchiveIsReadable(_SeededBase):

    def test_the_archive_index_lists_entries(self):
        reports_handlers = api.reports_handlers_mod
        idx = reports_handlers._archive_index()
        self.assertTrue(idx, 'Reports -> Archive renders "No reports delivered '
                             'yet" on the seeded demo')
        for e in idx:
            self.assertTrue(str(e.get('id', '')).startswith('rpt-'))
            self.assertGreater(int(e.get('ts') or 0), 0)


class TestVirtualizationHasAPlatform(_SeededBase):

    def test_a_lifecycle_capable_integration_is_configured(self):
        hypervisor = api.hypervisor_mod
        status, body = self.call(api.handle_virt_platforms)
        self.assertEqual(status, 200)
        self.assertTrue(body.get('platforms'),
                        'the Virtualization page renders its header over an '
                        'empty table')
        for pf in body['platforms']:
            self.assertTrue(hypervisor.has_lifecycle(pf['type']))
            self.assertTrue(pf.get('power_actions'))


class TestDependencyEdgesResolve(_SeededBase):

    def test_declared_edges_have_state_and_it_is_not_pruned(self):
        """run_flow_dep_check_if_due drops any flow_deps edge that is not
        currently declared, so a seeded edge whose device has no depends_on is
        deleted on the first sweep."""
        devices = _store('devices.json')
        declared = {f'{d}:{u}' for d, dev in devices.items()
                    for u in (dev.get('depends_on') or []) if u in devices}
        self.assertTrue(declared, 'no device declares a depends_on edge, so '
                                  'the network map reports 0 dependency edges')
        seeded = set((_store('flow_deps.json').get('edges') or {}))
        self.assertTrue(seeded,
                        'flow_deps.json has no edge state, so /dependency-health '
                        'reports every declared link as never-observed')
        self.assertEqual(seeded - declared, set(),
                         'flow_deps holds edges nothing declares — the first '
                         'sweep prunes them')

    def test_flow_conversations_resolve_to_fleet_devices(self):
        """_dep_ip_index maps a conversation endpoint to a device by its
        ip/hostname. Addresses outside the fleet confirm nothing."""
        flow_handlers = api.flow_handlers_mod
        devices = api.load(api.DEVICES_FILE) or {}
        idx = flow_handlers._dep_ip_index(devices)
        observed = flow_handlers._dep_observed_edges(devices, int(time.time()))
        self.assertTrue(observed,
                        'no seeded flow conversation resolves to a pair of '
                        'fleet devices, so nothing verifies any declared link')
        for exporter in _store('flow.json'):
            self.assertIn(exporter, devices,
                          f'flow.json exporter {exporter!r} is not a device')
        declared = {frozenset((d, u)) for d, dev in devices.items()
                    for u in (dev.get('depends_on') or []) if u in devices}
        self.assertTrue(declared & observed,
                        'not one declared dependency is confirmed by flow')
        self.assertTrue(idx)


class TestMaintenanceUsesTheScopesTheProductSupports(_SeededBase):

    def test_site_tag_and_smart_scopes_are_exercised(self):
        windows = _store('maintenance.json')['windows']
        scopes = {w.get('scope') for w in windows}
        self.assertTrue(set(api._MAINTENANCE_SCOPES) >= scopes,
                        f'unknown scope in maintenance.json: '
                        f'{scopes - set(api._MAINTENANCE_SCOPES)}')
        for want in ('site', 'tag', 'smart'):
            self.assertIn(want, scopes,
                          f'no {want}-scoped window — v7.0.2 shipped that '
                          f'scope and the demo shows nothing using it')

    def test_every_scoped_window_has_a_target_that_resolves(self):
        devices = _store('devices.json')
        sites = set(_store('sites.json'))
        smart = set(_store('smart_groups.json'))
        tags = {t for d in devices.values() for t in (d.get('tags') or [])}
        groups = {d.get('group') for d in devices.values() if d.get('group')}
        for w in _store('maintenance.json')['windows']:
            scope, target = w.get('scope'), w.get('target')
            if scope == 'global':
                continue
            self.assertTrue(target, f'{w["id"]}: {scope} window with no target')
            pool = {'device': set(devices), 'site': sites, 'smart': smart,
                    'tag': tags, 'group': groups}[scope]
            self.assertIn(target, pool,
                          f'{w["id"]}: {scope} target {target!r} matches nothing')


class TestPatchCatalogAggregates(_SeededBase):

    def test_the_by_package_rollup_is_not_empty(self):
        """handle_patch_catalog groups BY PACKAGE off
        sysinfo.packages.upgradable_names; with only the integer `upgradable`
        every host lands in "devices without detail"."""
        status, body = self.call(api.handle_patch_catalog)
        self.assertEqual(status, 200)
        self.assertTrue(body.get('packages'),
                        'the Patch catalog aggregates zero packages')
        self.assertEqual(body.get('devices_without_detail') or [], [],
                         'hosts report a pending count with no package names')


class TestResultStoresAreFreshEnoughToSurviveTheFirstSweep(_SeededBase):
    """TLS, DNSBL and resolver-health have no config cadence marker: their
    sweeps re-check any TARGET whose own `checked_at` is older than the
    interval. A result seeded older than that is replaced on the first page
    load by a real probe of an unresolvable .lab name."""

    CASES = (
        ('resolver_health_results.json', 'RESOLVER_HEALTH_INTERVAL'),
        ('ip_reputation_results.json', 'IP_REP_SCAN_INTERVAL'),
        ('tls_results.json', 'TLS_SCAN_INTERVAL'),
    )

    def test_every_result_is_younger_than_its_recheck_interval(self):
        now = int(time.time())
        checked = 0
        for store, const in self.CASES:
            interval = getattr(api, const)
            for rid, rec in _store(store).items():
                ts = int((rec or {}).get('checked_at') or 0)
                self.assertGreater(ts, 0, f'{store}:{rid} has no checked_at')
                checked += 1
                self.assertLess(
                    now - ts, interval,
                    f'{store}:{rid} was checked {now - ts}s ago against a '
                    f'{interval}s {const} — the first sweep re-probes it and '
                    f'overwrites the curated result')
        self.assertGreater(checked, 5, 'too few results to be measuring anything')


if __name__ == '__main__':
    unittest.main()
