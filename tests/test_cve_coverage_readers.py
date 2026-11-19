"""What a text that says "no CVEs" says about the packages it did not look at (8.0.2 review).

The first version of the account of what a CVE scan checked was read by the CVE page, the host view and the SBOM through the
derived account (`cve_scanner.entry_package_coverage`) and by the assistant's CVE tool, the runbook, the ticket text and the
dashboard through the stored block alone. A host nothing is matched against (Arch, openSUSE, Windows, macOS) has no scan
record and so no stored block: those four readers called it a host with no CVEs while the page said none of its packages
could be checked. This file holds the readers to the one account, and two rules of the account that no fixture reached.

  * the assistant's tool, the runbook snapshot, the ticket and the dashboard payload say what the host view says, for a host
    nothing is matched against, and read the packages store only for a host whose record has no account of its own;
  * a ticket does not say "none found" beside a count of vulnerabilities, and a cut answer is "unanswered" whatever the
    host is asked by.

The fleet is the one of tests/test_cve_package_coverage.py: real ingest, the real scan worker against the recordings of the data
source, the real handlers.
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_cve_coverage_page_review as page  # noqa: E402
import test_cve_package_coverage as base  # noqa: E402

api = base.api
cve_scanner = base.cve_scanner
cve_fixes = base.cve_fixes


class TestACutAnswerIsUnansweredWhateverTheHostIsAskedBy(unittest.TestCase):
    """Debian 12 without source names: asked by installed name, so the host's own reason is "no source name". A package whose
    advisory list was cut at the last page has no whole answer, and that is the reason that comes first."""
    PACKAGES = [{'name': 'sudo', 'version': '1.9.13p3-1+deb12u1', 'arch': 'amd64'}]

    @staticmethod
    def endless(vulns):
        return lambda queries: [{'vulns': list(vulns), 'next_page_token': 't'} for _ in queries]

    def scan(self, querybatch):
        with mock.patch.object(cve_scanner, '_osv_querybatch', querybatch), \
                mock.patch.object(cve_scanner, '_osv_vuln_details', lambda vid: None):
            return cve_scanner.scan_device('h', self.PACKAGES, 'Debian:12', Path(base._tmp('rp-cov-cut-')), has_meta=False)

    def test_a_cut_answer_that_names_advisories_is_not_checked(self):
        named = [{'id': 'X-1', 'modified': '2026-11-10T08:00:00.123456Z'}]
        result = self.scan(self.endless(named))
        self.assertEqual(result['cut'], ['sudo'])
        self.assertEqual(result['covered']['reasons'], {'unanswered': 1})        # the named advisory does not make it checked
        self.assertEqual(result['covered']['checked'], 0)

    def test_a_cut_answer_that_names_nothing_is_unanswered_and_not_a_missing_source(self):
        result = self.scan(self.endless([]))
        self.assertEqual(result['cut'], ['sudo'])
        self.assertEqual(result['covered']['reasons'], {'unanswered': 1})

    def test_the_same_package_with_a_whole_empty_answer_has_the_reason_of_the_host(self):
        """The control: without the cut the reason is the host's, so the two tests above see the order and not the package."""
        result = self.scan(base.no_findings)
        self.assertEqual(result['cut'], [])
        self.assertEqual(result['covered']['reasons'], {'no_source': 1})

    def test_package_coverage_says_the_same_without_a_scan(self):
        packages = [{'name': 'a', 'version': '1'}, {'name': 'b', 'version': '1'}]
        units = [{'name': 'a', 'version': '1', 'rows': [0]}, {'name': 'b', 'version': '1', 'rows': [1]}]
        answers = [{'vulns': [], 'truncated': True}, {'vulns': []}]
        block = cve_scanner.package_coverage(packages, units, answers, 'needs_agent', cut={0})
        self.assertEqual([(r['name'], r['reason']) for r in block['packages']], [('a', 'unanswered'), ('b', 'no_source')])


class TestTheTicketOfAHostThatListsNothingAndCountsMuch(base._Fleet):
    """The text of a ticket for a new-CVE alert. A Debian host whose scan listed nothing and counted 400 vulnerabilities per
    package, and did not check 2 of its 3 packages."""
    COUNTED = {'total': 400, 'severity': {'medium': 400}, 'fix': {'none': 400}}
    COVERED = {'listed': 3, 'checked': 1, 'not_checked': 2, 'reasons': {'no_source': 2}, 'packages': [], 'more': 2}

    def ticket(self, **record):
        store = api.load(api.CVE_FINDINGS_FILE)
        store[self.DEB_OLD] = dict({'scanned_at': 5, 'ecosystem': 'Debian:12', 'findings': []}, **record)
        api.save(api.CVE_FINDINGS_FILE, store)
        api._LOAD_CACHE.clear()
        return api._alert_ticket_detail({'event': 'cve_found', 'device_id': self.DEB_OLD, 'title': 'New CVEs',
                                         'payload': {'device_id': self.DEB_OLD}})

    def test_the_count_and_what_was_not_checked_are_said_and_none_found_is_not(self):
        text = self.ticket(rollup=self.COUNTED, covered=self.COVERED)
        self.assertIn('400 more known vulnerabilities are counted per package and not listed one by one.', text)
        self.assertIn('Checked 1 of 3 packages; 2 not checked: 2 have no source name.', text)
        self.assertNotIn('None found', text)
        self.assertNotIn('none found', text)

    def test_without_the_count_the_same_host_does_say_none_found_in_the_packages_that_could_be_checked(self):
        """The control: the instrument sees the sentence the test above says is absent."""
        text = self.ticket(covered=self.COVERED)
        self.assertIn('None found in the 1 package that could be checked.', text)
        self.assertIn('Checked 1 of 3 packages; 2 not checked: 2 have no source name.', text)


class TestAHostNothingIsMatchedAgainst(base._Fleet):
    """covwin (8 applications) and covarch (1 package) are never scanned: no record, so no stored block. The account of what was
    checked is the one their package lists give, and every reader says it."""
    NONE_OF = {base._Fleet.WIN: 8, base._Fleet.ARCH: 1}

    def dev(self, dev_id):
        return api.load(api.DEVICES_FILE)[dev_id]

    def reads_of_the_packages_store(self, call):
        """(what `call` returned, how many times it asked for the packages store through the shared read)."""
        seen = []
        real = api._load_ro

        def spy(path):
            if path == api.PACKAGES_FILE:
                seen.append(path)
            return real(path)
        with mock.patch.object(api, '_load_ro', spy):
            out = call()
        return out, len(seen)

    def without_findings(self):
        """Every scanned host lists nothing and counts nothing: only what each checked is left."""
        store = api.load(api.CVE_FINDINGS_FILE)
        for dev_id in (self.DEB_NEW, self.DEB_OLD):
            store[dev_id]['findings'] = []
            store[dev_id].pop('rollup', None)
        api.save(api.CVE_FINDINGS_FILE, store)
        api._LOAD_CACHE.clear()

    def home_body(self, **kw):
        with mock.patch.object(api, 'verify_token', kw.pop('verify', lambda tok=None: ('root', 'admin'))):
            status, body = self.get(api.handle_home, **kw)
        self.assertEqual(status, 200, body)
        return body

    def home(self, **kw):
        return {r['device_id']: r for r in self.home_body(**kw)['cves']['devices']}

    # the assistant's tool
    def test_the_assistants_tool_says_none_of_the_packages_could_be_checked(self):
        self.assertEqual(self.record(self.WIN), {})
        for host, n in self.NONE_OF.items():
            text = api._triage_tools(host, self.dev(host))['cves']({})
            self.assertIn(f'none found, but none of the {n} package', text, host)
            self.assertIn(f'Checked 0 of {n} package', text, host)
            self.assertIn("have no matcher for this host's package manager", text, host)
            self.assertNotEqual(text, '(no open CVE findings for this host)', host)

    def test_a_host_that_was_checked_whole_keeps_the_plain_sentence_and_does_not_read_the_packages_store(self):
        self.without_findings()
        text, reads = self.reads_of_the_packages_store(
            lambda: api._triage_tools(self.DEB_NEW, self.dev(self.DEB_NEW))['cves']({}))
        self.assertEqual(text, '(no open CVE findings for this host)')
        self.assertEqual(reads, 0)
        _, reads = self.reads_of_the_packages_store(lambda: api._triage_tools(self.WIN, self.dev(self.WIN))['cves']({}))
        self.assertGreaterEqual(reads, 1)           # the control: the instrument sees a read

    # the runbook
    def test_the_runbook_snapshot_carries_the_account_of_a_host_nothing_is_matched_against(self):
        for host, n in self.NONE_OF.items():
            snap = api._build_runbook_snapshot(host, api.load(api.DEVICES_FILE))
            self.assertEqual(snap['cve_coverage'], {'listed': n, 'checked': 0, 'not_checked': n, 'reasons': {'no_matcher': n}}, host)
            self.assertEqual((snap['cve_findings'], snap['cve_counted']), ([], 0), host)

    def test_a_host_that_can_be_scanned_and_was_not_says_nothing_of_its_packages(self):
        store = api.load(api.CVE_FINDINGS_FILE)
        store.pop(self.DEB_NEW)
        api.save(api.CVE_FINDINGS_FILE, store)
        api._LOAD_CACHE.clear()
        snap = api._build_runbook_snapshot(self.DEB_NEW, api.load(api.DEVICES_FILE))
        self.assertIsNone(snap['cve_coverage'])
        self.assertEqual(api._triage_tools(self.DEB_NEW, self.dev(self.DEB_NEW))['cves']({}),
                         '(no open CVE findings for this host)')

    def test_the_runbook_of_a_host_with_a_block_does_not_read_the_packages_store(self):
        snap, reads = self.reads_of_the_packages_store(
            lambda: api._build_runbook_snapshot(self.DEB_OLD, api.load(api.DEVICES_FILE)))
        self.assertEqual(snap['cve_coverage']['not_checked'], 2)
        self.assertEqual(reads, 0)

    # the ticket
    def test_the_text_of_a_ticket_for_such_a_host_says_none_could_be_checked(self):
        text = api._alert_ticket_detail({'event': 'cve_found', 'device_id': self.WIN, 'title': 'New CVEs',
                                         'payload': {'device_id': self.WIN}})
        self.assertIn('Open CVEs on this host: 0 total', text)
        self.assertIn('None found, but none of the 8 packages could be checked.', text)

    # the dashboard
    def test_the_dashboard_is_told_when_nothing_shows_a_finding(self):
        self.without_findings()
        rows = self.home()
        self.assertEqual({k: v['not_checked'] for k, v in rows.items()},
                         {self.DEB_NEW: 0, self.DEB_OLD: 2, self.WIN: 8, self.ARCH: 1})
        self.assertTrue(all(v['counted'] == 0 and not any(v['counts'].values()) for v in rows.values()))

    @page.NEEDS_NODE
    def test_the_tile_the_payload_makes_is_not_green_over_hosts_nothing_is_matched_against(self):
        """The payload of the real handler through the real tile. Every host that is scanned was checked whole and shows nothing:
        only the two hosts nothing is matched against make the tile say that part of the fleet was not looked at."""
        self.without_findings()
        devices = api.load(api.DEVICES_FILE)
        devices.pop(self.DEB_OLD)                                  # the one whose own scan says that 2 of its 3 were not checked
        api.save(api.DEVICES_FILE, devices)
        body = self.home_body()
        self.assertEqual({r['device_id']: r['not_checked'] for r in body['cves']['devices']},
                         {self.DEB_NEW: 0, self.WIN: 8, self.ARCH: 1})
        got = page.tile_of(body['devices'], body['cves']['devices'])
        self.assertEqual((got['cls'], got['sub']), ('', 'None found in the packages that could be checked'))
        # and without the two it is the green it was
        for dev_id in (self.WIN, self.ARCH):
            devices.pop(dev_id)
        api.save(api.DEVICES_FILE, devices)
        body = self.home_body()
        got = page.tile_of(body['devices'], body['cves']['devices'])
        self.assertEqual((got['cls'], got['sub']), ('ok', 'No active CVEs'))

    def test_the_dashboard_reads_no_list_of_the_fleet_whether_or_not_a_host_shows_a_finding(self):
        """8.0.2: the account of a host nothing is matched against is worked out when its list arrives and kept with the host, so the
        page reads no packages store. It read the whole store on a quiet fleet, on every poll of every open tab (940 ms at 24 MB)."""
        rows, reads = self.reads_of_the_packages_store(lambda: self.home())
        self.assertTrue(any(any(v['counts'].values()) or v['counted'] for v in rows.values()))   # the control: there are some
        self.assertEqual(reads, 0)
        self.assertEqual((rows[self.DEB_OLD]['not_checked'], rows[self.WIN]['not_checked']), (2, 8))
        # and with nothing found, where the number decides what the tile says, it is the same and still reads nothing
        self.without_findings()
        rows, reads = self.reads_of_the_packages_store(lambda: self.home())
        self.assertEqual(reads, 0)
        self.assertEqual((rows[self.WIN]['not_checked'], rows[self.ARCH]['not_checked']), (8, 1))

    def test_the_dashboard_does_not_read_them_for_a_host_the_tile_leaves_out(self):
        """An unmonitored host is not in the tile. With the monitored hosts checked whole nothing needs the lists."""
        self.without_findings()
        devices = api.load(api.DEVICES_FILE)
        for host in (self.DEB_OLD, self.WIN, self.ARCH):
            devices[host]['monitored'] = False
        api.save(api.DEVICES_FILE, devices)
        rows, reads = self.reads_of_the_packages_store(lambda: self.home())
        self.assertEqual(reads, 0)
        self.assertEqual(rows[self.WIN]['not_checked'], 0)

    def test_the_dashboard_does_not_read_them_for_an_agentless_device_that_has_no_list(self):
        """A switch or an access point is monitored and never sends a package list: it must not start the read of every list."""
        self.without_findings()
        devices = api.load(api.DEVICES_FILE)
        for host in (self.WIN, self.ARCH):
            devices[host]['monitored'] = False
        devices['covswitch'] = dict(self.device('covswitch', 'tenantB', 'Switch'), agentless=True)
        api.save(api.DEVICES_FILE, devices)
        rows, reads = self.reads_of_the_packages_store(lambda: self.home())
        self.assertIn('covswitch', rows)                       # the control: the switch is a monitored host of the payload
        self.assertEqual(reads, 0)
        self.assertEqual(rows['covswitch']['not_checked'], 0)

    def test_a_tenant_administrator_is_told_of_their_own_hosts_only(self):
        self.without_findings()
        status, home = self.as_tenant_admin(api.handle_home, user=('bruno', 'admin'))
        self.assertEqual(status, 200, home)
        rows = {r['device_id']: r['not_checked'] for r in home['cves']['devices']}
        self.assertEqual(rows, {self.WIN: 8, self.ARCH: 1})
        status, home = self.as_tenant_admin(api.handle_home)
        self.assertEqual({r['device_id']: r['not_checked'] for r in home['cves']['devices']}, {self.DEB_NEW: 0, self.DEB_OLD: 2})

    def test_a_read_only_user_reads_their_tenants_numbers(self):
        self.without_findings()
        status, home = self.as_read_only(api.handle_home)
        self.assertEqual(status, 200, home)
        self.assertEqual({r['device_id']: r['not_checked'] for r in home['cves']['devices']}, {self.DEB_NEW: 0, self.DEB_OLD: 2})


class TestTheFleetLineSaysHowManyHostsItDoesNotCount(base._Fleet):
    """The fleet line of the CVE page adds up the account of each host. After an upgrade a scanned host has a record from before
    the block existed, and an upgrade starts no scan: it was in neither number, and "Packages checked: 0 / 8" read as the whole
    of a fleet of thirty scanned hosts. The report says how many such hosts there are."""

    def summary(self, **kw):
        status, report = self.get(api.handle_cve_findings, **kw)
        self.assertEqual(status, 200, report)
        return report['summary']['covered']

    def scanned_before_the_block(self, *hosts):
        store = api.load(api.CVE_FINDINGS_FILE)
        for host in hosts:
            store[host].pop('covered')
        api.save(api.CVE_FINDINGS_FILE, store)
        api._LOAD_CACHE.clear()

    def test_a_fleet_whose_scans_all_state_their_packages_has_no_host_left_out(self):
        covered = self.summary()
        self.assertEqual(covered['hosts_unstated'], 0)
        self.assertEqual(covered['listed'], 18)

    def test_a_scanned_host_without_the_block_is_counted_in_neither_number_and_is_named_as_left_out(self):
        self.scanned_before_the_block(self.DEB_NEW)
        covered = self.summary()
        self.assertEqual(covered['hosts_unstated'], 1)
        self.assertEqual((covered['listed'], covered['not_checked']), (12, 11))        # the 6 packages of that host are not in it

    def test_a_host_that_was_never_scanned_is_not_one_of_them_and_a_host_nothing_is_matched_against_is_not_either(self):
        store = api.load(api.CVE_FINDINGS_FILE)
        store.pop(self.DEB_NEW)
        api.save(api.CVE_FINDINGS_FILE, store)
        api._LOAD_CACHE.clear()
        covered = self.summary()
        self.assertEqual(covered['hosts_unstated'], 0)       # no record at all: the table says "not scanned"
        self.assertEqual(covered['listed'], 12)              # WIN and ARCH state theirs from their lists

    def test_a_host_with_no_list_of_packages_is_not_one_of_them(self):
        devices = api.load(api.DEVICES_FILE)
        devices['covbare'] = self.device('covbare', 'tenantA', 'Switch')              # no agent list, so nothing to scan
        api.save(api.DEVICES_FILE, devices)
        api._LOAD_CACHE.clear()
        status, report = self.get(api.handle_cve_findings)
        self.assertEqual(status, 200, report)
        self.assertEqual({r['device_id']: r['status'] for r in report['devices']}['covbare'], 'no_packages')
        self.assertEqual(report['summary']['covered']['hosts_unstated'], 0)

    def test_after_an_upgrade_the_line_counts_every_host_it_leaves_out(self):
        """Thirty scanned Debian hosts whose records are from before the block, beside the four hosts of the fleet."""
        devices, packages, findings = api.load(api.DEVICES_FILE), api.load(api.PACKAGES_FILE), {}
        for i in range(30):
            dev_id = f'old{i:02d}'
            devices[dev_id] = self.device(dev_id, 'tenantA', 'Debian 12')
            packages[dev_id] = {'ecosystem': 'Debian:12', 'pkg_manager': 'apt', 'count': 1500, 'os_id': 'debian',
                                'version_id': '12', 'sources': True, 'packages': [{'name': 'bash', 'version': '5.2.15-2'}] * 3}
            findings[dev_id] = {'scanned_at': 5, 'ecosystem': 'Debian:12', 'findings': []}
        api.save(api.DEVICES_FILE, devices)
        api.save(api.PACKAGES_FILE, packages)
        api.save(api.CVE_FINDINGS_FILE, dict(api.load(api.CVE_FINDINGS_FILE), **findings))
        api._LOAD_CACHE.clear()
        covered = self.summary()
        self.assertEqual(covered['hosts_unstated'], 30)
        self.assertEqual(covered['listed'], 18)              # what the four hosts of the fleet state is still what it was

    def test_a_tenant_administrator_and_a_read_only_user_read_their_own_tenants_number(self):
        self.scanned_before_the_block(self.DEB_NEW, self.DEB_OLD)
        self.assertEqual(self.summary()['hosts_unstated'], 2)
        status, report = self.as_tenant_admin(api.handle_cve_findings)
        self.assertEqual((status, report['summary']['covered']['hosts_unstated']), (200, 2))
        status, report = self.as_tenant_admin(api.handle_cve_findings, user=('bruno', 'admin'))
        self.assertEqual((status, report['summary']['covered']['hosts_unstated']), (200, 0))
        status, report = self.as_read_only(api.handle_cve_findings)
        self.assertEqual((status, report['summary']['covered']['hosts_unstated']), (200, 2))


class TestNoReaderTakesAStoredBlockAlone(unittest.TestCase):
    """Every place in the server that reads a key called `covered`, found by syntax tree, and what each one reads. A reader of
    the block a scan stored on a host's record that is not one of these sees nothing for a host nothing is matched against,
    which is the defect this file holds: it goes through `_cve_account` (a sentence) or `cve_scanner.entry_package_coverage`."""
    SITES = {
        'cve_scanner.py:entry_package_coverage': 'the derived account: the stored block, or what the package list gives',
        'api.py:_cve_account': 'the readers that print a sentence: the stored block, or the derived account',
        'api.py:handle_home': 'the dashboard: the stored block, and for a host nothing is matched against the account kept with the host'
                              ' when its list arrived (`pkg_account`), so that it reads no store',
        'api.py:_cve_scan_worker': 'not a page: hands the account of each scan to the alert path (cve_fixes.clear_is_trusted)',
        'api.py:_merge_findings': 'not a page: the same, inside the worker',
        'cve_handlers.py:handle_cve_findings': 'reads the derived account the line above returns, not a record',
        'mcp_http.py:tool_get_cves': 'reads the answer of the host view, not a record',
        'api.py:handle_edr_coverage': 'not this: the hosts an EDR product covers',
        'prometheus_export.py:_emit_device_uptime': 'not this: the rows of an uptime report that cover a window',
    }

    @staticmethod
    def census():
        import ast
        found = {}
        for path in sorted((Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin').glob('*.py')):
            for fn in ast.walk(ast.parse(path.read_text())):
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for n in ast.walk(fn):
                    named = (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == 'get'
                             and n.args and isinstance(n.args[0], ast.Constant) and n.args[0].value == 'covered') or (
                        isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant) and n.slice.value == 'covered'
                        and isinstance(n.ctx, ast.Load))
                    if named:
                        found[f'{path.name}:{fn.name}'] = fn.lineno
        return found

    def test_every_site_is_accounted_for_and_none_is_listed_that_is_gone(self):
        found = self.census()
        self.assertGreaterEqual(len(found), 5)                                  # a census of nothing proves nothing
        for known in ('api.py:handle_home', 'api.py:_cve_account', 'cve_scanner.py:entry_package_coverage'):
            self.assertIn(known, found)
        self.assertEqual(sorted(set(found) - set(self.SITES)), [],
                         'a function reads a `covered` key and is not classified: if it reads the block of a scan record it '
                         'must go through api._cve_account or cve_scanner.entry_package_coverage')
        self.assertEqual(sorted(set(self.SITES) - set(found)), [], 'SITES lists a function that no longer reads one')

    def test_the_readers_of_a_record_use_the_one_account(self):
        import apisrc
        import srcpin
        source = apisrc.api_source()
        for name in ('_triage_tools', '_build_runbook_snapshot', '_alert_ticket_detail'):
            body = srcpin.py_function(source, name)
            self.assertIn('_cve_account(', body, name)
            self.assertNotIn(".get('covered')", body, name)
        # the dashboard reads the account kept with the host, which the ingest derives with the one account
        self.assertIn("'pkg_account'", srcpin.py_function(source, 'handle_home'))
        self.assertIn('entry_package_coverage(', srcpin.py_function(source, 'handle_packages_submit'))


if __name__ == '__main__':
    unittest.main()
