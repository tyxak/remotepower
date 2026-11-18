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


if __name__ == '__main__':
    unittest.main()
