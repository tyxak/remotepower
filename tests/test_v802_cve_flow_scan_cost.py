#!/usr/bin/env python3
"""One host's package list decides how much memory, how many requests and how many bytes of the shared stores a scan takes.

A host sends its own list (up to 10,000 rows). A scan of it, which the host's tenant administrator can queue and which every fleet
scan repeats, asked the advisory service about every distinct source, held every advisory of every answer, read every record it did
not have, wrote the whole cache of advisory records (shared by every organisation, never trimmed, read whole by every later scan of
every host) after every 250 records, and stored every finding of a host whose findings are not chosen by the Debian rule. The 8.0.2
review measured, with a stand-in for the service that answers the sizes the project recorded:

* 250, 500 and 1,000 distinct sources of 20 advisories: 59, 230 and 889 MB written (40 times the cache), 22, 42 and 81 whole writes;
* one source listed at 1, 10, 40, 100 and 200 versions, each answered with the 8,882 advisories of one old kernel: 93 MB to 1,687 MB
  resident (8 MB for each version listed);
* `plan_host` of 10,000 RPM packages of one source and 16 kernel images: 6.4 s, against 0.04 s for a normal host (list membership
  tests inside loops over the packages of one source, run twice for every fleet scan);
* an Alpine host that lists 1,000 origins of 20 advisories stores 20,000 findings (12 MB) in the store every page reads.

What this holds, with the real planner and the real scan against a stand-in for the advisory service:

* the planner and the kernel state give the answers they gave, for random lists, and take a fraction of a second for the hostile ones;
* no name is asked about at more than MAX_UNITS_PER_NAME versions, and the unit of the running kernel is taken first; a package whose
  question was not asked is "not checked" in the host's account;
* what is held for a host has a ceiling while the answers come in (`_osv_query_all(budget=...)`), and the questions after it are not
  asked; the map a fleet scan shares has a ceiling of its own, leaves out what it cut, and the host's own scan asks for that, so the
  findings are the ones the scan gives without a ceiling;
* a scan reads at most MAX_DETAIL_FETCHES_PER_SCAN records, the next scan reading the rest; the cache is written once for a scan, and
  past DETAILS_CACHE_MAX_RECORDS the oldest records go and never the ones the scan holds;
* a host whose findings are all listed keeps at most KEEP_UNRULED_PER_HOST of them, the most pressing first, and the rest are counted;
* the scan worker reads the store of package lists without a copy and does not change it.
"""
import json
import os
import random
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v802-sc-"))
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
import cve_fixes  # noqa: E402
import cve_scanner  # noqa: E402

_TMP = []


def tearDownModule():
    import shutil
    for d in _TMP:
        shutil.rmtree(d, ignore_errors=True)


def _tmp():
    d = tempfile.mkdtemp(prefix="rp-v802-sc-run-")
    _TMP.append(d)
    return Path(d)


# The two functions as they were before 8.0.2, run in the namespace of the module, as the reference the new ones are held to.
_OLD_PLAN = r'''def _old_plan(packages, ecosystem, has_meta: bool = False, deb_by_source: bool = False) -> list:
    """The units to ask the advisory database for, for one host's package list. `deb_by_source` is
    `by_source(ecosystem, release)` of the host.

    Each unit is {'name', 'version'} (the question), 'package' and 'shown' (the name and version on a
    finding), 'epoch_known' (whether the version carries its epoch), 'binaries' (the installed packages
    the unit speaks for; empty when the unit is the installed package itself) and, since 8.0.2, 'rows' (the
    places of those packages in the list, which is how a scan says which package was checked)."""
    fam = family(ecosystem)
    units: dict = {}

    def unit(name, version, package, epoch_known, binary, row):
        key = (name, version)
        found = units.get(key)
        if found is None:
            found = units[key] = {'name': name, 'version': version, 'package': package, 'shown': version,
                                  'epoch_known': epoch_known, 'binaries': [], 'rows': []}
        if binary and binary not in found['binaries']:
            found['binaries'].append(binary)
        if row not in found['rows']:
            found['rows'].append(row)

    grouped = bool(has_meta) and (fam in ('apk', 'rpm') or (fam == 'deb' and bool(deb_by_source)))
    both_names = grouped and fam == 'rpm' and isinstance(ecosystem, str) and ecosystem.startswith('Rocky Linux')
    sources: dict = {}   # (source, its version-release) -> {'members': [(name, row)], 'epochs': set()}
    for row, p in enumerate((packages if isinstance(packages, list) else [])[:MAX_PACKAGES]):
        if not isinstance(p, dict):
            continue
        name, version = _text(p.get('name')), _text(p.get('version'))
        if not name or not version:
            continue
        if fam == 'rpm' and name in _KEY_RECORDS:
            continue
        if not grouped:
            # an RPM list without epochs: the version is asked for as it is, which answers with every
            # advisory of a package that has an epoch, and the "already patched" check sorts them out
            unit(name, version, name, fam != 'rpm', None, row)
            continue
        source = _text(p.get('source')) or name
        if fam == 'apk':
            unit(source, version, source, True, name, row)   # a subpackage has its origin's version
            continue
        if fam == 'deb':
            # a Debian package may have another version than its source ("12.2.0-14+b1" of "12.2.0-14")
            unit(source, _text(p.get('source_version')) or version, source, True, name, row)
            continue
        epoch = _text(p.get('epoch'))
        if not (epoch.isascii() and epoch.isdigit()) or int(epoch) == 0:
            epoch = ''
        unit(name, f'{epoch}:{version}' if epoch else version, source, True, name, row)
        if both_names:
            source_version = _text(p.get('source_version')) or version
            group = sources.setdefault((source, source_version), {'members': [], 'epochs': set()})
            group['members'].append((name, row))
            if version == source_version:
                group['epochs'].add(epoch)
    for (source, source_version), group in sources.items():
        # The source package's own epoch is not in what a host can report. It is the epoch of a package
        # built from it with the source's version, when they agree on one; otherwise the source is not
        # asked for by name and its packages still are.
        if len(group['epochs']) != 1:
            continue
        epoch = next(iter(group['epochs']))
        for binary, row in group['members']:
            unit(source, f'{epoch}:{source_version}' if epoch else source_version, source, True, binary, row)
    return list(units.values())
'''
_OLD_KERNEL_STATE = r'''def _old_kernel_state(report, packages, units, fam: str):
    """(the block a scan stores as `kernel`, the places of the units that hold the running kernel's package, and for
    each other installed kernel image ([the places of its units], its label)).

    The block is None for a host with no kernel to speak of (a family no agent reports one for, or no kernel package at
    all). Otherwise it names the running release and is `matched`, with the package, or `unknown`, with why
    (cve_fixes.KERNEL_WHY): the agent sent no report, found no image, no image owns the running release, two images that
    are built from different versions do, or the owner is not in the list. Two images of one version (a signed
    package and the unsigned one it holds) are one owner."""
    if fam not in _KERNEL_PACKAGE:
        return None, [], []
    rep = kernel_report(report)
    block = {'running': rep.get('release', '')}

    def unknown(why):
        if not _has_kernel_package(fam, packages):
            return None, [], []
        return dict(block, state=cve_fixes.KERNEL_UNKNOWN, why=why), [], []

    if not rep:
        return unknown('not_reported')
    images = rep['images']
    if not images:
        return unknown('no_images')
    rows_of: dict = {}
    for i, p in enumerate((packages if isinstance(packages, list) else [])[:MAX_PACKAGES]):
        if isinstance(p, dict):
            rows_of.setdefault((_text(p.get('name')), _text(p.get('version'))), i)
    by_row: dict = {}
    for k, u in enumerate(units):
        for row in u.get('rows', ()):
            by_row.setdefault(row, []).append(k)
    # An RPM kernel is several packages built together (kernel, kernel-core, kernel-modules, kernel-modules-core, ...), the
    # plan asks about each by its own name and version, and the agent names only kernel-core, the one that owns the file. The
    # others carry the advisories of the same kernel, so the units of every package built from the same source package at
    # the same version as an image are that kernel's units. A Debian or Alpine unit is already one source and its version,
    # so there it is the unit of the image.
    built: dict = {}
    if fam == 'rpm':
        for i, p in enumerate((packages if isinstance(packages, list) else [])[:MAX_PACKAGES]):
            if isinstance(p, dict):
                built.setdefault(_built_from(p), []).append(i)

    def held_by(image):
        row = rows_of.get((image['name'], image['version']))
        places = list(by_row.get(row, []))           # the image's own units first: the version a finding is held against
        if row is not None and built:
            for mate in built.get(_built_from(packages[row]), ()):
                places += [k for k in by_row.get(mate, []) if k not in places]
        return places

    owners = [im for im in images if im.get('release') == rep['release']]
    if not owners:
        return unknown('no_owner')
    sets = [frozenset(held_by(im)) for im in owners]
    if not all(sets):
        return unknown('not_in_list')
    if len(set(sets)) > 1:
        return unknown('several_owners')
    running = sorted(sets[0])
    owner = min(owners, key=lambda im: (im['name'], im['version']))
    others = []
    for im in images:
        if im in owners:
            continue
        places = [k for k in held_by(im) if k not in running]
        if places:
            others.append((places, f"{im['name']} {im['version']}"))
    return dict(block, state=cve_fixes.KERNEL_MATCHED, package=owner['name'], version=owner['version']), running, others
'''
_ns = dict(vars(cve_scanner))
exec(_OLD_PLAN, _ns)
exec(_OLD_KERNEL_STATE, _ns)
old_plan = _ns["_old_plan"]
old_kernel_state = _ns["_old_kernel_state"]


def _debian(n, source=None, versions=1, prefix="p"):
    rows = []
    for i in range(n):
        src = source or "%s%d" % (prefix, i)
        v = "1.%d-1" % (i % versions)
        rows.append({"name": "%s%d" % (prefix, i), "version": v, "arch": "amd64", "source": src, "source_version": v})
    return rows


class TestTheAnswersAreTheOnesTheyWere(unittest.TestCase):

    def test_plan_gives_the_old_answer_for_random_lists(self):
        rng = random.Random(8023)
        for case in range(300):
            fam = rng.choice(["Debian:12", "Alpine:v3.19", "Rocky Linux:9", "Ubuntu:22.04:LTS", "Red Hat:9", ""])
            n = rng.choice([0, 1, 4, 30, 200])
            pk = []
            for i in range(n):
                pk.append({"name": rng.choice(["a%d" % rng.randrange(20), "libx", "kernel-core", "gpg-pubkey"]),
                           "version": rng.choice(["1.0", "1.0-1", "2.3", ""]), "arch": "x86_64",
                           "source": rng.choice(["s%d" % rng.randrange(6), "", None, 7]),
                           "source_version": rng.choice(["1.0", "1.0-1", "", None]), "epoch": rng.choice(["", "0", "2", None, 3])})
            for has_meta in (True, False):
                for by_src in (True, False):
                    want = old_plan(pk, fam, has_meta, by_src)
                    got = cve_scanner.plan(pk, fam, has_meta, by_src)
                    self.assertEqual(got, want, "case %d %s meta=%s by_source=%s" % (case, fam, has_meta, by_src))

    def test_the_kernel_state_gives_the_old_answer_for_random_hosts(self):
        rng = random.Random(8024)
        matched = 0
        for case in range(300):
            fam = rng.choice(["rpm", "deb", "apk"])
            n = rng.choice([3, 12, 60])
            pk = []
            for i in range(n):
                src = rng.choice(["kernel", "linux", "other%d" % rng.randrange(3)])
                v = rng.choice(["5.14.0-1", "5.14.0-2", "6.1.0-1"])
                name = rng.choice(["kernel-core", "kernel-modules", "linux-image-x", "pkg%d" % i])
                pk.append({"name": name, "version": v, "arch": "x86_64", "source": src, "source_version": v})
            images = [{"name": rng.choice(["kernel-core", "linux-image-x"]), "version": rng.choice(["5.14.0-1", "5.14.0-2", "6.1.0-1"]),
                       "release": rng.choice(["5.14.0-1.x86_64", "5.14.0-2.x86_64", "6.1.0-1.x86_64"])} for _ in range(rng.randrange(0, 5))]
            report = {"release": rng.choice(["5.14.0-1.x86_64", "5.14.0-2.x86_64", "6.1.0-1.x86_64"]), "images": images}
            ecosystem = {"rpm": "Rocky Linux:9", "deb": "Debian:12", "apk": "Alpine:v3.19"}[fam]
            units = cve_scanner.plan(pk, ecosystem, True, True)
            want = old_kernel_state(report, pk, units, fam)
            got = cve_scanner.kernel_state(report, pk, units, fam)
            self.assertEqual(got, want, "case %d" % case)
            matched += bool(got[0] and got[0].get("state") == "matched")
        self.assertGreater(matched, 10, "control: some hosts had a kernel that was told apart")


class TestTheHostileListsAreCheap(unittest.TestCase):

    def test_ten_thousand_packages_of_one_source_are_planned_in_a_fraction_of_a_second(self):
        pk = _debian(10000, source="linux", versions=1)
        t = time.process_time()
        units = cve_scanner.plan(pk, "Debian:12", True, True)
        took = time.process_time() - t
        self.assertEqual(len(units), 1)
        self.assertEqual(len(units[0]["binaries"]), 10000)
        self.assertEqual(len(units[0]["rows"]), 10000)
        self.assertLess(took, 0.3, "%.2f s (0.6 s before 8.0.2: a membership test in a list of 10,000 for each package)" % took)

    def test_an_rpm_host_of_ten_thousand_packages_of_one_source_and_sixteen_kernels(self):
        n = 10000
        rpm = [{"name": "kernel-m%d" % i, "version": "1.%d-1.el9" % i, "arch": "x86_64", "source": "kernel", "source_version": "5.14-1.el9"}
               for i in range(n)]
        images = [{"name": "kernel-m%d" % i, "version": "1.%d-1.el9" % i, "release": "5.14.0-%d.el9.x86_64" % i} for i in range(16)]
        report = {"release": "5.14.0-0.el9.x86_64", "images": images}
        t = time.process_time()
        units, block, later, left_out = cve_scanner.plan_host(rpm, "Rocky Linux:9", True, None, report)
        took = time.process_time() - t
        self.assertLess(took, 1.0, "%.1f s (6.4 s before 8.0.2: `k not in places` over a list of 10,000 for each of the 16 images)" % took)
        self.assertEqual(block["state"], "matched")
        self.assertEqual(len(units), n, "every name is its own question, and none of the packages is a second version of one")


class TestWhatAHostCanMakeAScanAsk(unittest.TestCase):

    def test_a_name_is_asked_at_no_more_than_the_ceiling_of_versions(self):
        units = [{"name": "linux", "version": "0.%d-1" % i, "rows": [i]} for i in range(100)] + [{"name": "openssl", "version": "3.0", "rows": [200]}]
        kept = cve_scanner.cap_units(units)
        self.assertEqual([u["version"] for u in kept if u["name"] == "linux"], ["0.%d-1" % i for i in range(cve_scanner.MAX_UNITS_PER_NAME)],
                         "the first of them, in the order of the plan")
        self.assertEqual(sum(1 for u in kept if u["name"] == "openssl"), 1)
        self.assertEqual([u for u in kept], [u for u in units if u in kept], "and the units keep their order")

    def test_a_normal_host_is_asked_about_all_it_lists(self):
        units = [{"name": "linux", "version": "6.1.%d-1" % i, "rows": [i]} for i in range(5)] + [{"name": "p%d" % i, "version": "1", "rows": [10 + i]} for i in range(900)]
        self.assertEqual(cve_scanner.cap_units(units), units)
        self.assertGreaterEqual(cve_scanner.MAX_UNITS_PER_NAME, 16, "an agent reports at most 16 kernel images, and each is a version of one name")

    def test_the_unit_of_the_running_kernel_is_taken_first(self):
        units = [{"name": "linux", "version": "0.%d-1" % i, "rows": [i]} for i in range(60)]
        units.append({"name": "linux", "version": "9.9-1", "rows": [90], "kernel": "running"})
        kept = cve_scanner.cap_units(units)
        self.assertIn("9.9-1", [u["version"] for u in kept], "a list that fills the ceiling with other versions does not leave it out")
        self.assertEqual(sum(1 for u in kept if u["name"] == "linux"), cve_scanner.MAX_UNITS_PER_NAME, "and it is not exempt from the ceiling")

    def test_a_host_cannot_mark_every_version_of_a_name_as_the_running_kernel(self):
        units = [{"name": "kernel-core", "version": "5.%d-1" % i, "rows": [i], "kernel": "running"} for i in range(100)]
        self.assertEqual(len(cve_scanner.cap_units(units)), cve_scanner.MAX_UNITS_PER_NAME)

    def test_the_plan_of_the_host_applies_it_so_that_the_fleet_prefetch_asks_what_the_scan_asks(self):
        pk = [{"name": "linux-image-%d" % i, "version": "6.1.%d-1" % i, "arch": "amd64", "source": "linux", "source_version": "6.1.%d-1" % i}
              for i in range(100)]
        units = cve_scanner.plan_host(pk, "Debian:12", True, "Debian:12", None)[0]
        self.assertEqual(len(units), cve_scanner.MAX_UNITS_PER_NAME)

    def test_a_package_whose_question_was_not_asked_is_not_checked_in_the_account(self):
        pk = [{"name": "linux-image-%d" % i, "version": "0.%d-1" % i, "arch": "amd64", "source": "linux", "source_version": "0.%d-1" % i}
              for i in range(60)]
        units = cve_scanner.plan_host(pk, "Debian:12", True, "Debian:12", None)[0]
        covered = cve_scanner.package_coverage(pk, units, [{"vulns": []}] * len(units), "")
        self.assertEqual(covered["listed"], 60)
        self.assertEqual(covered["checked"], cve_scanner.MAX_UNITS_PER_NAME)
        self.assertEqual(covered["reasons"], {"unanswered": 60 - cve_scanner.MAX_UNITS_PER_NAME})


class _Paged:
    """A stand-in for the batch endpoint of the advisory service: the answer to a question is `size(name)` advisories, in pages of
    `page` of them, and a question is a unit of work to count. `asked` is every (name, version, page) the service was asked."""

    def __init__(self, size, page=1000):
        self.size, self.page = size, page
        self.asked = []
        self.calls = 0

    def querybatch(self, body):
        self.calls += 1
        out = []
        for q in body:
            name, version = q["package"]["name"], q["version"]
            start = int(q.get("page_token") or 0)
            self.asked.append((name, version, start))
            total = self.size(name) if callable(self.size) else self.size
            ids = ["ADV-%s-%d" % (name, i) for i in range(start, min(total, start + self.page))]
            ans = {"vulns": [{"id": i, "modified": "2026-11-10T08:00:00.000000Z"} for i in ids]}
            if start + self.page < total:
                ans["next_page_token"] = str(start + self.page)
            out.append(ans)
        return out


def _queries(n, prefix="p"):
    return [{"package": {"name": "%s%d" % (prefix, i), "ecosystem": "Debian:12"}, "version": "1"} for i in range(n)]


class TestTheQuestionsHaveABudget(unittest.TestCase):

    def _run(self, svc, queries, budget=None):
        with mock.patch.object(cve_scanner, "_osv_querybatch", svc.querybatch):
            return cve_scanner._osv_query_all(queries, budget=budget)

    def test_without_a_budget_every_page_is_followed_as_before(self):
        svc = _Paged(2500)
        res = self._run(svc, _queries(2))
        self.assertEqual([len(r["vulns"]) for r in res], [2500, 2500])
        self.assertFalse(any(r.get("truncated") or r.get("held_back") for r in res))

    def test_a_list_that_does_not_end_is_cut_at_the_last_page_and_that_is_not_the_budget(self):
        svc = _Paged(10 ** 6)
        res = self._run(svc, _queries(1))
        self.assertEqual(len(res[0]["vulns"]), 1000 * cve_scanner.OSV_MAX_PAGES)
        self.assertTrue(res[0]["truncated"])
        self.assertNotIn("held_back", res[0], "the data source's own limit is not this call's")

    def test_a_budget_cuts_an_answer_where_it_is_reached_and_says_so(self):
        svc = _Paged(1000)
        res = self._run(svc, _queries(3), budget=1500)
        self.assertEqual([len(r["vulns"]) for r in res], [1000, 500, 0])
        self.assertEqual(sum(len(r["vulns"]) for r in res), 1500, "what is held is the budget")
        self.assertNotIn("truncated", res[0])
        self.assertTrue(res[1]["truncated"] and res[1]["held_back"])
        self.assertTrue(res[2]["truncated"] and res[2]["held_back"])

    def test_a_question_reached_after_the_budget_is_not_asked(self):
        svc = _Paged(1)
        with mock.patch.object(cve_scanner, "OSV_BATCH_SIZE", 2):
            res = self._run(svc, _queries(10), budget=3)
        self.assertEqual(len(svc.asked), 4, "two batches of two: the third batch is not sent, the budget is spent")
        self.assertEqual(sum(len(r["vulns"]) for r in res), 3)
        unasked = [r for r in res[4:]]
        self.assertTrue(all(r == {"vulns": [], "truncated": True, "held_back": True} for r in unasked), unasked)

    def test_the_pages_of_an_answer_are_not_asked_for_once_the_budget_is_spent(self):
        svc = _Paged(5000)
        res = self._run(svc, _queries(1), budget=2500)
        self.assertEqual(len(res[0]["vulns"]), 2500)
        self.assertEqual(len(svc.asked), 3, "pages 0, 1000 and 2000: the one that would have passed the budget is the last")
        self.assertTrue(res[0]["held_back"])

    def test_a_budget_that_is_not_reached_changes_nothing(self):
        svc_a, svc_b = _Paged(lambda n: 3 * len(n)), _Paged(lambda n: 3 * len(n))
        self.assertEqual(self._run(svc_a, _queries(40)), self._run(svc_b, _queries(40), budget=10 ** 6))

    def test_a_budget_of_zero_asks_nothing(self):
        svc = _Paged(5)
        res = self._run(svc, _queries(3), budget=0)
        self.assertEqual(svc.calls, 0)
        self.assertTrue(all(r["held_back"] and r["truncated"] and not r["vulns"] for r in res))

    def test_what_is_held_never_passes_the_budget_for_random_answers(self):
        rng = random.Random(8025)
        for case in range(60):
            sizes = {"p%d" % i: rng.choice([0, 1, 7, 300, 1200, 2600]) for i in range(rng.randrange(1, 40))}
            budget = rng.choice([0, 1, 50, 999, 1000, 1001, 4000])
            svc = _Paged(lambda name, sizes=sizes: sizes[name])
            with mock.patch.object(cve_scanner, "OSV_BATCH_SIZE", rng.choice([2, 5, 500])):
                res = self._run(svc, _queries(len(sizes)), budget=budget)
            held = sum(len(r["vulns"]) for r in res)
            self.assertLessEqual(held, budget, "case %d" % case)
            for k, r in enumerate(res):
                full = min(sizes["p%d" % k], 1000 * cve_scanner.OSV_MAX_PAGES)
                if len(r["vulns"]) < full:
                    self.assertTrue(r.get("held_back"), "case %d: an answer that was cut says so" % case)


def _debian_host(n):
    """A Debian 12 list of `n` distinct sources, each at one version."""
    return [{"name": "lib%d" % i, "version": "1.0-1", "arch": "amd64", "source": "src%d" % i, "source_version": "1.0-1"} for i in range(n)]


class _Service:
    """A stand-in for the advisory service: `per_unit` advisories for every (name, version) asked, ids that are the unit's own unless
    `shared` is set (then the ids of a name are the same for every version of it, as for one kernel)."""

    def __init__(self, per_unit, shared=False):
        self.per_unit, self.shared = per_unit, shared
        self.asked = []
        self.details = 0

    def ids(self, name, version):
        return ["DEBIAN-CVE-2024-%s-%d" % (name if self.shared else "%s-%s" % (name, version), i) for i in range(self.per_unit)]

    def querybatch(self, queries):
        out = []
        for q in queries:
            self.asked.append((q["package"]["name"], q["version"]))
            out.append({"vulns": [{"id": i, "modified": "2026-11-10T08:00:00.000000Z"} for i in self.ids(q["package"]["name"], q["version"])]})
        return out

    def record(self, vid):
        self.details += 1
        return {"id": vid, "modified": "2026-11-10T08:00:00.000000Z", "published": "2024-03-01T10:00:00Z", "summary": "a flaw",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}], "references": [],
                "affected": [{"package": {"ecosystem": "Debian:12", "name": "x"},
                              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9-1~deb12u1"}]}]}]}

    def patched(self):
        return (mock.patch.object(cve_scanner, "_osv_querybatch", self.querybatch),
                mock.patch.object(cve_scanner, "_osv_vuln_details", self.record))


def _scan(pk, service, cache=None, ecosystem="Debian:12", **kw):
    cache = cache or _tmp()
    a, b = service.patched()
    with a, b:
        return cve_scanner.scan_device("h", pk, ecosystem, cache, has_meta=True, release=ecosystem, **kw), cache


class TestTheFleetMapHasABudget(unittest.TestCase):

    def _fleet(self):
        # three hosts that share most of their packages, and one that lists names of its own
        shared = [{"name": "lib%d" % i, "version": "1.0-1", "arch": "amd64", "source": "src%d" % i, "source_version": "1.0-1"} for i in range(10)]
        own = [{"name": "own%d" % i, "version": "1.0-1", "arch": "amd64", "source": "own%d" % i, "source_version": "1.0-1"} for i in range(10)]
        entry = lambda pk: {"hash": "h", "collected_at": 1, "ecosystem": "Debian:12", "pkg_manager": "apt", "count": len(pk),  # noqa: E731
                            "sources": True, "os_id": "debian", "version_id": "12", "packages": pk}
        return {"a": entry(shared), "b": entry(shared), "c": entry(shared + own)}

    def test_the_map_holds_what_it_may_and_leaves_out_what_it_cut(self):
        svc = _Service(per_unit=5)
        with mock.patch.object(cve_scanner, "_osv_querybatch", svc.querybatch), mock.patch.object(cve_scanner, "PREFETCH_MAX_HITS", 60):
            m = cve_scanner.prefetch_osv(self._fleet(), _tmp())
        self.assertEqual(len(svc.asked), 20, "ten shared and ten own questions, each once")
        held = sum(len(r["vulns"]) for r in m.values())
        self.assertEqual(held, 60, "twelve whole answers, and nothing else")
        self.assertEqual(len(m), 12)
        self.assertFalse(any(r.get("held_back") for r in m.values()), "a cut answer is not in the map")
        self.assertTrue(all(len(r["vulns"]) == 5 for r in m.values()))

    def test_a_map_that_is_not_full_holds_every_question(self):
        svc = _Service(per_unit=5)
        with mock.patch.object(cve_scanner, "_osv_querybatch", svc.querybatch):
            m = cve_scanner.prefetch_osv(self._fleet(), _tmp())
        self.assertEqual(len(m), 20)
        self.assertEqual(sum(len(r["vulns"]) for r in m.values()), 100)

    def test_the_findings_of_a_scan_are_the_same_whether_the_map_held_the_answers_or_the_host_asked_for_them(self):
        fleet = self._fleet()
        entry = fleet["c"]
        want = None
        for ceiling in (10 ** 6, 60, 0):
            svc = _Service(per_unit=5)
            with mock.patch.object(cve_scanner, "_osv_querybatch", svc.querybatch), mock.patch.object(cve_scanner, "PREFETCH_MAX_HITS", ceiling):
                m = cve_scanner.prefetch_osv(fleet, _tmp())
            result, _ = _scan(entry["packages"], svc, osv_prefetch=m)
            got = sorted((f["package"], f["vuln_id"]) for f in result["findings"])
            self.assertEqual(len(got), 100, "ceiling %d: ten units of five advisories for each of twenty names" % ceiling)
            want = want or got
            self.assertEqual(got, want, "ceiling %d" % ceiling)
            self.assertFalse(result.get("cut"), "ceiling %d: nothing is cut for the host: its own ceiling is not reached" % ceiling)
            self.assertEqual(result["covered"]["not_checked"], 0)


class TestTheScanHoldsAndReadsWhatItMay(unittest.TestCase):

    def test_a_source_listed_at_a_hundred_versions_is_asked_at_the_ceiling_and_the_rest_is_not_checked(self):
        pk = [{"name": "linux-image-%d" % i, "version": "0.%d-1" % i, "arch": "amd64", "source": "linux", "source_version": "0.%d-1" % i}
              for i in range(100)] + [{"name": "bash", "version": "5.2-1", "arch": "amd64", "source": "bash", "source_version": "5.2-1"}]
        svc = _Service(per_unit=3, shared=True)
        result, _ = _scan(pk, svc)
        kernels = [a for a in svc.asked if a[0] == "linux"]
        self.assertEqual(len(kernels), cve_scanner.MAX_UNITS_PER_NAME, "the service was asked 100 times before")
        self.assertIn(("bash", "5.2-1"), svc.asked)
        covered = result["covered"]
        self.assertEqual(covered["listed"], 101)
        self.assertEqual(covered["reasons"], {"unanswered": 100 - cve_scanner.MAX_UNITS_PER_NAME})
        self.assertEqual(covered["checked"], cve_scanner.MAX_UNITS_PER_NAME + 1)

    def test_the_answers_held_for_a_host_are_bounded_while_they_come_in_and_the_rest_is_cut_and_said_to_be(self):
        pk = _debian_host(40)
        svc = _Service(per_unit=50)
        with mock.patch.object(cve_scanner, "MAX_HITS_PER_HOST", 300):
            result, _ = _scan(pk, svc)
        self.assertTrue(result["cut"], "the host's page says the list was cut")
        self.assertGreater(result["covered"]["reasons"].get("unanswered", 0), 0)
        self.assertLessEqual(svc.details, 300, "no record is read for an answer that is not held")
        self.assertEqual(len(result["findings"]), 300)

    def test_the_answers_of_the_fleet_map_count_against_the_host_too(self):
        pk = _debian_host(4)
        svc = _Service(per_unit=200)
        fleet = {(("Debian:12"), "src%d" % i, "1.0-1"): {"vulns": [{"id": v, "modified": "2026-11-10T08:00:00.000000Z"}
                                                                for v in svc.ids("src%d" % i, "1.0-1")]} for i in range(4)}
        with mock.patch.object(cve_scanner, "MAX_HITS_PER_HOST", 250):
            result, _ = _scan(pk, svc, osv_prefetch=fleet)
        self.assertEqual(len(svc.asked), 0, "everything came from the map")
        self.assertEqual(len(result["findings"]) + cve_fixes.rollup_total(result), 250, "no more than 250 of the 800 are held, listed or counted")
        self.assertEqual(sorted(result["cut"]), ["src1", "src2", "src3"], "the unit that was cut part-way and the ones after it")
        self.assertLessEqual(svc.details, 250)

    def test_a_name_that_was_cut_at_several_versions_is_listed_once(self):
        pk = [{"name": "bin%d-%d" % (j, v), "version": "1.%d-1" % v, "arch": "amd64", "source": "s%d" % j, "source_version": "1.%d-1" % v}
              for j in range(5) for v in range(20)]
        svc = _Service(per_unit=3)
        with mock.patch.object(cve_scanner, "MAX_HITS_PER_HOST", 3):
            result, _ = _scan(pk, svc)
        self.assertEqual(result["cut"], ["s0", "s1", "s2", "s3", "s4"], "five names at twenty versions each, cut: each is on the record once")

    def test_a_scan_reads_at_most_the_ceiling_of_new_records_and_the_next_scan_reads_the_rest(self):
        pk = _debian_host(30)
        svc = _Service(per_unit=10)                                   # 300 records
        cache = _tmp()
        with mock.patch.object(cve_scanner, "MAX_DETAIL_FETCHES_PER_SCAN", 100):
            first, _ = _scan(pk, svc, cache)
            read_first = svc.details
            self.assertEqual(read_first, 100, "the ceiling is exact, not a multiple of the eight it asks for at once")
            self.assertTrue(first.get("partial"), "a host whose records were not all read says so")
            self.assertEqual(first["unread"], 200)
            self.assertIn("at most 100 records", first["error"])
            self.assertIn("the next scan reads the rest", first["error"])
            second, _ = _scan(pk, svc, cache)
            self.assertEqual(svc.details, 200)
            third, _ = _scan(pk, svc, cache)
        self.assertEqual(svc.details, 300, "each record was read once, over three scans")
        self.assertFalse(third.get("partial"))
        self.assertEqual(len(third["findings"]), 300)

    def test_a_ceiling_that_is_not_a_multiple_of_the_round_is_still_exact(self):
        pk = _debian_host(3)
        svc = _Service(per_unit=10)
        with mock.patch.object(cve_scanner, "MAX_DETAIL_FETCHES_PER_SCAN", 13):
            _scan(pk, svc)
        self.assertEqual(svc.details, 13)

    def test_the_cache_is_written_once_for_a_scan_and_not_once_for_every_two_hundred_and_fifty_records(self):
        pk = _debian_host(150)
        svc = _Service(per_unit=20)                                   # 3,000 records; 12 writes before 8.0.2
        saves = []
        real = cve_scanner._save_json

        def counting(path, data):
            if Path(path).name == "cve_details_cache.json":
                saves.append(len(data))
            real(path, data)
        with mock.patch.object(cve_scanner, "_save_json", counting):
            _scan(pk, svc)
        self.assertEqual(saves, [3000], "written whole once, with everything the scan read")

    def test_the_cache_is_also_written_on_the_way_when_a_minute_has_gone(self):
        pk = _debian_host(20)
        svc = _Service(per_unit=20)
        saves = []
        real = cve_scanner._save_json

        def counting(path, data):
            if Path(path).name == "cve_details_cache.json":
                saves.append(len(data))
            real(path, data)
        with mock.patch.object(cve_scanner, "_save_json", counting), mock.patch.object(cve_scanner, "DETAIL_SAVE_EVERY_S", 0):
            _scan(pk, svc)
        self.assertGreater(len(saves), 2, "a runner that is killed keeps what it read: with no wait it writes after every round")
        self.assertEqual(saves[-1], 400)
        self.assertEqual(sorted(saves), saves, "and each write holds what the one before did")

    def test_a_scan_that_read_nothing_new_writes_nothing(self):
        pk = _debian_host(10)
        svc = _Service(per_unit=5)
        cache = _tmp()
        _scan(pk, svc, cache)
        saves = []
        real = cve_scanner._save_json

        def counting(path, data):
            saves.append(Path(path).name)
            real(path, data)
        with mock.patch.object(cve_scanner, "_save_json", counting):
            _scan(pk, svc, cache)
        self.assertNotIn("cve_details_cache.json", saves)


class TestAHostThatListsEveryFindingKeepsAtMostACeilingOfThem(unittest.TestCase):

    def _alpine(self, n):
        return [{"name": "lib%d" % i, "version": "1.0-r0", "arch": "x86_64", "source": "orig%d" % i, "source_version": "1.0-r0"} for i in range(n)]

    def test_the_most_pressing_are_kept_and_the_rest_are_counted(self):
        svc = _Service(per_unit=20)
        with mock.patch.object(cve_fixes, "KEEP_UNRULED_PER_HOST", 500):
            result, _ = _scan(self._alpine(100), svc, ecosystem="Alpine:v3.19")
        self.assertEqual(len(result["findings"]), 500)
        self.assertEqual(result["rollup"]["total"], 2000 - 500)
        self.assertEqual(sum(result["rollup"]["severity"].values()), 1500)
        self.assertEqual(cve_fixes.rollup_total(result), 1500)
        self.assertIn("host", result["listed_to"], "the scan after this one can tell what was counted from what is new")
        self.assertNotIn("ruled", result)

    def test_a_host_within_the_ceiling_is_stored_as_it_always_was(self):
        svc = _Service(per_unit=20)
        result, _ = _scan(self._alpine(100), svc, ecosystem="Alpine:v3.19")
        self.assertEqual(len(result["findings"]), 2000)
        self.assertNotIn("rollup", result)
        self.assertNotIn("listed_to", result)

    def test_no_finding_is_lost_it_is_listed_or_counted(self):
        rng = random.Random(8026)
        for case in range(40):
            n = rng.randrange(0, 60)
            rows = [{"package": "p%d" % rng.randrange(7), "version": "1", "vuln_id": "CVE-%d-%d" % (rng.choice([2019, 2024]), i),
                     "severity": rng.choice(["critical", "high", "medium", "low", "unknown", "odd", None]),
                     "fix_status": rng.choice(["fixed", "none", "reboot", None])} for i in range(n)]
            ceiling = rng.choice([1, 5, 20, 100])
            stored, counted, mark = cve_fixes.cap(rows, None, ceiling)
            self.assertEqual(len(stored) + (counted.get("total", 0) if counted else 0), n, "case %d" % case)
            self.assertLessEqual(len(stored), ceiling)
            self.assertEqual([r for r in rows if r in stored], stored, "the stored ones keep the order they came in")
            if n <= ceiling:
                self.assertEqual((counted, mark), ({}, {}))
            else:
                counted_rows = [r for r in rows if r not in stored]
                last_stored = max(cve_fixes._pressing(r, None) for r in stored)
                first_counted = min(cve_fixes._pressing(r, None) for r in counted_rows)
                self.assertLessEqual(last_stored, first_counted, "case %d: nothing counted is more pressing than something stored" % case)
                self.assertEqual(mark, {"host": list(last_stored)}, "case %d" % case)

    def test_a_debian_host_is_still_chosen_by_the_debian_rule(self):
        svc = _Service(per_unit=20)
        result, _ = _scan(_debian_host(100), svc)
        self.assertEqual(len(result["findings"]), cve_fixes.KEEP_PER_HOST)
        self.assertTrue(result["ruled"])

    def test_the_ceiling_is_read_when_a_scan_is_made_and_not_when_the_module_was_loaded(self):
        rows = [{"severity": "low", "vuln_id": "CVE-2024-%d" % i} for i in range(5)]
        self.assertEqual(cve_fixes.cap(rows), (rows, {}, {}))
        with mock.patch.object(cve_fixes, "KEEP_UNRULED_PER_HOST", 2):
            stored, counted, _ = cve_fixes.cap(rows)
        self.assertEqual((len(stored), counted["total"]), (2, 3))


class TestTheCacheHasACeiling(unittest.TestCase):

    def test_the_oldest_records_go_and_never_the_ones_in_hand(self):
        cache = {"r%03d" % i: {"cached_at": 1000 + i} for i in range(150)}
        with mock.patch.object(cve_scanner, "DETAILS_CACHE_MAX_RECORDS", 100):
            dropped = cve_scanner._trim_details(cache, keep={"r000", "r001"})
        self.assertEqual(dropped, 50 + 10, "the excess, and a tenth of the ceiling more so that the next scan does not trim again")
        self.assertEqual(len(cache), 90)
        self.assertIn("r000", cache)
        self.assertIn("r001", cache)
        self.assertNotIn("r002", cache)
        self.assertNotIn("r061", cache)
        self.assertIn("r062", cache, "the 60 oldest that were not in hand went, and nothing newer")

    def test_a_cache_within_the_ceiling_is_left_alone(self):
        cache = {"r%d" % i: {"cached_at": i} for i in range(50)}
        with mock.patch.object(cve_scanner, "DETAILS_CACHE_MAX_RECORDS", 100):
            self.assertEqual(cve_scanner._trim_details(cache), 0)
        self.assertEqual(len(cache), 50)

    def test_a_record_that_says_nothing_of_its_age_is_the_oldest(self):
        cache = {"junk": "x", "none": {}, "bool": {"cached_at": True}, "new": {"cached_at": 5}}
        with mock.patch.object(cve_scanner, "DETAILS_CACHE_MAX_RECORDS", 3):
            dropped = cve_scanner._trim_details(cache)
        self.assertEqual(dropped, 1)
        self.assertEqual(sorted(cache), ["bool", "new", "none"], "one of the three that say nothing went, the first of them")
        with mock.patch.object(cve_scanner, "DETAILS_CACHE_MAX_RECORDS", 1):
            cve_scanner._trim_details(cache)
        self.assertEqual(sorted(cache), ["new"], "and the one that has an age is the last to go")

    def test_a_fetch_trims_before_it_writes_and_what_it_read_is_there(self):
        cache = {"old%03d" % i: {"cached_at": 100 + i, "v": cve_scanner.DETAILS_FORMAT} for i in range(120)}
        path = _tmp() / "cve_details_cache.json"
        svc = _Service(per_unit=1)
        with mock.patch.object(cve_scanner, "DETAILS_CACHE_MAX_RECORDS", 100), mock.patch.object(cve_scanner, "_osv_vuln_details", svc.record):
            unread = cve_scanner._fetch_details({"new%d" % i for i in range(10)}, "Debian:12", cache, path)
        self.assertEqual(unread, 0)
        self.assertTrue(all("new%d" % i in cache for i in range(10)), "the ten it read are in the cache")
        self.assertLessEqual(len(cache), 100)
        on_disk = cve_scanner._load_json(path)
        self.assertEqual(sorted(on_disk), sorted(cache), "and the file holds what the map holds")
        self.assertNotIn("old000", cache)
        self.assertIn("old119", cache)

    def test_the_records_a_scan_holds_are_not_dropped_to_make_room_for_the_ones_it_read(self):
        cache = {"held%d" % i: {"cached_at": 1 + i, "v": cve_scanner.DETAILS_FORMAT} for i in range(5)}
        cache.update({"other%03d" % i: {"cached_at": 500 + i, "v": cve_scanner.DETAILS_FORMAT} for i in range(95)})
        path = _tmp() / "cve_details_cache.json"
        svc = _Service(per_unit=1)
        with mock.patch.object(cve_scanner, "DETAILS_CACHE_MAX_RECORDS", 100), mock.patch.object(cve_scanner, "_osv_vuln_details", svc.record):
            cve_scanner._fetch_details({"new%d" % i for i in range(20)}, "Debian:12", cache, path, keep={"held%d" % i for i in range(5)})
        self.assertTrue(all("held%d" % i in cache for i in range(5)), "they were the oldest, and the scan is about to read them")
        self.assertTrue(all("new%d" % i in cache for i in range(20)))
        self.assertNotIn("other000", cache)


class TestTheGuideSaysWhatTheLimitsAre(unittest.TestCase):

    def test_the_numbers_in_the_guide_are_the_ones_in_the_code(self):
        text = (_ROOT / "docs" / "cve.md").read_text(encoding="utf-8")
        start = text.index("- A host sends its own package list")
        bullet = " ".join(text[start:text.index("\n- ", start + 3)].split())
        for phrase in (
            "at no more than %d versions" % cve_scanner.MAX_UNITS_PER_NAME,
            "no more than %s advisory answers" % format(cve_scanner.MAX_HITS_PER_HOST, ","),
            "reads no more than %s advisory records" % format(cve_scanner.MAX_DETAIL_FETCHES_PER_SCAN, ","),
            "keeps at most %s records" % format(cve_scanner.DETAILS_CACHE_MAX_RECORDS, ","),
            "keeps its %s most pressing findings" % format(cve_fixes.KEEP_UNRULED_PER_HOST, ","),
        ):
            self.assertIn(phrase, bullet)


# ---- the scan worker, in a process of its own -----------------------------------------------------------------------------

_DRIVER = r"""
import json, sys, time
sys.path.insert(0, sys.argv[1])
sys.dont_write_bytecode = True
import wsgi
api = wsgi.api
cs = api.cve_scanner
now = int(time.time())


def put(attr, obj):
    api.save(getattr(api, attr), obj)
    api._invalidate_load_cache(getattr(api, attr))


def entry(pk):
    return {"hash": "h", "collected_at": now - 50, "ecosystem": "Debian:12", "pkg_manager": "apt", "count": len(pk), "sources": True,
            "os_id": "debian", "version_id": "12", "packages": pk}


def host_list(shared, own, prefix):
    return ([{"name": "lib%d" % i, "version": "1.0-1", "arch": "amd64", "source": "src%d" % i, "source_version": "1.0-1"} for i in range(shared)]
            + [{"name": "%s%d" % (prefix, i), "version": "1.0-1", "arch": "amd64", "source": "%s%d" % (prefix, i), "source_version": "1.0-1"}
               for i in range(own)])


HOSTS = {"h1": host_list(8, 0, "x"), "h2": host_list(8, 0, "x"), "h3": host_list(8, 6, "own")}
put("DEVICES_FILE", {h: {"name": h.upper(), "hostname": h, "os": "Debian 12", "monitored": True, "last_seen": now, "token": "T-" + h,
                         "group": "g", "ip": "10.0.0.1"} for h in HOSTS})
store = {h: entry(pk) for h, pk in HOSTS.items()}
put("PACKAGES_FILE", store)
before = json.dumps(api.load(api.PACKAGES_FILE), sort_keys=True)

asked = []


def querybatch(queries):
    out = []
    for q in queries:
        asked.append([q["package"]["name"], q["version"]])
        out.append({"vulns": [{"id": "DEBIAN-CVE-2024-%s-%d" % (q["package"]["name"], i), "modified": "2026-11-10T08:00:00.000000Z"} for i in range(5)]})
    return out


def details(vid):
    return {"id": vid, "modified": "2026-11-10T08:00:00.000000Z", "published": "2024-03-01T10:00:00Z", "summary": "a flaw",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}], "references": [],
            "affected": [{"package": {"ecosystem": "Debian:12", "name": "x"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9-1~deb12u1"}]}]}]}


cs._osv_querybatch = querybatch
cs._osv_vuln_details = details
loaded = {"ro": [], "copy": []}
real_ro, real_load = api._load_ro, api.load
api._load_ro = lambda p, *a, **k: (loaded["ro"].append(str(p)), real_ro(p, *a, **k))[1]
api.load = lambda p, *a, **k: (loaded["copy"].append(str(p)), real_load(p, *a, **k))[1]


def run(ceiling):
    put("CVE_FINDINGS_FILE", {})
    put("CVE_SCAN_STATUS_FILE", {"running": True, "updated": now, "run": "r1", "owner": None, "total": 3})
    cs.PREFETCH_MAX_HITS = ceiling
    del asked[:]
    api._cve_scan_worker("t", None)
    api._invalidate_load_cache(api.CVE_FINDINGS_FILE)
    f = real_load(api.CVE_FINDINGS_FILE)
    return {"findings": {h: sorted([x["package"], x["vuln_id"]] for x in f[h]["findings"]) for h in sorted(f)},
            "asked": len(asked), "distinct_asked": len({tuple(a) for a in asked}), "covered": {h: f[h]["covered"]["not_checked"] for h in sorted(f)}}


out = {"whole": run(10 ** 6), "tiny": run(30), "none": run(0)}
api._invalidate_load_cache(api.PACKAGES_FILE)
out["store_unchanged"] = json.dumps(real_load(api.PACKAGES_FILE), sort_keys=True) == before
out["packages_read_without_copy"] = [any(p.endswith("packages.json") for p in loaded["ro"]), any(p.endswith("packages.json") for p in loaded["copy"])]
print("RESULT " + json.dumps(out))
"""


class TestTheWorkerOfAFleetScan(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        data = tempfile.mkdtemp(prefix="rp-v802-sc-worker-")
        _TMP.append(data)
        env = dict(os.environ, RP_DATA_DIR=data)
        proc = subprocess.run([sys.executable, "-c", _DRIVER, str(_CGI)], env=env, capture_output=True, text=True, timeout=600)
        lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("RESULT ")]
        if not lines:
            raise AssertionError("the driver gave no result:\n%s\n%s" % (proc.stdout[-2000:], proc.stderr[-3000:]))
        cls.out = json.loads(lines[-1][len("RESULT "):])

    def test_the_findings_are_the_same_with_a_full_map_a_small_one_and_none(self):
        whole, tiny, none = self.out["whole"], self.out["tiny"], self.out["none"]
        self.assertEqual(sorted(whole["findings"]), ["h1", "h2", "h3"])
        self.assertEqual([len(v) for v in whole["findings"].values()], [40, 40, 70], "five advisories for each of 8, 8 and 14 sources")
        self.assertEqual(tiny["findings"], whole["findings"])
        self.assertEqual(none["findings"], whole["findings"])
        self.assertEqual(whole["covered"], {"h1": 0, "h2": 0, "h3": 0})
        self.assertEqual(tiny["covered"], whole["covered"])

    def test_a_map_that_cut_the_answers_makes_the_hosts_ask_for_them(self):
        whole, tiny, none = self.out["whole"], self.out["tiny"], self.out["none"]
        self.assertEqual(whole["asked"], 14, "the fleet's questions, each once: the 8 shared names and the 6 of the host that lists its own")
        self.assertGreater(tiny["asked"], whole["asked"], "the answers the map could not hold were asked for again by the hosts")
        self.assertEqual(none["asked"], 8 + 8 + 14, "with no room in the map the sweep asks nothing and every host asks for everything it lists")
        self.assertGreater(none["asked"], tiny["asked"])

    def test_the_worker_reads_the_package_store_as_it_is_held_and_does_not_change_it(self):
        self.assertTrue(self.out["store_unchanged"])
        read_ro, read_copy = self.out["packages_read_without_copy"]
        self.assertTrue(read_ro, "read through _load_ro")
        self.assertFalse(read_copy, "and not copied: a copy of every host's list was held for the length of the scan")


if __name__ == "__main__":
    unittest.main()
