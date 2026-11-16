"""Two recordings of api.osv.dev (2026-11-15), and a stand-in for the database that answers from them.

Not a test module. tests/test_v801_deb_source_matching.py and tests/test_v801_cve_readers.py both scan a host
against these, so that what a reader is handed is what a scan writes and not a shape made up for the reader.

tests/data/osv_recorded_debian_2026-11-15.tsv and osv_recorded_ubuntu_2026-11-15.tsv hold the queries that were
made, the ids each returned, and what each advisory record says about the packages asked. A query that was not
recorded raises `NotRecorded`, so a test cannot pass on an answer nobody gave.
"""
import threading
from pathlib import Path

DATA = Path(__file__).resolve().parent / 'data'
# the ids that are one record per CVE; the scanner's own tuple is held equal to this by a test
PER_CVE_IDS = ('DEBIAN-CVE-', 'UBUNTU-CVE-')


class Recording:
    """One recording: what each query returned and what each advisory record says."""

    def __init__(self, name):
        self.queries, self.entries, self.facts = {}, {}, {}
        for line in (DATA / name).read_text().splitlines():
            if not line or line.startswith('#'):
                continue
            kind, *rest = line.split('\t')
            if kind == 'Q':
                ecosystem, package, version, ids = rest
                self.queries[(ecosystem, package, version)] = [] if ids == '-' else ids.split(',')
            elif kind == 'A':
                vid, ecosystem, package, introduced, fixed, urgency = rest
                self.entries.setdefault(vid, []).append((ecosystem, package, introduced, fixed, urgency))
            elif kind == 'V':
                vid, key, value = rest
                self.facts.setdefault(vid, {})[key] = value

    def ids(self, ecosystem, package, version, family=None):
        got = self.queries[(ecosystem, package, version)]
        return sorted(i for i in got if family is None or i.startswith(family))

    def record(self, vid):
        """The advisory as the database serves it, as far as the recording kept it."""
        affected = []
        for ecosystem, package, introduced, fixed, urgency in self.entries.get(vid, ()):
            events = [] if introduced == '-' else [{'introduced': introduced}]
            if fixed != '-':
                events.append({'fixed': fixed})
            entry = {'package': {'ecosystem': ecosystem, 'name': package},
                     'ranges': [{'type': 'ECOSYSTEM', 'events': events}]}
            if urgency != '-':
                entry['ecosystem_specific'] = {'urgency': urgency}
            affected.append(entry)
        facts = self.facts.get(vid, {})
        record = {'id': vid, 'details': 'A description, as these records have no summary.', 'affected': affected,
                  'modified': '2026-11-10T08:00:00.123456789Z'}
        if 'upstream' in facts:
            record['upstream'] = facts['upstream'].split(',')
        severity = []
        if 'priority' in facts:
            severity.append({'type': 'Ubuntu', 'score': facts['priority']})
        if 'cvss' in facts:
            severity.append({'type': 'CVSS_V4' if facts['cvss'].startswith('CVSS:4') else 'CVSS_V3', 'score': facts['cvss']})
        if severity:
            record['severity'] = severity
        return record


DEB = Recording('osv_recorded_debian_2026-11-15.tsv')
UBU = Recording('osv_recorded_ubuntu_2026-11-15.tsv')


class NotRecorded(AssertionError):
    pass


class Database:
    """`extra` adds answers to queries ({(ecosystem, package, version): [ids]}; ids are added to a recorded
    answer) and `records` adds advisory records ({id: record}), for a case the recordings do not hold."""

    def __init__(self, recording, extra=None, records=None):
        self.rec, self.extra, self.records = recording, dict(extra or {}), dict(records or {})
        self.asked, self.read = [], []
        self._lock = threading.Lock()

    def querybatch(self, body):
        out = []
        for q in body:
            key = (q['package']['ecosystem'], q['package']['name'], q['version'])
            self.asked.append(key)
            if key in self.rec.queries:
                ids = self.rec.queries[key] + [i for i in self.extra.get(key, []) if i not in self.rec.queries[key]]
            elif key in self.extra:
                ids = self.extra[key]
            else:
                raise NotRecorded(f'this query was never recorded: {key}')
            # the stamp as a query answer writes it: six digits for the instant the record writes with nine
            out.append({'vulns': [{'id': i, 'modified': '2026-11-10T08:00:00.123456Z'} for i in ids]})
        return out

    def details(self, vid):
        with self._lock:
            self.read.append(vid)
        if vid in self.records:
            return self.records[vid]
        if vid not in self.rec.entries and vid not in self.rec.facts:
            raise NotRecorded(f'no recorded record for {vid}')
        return self.rec.record(vid)


BEHIND = [{'name': 'libc6', 'version': '2.36-9+deb12u3', 'arch': 'amd64', 'source': 'glibc'},
          {'name': 'libc-bin', 'version': '2.36-9+deb12u3', 'arch': 'amd64', 'source': 'glibc'},
          {'name': 'openssh-server', 'version': '1:9.2p1-2+deb12u2', 'arch': 'amd64', 'source': 'openssh'},
          {'name': 'openssh-client', 'version': '1:9.2p1-2+deb12u2', 'arch': 'amd64', 'source': 'openssh'},
          {'name': 'sudo', 'version': '1.9.13p3-1+deb12u1', 'arch': 'amd64'},
          {'name': 'zlib1g', 'version': '1:1.2.13.dfsg-1+b1', 'arch': 'amd64', 'source': 'zlib',
           'source_version': '1:1.2.13.dfsg-1'}]
BEHIND_ASKED = [('Debian:12', 'glibc', '2.36-9+deb12u3'), ('Debian:12', 'openssh', '1:9.2p1-2+deb12u2'),
                ('Debian:12', 'sudo', '1.9.13p3-1+deb12u1'), ('Debian:12', 'zlib', '1:1.2.13.dfsg-1')]
PATCHED = [{'name': 'libc6', 'version': '2.36-9+deb12u14', 'arch': 'amd64', 'source': 'glibc'},
           {'name': 'openssh-server', 'version': '1:9.2p1-2+deb12u10', 'arch': 'amd64', 'source': 'openssh'},
           {'name': 'sudo', 'version': '1.9.13p3-1+deb12u4', 'arch': 'amd64'},
           {'name': 'zlib1g', 'version': '1:1.2.13.dfsg-1+b1', 'arch': 'amd64', 'source': 'zlib',
            'source_version': '1:1.2.13.dfsg-1'}]


def per_cve(recording, keys):
    """The ids of the queries that are one record per CVE (not a notice)."""
    return sorted({i for k in keys for i in recording.queries[k] if i.startswith(PER_CVE_IDS)})
