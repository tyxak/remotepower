"""RemotePower: the state of a host's package-list refresh.

A Linux agent can refresh its host's package lists with the distribution's own fixed command (apt-get update, dnf makecache and
their kin) and says how that went: {at, status, source, error_class}. Every value in it comes from a fixed set, so nothing the
agent sends is free text on the server: a value outside its set is dropped or becomes "unknown".

The sets are the agent's own (client/remotepower-agent.py: _PKG_REFRESH_STATUSES, _PKG_REFRESH_SOURCES,
_PKG_REFRESH_CLASSES), and tests/test_pkg_refresh.py holds the two copies together.

Pure functions only, so the heartbeat ingest and the tests share one reading of the record.
"""

# The command verb the server queues for "Check for updates now". Linux only (api._VERB_OS_SUPPORT).
VERB = 'pkg_refresh'

# The first agent release that has the verb. An older agent logs "Unknown command" and drops it without a result, so the operator would see
# "Refresh queued" and nothing would ever change: the server refuses to queue it for an agent below this version (api._VERB_MIN_AGENT).
MIN_AGENT = (8, 0, 2)

STATUSES = ('ok', 'partial', 'failed', 'unsupported')
SOURCES = ('', 'apt', 'dnf', 'yum', 'zypper', 'apk', 'pacman')
CLASSES = ('', 'lock', 'network', 'repository', 'disk', 'permission', 'timeout',
           'no_safe_way', 'no_manager', 'container', 'unknown')

# A record older than this is not a record of this host's lists any more (a restored backup, a clock that was wrong).
_OLDEST_S = 5 * 365 * 86400
# A clock that runs ahead by a little is not a reason to drop the record; it is read as "now". Further ahead is not believed.
_SKEW_S = 300


def _whole(v):
    return isinstance(v, int) and not isinstance(v, bool)


def clean(raw, now):
    """The record the agent reported, as the server keeps it, or None when it is not one.

    `at` is the agent's clock. A time a few minutes ahead of the server's is read as now; one further ahead, and one older than
    five years, is not believed and drops the record. A status outside the fixed set makes the record unusable; a source outside
    its set is blank and a class outside its set is "unknown" (an agent newer than this server may have a class this server has
    no word for). A refresh that worked has no class."""
    if not isinstance(raw, dict):
        return None
    now = int(now)
    at = raw.get('at')
    if not _whole(at) or at <= 0 or at < now - _OLDEST_S or at > now + _SKEW_S:
        return None
    status = raw.get('status')
    if status not in STATUSES:
        return None
    source = raw.get('source')
    cls = raw.get('error_class')
    if status == 'ok':
        cls = ''
    elif cls not in CLASSES:
        cls = 'unknown'
    return {'at': min(at, now),
            'status': status,
            'source': source if source in SOURCES else '',
            'error_class': cls}
