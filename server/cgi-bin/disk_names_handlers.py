"""RemotePower — Names for a host's disks, kept against the serial number

A bound-module carve-out following the tls_ct_handlers / dmarc_handlers /
rack_ipam_handlers pattern:

  - api.py execs a PRIVATE instance and binds its own ``globals()`` here, so
    every api service is reached as ``A.<name>`` — a DYNAMIC attribute lookup,
    which keeps the test suite's monkeypatching of api.respond / api.save / …
    working, and resolves identically under the CGI (__main__) and
    imported-module (wsgi.py/scheduler.py) models.
  - api.py then from-imports every public + private name back into its own
    globals, so the route tables, main()'s _safe() cadence and scheduler.py's
    CADENCE tuple keep resolving the names unchanged.
  - Calls BETWEEN these functions ALSO go through ``A.`` so a test that patches
    one of them is seen by its caller.

Constants stay in api.py and are read here through A. Pure logic goes in a
sibling module (imported directly, like dmarc_monitor / tls_monitor).
"""
import re


class _ApiNamespace:
    __slots__ = ('_g',)

    def __init__(self, g):
        self._g = g

    def __getattr__(self, name):
        try:
            return self._g[name]
        except KeyError:
            raise AttributeError(f'api namespace has no {name!r}') from None


A = None


def bind(api_globals):
    """Called once by api.py right after importing this module, with
    api's ``globals()``."""
    global A
    A = _ApiNamespace(api_globals)


# A name is a label for a person to read: short enough for a table cell and an alert title.
_NAME_MAX = 64
# More than the 32 disks a heartbeat reports, so a host that has had drives swapped keeps the names of
# the ones it has had, and a bound on what one host can make the store hold.
_PER_HOST_MAX = 128
_CONTROL = re.compile(r'[\x00-\x1f\x7f]+')


def _clean_name(value):
    """A name as it is kept: text, control characters turned into spaces, whitespace squeezed, cut at
    _NAME_MAX. Returns None for anything that is not text, and '' for text with nothing in it."""
    if not isinstance(value, str):
        return None
    return ' '.join(_CONTROL.sub(' ', value).split())[:_NAME_MAX].strip()


def handle_device_disk_names(dev_id):
    """PUT /api/devices/<id>/disk-names — give a host's disks names, kept against the serial number.

    Body: {"names": {"<serial>": "<name>", ...}}. Each pair sets that disk's name and an empty name
    removes it; a serial that is not in the body is left alone, so naming one disk never forgets
    another. The key is the serial number, not the device letter, because the letter moves (after a
    reboot, a controller change, another tool's numbering) and the drive does not.

    A name can be set for a serial the host reports now, or one it already has a name for (so a
    drive that was pulled can still be renamed or cleared). Anything else is left out and listed in
    ``ignored``, as is a value that is not text. A disk that reports no serial cannot be named: the
    letter is all it has, and that is the thing that moves.

    Editing a label is editorial, like a CMDB note: an administrator or a role with an action
    permission. The route is under /api/devices/<id>/, so a host outside the caller's tenant or role
    scope is refused before this runs.
    """
    actor = A.require_write_role('name disks')
    if A.method() != 'PUT':
        A.respond(405, {'error': 'Method not allowed'})
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'Host not found'})
    if not A.device_get(dev_id):
        A.respond(404, {'error': 'Host not found'})
    body = A._read_valid(A.request_models.DiskNamesRequest)
    names = body.get('names')
    if not isinstance(names, dict):
        A.respond(400, {'error': 'names must be an object of serial number to name'})

    present = set()
    rec = A._entity_read_one(A.HARDWARE_FILE, dev_id, None) or {}
    for d in (rec.get('smart') or []):
        if isinstance(d, dict):
            serial = str(d.get('serial') or '').strip()
            if serial:
                present.add(serial)

    wanted = []
    for key, value in list(names.items())[:_PER_HOST_MAX]:
        serial = A._sanitize_str(str(key), 64).strip()
        if serial:
            wanted.append((serial, _clean_name(value)))

    ignored = []
    with A._LockedUpdate(A.DISK_NAMES_FILE) as store:
        raw = store.get(dev_id)
        mine = {k: v for k, v in raw.items() if isinstance(k, str) and isinstance(v, str)} \
            if isinstance(raw, dict) else {}
        set_n = cleared_n = 0
        for serial, name in wanted:
            if name is None:
                ignored.append(serial)              # not text
            elif not name:
                if mine.pop(serial, None) is not None:
                    cleared_n += 1
            elif serial in present or serial in mine:
                if mine.get(serial) != name:
                    set_n += 1
                mine[serial] = name
            else:
                ignored.append(serial)              # a drive this host does not have
        if len(mine) > _PER_HOST_MAX:
            A.respond(400, {'error': 'Too many disk names for one host', 'limit': _PER_HOST_MAX})
        if mine:
            store[dev_id] = mine
        else:
            store.pop(dev_id, None)
    # Counts, not labels: the trail says that somebody named disks on this host, and the table has
    # the words.
    A.audit_log(actor, 'disk_names_set', detail=f'host={dev_id} set={set_n} cleared={cleared_n}')
    A.respond(200, {'ok': True, 'names': mine, 'ignored': ignored})
