"""Threat intel's two documents, read and written as the one store they used to be.

The table of addresses is `IPINTEL_FILE`. What arrives between sweeps is
`IPINTEL_INTAKE_FILE`: the queue, each host's sensor record and the edge feeds'
places in their logs. Before 7.4.0 all of it was one document, and most of the
Threat intel tests were written against that shape. `read()` gives them that one
dict (`queue` and `sensors` at the top, the feeds' places as `edge.cf_to` and
`edge.trap_to`) and `write()` splits it again, so a test says what the code does
and not which key it landed in. The tests of where things live, and of the
move from the old shape, are in `test_v740_ipintel_intake.py`.
"""

INTAKE_KEYS = ('queue', 'sensors')
FEEDS = ('cf', 'trap')


def read_intake(api):
    """The intake document as stored, or {}."""
    return (api.load(api.IPINTEL_INTAKE_FILE) or {}) if api.backend_exists(api.IPINTEL_INTAKE_FILE) else {}


def read(api):
    """The table and the intake as one dict in the shape the store had before 7.4.0."""
    st = dict(api.load(api.IPINTEL_FILE) or {})
    intake = read_intake(api)
    for key in INTAKE_KEYS:
        if key in intake:
            st[key] = intake[key]
    cursors = intake.get('cursors') if isinstance(intake.get('cursors'), dict) else {}
    if cursors:
        st['edge'] = dict(st.get('edge') or {}, **{feed + '_to': t for feed, t in cursors.items()})
    return st


def write(api, st):
    """Save a dict in the old shape: the intake's parts go to the intake document."""
    st = dict(st)
    intake = dict(read_intake(api))
    touched = False
    for key in INTAKE_KEYS:
        if key in st:
            intake[key] = st.pop(key)
            touched = True
    edge = st.get('edge')
    if isinstance(edge, dict) and any(feed + '_to' in edge for feed in FEEDS):
        edge = dict(edge)
        cursors = dict(intake.get('cursors') or {})
        for feed in FEEDS:
            if feed + '_to' in edge:
                cursors[feed] = edge.pop(feed + '_to')
        intake['cursors'] = cursors
        st['edge'] = edge
        touched = True
    api.save(api.IPINTEL_FILE, st)
    if touched:
        intake['adopted'] = True
        for key, kind in (('queue', list), ('sensors', dict), ('cursors', dict)):
            if not isinstance(intake.get(key), kind):
                intake[key] = kind()
        api.save(api.IPINTEL_INTAKE_FILE, intake)
    api._LOAD_CACHE.clear()


def update(api, **keys):
    """Merge keys into the store (old shape) and save."""
    st = read(api)
    st.update(keys)
    write(api, st)
