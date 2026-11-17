"""RemotePower — smart groups: look at the members of a rule before it is saved

A smart group is a saved rule whose members are worked out from the fleet, so until now the only way to learn what a rule
matches was to save the group and open its member list, then edit and save again. ``POST /api/smart-groups/preview`` takes
the rules of the editor as they stand and answers with how many hosts they match and the first 50 of them. It changes
nothing: no group is stored, nothing is written to the audit log, and no cadence runs.

It does not match anything itself. The count and the names come from ``_materialize_smart_group``, the function that works
out a saved group's members at creation, on edit and every minute after, called here with the tenant the caller would save
the group under. The rules go through ``_validate_smart_rules`` and the same refusal for an empty rule set, so a rule that
cannot be saved cannot be previewed either, with the same message.

Bound-module carve-out following the tls_ct_handlers / dmarc_handlers pattern: api.py execs a private instance and binds
its own ``globals()``, so every api service is reached as ``A.<name>`` (a DYNAMIC lookup, which keeps the suite's
monkeypatching of api.respond / api.load working and resolves identically under the __main__ and imported-module models).
"""


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


# How many host names an answer carries. The count is always the whole number of matches; the list is capped so a rule that matches a
# fleet of tens of thousands answers in a few kilobytes, and the page can show it in a box that does not grow.
PREVIEW_HOSTS = 50
# The longest display name sent back. Names are the host's own words (an agent reports one), so they are cut here as well as escaped
# where they are drawn.
PREVIEW_NAME_CHARS = 128


def handle_smart_group_preview():
    """POST /api/smart-groups/preview — body ``{"rules": {...}}``, the shape the create call takes (a ``name`` may be there and is
    ignored). Answers ``{"count": N, "limit": 50, "hosts": [{"id", "name"}, ...]}``: how many hosts the rules match and the first
    50, in the order a saved group lists its members.

    Admin only, as viewing the groups is. A tenant administrator previews against their own tenant's hosts and no others: the
    pool is narrowed exactly as it is when the group is saved, so the preview of a rule and the members of the group saved from it
    are the same list. An API key that has a device scope previews against the hosts of that scope and no others, as the host
    list does: a count over every host would tell it how many hosts outside its scope carry a tag or a group, and the names would
    be the hosts themselves. Rules are checked as a save checks them (a malformed number, rules that are not an object, and an
    empty set are all refused with the same 400), and a body that names hosts or scopes is not read for them: the rules are the
    only part of the body that is used."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.SmartGroupsRequest)
    rules = A._validate_smart_rules(body.get('rules') or {})
    if not rules:
        A.respond(400, {'error': 'at least one rule is required'})
    tenant = A._caller_effective_tenant(actor)
    # the fleet as this caller may see it: a key with a device scope reads the hosts of its scope and a tenant administrator the
    # hosts of the tenant. For a caller that neither confines, this is the shared read-only view itself: nothing below writes to it,
    # and a copy of a large host list is the one cost that grows
    devices = A._scope_filter_devices(A._load_ro(A.DEVICES_FILE) or {})
    ids = A._materialize_smart_group(rules, devices, tenant)
    hosts = []
    for did in ids[:PREVIEW_HOSTS]:
        rec = devices.get(did)
        name = rec.get('name') if isinstance(rec, dict) else None
        hosts.append({'id': did, 'name': str(name or did)[:PREVIEW_NAME_CHARS]})
    A.respond(200, {'count': len(ids), 'limit': PREVIEW_HOSTS, 'hosts': hosts})
