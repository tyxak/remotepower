#!/usr/bin/env python3
"""Puts back what a test module changed on the one `api` of the process, and on its `storage`, when the module ends.

About a hundred test modules import `api` by name and so share one copy of it. A module that stubs a function, moves a store to a directory of its own or flips a flag on it, and does not put
it back, is read by every later module in the same process. The suite passed in one order and failed in another: `test_password_history_max_age` and the export test of
`test_tenant_password_reset_and_export` failed ("There is no item named 'users.json' in the archive") after `test_auth_before_lookup` had moved five stores, and 15 tests of
`test_v702_mitigate_gates` failed after a module that left three body readers stubbed. Each module ran in a process of its own and the public names of `api` that are functions, paths, strings
and flags were compared before and after (dev-tools/sweep-8.0.2/api_census.py): 8 of 99 left something changed.

A module that does that uses this as its module hooks, and the next module meets `api` as it was:

    def setUpModule():
        __import__("sys").path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import api_guard

        api_guard.save(__name__)

    def tearDownModule():
        import api_guard

        api_guard.restore(__name__)

It remembers the functions (by identity), paths, strings and flags that `api` has when the module starts, and puts back each one that is different when it ends. Containers and numbers are left:
caches and counters change in use. A name that the module added is left too: only what was there can be put back.

Which `api`: the one in sys.modules under that name, and every module-level name of the test module that is a copy of the same file (`api`, an alias, the one `wsgi` holds). They are not always the
same object. `test_audit_log_wrapped` and a dozen others load `api` and `storage` again (they take the name out of sys.modules and import it), so a module that was imported earlier keeps
the first copy in its own `api` while sys.modules names the new one. The hooks of `test_authz_smoke` looked at sys.modules, restored the new copy and left the five stores that the module had
moved on the copy it really used; `test_tenant_password_reset_and_export` moves "the stores that lie in the data directory" and found five of them somewhere else (the export then had no
users.json). The entries of sys.modules for `api` and `storage` and the RP_* variables of the environment are put back as well: a module that re-imports `api` sets RP_DATA_DIR to a directory
of its own, and the next import reads it.

`storage` is guarded the same way (GUARDED). It is the layer under every store, one copy for the process, and it holds the data directory that `backend_iter_files()` lists: twelve modules of
sixty-seven that touch it left `storage.DATA_DIR` pointing at a directory of their own, and the export archive of `test_tenant_password_reset_and_export` and four tests of
`test_password_history_max_age` then listed that directory and found no users.json, in some large shared runs only (they failed the same way at 88afc118). The flag `_ATEXIT_REGISTERED` is
not put back: it says that the one handler of `atexit` was registered, and clearing it would register it twice.
"""
import os
import sys
import types

_SAVED = {}
_MISSING = object()
GUARDED = ('api', 'storage')           # the modules that the suite shares between its test modules
_NOT_PUT_BACK = ('_ATEXIT_REGISTERED',)


def _snapshot(api):
    out = {}
    for name, value in list(vars(api).items()):
        if name.startswith('__') or name in _NOT_PUT_BACK:
            continue
        if isinstance(value, (os.PathLike, str, bool)) or (callable(value) and not isinstance(value, type)):
            out[name] = value
    return out


def _is_shared(module):
    """A copy of one of the shared modules: the name says so, or the file is the one that `api` or `storage` is loaded from."""
    if not isinstance(module, types.ModuleType):
        return False
    base = os.path.basename(getattr(module, '__file__', None) or '')
    return module.__name__ in GUARDED or base in tuple(g + '.py' for g in GUARDED)


def _modules_of(name):
    """The modules a test module may be changing: the entries of sys.modules for the shared names, and the copies that the test module (or `wsgi`) holds under any name of its own."""
    found = []

    def add(module, named_by_sys_modules=False):
        if (named_by_sys_modules and isinstance(module, types.ModuleType) or _is_shared(module)) and all(module is not other for other in found):
            found.append(module)

    for shared in GUARDED:
        add(sys.modules.get(shared), named_by_sys_modules=True)     # whatever sits under the shared name is the shared module
    for holder in (sys.modules.get(name), sys.modules.get('wsgi')):
        if holder is not None:
            for value in list(vars(holder).values()):
                add(value)
    return found


def _rp_env():
    return {k: v for k, v in os.environ.items() if k.startswith('RP_')}


def save(name, api=None):
    """Remember the functions, paths, strings and flags of the shared modules, under the name of the module that asks. With no module given: every copy of `api` and `storage` that the module
    can reach (_modules_of), the entries of sys.modules for them and the RP_* variables. With a module given: that module only."""
    if api is not None:
        _SAVED[name] = {'mods': [(api, _snapshot(api))], 'entries': None, 'env': None}
        return
    _SAVED[name] = {'mods': [(m, _snapshot(m)) for m in _modules_of(name)],
                    'entries': {g: sys.modules.get(g) for g in GUARDED},
                    'env': _rp_env()}


def restore(name):
    """Put back what `save(name)` found: a function that was replaced, a path, a string or a flag that was changed. Nothing is done when nothing was saved under this name."""
    got = _SAVED.pop(name, None)
    if got is None:
        return []
    put_back = []
    for api, before in got['mods']:
        for key, value in before.items():
            now = vars(api).get(key, _MISSING)
            if isinstance(value, (os.PathLike, str, bool)):
                same = now is not _MISSING and type(now) is type(value) and now == value
            else:
                same = now is value
            if not same:
                setattr(api, key, value)
                put_back.append(key)
    for shared, module in (got['entries'] or {}).items():
        if sys.modules.get(shared) is not module:
            if module is None:
                sys.modules.pop(shared, None)
            else:
                sys.modules[shared] = module
            put_back.append("sys.modules['%s']" % shared)
    if got['env'] is not None:
        now = _rp_env()
        for key in sorted(set(now) | set(got['env'])):
            if now.get(key) != got['env'].get(key):
                if key in got['env']:
                    os.environ[key] = got['env'][key]
                else:
                    os.environ.pop(key, None)
                put_back.append('$' + key)
    return put_back
