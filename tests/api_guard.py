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

`storage` is guarded the same way (GUARDED). It is the layer under every store, one copy for the process, and it holds the data directory that `backend_iter_files()` lists: twelve modules of
sixty-seven that touch it left `storage.DATA_DIR` pointing at a directory of their own, and the export archive of `test_tenant_password_reset_and_export` and four tests of
`test_password_history_max_age` then listed that directory and found no users.json, in some large shared runs only (they failed the same way at 88afc118). The flag `_ATEXIT_REGISTERED` is
not put back: it says that the one handler of `atexit` was registered, and clearing it would register it twice.
"""
import os
import sys

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


def save(name, api=None):
    """Remember the functions, paths, strings and flags of the shared modules (`api` and `storage`, or the one module given), under the name of the module that asks."""
    mods = [api] if api is not None else [sys.modules[m] for m in GUARDED if m in sys.modules]
    _SAVED[name] = [(m, _snapshot(m)) for m in mods]


def restore(name):
    """Put back what `save(name)` found: a function that was replaced, a path, a string or a flag that was changed. Nothing is done when nothing was saved under this name."""
    got = _SAVED.pop(name, None)
    if got is None:
        return []
    put_back = []
    for api, before in got:
        for key, value in before.items():
            now = vars(api).get(key, _MISSING)
            if isinstance(value, (os.PathLike, str, bool)):
                same = now is not _MISSING and type(now) is type(value) and now == value
            else:
                same = now is value
            if not same:
                setattr(api, key, value)
                put_back.append(key)
    return put_back
