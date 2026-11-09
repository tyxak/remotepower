#!/usr/bin/env python3
"""Puts the request variables of the process back when a test module ends.

A request is described to the server by environment variables (REQUEST_METHOD, PATH_INFO, QUERY_STRING, CONTENT_LENGTH, a header as HTTP_*), and `api._env()` reads the process
environment for a request that sets none of its own. A test module that writes one and leaves it there is read by the next module that does not set its own: the suite passed in
the alphabetical order of the gate and failed in a subset run (two modules did, in 8.0.0). Writing one at import time is worse, because discovery imports every module first, so
the last module imported decided what every module saw until it set its own.

A module that writes a request variable uses this as its module hooks, and writes the variable in `setUpModule`, never at import:

    def setUpModule():
        __import__("sys").path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import env_guard

        env_guard.save(__name__)
        os.environ["REQUEST_METHOD"] = "GET"

    def tearDownModule():
        import env_guard

        env_guard.restore(__name__)

`tests/test_v800_env_restored.py` holds both rules for every test module.
"""
import os
import re

REQUEST_VAR = re.compile(
    r"^(QUERY_STRING|REQUEST_METHOD|PATH_INFO|CONTENT_LENGTH|CONTENT_TYPE|REMOTE_ADDR|SERVER_NAME|SERVER_PORT|SCRIPT_NAME|REQUEST_URI|HTTPS|HTTP_[A-Z0-9_]+)$"
)
_SAVED = {}


def request_vars(environ=None):
    """The request variables in the environment (the process's, or the mapping given)."""
    environ = os.environ if environ is None else environ
    return {k: v for k, v in environ.items() if REQUEST_VAR.match(k)}


def save(name):
    """Remember the request variables as they are now, under the name of the module."""
    _SAVED[name] = request_vars()


def restore(name):
    """Put the request variables back as `save(name)` found them: a variable set since is removed, one that was changed is reset."""
    before = _SAVED.pop(name, None)
    if before is None:                      # setUpModule did not run for this name: nothing was saved, so nothing is undone
        return
    for key in list(request_vars()):
        if key not in before:
            del os.environ[key]
    os.environ.update(before)
