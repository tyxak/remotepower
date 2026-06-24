#!/usr/bin/env python3
"""CGI entry shim for the RemotePower backend.

fcgiwrap runs the file named by SCRIPT_FILENAME as the request's *main script*,
and CPython never uses the cached .pyc for a main script -- it recompiles the
source every run. For api.py (~50k lines) that is ~1s of pure compile on every
request.

runpy.run_module runs api AS __main__ from its cached bytecode
(cgi-bin/__pycache__/api.cpython-*.pyc) instead of recompiling, so api's
existing `if __name__ == '__main__'` block fires unchanged -- including the
HTTPError -> render path. (A plain `import api; api.main()` would skip that
block and lose the HTTPError handling; run_name='__main__' preserves it.)

api.py is left untouched: it stays directly executable AND is still imported as
a plain module by api_worker.py and cve_scan_runner.py, so it is neither renamed
nor edited.

Precompile once at install time so the .pyc exists for the (root-owned,
read-only-to-the-CGI-user) cgi-bin dir:  python3 -m compileall cgi-bin/
"""
import runpy

runpy.run_module('api', run_name='__main__', alter_sys=True)
