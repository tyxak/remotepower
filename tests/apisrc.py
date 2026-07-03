"""Shared helper: the COMBINED server-Python source for source-pin tests.

api.py's request-coupled subsystems are being decomposed into bound modules
(tickets_handlers.py, provisioning_handlers.py, backups_handlers.py,
cmdb_handlers.py, ...). A test that greps api.py's raw source for a moved
`def handle_x(` breaks on every extraction even though the behaviour is
unchanged — the same failure class the app.js page-module split hit, solved
there by clientjs.client_js(). This is the server-side twin: read the
combined source instead of api.py alone.

NB: inside the bound modules, api services are accessed as ``A.<name>`` —
a pin like r"save\\(DEVICES_FILE" must tolerate the prefix (match
``(?:A\\.)?save\\((?:A\\.)?DEVICES_FILE`` or just assert on substrings that
survive prefixing).
"""
from pathlib import Path

_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'


def api_source():
    """api.py + every *_handlers.py bound module, concatenated."""
    parts = [(_CGI / 'api.py').read_text()]
    for p in sorted(_CGI.glob('*_handlers.py')):
        parts.append(p.read_text())
    return '\n'.join(parts)
