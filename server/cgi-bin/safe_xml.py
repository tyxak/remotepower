"""Dependency-free XML hardening.

stdlib `xml.etree.ElementTree` expands INTERNAL entities (billion-laughs DoS) but
does NOT resolve EXTERNAL entities (so no XXE file-read/SSRF — verified). The single
sufficient guard is therefore: reject any input that declares a DTD/entity BEFORE
parsing. Legitimate data XML (DMARC aggregate reports, Zabbix/EC2 exports) never
carries a DTD.

The scan covers the WHOLE buffer, not a fixed leading window: a DOCTYPE hidden past
an N-byte window (e.g. behind a big leading comment) is a real bypass — dmarc_monitor
(v5.5.0 M1) fixed exactly that, and cloud_import still had the 4 KB-window bug this
module centralises the fix for. Keep every ET.fromstring on untrusted input routed
through here so the three call sites can't drift apart again.
"""
import re
# This module IS the hardening: fromstring() below refuses any DTD/entity
# declaration (the billion-laughs vector) before parsing, and stdlib ET does not
# resolve external entities (no XXE). Routing untrusted call sites through here is
# the mitigation, not a vulnerability.
import xml.etree.ElementTree as _ET  # nosec B405

# Re-export so callers catch `safe_xml.ParseError` without importing ElementTree.
ParseError = _ET.ParseError

_DTD_RE = re.compile(rb'<!\s*(?:doctype|entity)', re.IGNORECASE)


def has_dtd(data):
    """True if the buffer declares a DTD/entity anywhere (billion-laughs marker)."""
    raw = data if isinstance(data, (bytes, bytearray)) else str(data).encode('utf-8', 'replace')
    return bool(_DTD_RE.search(raw))


def fromstring(data):
    """Like ET.fromstring, but raises ValueError on ANY DTD/entity declaration.

    Callers already wrapping parse in `except ParseError` should add `ValueError`
    (or let it propagate to a handler that turns ValueError into a 400)."""
    if has_dtd(data):
        raise ValueError('XML with a DTD/entity declaration is not allowed '
                         '(entity-expansion DoS guard)')
    # has_dtd() above rejects the entity-expansion vector before we get here;
    # external entities aren't resolved by stdlib ET.
    return _ET.fromstring(data)  # nosec B314
