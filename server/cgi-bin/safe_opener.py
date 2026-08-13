#!/usr/bin/env python3
"""One place that takes urllib's local-file schemes away from an opener.

`urllib.request.build_opener()` ALWAYS installs its default handler set, and
passing custom HTTP/HTTPS handlers replaces only those two. `FileHandler`,
`FTPHandler` and `DataHandler` survive — so an opener built specifically to
constrain where a request may go will still open `file:///etc/shadow`. That was
verified by driving it, not by reading it.

Every outbound client in this codebase builds its own opener with its own
connect-time guards, which is correct — the guards differ per client. What they
were all inheriting for free was three schemes none of them wants. Six call
sites had the same gap, which is why this is a shared function rather than a
sixth copy of the same three lines: a rule applied in five places and missed in
one is this project's most reliable source of security findings.

This is defence in depth. Callers run a pre-flight that rejects such URLs today,
so no reachable path is known. It belongs here anyway, because these openers are
handed to connectors, monitors and integrations that each decide what to fetch,
and defence that depends on every caller remembering a check is defence that
eventually fails.
"""

import urllib.request

# DataHandler and CacheFTPHandler are version-dependent; look them up rather
# than assume, so this never raises on a Python that lacks one.
_LOCAL_HANDLERS = tuple(
    h
    for h in (
        getattr(urllib.request, "FileHandler", None),
        getattr(urllib.request, "FTPHandler", None),
        getattr(urllib.request, "CacheFTPHandler", None),
        getattr(urllib.request, "DataHandler", None),
    )
    if h is not None
)

_LOCAL_SCHEMES = ("file", "ftp", "data")


def strip_local_schemes(opener):
    """Remove file/ftp/data support from a built opener, in place.

    Returns the same opener so it can wrap a build_opener() call directly:

        return strip_local_schemes(urllib.request.build_opener(...))

    Both the handler list and the dispatch table are cleared. Clearing only the
    list is not enough: `handle_open` is what `open()` actually consults, so a
    handler removed from one and left in the other stays reachable.
    """
    for cls in _LOCAL_HANDLERS:
        for h in [x for x in opener.handlers if isinstance(x, cls)]:
            opener.handlers.remove(h)
    for scheme in _LOCAL_SCHEMES:
        opener.handle_open.pop(scheme, None)
    return opener
