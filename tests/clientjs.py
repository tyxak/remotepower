"""Return the full client-side JS as one string, for tests that assert on it.

app.js was split into several plain `<script>` files (no bundler — they share
one global scope and load in order). Tests that grep "the app JS" should not
care which file a function ended up in, so they read this concatenation of
every static/js/*.js instead of a single hard-coded file. Splitting or moving
code between those files therefore never breaks a content assertion.

Order is the load order declared in index.html (so positional assertions like
"X must appear before Y" still hold across files), with any remaining files
appended deterministically.
"""
import re
from pathlib import Path

_JS_DIR = Path(__file__).resolve().parent.parent / "server" / "html" / "static" / "js"
_INDEX = Path(__file__).resolve().parent.parent / "server" / "html" / "index.html"


def _load_order():
    """File names in the order index.html loads them, then any leftovers."""
    html = _INDEX.read_text()
    ordered = []
    for m in re.finditer(r'<script\s+src="static/js/([A-Za-z0-9_.\-]+)"', html):
        name = m.group(1)
        if name not in ordered:
            ordered.append(name)
    # Append any *.js present on disk but not referenced (defensive).
    for f in sorted(_JS_DIR.glob("*.js")):
        if f.name not in ordered:
            ordered.append(f.name)
    return ordered


def client_js():
    parts = []
    for name in _load_order():
        f = _JS_DIR / name
        if f.is_file():
            parts.append(f"// ===== {name} =====\n" + f.read_text())
    return "\n".join(parts)
