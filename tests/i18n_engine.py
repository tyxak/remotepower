"""Facts about the i18n engine that a test has to read from its source.

Restating them in a test lets the two drift: the text-node cap was once
hardcoded in three places, nine descriptions sat just above it, and every key
was present while nothing translated.
"""
import re
from pathlib import Path

I18N_JS = Path(__file__).resolve().parent.parent / 'server' / 'html' / 'static' / 'js' / 'i18n.js'


def text_node_cap(src=None):
    """The longest text node `translateTextNode` will translate.

    A node above it is skipped before the dictionary is consulted, so a string
    that long cannot be translated even with a complete DICT entry.
    """
    text = src if src is not None else I18N_JS.read_text(encoding='utf-8')
    m = re.search(r'trimmed\.length\s*>\s*(\d+)', text)
    assert m, 'the text-node length cap is no longer in translateTextNode'
    return int(m.group(1))
