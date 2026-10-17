"""Small text helpers shared by the server modules.

Pure and stdlib-only, so any module may import it by name (the server directory is on sys.path)."""


def plural(n, one, other=None):
    """`plural(3, 'host')` -> '3 hosts'; `plural(1, 'host')` -> '1 host'.

    The count is part of the text, so nobody writes "host(s)". Pass the plural when it is not just an
    s (`plural(n, 'entry', 'entries')`). A count that is not a number is shown as it is, with the
    plural form; None counts as 0.
    """
    if n is None:
        n = 0
    try:
        is_one = float(n) == 1
    except (TypeError, ValueError):
        is_one = False
    return f"{n} {one if is_one else (other if other is not None else one + 's')}"


def agree(n, one, other):
    """The verb (or other word) that goes with a count: `agree(1, 'is', 'are')` -> 'is'. None counts as 0."""
    try:
        return one if float(0 if n is None else n) == 1 else other
    except (TypeError, ValueError):
        return other
