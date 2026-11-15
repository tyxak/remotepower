"""RemotePower — which of two package versions is newer, for RPM and Alpine packages (8.0.1).

The CVE scanner asks one question of a finding: is the installed package already at or past the version that
fixed it? For Debian and Ubuntu it asks dpkg. For everything else it used a comparator that split a version
on punctuation and compared the leading digits of each piece, which is wrong for both formats here:

  RPM     "1:3.0.7-28.el9_4" was read as 1, 0, 7, 28: the epoch took the place of the first number, so an
          installed "3.0.7-16.el9" (reported without its epoch) counted as newer than every fix and a host
          that needed the update showed nothing for the package. With an epoch above the version's first
          number (bind, 32:9.16) it went the other way and no update ever cleared the findings.
  Alpine  "-r5" and a letter after the number ("1.1.1w") were read as nothing, so a fix that only raised the
          revision or the letter counted as already installed.

Both orderings are written here from their published descriptions (the RPM version comparison document and
the Alpine package version format). Nothing is imported from api or the network code.

A version that cannot be read raises ValueError. The scanner keeps the finding in that case: a finding too
many is an annoyance, a finding hidden by a guess is the failure this module exists to prevent.
"""

from __future__ import annotations

import re

__all__ = ["rpm_compare", "rpm_ge", "rpm_split", "apk_compare", "apk_ge"]

MAX_LEN = 256


def _checked(version: object) -> str:
    if not isinstance(version, str):
        raise ValueError("a version is text")
    text = version.strip()
    if not text or len(text) > MAX_LEN:
        raise ValueError("a version is between 1 and %d characters" % MAX_LEN)
    return text


# ── RPM ──────────────────────────────────────────────────────────────────────────────────────────────────


def rpm_split(evr: object) -> tuple[int | None, str, str | None]:
    """(epoch, version, release) of "[epoch:]version[-release]". The epoch is None when the text has none,
    which is not the same as 0 to a caller that does not know whether the epoch was left out. The release is
    what follows the last dash, None without one."""
    text = _checked(evr)
    epoch: int | None = None
    head, colon, rest = text.partition(":")
    if colon:
        if not head.isdigit() or not head.isascii() or len(head) > 9:
            raise ValueError("an epoch is a whole number")
        epoch = int(head)
        text = rest
    version, dash, release = text.rpartition("-")
    if not dash:
        version, release_or_none = text, None
    else:
        release_or_none = release
    if not version or release_or_none == "":
        raise ValueError("no version")
    return epoch, version, release_or_none


def _rpm_segments(a: str, b: str) -> int:
    """The segment comparison RPM applies to a version and to a release, each on its own."""
    if a == b:
        return 0
    i = j = 0
    la, lb = len(a), len(b)
    while True:
        # separators carry no order of their own, apart from the tilde and the caret
        while i < la and not (a[i].isascii() and a[i].isalnum()) and a[i] not in "~^":
            i += 1
        while j < lb and not (b[j].isascii() and b[j].isalnum()) and b[j] not in "~^":
            j += 1
        tilde_a, tilde_b = i < la and a[i] == "~", j < lb and b[j] == "~"
        if tilde_a or tilde_b:  # a tilde sorts before everything, the end of the text included
            if not tilde_a:
                return 1
            if not tilde_b:
                return -1
            i += 1
            j += 1
            continue
        caret_a, caret_b = i < la and a[i] == "^", j < lb and b[j] == "^"
        if caret_a or caret_b:  # a caret sorts after the end of the text and before anything else
            if i >= la:
                return -1
            if j >= lb:
                return 1
            if not caret_a:
                return 1
            if not caret_b:
                return -1
            i += 1
            j += 1
            continue
        if i >= la or j >= lb:
            break
        numeric = a[i].isdigit()
        start_a, start_b = i, j
        if numeric:
            while i < la and a[i].isascii() and a[i].isdigit():
                i += 1
            while j < lb and b[j].isascii() and b[j].isdigit():
                j += 1
        else:
            while i < la and a[i].isascii() and a[i].isalpha():
                i += 1
            while j < lb and b[j].isascii() and b[j].isalpha():
                j += 1
        seg_a, seg_b = a[start_a:i], b[start_b:j]
        if not seg_b:  # a number against letters: the number is newer
            return 1 if numeric else -1
        if numeric:
            seg_a, seg_b = seg_a.lstrip("0"), seg_b.lstrip("0")
            if len(seg_a) != len(seg_b):
                return 1 if len(seg_a) > len(seg_b) else -1
        if seg_a != seg_b:
            return 1 if seg_a > seg_b else -1
    if i >= la and j >= lb:
        return 0
    return 1 if i < la else -1


def rpm_compare(a: object, b: object, assume_same_epoch: bool = False) -> int:
    """-1, 0 or 1 for a older than, equal to or newer than b, both "[epoch:]version[-release]".

    A missing epoch is 0, as RPM reads it. With `assume_same_epoch`, a side without an epoch takes the other
    side's: the answer for a package list that was collected without epochs, where "3.0.7-16.el9" really is
    1:3.0.7-16.el9 and reading it as epoch 0 would put it below every fix."""
    epoch_a, version_a, release_a = rpm_split(a)
    epoch_b, version_b, release_b = rpm_split(b)
    if assume_same_epoch and (epoch_a is None or epoch_b is None):
        epoch_a = epoch_b = 0
    left, right = epoch_a or 0, epoch_b or 0
    if left != right:
        return 1 if left > right else -1
    order = _rpm_segments(version_a, version_b)
    if order:
        return order
    # A side without a release is older than the same version with one, which is how the advisory database
    # orders them and the direction that keeps a finding.
    return _rpm_segments(release_a or "", release_b or "")


def rpm_ge(installed: object, fixed: object, assume_same_epoch: bool = False) -> bool:
    return rpm_compare(installed, fixed, assume_same_epoch) >= 0


# ── Alpine ───────────────────────────────────────────────────────────────────────────────────────────────

# number{.number}[letter]{_suffix[number]}[~hash][-r number]
_APK = re.compile(
    r"^(?P<digits>[0-9]+(?:\.[0-9]+)*)"
    r"(?P<letter>[a-z])?"
    r"(?P<suffixes>(?:_[a-z]+[0-9]*)*)"
    r"(?:~(?P<hash>[0-9a-f]+))?"
    r"(?:-r(?P<revision>[0-9]+))?$"
)
_APK_SUFFIX = re.compile(r"_([a-z]+)([0-9]*)")
# before the plain version, in this order, then the plain version (0), then after it, in this order
_APK_SUFFIX_RANK = {
    "alpha": -4,
    "beta": -3,
    "pre": -2,
    "rc": -1,
    "cvs": 1,
    "svn": 2,
    "git": 3,
    "hg": 4,
    "p": 5,
}


def _apk_key(version: object) -> tuple:
    text = _checked(version)
    match = _APK.match(text)
    if not match:
        raise ValueError("not an Alpine package version")
    numbers = []
    for position, part in enumerate(match.group("digits").split(".")):
        if position and part[0] == "0":
            # After the first number, one that starts with a zero is ordered like the digits of a fraction:
            # it sits below every number that does not (1.05 is below 1.1), more zeros sit lower (1.005 is
            # below 1.05), and what follows the zeros decides between two with the same count (1.05 is
            # below 1.050). A date written 2023.09 and 2023.10 comes out in calendar order this way.
            rest = part.lstrip("0")
            numbers.append((-(len(part) - len(rest)), int(rest) if rest else 0))
        else:
            numbers.append((int(part), 0))
    suffixes = []
    for name, number in _APK_SUFFIX.findall(match.group("suffixes") or ""):
        if name not in _APK_SUFFIX_RANK:
            raise ValueError("not an Alpine version suffix: _%s" % name)
        suffixes.append((_APK_SUFFIX_RANK[name], int(number) if number else 0))
    # A shorter list of numbers is older ("1.2" before "1.2.0") and the tuple order does that. A version
    # with no suffix has to sit between the two kinds, so the list ends with the plain rank 0.
    suffixes.append((0, 0))
    revision = match.group("revision")
    return (
        tuple(numbers),
        match.group("letter") or "",
        tuple(suffixes),
        match.group("hash") or "",
        int(revision) if revision is not None else -1,  # "1.0" is older than "1.0-r0"
    )


def apk_compare(a: object, b: object) -> int:
    """-1, 0 or 1 for a older than, equal to or newer than b, both Alpine package versions."""
    key_a, key_b = _apk_key(a), _apk_key(b)
    if key_a == key_b:
        return 0
    return 1 if key_a > key_b else -1


def apk_ge(installed: object, fixed: object) -> bool:
    return apk_compare(installed, fixed) >= 0
