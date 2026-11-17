"""The installed-software lists of Windows and macOS hosts.

A Linux agent sends the packages of its distribution: names without a space, versions the package manager
orders, and a vulnerability database that is filed under both. The agent of a Windows host sends what the
Uninstall keys of the registry hold, and the agent of a Mac sends the application bundles and the Homebrew
packages. A name there is the title a person reads ("Google Chrome", "Microsoft Visual C++ 2015-2022
Redistributable (x64) - 14.38.33130"), a version is whatever the vendor wrote, and nothing is matched against a
vulnerability database.

This module is the one place that says what such a list may hold and how a row of it is read, so that the pages
that read a list (the policy, the search, the software center, the metering, the SBOM, the CVE view) agree, and the
paths that are for the packages of a distribution can tell the two kinds apart. It is pure: no api globals, no I/O.

What a list is, and is not:

* `pkg_manager` of the list is `windows` or `macos`. A Mac holds two kinds of row, so each row names its own
  manager: `macos` for an application bundle, `brew` for a Homebrew formula or cask.
* No row of such a list is a package of a distribution. Nothing here reaches the vulnerability scan, the package
  snapshots or the install and remove commands, which are written for apt, dnf, yum, zypper, pacman and apk.
* Everything is capped: 5,000 rows to a host, 200 characters to a field.
"""

from __future__ import annotations

import datetime
import re
import unicodedata
from typing import Any

# What the agent of a Windows or macOS host says its list is made by (`pkg_manager` of POST /api/packages).
HOST_MANAGERS = ("windows", "macos")
# What one row of such a list may name: a Mac holds applications and Homebrew packages.
ROW_MANAGERS = {"windows": ("windows",), "macos": ("macos", "brew")}
INVENTORY_MANAGERS = ("windows", "macos", "brew")
# The managers whose names are a title a person reads. A process is not named like that, so a name here says
# nothing about what is running (the metering looks for the name among the processes of a Linux host).
DISPLAY_NAME_MANAGERS = ("windows", "macos")

MAX_PACKAGES = 5000
MAX_FIELD = 200
MAX_SKIPPED = 1_000_000

_ARCH = re.compile(r"[A-Za-z0-9_.-]{1,16}")
_DATE = re.compile(r"([0-9]{4})-?([0-9]{2})-?([0-9]{2})")
_DOTTED = re.compile(r"[0-9]+(?:\.[0-9]+)*")  # ASCII digits: int() reads more than a vendor means
_WHITESPACE_KINDS = ("Zs", "Zl", "Zp")


def manager_of(pkg_manager: Any) -> str:
    """`windows` or `macos` for the `pkg_manager` of a list that is an inventory of applications, else ''."""
    if isinstance(pkg_manager, str):
        text = pkg_manager.strip().lower()
        if text in HOST_MANAGERS:
            return text
    return ""


def is_inventory_host(pkg_manager: Any) -> bool:
    """Is a list with this `pkg_manager` an inventory of applications and not the packages of a distribution?"""
    return bool(manager_of(pkg_manager))


def row_manager(row: Any, host_manager: Any = "") -> str:
    """The inventory manager of a stored row: the one the row names, else the one of its host's list. '' for a
    package of a distribution, which no list of such a host holds and no row of a Linux host names.
    """
    if isinstance(row, dict):
        named = row.get("manager")
        if isinstance(named, str) and named.strip().lower() in INVENTORY_MANAGERS:
            return named.strip().lower()
    return manager_of(host_manager)


def clean_text(value: Any, limit: int = MAX_FIELD) -> str:
    """A field of a row as text a page can print: no control, format or private-use character (a bidirectional
    override makes one name read as another, a lone surrogate cannot be written), white space collapsed, at most
    `limit` characters. Anything that is not text is ''."""
    if not isinstance(value, str):
        return ""
    kept = []
    for ch in value:
        kind = unicodedata.category(ch)
        if kind in _WHITESPACE_KINDS or ch in "\t\n\r\x0b\x0c":
            kept.append(" ")
        elif kind[0] != "C":
            kept.append(ch)
    return " ".join("".join(kept).split())[:limit].strip()


def clean_arch(value: Any) -> str:
    """An architecture as a word (x64, x86, arm64), or ''."""
    if isinstance(value, str):
        text = value.strip()
        if _ARCH.fullmatch(text):
            return text
    return ""


def clean_date(value: Any) -> str:
    """An install date as YYYY-MM-DD from YYYY-MM-DD or YYYYMMDD (what the registry holds), or ''. A date that does
    not exist, or that is before 1990 or after 2100, is not one."""
    if not isinstance(value, str):
        return ""
    found = _DATE.fullmatch(value.strip())
    if not found:
        return ""
    try:
        day = datetime.date(int(found.group(1)), int(found.group(2)), int(found.group(3)))
    except ValueError:
        return ""
    return day.isoformat() if 1990 <= day.year <= 2100 else ""


def clean_skipped(value: Any) -> int:
    """How many entries the agent left out (updates and system components), as a whole number, else 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return value if 0 <= value <= MAX_SKIPPED else 0


def clean_entry(entry: Any, host_manager: Any) -> dict | None:
    """One row of a list as the server keeps it, or None when it is not a row.

    A row has a name; a version may be empty (a program that does not write one). Its manager is the one it names
    when that is one its host may hold, else the host's own. `publisher`, `installed` and `id` (the bundle
    identifier of an application) are kept when they hold something."""
    host = manager_of(host_manager)
    if not host or not isinstance(entry, dict):
        return None
    name = clean_text(entry.get("name"))
    if not name:
        return None
    manager = host
    named = entry.get("manager")
    if isinstance(named, str) and named.strip().lower() in ROW_MANAGERS[host]:
        manager = named.strip().lower()
    row: dict = {
        "name": name,
        "version": clean_text(entry.get("version")),
        "arch": clean_arch(entry.get("arch")),
        "manager": manager,
    }
    publisher = clean_text(entry.get("publisher"))
    if publisher:
        row["publisher"] = publisher
    installed = clean_date(entry.get("installed"))
    if installed:
        row["installed"] = installed
    ident = clean_text(entry.get("id"))
    if ident:
        row["id"] = ident
    return row


def clean_list(raw: Any, host_manager: Any) -> list:
    """The rows of a list as the server keeps them: at most MAX_PACKAGES are read, what is not a row is left out
    and so is a row that repeats another (the registry holds one program under two keys now and then).
    """
    rows: list = []
    seen: set = set()
    if not isinstance(raw, list):
        return rows
    for entry in raw[:MAX_PACKAGES]:
        row = clean_entry(entry, host_manager)
        if row is None:
            continue
        key = (
            row["manager"],
            row["name"].casefold(),
            row["version"],
            row["arch"],
            row.get("id", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        rows.append(row)
    return rows


def name_key(row: Any) -> str:
    """The name of a row as a rule or a search matches it: in lower case, so `teamviewer` finds `TeamViewer`."""
    return str(row.get("name") or "").casefold() if isinstance(row, dict) else ""


def _parts(version: Any) -> tuple | None:
    """The numbers of a version that is dotted numbers (10.0.19045.3693, 14.38.33130, v2.1), else None."""
    text = str(version if version is not None else "").strip()
    if text[:1] in ("v", "V") and text[1:2] in tuple("0123456789"):
        text = text[1:]
    if len(text) > MAX_FIELD or not _DOTTED.fullmatch(text):
        return None
    return tuple(int(part) for part in text.split("."))


def compare_versions(a: Any, b: Any) -> int:
    """-1, 0 or 1: the order of two versions that a vendor wrote.

    Two versions that are dotted numbers are compared as numbers, part by part, with the shorter one padded by
    zeros (10.0.9 is below 10.0.19045 and 1.2 equals 1.2.0). Anything else is compared as text, ignoring case:
    the vendor's own words have no order that is better than that, and it never raises. A text that is not a
    version at all, or is empty, is still ordered."""
    left, right = _parts(a), _parts(b)
    if left is not None and right is not None:
        width = max(len(left), len(right))
        padded_left = left + (0,) * (width - len(left))
        padded_right = right + (0,) * (width - len(right))
        return (padded_left > padded_right) - (padded_left < padded_right)
    text_left = str(a if a is not None else "").casefold()
    text_right = str(b if b is not None else "").casefold()
    return (text_left > text_right) - (text_left < text_right)
