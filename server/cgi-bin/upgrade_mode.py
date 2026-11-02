"""RemotePower — a host's apt upgrade mode: Standard or Extended (Discussion #30).

`apt-get upgrade` never installs a package that is not installed yet, so it keeps back an update whose new version
needs one: a new kernel image behind `linux-image-amd64`, or the split `linux-firmware` packages. It installs nothing for
that package, prints no error and exits 0. `apt-get upgrade --with-new-pkgs` installs the new packages such an update
needs and removes nothing.

  standard   `apt-get upgrade`, as before. The default.
  extended   `apt-get upgrade --with-new-pkgs`.

The mode is kept on the host and applies to every upgrade RemotePower runs on it: the patch button, auto-patch, a
scheduled upgrade, a rollout ring, and the autonomy loop's patch action. It matters only to a host that uses apt.

The command a host runs is one of two fixed strings, chosen by the mode. Nothing a request says is put into a command,
so the setting cannot carry a flag of its own. Nothing here imports api; the caller hands in the host and the command.
"""

from __future__ import annotations

from typing import Any

MODES = ("standard", "extended")
DEFAULT = "standard"

# The apt line of the upgrade command in api.py (`_UPGRADE_CMD`), standard and extended. The extended command is the
# standard one with this line swapped, so everything around it (the initramfs guard, the sandbox user, the lock wait,
# the autoremove, the log) is the same for both.
STANDARD_LINE = "apt-get $ALT -y upgrade &&"
EXTENDED_LINE = "apt-get $ALT -y upgrade --with-new-pkgs &&"


def extended(cmd: str) -> str:
    """The upgrade command with new packages allowed. Raises ValueError when `cmd` does not hold the apt upgrade line
    exactly once, so an edit that moves the line cannot leave Extended quietly the same as Standard.
    """
    if cmd.count(STANDARD_LINE) != 1:
        raise ValueError("the upgrade command has no single apt upgrade line to extend")
    return cmd.replace(STANDARD_LINE, EXTENDED_LINE)


def mode_of(dev: Any) -> str:
    """'extended' when the host's stored mode is exactly that word, otherwise 'standard'. A host that has none, a stored
    word that is not a mode and a record that is not a dict all read as Standard, which is what the host did before.
    """
    if isinstance(dev, dict) and dev.get("upgrade_mode") == "extended":
        return "extended"
    return DEFAULT


def not_applicable(family: str, manager: Any) -> str | None:
    """None when the mode can matter for a host of this OS family and package manager, otherwise why not:
    'not_linux' for a Windows or macOS host (their agents upgrade by their own verb) and 'not_apt' for a Linux host that
    reports another package manager. A manager the host has not reported yet ('' or 'unknown') is not held against it,
    because an agent that has not sent its first package scan is still an apt host."""
    if family != "linux":
        return "not_linux"
    if isinstance(manager, str) and manager and manager not in ("apt", "unknown"):
        return "not_apt"
    return None


REASONS = {
    "not_linux": "The upgrade mode applies to Linux hosts that use apt",
    "not_apt": "The upgrade mode applies to hosts that use apt, and this host uses another package manager",
}
