"""RemotePower — which way an observed TCP connection runs (v7.4.6, issue #58).

The Linux agent samples the established TCP connections of its host and reports the private addresses
at the far end, so the server can suggest "this host depends on that one". A socket does not say who
started the connection. One the host accepted shows the client's address and the client's source port,
and read as an upstream it made a server the client of its own clients.

Two places tell them apart:

* The agent leaves out a connection whose local port is one the host listens on. That is exact.
* The server never sees the local port, so for what an older agent reported it asks the host at the
  far end: a remote port in the ephemeral range that the far host does not listen on is that host's own
  source port, so the connection ran from it to the reporting host, not the other way.

Nothing here imports api. The caller hands in the device record and the port.
"""

from __future__ import annotations

from typing import Any

# The lowest port of the Linux default ephemeral range (32768-60999). Windows, macOS and the BSDs start
# higher (49152), so this is the wider of the ranges. Below it a port that nothing listens on is more
# likely a service reached through a port forward or a published container port than a source port.
EPHEMERAL_FLOOR = 32768

# The agent reports at most this many listening sockets, lowest port first. A list that long may have
# been cut, and the cut takes the high ports, which is where an ephemeral port would have been listed.
LISTENING_CAP = 80


def listening_tcp_ports(device: Any) -> set[int] | None:
    """The TCP ports a host reports listening on, or None when that is not known to be the whole list.

    None covers a host that sent no list (an agentless host, an older agent, a failed probe), an empty
    one, one that reaches the agent's cap and may have been cut, and one with a row that cannot be read.
    A list with a hole in it cannot say that a port is absent."""
    sysinfo = device.get("sysinfo") if isinstance(device, dict) else None
    rows = sysinfo.get("listening_ports") if isinstance(sysinfo, dict) else None
    if not isinstance(rows, list) or not rows or len(rows) >= LISTENING_CAP:
        return None
    ports: set[int] = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("proto"), str):
            return None
        raw = row.get("port")
        if raw is None:
            return None
        try:
            number = int(raw)
        except (TypeError, ValueError, OverflowError):
            return None
        if not 0 < number <= 65535:
            return None
        if row["proto"].lower().startswith("tcp"):
            ports.add(number)
    return ports


def is_client_source_port(device: Any, port: Any) -> bool:
    """True when `port`, seen at the far end of a connection, is a source port of `device` and not a
    service of it. The connection then ran from `device` to the host that reported it, which makes
    `device` a client of that host and not its upstream.

    Only a port in the ephemeral range counts, and only when `device` reports the whole list of what
    it listens on and the port is not in it. Anything less certain answers False and the suggestion
    stays, because a suggestion the operator can dismiss costs less than a dependency that is not
    offered."""
    try:
        number = int(port)
    except (TypeError, ValueError, OverflowError):
        return False
    if not EPHEMERAL_FLOOR <= number <= 65535:
        return False
    listening = listening_tcp_ports(device)
    return listening is not None and number not in listening
