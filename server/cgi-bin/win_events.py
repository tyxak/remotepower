"""RemotePower: the Windows event log as a source of log rules (pure).

A log rule matches the lines of one unit. A Windows host has no journal, so its agent reads the event log and sends the events as units named after the channel
and the event id: `eventlog.Security.4625` holds the failed logons of the Security log, `eventlog.System.7045` the services installed. A rule on such a unit is an
ordinary log rule (pattern, threshold, severity, message) and fires the ordinary `log_alert` event.

This module is the one place that says what such a unit looks like and which units a host's rules ask for. The server uses it to refuse a rule on a unit no agent
could feed, to tell a Windows agent which events to read and to keep these units out of a `*` rule. The agent applies the same shape again to what it is told, because
it does not rely on the server having checked.

How a Windows agent is told: the `log_watch` list of the heartbeat answer already holds the rules of the host itself, and the agent reads the event units out of it. A
fleet-wide rule is matched on the server, so it is not in that list; `fleet_unit_rules` gives a Windows host the event units of those rules, one `{"unit": ...}` each and
nothing else of the rule, to be added to the list. The agent then reads the events of both. No new key travels in the answer, so no other agent has anything to ignore.

Nothing here reads a store or the request.
"""

import re

CHANNELS = ("Security", "System", "Application")
UNIT_PREFIX = "eventlog."
MAX_EVENT_ID = 65535
MAX_IDS_PER_CHANNEL = 12  # event ids one host reads from one channel: each one is a query on the host at every check-in
UNIT_RE = re.compile(r"^eventlog\.(Security|System|Application)\.([1-9][0-9]{0,4})$")

# Said when a rule names an event log unit that is not of that shape. A fixed sentence, so it is a dictionary key of the interface.
BAD_UNIT = "an event log unit looks like eventlog.Security.4625: the channel (Security, System or Application), then the event id"


def parse_unit(unit):
    """(channel, event id) of an `eventlog.<Channel>.<id>` unit, or None for anything else."""
    m = UNIT_RE.fullmatch(unit) if isinstance(unit, str) else None
    if not m or int(m.group(2)) > MAX_EVENT_ID:
        return None
    return m.group(1), int(m.group(2))


def is_event_unit(unit):
    """Whether a unit is in the event log namespace (valid or not): a `*` rule never matches one."""
    return isinstance(unit, str) and unit.startswith(UNIT_PREFIX)


def watch_for(*rule_lists):
    """{channel: [event ids]} the rules ask a host to read: the units of every rule in the lists, validated, sorted, and capped for each channel.

    Each list is a list of rules (a host's own, the fleet-wide ones); a row that is not a rule, or whose unit is not an event log unit, asks for nothing. Only a channel with
    an id is in the answer, so an empty map means "read nothing".
    """
    want = {}
    for rules in rule_lists:
        for rule in rules if isinstance(rules, list) else []:
            parsed = parse_unit(rule.get("unit")) if isinstance(rule, dict) else None
            if parsed:
                want.setdefault(parsed[0], set()).add(parsed[1])
    return {ch: sorted(ids)[:MAX_IDS_PER_CHANNEL] for ch, ids in sorted(want.items())}


def unit_name(channel, event_id):
    """The unit of one channel and event id: `eventlog.Security.4625`."""
    return "%s%s.%d" % (UNIT_PREFIX, channel, event_id)


def fleet_unit_rules(own_rules, fleet_rules):
    """The one-field rules `{"unit": ...}` to add to a Windows host's `log_watch` for the fleet-wide rules on an event.

    A unit the host's own rules already name is left out, so the list does not name one twice. Valid, sorted and capped for each channel like `watch_for`. Nothing but the
    unit is handed over: the pattern, threshold and message of a fleet-wide rule are applied on the server, and the agent has no use for them.
    """
    own = (
        {r.get("unit") for r in own_rules if isinstance(r, dict)}
        if isinstance(own_rules, list)
        else set()
    )
    return [
        {"unit": unit_name(ch, i)}
        for ch, ids in watch_for(fleet_rules).items()
        for i in ids
        if unit_name(ch, i) not in own
    ]
