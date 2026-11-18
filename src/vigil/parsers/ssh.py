"""Parse OpenSSH login attempts from syslog-style authentication logs.

Two timestamp styles are common in the wild:

* RFC 3339, the default on current Debian and Ubuntu::

    2026-11-17T03:14:07.402318+00:00 web-01 sshd[2211]: Failed password for root from ...

* Classic BSD syslog, which records neither the year nor the time zone::

    Nov 17 03:14:07 web-01 sshd[2211]: Failed password for root from ...

Only "Failed ..." and "Accepted ..." lines become events. Related lines such as
"Invalid user ..." describe the same attempt, so counting them too would double-count.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime, timedelta, tzinfo
from ipaddress import ip_address

from vigil.events import AuthEvent, AuthOutcome

# OpenSSH 9.8+ logs per-connection messages from a separate "sshd-session" process.
SSH_PROGRAMS = frozenset({"sshd", "sshd-session"})

_HEADER_TAIL = r" (?P<host>\S+) (?P<program>[\w.-]+)(?:\[\d+\])?: (?P<message>.*)$"
_RFC3339_HEADER = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))"
    + _HEADER_TAIL
)
_BSD_HEADER = re.compile(
    r"^(?P<month>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2})" + _HEADER_TAIL
)

# The username is typed by whoever connects, so it can contain anything, including
# text like " from 10.0.0.1 port 22". The username is therefore matched greedily and
# the fields sshd writes itself (address, port) are anchored to the END of the line,
# so a crafted username can never spoof the source address.
_AUTH_MESSAGE = re.compile(
    r"^(?P<outcome>Failed|Accepted) (?P<method>[\w/-]+) for (?P<invalid>invalid user )?"
    r"(?P<username>.*) from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2(?:: .*)?)?$"
)

# Month names are matched by hand: strptime's %b depends on the machine's language.
_MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}
_CLOCK_SKEW_ALLOWANCE = timedelta(days=1)


def _bsd_timestamp(month: str, day: str, clock: str, *, now: datetime) -> datetime | None:
    """Rebuild a full timestamp for a year-less syslog date.

    Picks the most recent year that does not put the entry in the future, which handles
    December entries read in January and 29 February in non-leap years.
    """
    month_number = _MONTHS.get(month)
    if month_number is None:
        return None
    hour, minute, second = (int(part) for part in clock.split(":"))
    for year in range(now.year, now.year - 5, -1):  # a leap year is never more than 4 back
        try:
            candidate = datetime(
                year, month_number, int(day), hour, minute, second, tzinfo=now.tzinfo
            )
        except ValueError:  # an impossible date, such as 29 February in a non-leap year
            continue
        if candidate - now <= _CLOCK_SKEW_ALLOWANCE:
            return candidate
    return None


def parse_line(
    line: str, *, now: datetime | None = None, assume_tz: tzinfo = UTC
) -> AuthEvent | None:
    """Return an AuthEvent for an SSH login attempt, or None for any other line.

    Never raises on bad input: real logs are full of unrelated and malformed lines.

    ``now`` and ``assume_tz`` only matter for BSD timestamps, which lack a year and a
    time zone. Pass ``now`` explicitly in tests so results never depend on the clock.
    """
    line = line.rstrip("\r\n")
    header = _RFC3339_HEADER.match(line)
    if header is not None:
        try:
            timestamp: datetime | None = datetime.fromisoformat(header["timestamp"])
        except ValueError:
            return None
    else:
        header = _BSD_HEADER.match(line)
        if header is None:
            return None
        reference = now.astimezone(assume_tz) if now else datetime.now(assume_tz)
        timestamp = _bsd_timestamp(header["month"], header["day"], header["time"], now=reference)
    if timestamp is None or header["program"] not in SSH_PROGRAMS:
        return None

    message = _AUTH_MESSAGE.match(header["message"])
    if message is None:
        return None
    try:
        source_ip = ip_address(message["ip"])
    except ValueError:
        return None
    port = int(message["port"])
    if not 0 < port <= 65_535:
        return None

    return AuthEvent(
        timestamp=timestamp.astimezone(UTC),
        host=header["host"],
        outcome=AuthOutcome.SUCCESS if message["outcome"] == "Accepted" else AuthOutcome.FAILURE,
        username=message["username"],
        source_ip=source_ip,
        source_port=port,
        method=message["method"],
        user_exists=message["invalid"] is None,
        raw=line,
    )


def parse_lines(
    lines: Iterable[str], *, now: datetime | None = None, assume_tz: tzinfo = UTC
) -> Iterator[AuthEvent]:
    """Yield an AuthEvent for every SSH login attempt in ``lines``, skipping the rest."""
    reference = now or datetime.now(assume_tz)
    for line in lines:
        event = parse_line(line, now=reference, assume_tz=assume_tz)
        if event is not None:
            yield event
