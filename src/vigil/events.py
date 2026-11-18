"""Normalized security events: the common language every log parser translates into.

Detection rules only ever see these objects, never raw log text, so a new log format
needs a new parser but no changes to any rule.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address

type IPAddress = IPv4Address | IPv6Address


class AuthOutcome(StrEnum):
    FAILURE = "failure"
    SUCCESS = "success"


@dataclass(frozen=True, slots=True)
class AuthEvent:
    """One authentication attempt, whatever log format it came from."""

    timestamp: datetime  # always timezone-aware, normalized to UTC
    host: str
    outcome: AuthOutcome
    username: str  # chosen by the connecting party: untrusted
    source_ip: IPAddress
    source_port: int
    method: str  # e.g. "password", "publickey"
    user_exists: bool  # False when the server logged "invalid user"
    raw: str  # the original log line, kept as evidence
