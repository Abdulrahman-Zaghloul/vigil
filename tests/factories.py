"""Builders for test data, shared by every test module."""

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address

from vigil.events import AuthEvent, AuthOutcome

START = datetime(2026, 11, 17, 3, 0, tzinfo=UTC)
ATTACKER = "203.0.113.45"


def attempt(
    seconds: float,
    ip: str = ATTACKER,
    outcome: AuthOutcome = AuthOutcome.FAILURE,
    user: str = "root",
) -> AuthEvent:
    """A login attempt `seconds` after START."""
    return AuthEvent(
        timestamp=START + timedelta(seconds=seconds),
        host="web-01",
        outcome=outcome,
        username=user,
        source_ip=ip_address(ip),
        source_port=50_000,
        method="password",
        user_exists=True,
        raw=f"synthetic attempt at +{seconds}s from {ip}",
    )


def failures(*seconds: float, ip: str = ATTACKER, user: str = "root") -> list[AuthEvent]:
    return [attempt(s, ip=ip, user=user) for s in seconds]
