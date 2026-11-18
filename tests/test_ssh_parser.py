from datetime import UTC, datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path

import pytest

from vigil.events import AuthOutcome
from vigil.parsers.ssh import parse_line, parse_lines

SAMPLE_LOG = Path(__file__).parent / "data" / "sample_auth.log"
NOW = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)  # a fixed clock keeps tests repeatable


def test_failed_password_for_an_existing_user() -> None:
    event = parse_line(
        "2026-11-17T03:14:09.771029+00:00 web-01 sshd[2213]: "
        "Failed password for root from 203.0.113.45 port 52154 ssh2"
    )
    assert event is not None
    assert event.timestamp == datetime(2026, 11, 17, 3, 14, 9, 771029, tzinfo=UTC)
    assert event.host == "web-01"
    assert event.outcome is AuthOutcome.FAILURE
    assert event.username == "root"
    assert event.source_ip == ip_address("203.0.113.45")
    assert event.source_port == 52154
    assert event.method == "password"
    assert event.user_exists is True


def test_invalid_user_is_recorded_as_a_user_that_does_not_exist() -> None:
    event = parse_line(
        "2026-11-17T03:14:07+00:00 web-01 sshd[2211]: "
        "Failed password for invalid user admin from 203.0.113.45 port 52150 ssh2"
    )
    assert event is not None
    assert event.username == "admin"
    assert event.user_exists is False


def test_accepted_public_key_from_the_newer_sshd_session_process() -> None:
    event = parse_line(
        "2026-11-17T03:15:22+00:00 web-01 sshd-session[2301]: Accepted publickey for deploy "
        "from 198.51.100.8 port 50122 ssh2: ED25519 SHA256:3q2v7w9Zl1nYbLk0fJcV8aTzR4mHxQeU5s"
    )
    assert event is not None
    assert event.outcome is AuthOutcome.SUCCESS
    assert event.method == "publickey"


def test_ipv6_source_addresses_are_understood() -> None:
    event = parse_line(
        "2026-11-17T03:15:40+00:00 web-01 sshd[2310]: "
        "Accepted password for alice from 2001:db8::7 port 61022 ssh2"
    )
    assert event is not None
    assert event.source_ip == ip_address("2001:db8::7")


def test_timestamps_are_normalized_to_utc() -> None:
    event = parse_line(
        "2026-11-16T22:14:09-05:00 web-01 sshd[2213]: "
        "Failed password for root from 203.0.113.45 port 52154 ssh2"
    )
    assert event is not None
    assert event.timestamp == datetime(2026, 11, 17, 3, 14, 9, tzinfo=UTC)


def test_a_crafted_username_cannot_spoof_the_source_address() -> None:
    # An attacker picks the username, and tries to make it look like the line ends early.
    event = parse_line(
        "2026-11-17T03:14:09+00:00 web-01 sshd[2213]: Failed password for invalid user "
        "x from 10.0.0.1 port 22 from 203.0.113.45 port 52154 ssh2"
    )
    assert event is not None
    assert event.source_ip == ip_address("203.0.113.45")  # the real attacker, not 10.0.0.1
    assert event.username == "x from 10.0.0.1 port 22"


def test_an_empty_username_is_still_an_attempt() -> None:
    event = parse_line(
        "2026-11-17T03:14:09+00:00 web-01 sshd[2213]: "
        "Failed password for invalid user  from 203.0.113.45 port 52154 ssh2"
    )
    assert event is not None
    assert event.username == ""


class TestClassicSyslogTimestamps:
    def test_year_comes_from_the_reference_clock(self) -> None:
        event = parse_line(
            "Nov  7 03:14:09 web-01 sshd[2213]: "
            "Failed password for root from 203.0.113.45 port 52154 ssh2",
            now=NOW,
        )
        assert event is not None
        assert event.timestamp == datetime(2026, 11, 7, 3, 14, 9, tzinfo=UTC)

    def test_december_entries_read_in_january_belong_to_last_year(self) -> None:
        event = parse_line(
            "Dec 31 23:59:58 web-01 sshd[2213]: "
            "Failed password for root from 203.0.113.45 port 52154 ssh2",
            now=datetime(2027, 1, 1, 0, 5, tzinfo=UTC),
        )
        assert event is not None
        assert event.timestamp.year == 2026

    def test_29_february_resolves_to_the_most_recent_leap_year(self) -> None:
        event = parse_line(
            "Feb 29 10:00:00 web-01 sshd[2213]: "
            "Failed password for root from 203.0.113.45 port 52154 ssh2",
            now=datetime(2029, 3, 10, tzinfo=UTC),
        )
        assert event is not None
        assert event.timestamp.date().isoformat() == "2028-02-29"

    def test_the_servers_time_zone_can_be_supplied(self) -> None:
        eastern = timezone(timedelta(hours=-5))
        event = parse_line(
            "Nov 17 03:14:09 web-01 sshd[2213]: "
            "Failed password for root from 203.0.113.45 port 52154 ssh2",
            now=NOW,
            assume_tz=eastern,
        )
        assert event is not None
        assert event.timestamp == datetime(2026, 11, 17, 8, 14, 9, tzinfo=UTC)


@pytest.mark.parametrize(
    "line",
    [
        "",
        "this line is corrupted and matches nothing",
        "2026-11-17T03:14:01+00:00 web-01 CRON[2190]: session opened for user root",
        "2026-11-17T03:14:07+00:00 web-01 sshd[2211]: Invalid user admin from 203.0.113.45",
        "2026-11-17T03:14:09+00:00 web-01 sshd[2213]: "
        "Failed password for root from not-an-ip port 52154 ssh2",
        "2026-11-17T03:14:09+00:00 web-01 sshd[2213]: "
        "Failed password for root from 203.0.113.45 port 99999 ssh2",
        "2026-11-17T03:14:09+00:00 web-01 nginx[80]: "
        "Failed password for root from 203.0.113.45 port 52154 ssh2",
        "2026-13-45T03:14:09+00:00 web-01 sshd[2213]: "
        "Failed password for root from 203.0.113.45 port 52154 ssh2",
        "Foo 17 03:14:09 web-01 sshd[2213]: "
        "Failed password for root from 203.0.113.45 port 52154 ssh2",
    ],
    ids=[
        "empty",
        "garbage",
        "other-program",
        "invalid-user-notice",
        "bad-ip",
        "bad-port",
        "wrong-program",
        "impossible-date",
        "unknown-month",
    ],
)
def test_lines_that_are_not_login_attempts_are_skipped(line: str) -> None:
    assert parse_line(line, now=NOW) is None


def test_a_real_log_yields_only_the_login_attempts() -> None:
    lines = SAMPLE_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
    events = list(parse_lines(lines, now=NOW))

    assert len(lines) == 10
    assert [(e.outcome, e.username) for e in events] == [
        (AuthOutcome.FAILURE, "admin"),
        (AuthOutcome.FAILURE, "root"),
        (AuthOutcome.FAILURE, "root"),
        (AuthOutcome.SUCCESS, "deploy"),
        (AuthOutcome.SUCCESS, "alice"),
    ]
    assert all(e.raw in lines for e in events)
