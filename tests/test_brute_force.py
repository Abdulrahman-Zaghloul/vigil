from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path

import pytest

from vigil.alerts import Severity
from vigil.detection.brute_force import BruteForceDetector, detect_brute_force
from vigil.events import AuthEvent, AuthOutcome
from vigil.parsers.ssh import parse_lines

START = datetime(2026, 11, 17, 3, 0, tzinfo=UTC)
ATTACKER = "203.0.113.45"
SAMPLE_LOG = Path(__file__).parent / "data" / "sample_auth.log"


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


def failures(*seconds: float, ip: str = ATTACKER) -> list[AuthEvent]:
    return [attempt(s, ip=ip) for s in seconds]


def test_four_failures_in_a_minute_is_not_an_attack() -> None:
    assert detect_brute_force(failures(0, 10, 20, 30)) == []


def test_five_failures_in_a_minute_raises_one_alert() -> None:
    events = failures(0, 10, 20, 30, 40)

    [alert] = detect_brute_force(events)

    assert alert.rule_id == "ssh-brute-force"
    assert alert.technique == "T1110.001"
    assert alert.severity is Severity.MEDIUM
    assert alert.source_ip == ip_address(ATTACKER)
    assert alert.first_seen == events[0].timestamp
    assert alert.last_seen == events[-1].timestamp
    assert alert.evidence == tuple(events)
    assert alert.event_count == 5


def test_the_window_includes_its_edge() -> None:
    assert len(detect_brute_force(failures(0, 15, 30, 45, 60))) == 1


def test_failures_spread_beyond_the_window_do_not_add_up() -> None:
    # Five failures, but never five inside any 60-second stretch.
    assert detect_brute_force(failures(0, 20, 40, 61, 82)) == []


def test_successful_logins_do_not_count_as_failures() -> None:
    events = [*failures(0, 10, 20, 30), attempt(35, outcome=AuthOutcome.SUCCESS)]
    assert detect_brute_force(events) == []


def test_each_source_address_is_counted_separately() -> None:
    events = failures(0, 5, 10) + failures(1, 6, 11, ip="198.51.100.9")
    assert detect_brute_force(events) == []


def test_a_long_attack_raises_one_alert_not_dozens() -> None:
    hammering = failures(*range(0, 120, 2))  # 60 failures in two minutes
    assert len(detect_brute_force(hammering)) == 1


def test_a_new_attack_after_the_cooldown_raises_a_new_alert() -> None:
    first = failures(0, 1, 2, 3, 4)
    second = failures(*(s + 16 * 60 for s in range(5)))  # 16 minutes later
    assert len(detect_brute_force(first + second, cooldown=timedelta(minutes=15))) == 2


def test_out_of_order_input_is_sorted_by_time() -> None:
    assert len(detect_brute_force(failures(40, 0, 30, 10, 20))) == 1


def test_thresholds_can_be_tuned() -> None:
    events = failures(0, 100, 200)
    assert len(detect_brute_force(events, threshold=3, window=timedelta(minutes=5))) == 1


@pytest.mark.parametrize(
    "settings",
    [
        {"threshold": 1},
        {"window": timedelta(0)},
        {"cooldown": timedelta(seconds=-1)},
    ],
    ids=["threshold-too-low", "empty-window", "negative-cooldown"],
)
def test_nonsense_settings_are_rejected(settings: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="must"):
        BruteForceDetector(**settings)  # type: ignore[arg-type]


def test_memory_stays_bounded_when_attackers_rotate_addresses() -> None:
    detector = BruteForceDetector()
    for i in range(5_000):  # one failure each from 5,000 different addresses, 1s apart
        detector.process(attempt(i, ip=f"10.0.{i // 256}.{i % 256}"))
    assert detector.tracked_sources <= 1_000


def test_end_to_end_from_a_real_log_file() -> None:
    lines = SAMPLE_LOG.read_text(encoding="utf-8").splitlines()
    events = list(parse_lines(lines, now=START))

    assert detect_brute_force(events) == []  # 3 failures: below the default of 5
    [alert] = detect_brute_force(events, threshold=3)
    assert alert.source_ip == ip_address(ATTACKER)
    assert [e.username for e in alert.evidence] == ["admin", "root", "root"]
