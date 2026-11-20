from collections.abc import Iterable
from datetime import timedelta
from ipaddress import ip_address

import pytest
from factories import ATTACKER, attempt, failures

from vigil.alerts import Alert, Severity
from vigil.detection.compromise import SuccessAfterFailuresDetector
from vigil.detection.engine import Rule
from vigil.detection.password_spray import PasswordSprayDetector
from vigil.events import AuthEvent, AuthOutcome

ACCOUNTS = [
    "admin", "oracle", "postgres", "ubuntu", "test", "guest",
    "deploy", "git", "jenkins", "minecraft", "backup", "support",
]  # fmt: skip


def run(rule: Rule, events: Iterable[AuthEvent]) -> list[Alert]:
    alerts = (rule.process(e) for e in sorted(events, key=lambda e: e.timestamp))
    return [a for a in alerts if a is not None]


def spray(accounts: int, *, gap: float = 20, ip: str = ATTACKER) -> list[AuthEvent]:
    """One failed guess per account, `gap` seconds apart, all from one address."""
    return [attempt(i * gap, ip=ip, user=ACCOUNTS[i]) for i in range(accounts)]


def login(seconds: float, *, user: str = "alice", ip: str = ATTACKER) -> AuthEvent:
    return attempt(seconds, ip=ip, outcome=AuthOutcome.SUCCESS, user=user)


class TestPasswordSpraying:
    def test_ten_accounts_from_one_address_is_spraying(self) -> None:
        events = spray(10)

        [alert] = run(PasswordSprayDetector(), events)

        assert alert.rule_id == "ssh-password-spray"
        assert alert.technique == "T1110.003"
        assert alert.severity is Severity.MEDIUM
        assert alert.source_ip == ip_address(ATTACKER)
        assert alert.evidence == tuple(events)
        assert "10 different accounts" in alert.title

    def test_nine_accounts_is_below_the_threshold(self) -> None:
        assert run(PasswordSprayDetector(), spray(9)) == []

    def test_many_guesses_at_one_account_is_not_spraying(self) -> None:
        assert run(PasswordSprayDetector(), failures(*range(0, 200, 10))) == []

    def test_accounts_spread_beyond_the_window_do_not_add_up(self) -> None:
        assert run(PasswordSprayDetector(), spray(10, gap=70)) == []  # 10 accounts in 10.5 min

    def test_an_ongoing_spray_raises_one_alert(self) -> None:
        assert len(run(PasswordSprayDetector(), spray(12))) == 1

    def test_nonsense_settings_are_rejected(self) -> None:
        with pytest.raises(ValueError, match="must"):
            PasswordSprayDetector(distinct_accounts=1)


class TestSuccessAfterFailures:
    def test_a_login_after_repeated_failures_is_a_possible_compromise(self) -> None:
        events = [*failures(0, 5, 10, 15, 20), login(30)]

        [alert] = run(SuccessAfterFailuresDetector(), events)

        assert alert.rule_id == "ssh-success-after-failures"
        assert alert.technique == "T1110"
        assert alert.severity is Severity.HIGH
        assert alert.evidence == tuple(events)
        assert "alice" in alert.title

    def test_a_root_login_after_failures_is_critical(self) -> None:
        [alert] = run(
            SuccessAfterFailuresDetector(), [*failures(0, 5, 10, 15, 20), login(30, user="root")]
        )
        assert alert.severity is Severity.CRITICAL

    def test_a_couple_of_typos_before_logging_in_is_normal(self) -> None:
        assert run(SuccessAfterFailuresDetector(), [*failures(0, 5), login(10)]) == []

    def test_old_failures_do_not_count(self) -> None:
        events = [*failures(0, 5, 10, 15, 20), login(20 * 60)]  # 20 minutes later
        assert run(SuccessAfterFailuresDetector(window=timedelta(minutes=15)), events) == []

    def test_a_login_from_a_different_address_is_not_linked(self) -> None:
        events = [*failures(0, 5, 10, 15, 20), login(30, ip="198.51.100.9")]
        assert run(SuccessAfterFailuresDetector(), events) == []

    def test_one_compromise_raises_one_alert(self) -> None:
        events = [*failures(0, 5, 10, 15, 20), login(30), login(31)]
        assert len(run(SuccessAfterFailuresDetector(), events)) == 1

    @pytest.mark.parametrize(
        "settings",
        [{"min_failures": 0}, {"window": timedelta(0)}],
        ids=["no-failures", "empty-window"],
    )
    def test_nonsense_settings_are_rejected(self, settings: dict[str, object]) -> None:
        with pytest.raises(ValueError, match="must"):
            SuccessAfterFailuresDetector(**settings)  # type: ignore[arg-type]
