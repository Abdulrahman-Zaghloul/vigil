from pathlib import Path

import pytest
from factories import START, attempt

from vigil.alerts import Alert, Severity
from vigil.attack import TECHNIQUES, technique
from vigil.detection.brute_force import BruteForceDetector
from vigil.detection.engine import DetectionEngine, default_rules
from vigil.events import AuthEvent, AuthOutcome
from vigil.parsers.ssh import parse_lines

DATA = Path(__file__).parent / "data"


def scan(log_name: str) -> list[Alert]:
    lines = (DATA / log_name).read_text(encoding="utf-8").splitlines()
    return DetectionEngine(default_rules()).run(parse_lines(lines, now=START))


def test_each_attack_in_the_scenario_raises_exactly_one_alert() -> None:
    alerts = scan("attack_scenario.log")

    assert [(a.rule_id, str(a.source_ip), a.severity) for a in alerts] == [
        ("ssh-password-spray", "203.0.113.77", Severity.MEDIUM),
        ("ssh-brute-force", "198.51.100.23", Severity.MEDIUM),
        ("ssh-success-after-failures", "198.51.100.23", Severity.CRITICAL),
    ]


def test_ordinary_activity_raises_nothing() -> None:
    assert scan("sample_auth.log") == []


def test_one_event_can_trigger_several_rules() -> None:
    burst = [attempt(i, user=f"user{i}") for i in range(10)]  # fast AND across many accounts

    alerts = DetectionEngine(default_rules()).run(burst)

    assert sorted(a.rule_id for a in alerts) == ["ssh-brute-force", "ssh-password-spray"]


def test_rule_ids_must_be_unique() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        DetectionEngine([BruteForceDetector(), BruteForceDetector()])


def test_any_object_with_the_rule_shape_plugs_in() -> None:
    class RootLogin:
        """A custom rule written outside Vigil: any successful root login."""

        rule_id = "ssh-root-login"
        technique = "T1078"

        def process(self, event: AuthEvent) -> Alert | None:
            if event.outcome is not AuthOutcome.SUCCESS or event.username != "root":
                return None
            return Alert(
                rule_id=self.rule_id,
                title=f"root logged in from {event.source_ip}",
                severity=Severity.LOW,
                technique=self.technique,
                source_ip=event.source_ip,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                evidence=(event,),
            )

    engine = DetectionEngine([*default_rules(), RootLogin()])
    alerts = engine.run([attempt(0, outcome=AuthOutcome.SUCCESS, user="root")])

    assert [a.rule_id for a in alerts] == ["ssh-root-login"]


def test_every_default_rule_maps_to_a_known_attack_technique() -> None:
    assert all(rule.technique in TECHNIQUES for rule in default_rules())


def test_the_engine_reports_which_techniques_it_covers() -> None:
    assert DetectionEngine(default_rules()).techniques == ("T1110", "T1110.001", "T1110.003")


def test_techniques_link_to_the_attack_website() -> None:
    spraying = technique("T1110.003")
    assert spraying.name == "Brute Force: Password Spraying"
    assert spraying.tactic == "Credential Access"
    assert spraying.url == "https://attack.mitre.org/techniques/T1110/003/"
    assert technique("T1110").url == "https://attack.mitre.org/techniques/T1110/"
