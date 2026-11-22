import dataclasses
from datetime import timedelta
from pathlib import Path

import pytest

pytest.importorskip("sqlalchemy", reason="install the db extra: pip install -e '.[db]'")

from factories import START, attempt
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from vigil.alerts import Alert, Severity
from vigil.detection.engine import DetectionEngine, default_rules
from vigil.events import AuthEvent
from vigil.parsers.ssh import parse_lines
from vigil.storage.migrate import check
from vigil.storage.store import SaveResult, Store

DATA = Path(__file__).parent / "data"


def scan(log_name: str) -> tuple[list[AuthEvent], list[Alert]]:
    lines = (DATA / log_name).read_text(encoding="utf-8").splitlines()
    events = list(parse_lines(lines, now=START))
    return events, DetectionEngine(default_rules()).run(events)


def test_a_scan_is_saved_with_its_alerts(store: Store) -> None:
    events, alerts = scan("attack_scenario.log")

    assert store.save(events, alerts) == SaveResult(events_added=19, alerts_added=3)
    assert store.counts() == (19, 3)


def test_saving_the_same_scan_twice_adds_nothing(store: Store) -> None:
    store.save(*scan("attack_scenario.log"))

    assert store.save(*scan("attack_scenario.log")) == SaveResult(events_added=0, alerts_added=0)
    assert store.counts() == (19, 3)


def test_alerts_keep_links_to_their_evidence(store: Store) -> None:
    store.save(*scan("attack_scenario.log"))

    [compromise] = store.recent_alerts(min_severity=Severity.CRITICAL)
    evidence = store.evidence(compromise.id)

    assert compromise.rule_id == "ssh-success-after-failures"
    assert compromise.event_count == 7
    assert len(evidence) == 7
    assert "Accepted password for root" in evidence[-1]


def test_recent_alerts_are_listed_newest_first(store: Store) -> None:
    store.save(*scan("attack_scenario.log"))

    assert [a.rule_id for a in store.recent_alerts()] == [
        "ssh-success-after-failures",
        "ssh-brute-force",
        "ssh-password-spray",
    ]
    assert len(store.recent_alerts(limit=1)) == 1


@pytest.mark.parametrize("limit", [0, 1_001])
def test_unreasonable_page_sizes_are_refused(store: Store, limit: int) -> None:
    with pytest.raises(ValueError, match="limit"):
        store.recent_alerts(limit=limit)


def test_addresses_are_stored_as_real_network_addresses(store: Store) -> None:
    store.save(*scan("attack_scenario.log"))

    with store.engine.connect() as connection:
        sprayed = connection.execute(
            text("SELECT count(*) FROM events WHERE source_ip << '203.0.113.0/24'")
        ).scalar_one()

    assert sprayed == 10  # PostgreSQL's INET type understands whole networks


def test_the_database_itself_refuses_impossible_values(store: Store) -> None:
    with pytest.raises(IntegrityError, match="outcome_valid"), store.engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO events (fingerprint, occurred_at, host, outcome, username,"
                " source_ip, source_port, method, user_exists, raw) VALUES"
                " ('x', now(), 'web-01', 'maybe', 'root', '192.0.2.1', 22, 'password', true, 'x')"
            )
        )


def test_null_characters_from_hostile_logs_cannot_break_saving(store: Store) -> None:
    # PostgreSQL text cannot hold the NUL character; an attacker should not be able to
    # crash ingestion by smuggling one into a username.
    hostile = dataclasses.replace(attempt(0, user="ev\x00il"), raw="line with a \x00 inside")

    assert store.save([hostile], []) == SaveResult(events_added=1, alerts_added=0)
    with store.engine.connect() as connection:
        username = connection.execute(text("SELECT username FROM events")).scalar_one()
    assert username == "ev�il"


def test_the_migrations_match_the_schema_in_code(database_url: str) -> None:
    check(database_url)  # raises if a table definition changed without a migration


def test_timestamps_come_back_in_utc_whatever_the_servers_time_zone(store: Store) -> None:
    store.save(*scan("attack_scenario.log"))
    with store.engine.begin() as connection:  # a server configured for New York, say
        connection.execute(text("ALTER DATABASE vigil_test SET timezone = 'America/New_York'"))
    try:
        reconnected = Store.connect(str(store.engine.url.render_as_string(hide_password=False)))
        [alert] = reconnected.recent_alerts(min_severity=Severity.CRITICAL)
        reconnected.close()
    finally:
        with store.engine.begin() as connection:
            connection.execute(text("ALTER DATABASE vigil_test RESET timezone"))

    assert alert.first_seen.utcoffset() == timedelta(0)
    assert alert.first_seen.isoformat() == "2026-11-17T03:10:00+00:00"
