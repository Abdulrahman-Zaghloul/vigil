"""Save and read events and alerts in PostgreSQL."""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from itertools import batched
from typing import Any

from sqlalchemy import Connection, Engine, Row, create_engine, func, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError

from vigil.alerts import Alert, Severity
from vigil.events import AuthEvent
from vigil.keys import Scope, generate_key, hash_secret, parse_key
from vigil.storage.schema import alert_evidence, alerts, api_keys, events

BATCH_SIZE = 1_000  # rows per INSERT: big enough to be fast, small enough to be safe
MAX_PAGE_SIZE = 1_000
KEY_NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_LAST_USED_RESOLUTION = timedelta(minutes=1)  # don't write to the database on every request


@dataclass(frozen=True, slots=True)
class SaveResult:
    events_added: int
    alerts_added: int


@dataclass(frozen=True, slots=True)
class StoredAlert:
    id: int
    rule_id: str
    severity: Severity
    technique: str
    title: str
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    created_at: datetime


@dataclass(frozen=True, slots=True)
class ApiKeyInfo:
    """Everything about a key except its secret, which Vigil never has."""

    id: int
    key_id: str
    name: str
    scopes: frozenset[Scope]
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None


def event_fingerprint(event: AuthEvent) -> str:
    """Identify an event by its original log line (which includes host and timestamp)."""
    return hashlib.sha256(event.raw.encode("utf-8", "surrogatepass")).hexdigest()


def alert_fingerprint(alert: Alert) -> str:
    """Rules are deterministic, so a re-scan reproduces the same rule, source and start."""
    key = f"{alert.rule_id}|{alert.source_ip}|{alert.first_seen.isoformat()}"
    return hashlib.sha256(key.encode()).hexdigest()


def _text(value: str) -> str:
    """PostgreSQL text cannot contain NUL; replace it rather than let a log line crash us."""
    return value.replace("\x00", "�")


def _event_row(event: AuthEvent) -> dict[str, object]:
    return {
        "fingerprint": event_fingerprint(event),
        "occurred_at": event.timestamp,
        "host": _text(event.host),
        "outcome": event.outcome.value,
        "username": _text(event.username),
        "source_ip": str(event.source_ip),
        "source_port": event.source_port,
        "method": _text(event.method),
        "user_exists": event.user_exists,
        "raw": _text(event.raw),
    }


class Store:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    @classmethod
    def connect(cls, url: str) -> Store:
        # pool_pre_ping quietly replaces connections the database has dropped.
        # timezone=UTC: PostgreSQL stores instants correctly but *displays* them in each
        # connection's zone, which depends on server settings. Vigil always speaks UTC.
        return cls(
            create_engine(url, pool_pre_ping=True, connect_args={"options": "-c timezone=UTC"})
        )

    def close(self) -> None:
        self.engine.dispose()

    def save(self, new_events: Iterable[AuthEvent], new_alerts: Iterable[Alert]) -> SaveResult:
        """Store a scan's events and alerts in ONE transaction: all of it, or none of it.

        Saving the same scan again adds nothing, because rows are matched by fingerprint.
        """
        with self.engine.begin() as connection:
            events_added = self._insert_events(connection, new_events)
            alerts_added = 0
            for alert in new_alerts:
                if self._insert_alert(connection, alert):
                    alerts_added += 1
        return SaveResult(events_added=events_added, alerts_added=alerts_added)

    def _insert_events(self, connection: Connection, new_events: Iterable[AuthEvent]) -> int:
        added = 0
        for batch in batched(new_events, BATCH_SIZE):
            rows = {row["fingerprint"]: row for row in map(_event_row, batch)}  # de-duplicate
            statement = (
                insert(events)
                .values(list(rows.values()))
                .on_conflict_do_nothing(index_elements=["fingerprint"])
                .returning(events.c.id)
            )
            added += len(connection.execute(statement).all())
        return added

    def _insert_alert(self, connection: Connection, alert: Alert) -> bool:
        alert_id = connection.execute(
            insert(alerts)
            .values(
                fingerprint=alert_fingerprint(alert),
                rule_id=alert.rule_id,
                severity=alert.severity.value,
                technique=alert.technique,
                title=_text(alert.title),
                source_ip=str(alert.source_ip),
                first_seen=alert.first_seen,
                last_seen=alert.last_seen,
                event_count=alert.event_count,
            )
            .on_conflict_do_nothing(index_elements=["fingerprint"])
            .returning(alerts.c.id)
        ).scalar_one_or_none()
        if alert_id is None:
            return False  # an earlier scan already stored this alert

        self._insert_events(connection, alert.evidence)  # make sure its evidence exists
        fingerprints = {event_fingerprint(e) for e in alert.evidence}
        event_ids = connection.execute(
            select(events.c.id).where(events.c.fingerprint.in_(fingerprints))
        ).scalars()
        connection.execute(
            insert(alert_evidence),
            [{"alert_id": alert_id, "event_id": event_id} for event_id in event_ids],
        )
        return True

    def counts(self) -> tuple[int, int]:
        """(number of events, number of alerts)."""
        with self.engine.connect() as connection:
            event_total = connection.execute(select(func.count()).select_from(events))
            alert_total = connection.execute(select(func.count()).select_from(alerts))
            return event_total.scalar_one(), alert_total.scalar_one()

    def recent_alerts(
        self, *, limit: int = 50, min_severity: Severity = Severity.LOW
    ) -> list[StoredAlert]:
        """Alerts at or above `min_severity`, newest first."""
        if not 1 <= limit <= MAX_PAGE_SIZE:
            raise ValueError(f"limit must be between 1 and {MAX_PAGE_SIZE}")
        allowed = [s.value for s in Severity if s.rank >= min_severity.rank]
        query = (
            select(alerts)
            .where(alerts.c.severity.in_(allowed))
            .order_by(alerts.c.first_seen.desc(), alerts.c.id.desc())
            .limit(limit)
        )
        with self.engine.connect() as connection:
            return [_stored_alert(row) for row in connection.execute(query)]

    def get_alert(self, alert_id: int) -> StoredAlert | None:
        with self.engine.connect() as connection:
            row = connection.execute(select(alerts).where(alerts.c.id == alert_id)).first()
        return None if row is None else _stored_alert(row)

    # --- API keys ------------------------------------------------------------------------

    def create_api_key(self, name: str, scopes: Iterable[Scope]) -> str:
        """Create a key and return it. This is the only time the full key exists."""
        if not KEY_NAME_PATTERN.fullmatch(name):
            raise ValueError(
                "key name must be 1-64 characters: lowercase letters, digits, '.', '_' or '-'"
            )
        chosen = sorted({Scope(scope) for scope in scopes})
        if not chosen:
            raise ValueError("a key needs at least one scope")
        key = generate_key()
        try:
            with self.engine.begin() as connection:
                connection.execute(
                    insert(api_keys).values(
                        key_id=key.key_id,
                        name=name,
                        secret_hash=hash_secret(key.secret),
                        scopes=[scope.value for scope in chosen],
                    )
                )
        except IntegrityError as error:
            raise ValueError(f"an active key named {name!r} already exists") from error
        return key.token

    def authenticate(self, token: str) -> ApiKeyInfo | None:
        """The key behind `token`, or None if it is malformed, unknown, wrong or revoked."""
        parsed = parse_key(token)
        if parsed is None:
            return None
        key_id, secret = parsed
        with self.engine.begin() as connection:
            row = connection.execute(
                select(api_keys).where(api_keys.c.key_id == key_id, api_keys.c.revoked_at.is_(None))
            ).first()
            if row is None or not hmac.compare_digest(row.secret_hash, hash_secret(secret)):
                return None
            connection.execute(
                update(api_keys)
                .where(
                    api_keys.c.id == row.id,
                    or_(
                        api_keys.c.last_used_at.is_(None),
                        api_keys.c.last_used_at < func.now() - _LAST_USED_RESOLUTION,
                    ),
                )
                .values(last_used_at=func.now())
            )
        return _api_key_info(row)

    def api_keys(self) -> list[ApiKeyInfo]:
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(api_keys).order_by(api_keys.c.created_at, api_keys.c.id)
            )
            return [_api_key_info(row) for row in rows]

    def revoke_api_key(self, name: str) -> bool:
        """Revoke the active key with this name. False if there is none."""
        with self.engine.begin() as connection:
            revoked = connection.execute(
                update(api_keys)
                .where(api_keys.c.name == name, api_keys.c.revoked_at.is_(None))
                .values(revoked_at=func.now())
                .returning(api_keys.c.id)
            ).first()
        return revoked is not None

    def ping(self) -> None:
        """Raise if the database cannot answer a trivial query."""
        with self.engine.connect() as connection:
            connection.execute(text("SELECT 1"))

    def evidence(self, alert_id: int) -> list[str]:
        """The original log lines behind an alert, oldest first."""
        query = (
            select(events.c.raw)
            .join(alert_evidence, alert_evidence.c.event_id == events.c.id)
            .where(alert_evidence.c.alert_id == alert_id)
            .order_by(events.c.occurred_at, events.c.id)
        )
        with self.engine.connect() as connection:
            return list(connection.execute(query).scalars())


def _stored_alert(row: Row[Any]) -> StoredAlert:
    return StoredAlert(
        id=row.id,
        rule_id=row.rule_id,
        severity=Severity(row.severity),
        technique=row.technique,
        title=row.title,
        source_ip=str(row.source_ip),
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        event_count=row.event_count,
        created_at=row.created_at,
    )


def _api_key_info(row: Row[Any]) -> ApiKeyInfo:
    return ApiKeyInfo(
        id=row.id,
        key_id=row.key_id,
        name=row.name,
        scopes=frozenset(Scope(scope) for scope in row.scopes),
        created_at=row.created_at,
        last_used_at=row.last_used_at,
        revoked_at=row.revoked_at,
    )
