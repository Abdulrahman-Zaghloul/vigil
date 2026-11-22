"""The Vigil web API: log shippers send events in, analysts read alerts out.

Every data endpoint needs the API token. Part 10 replaces this single shared token with
per-client keys, signed requests and rate limits.
"""

from __future__ import annotations

import hmac
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.exc import SQLAlchemyError

from vigil import __version__
from vigil.alerts import Severity
from vigil.api.models import (
    MAX_LINE_LENGTH,
    MAX_LINES,
    AlertDetail,
    AlertOut,
    EventBatch,
    IngestResult,
)
from vigil.parsers.ssh import parse_lines
from vigil.storage.store import MAX_PAGE_SIZE, Store

__all__ = ["MAX_LINES", "MAX_LINE_LENGTH", "MIN_TOKEN_LENGTH", "create_app"]

MIN_TOKEN_LENGTH = 32
_bearer = HTTPBearer(auto_error=False)


def _token_checker(expected: str) -> Callable[[HTTPAuthorizationCredentials | None], None]:
    expected_bytes = expected.encode()

    def require_token(
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    ) -> None:
        # compare_digest takes the same time whether the first or the last character is
        # wrong, so response timing cannot be used to guess the token one character at
        # a time.
        if credentials is None or not hmac.compare_digest(
            credentials.credentials.encode(), expected_bytes
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="missing or invalid API token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    return require_token


def create_app(*, store: Store, api_token: str) -> FastAPI:
    """Build the API around a store. Refuses to start with a guessable token."""
    if len(api_token) < MIN_TOKEN_LENGTH:
        raise ValueError(f"the API token must be at least {MIN_TOKEN_LENGTH} characters long")

    app = FastAPI(
        title="Vigil",
        version=__version__,
        description="Threat detection for security logs: send events in, read alerts out.",
    )
    authenticated = [Depends(_token_checker(api_token))]

    @app.get("/health", tags=["operations"], summary="Is the process running?")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get(
        "/health/ready",
        tags=["operations"],
        summary="Can the service do its job (is the database reachable)?",
        responses={503: {"description": "The database is unreachable"}},
    )
    def ready() -> JSONResponse:
        try:
            store.ping()
        except SQLAlchemyError:
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return JSONResponse({"status": "ready"})

    @app.post(
        "/v1/events",
        dependencies=authenticated,
        tags=["events"],
        summary="Send raw log lines; SSH login attempts are parsed and stored",
    )
    def ingest(batch: EventBatch) -> IngestResult:
        events = list(parse_lines(batch.lines))
        result = store.save(events, [])
        return IngestResult(
            received=len(batch.lines), parsed=len(events), stored=result.events_added
        )

    @app.get(
        "/v1/alerts",
        dependencies=authenticated,
        tags=["alerts"],
        summary="Alerts, newest first",
    )
    def list_alerts(
        limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
        min_severity: Severity = Severity.LOW,
    ) -> list[AlertOut]:
        alerts = store.recent_alerts(limit=limit, min_severity=min_severity)
        return [AlertOut.from_stored(alert) for alert in alerts]

    @app.get(
        "/v1/alerts/{alert_id}",
        dependencies=authenticated,
        tags=["alerts"],
        summary="One alert with the log lines behind it",
        responses={404: {"description": "No such alert"}},
    )
    def get_alert(alert_id: int) -> AlertDetail:
        alert = store.get_alert(alert_id)
        if alert is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="alert not found")
        summary = AlertOut.from_stored(alert)
        return AlertDetail(**summary.model_dump(), evidence=store.evidence(alert_id))

    return app
