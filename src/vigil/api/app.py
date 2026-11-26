"""The Vigil web API: log shippers send events in, analysts read alerts out.

Every data endpoint needs an API key with the right scope: shippers hold `ingest` keys
and can only send events; analysts and dashboards hold `read` keys and can only read.
A stolen shipper key, which lives on a server, therefore cannot read any alerts.

Abuse limits sit in front of everything: a rate limit per key, a throttle on addresses
that present bad keys, and a cap on request size (see limits.py and middleware.py).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.exc import SQLAlchemyError

from vigil import __version__
from vigil.alerts import Severity
from vigil.api.limits import Limits, RateLimiter
from vigil.api.middleware import BodySizeLimit, SecurityHeaders
from vigil.api.models import (
    MAX_LINE_LENGTH,
    MAX_LINES,
    AlertDetail,
    AlertOut,
    EventBatch,
    IngestResult,
)
from vigil.keys import Scope
from vigil.parsers.ssh import parse_lines
from vigil.storage.store import MAX_PAGE_SIZE, Store

__all__ = ["MAX_LINES", "MAX_LINE_LENGTH", "Limits", "create_app"]

_bearer = HTTPBearer(auto_error=False)


def _too_many_requests(retry_after: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="too many requests; slow down",
        headers={"Retry-After": str(retry_after)},
    )


def _scope_checker(
    store: Store, scope: Scope, *, per_key: RateLimiter, failed_auth: RateLimiter
) -> Callable[[Request, HTTPAuthorizationCredentials | None], None]:
    def require_scope(
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    ) -> None:
        address = request.client.host if request.client else "unknown"
        # An address that keeps presenting bad keys is refused before its key is even
        # looked up: guessing gets slow, and junk requests stop costing database queries.
        throttled = failed_auth.check(address)
        if not throttled.allowed:
            raise _too_many_requests(throttled.retry_after)

        key = None if credentials is None else store.authenticate(credentials.credentials)
        if key is None:
            failed_auth.consume(address)
            # 401: "we don't know who you are" (missing, malformed, unknown or revoked key)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="missing or invalid API key",
                headers={"WWW-Authenticate": "Bearer"},
            )

        allowed = per_key.consume(key.key_id)
        if not allowed.allowed:
            raise _too_many_requests(allowed.retry_after)
        if scope not in key.scopes:
            # 403: "we know who you are, and you may not do this"
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"this key lacks the '{scope}' scope",
            )

    return require_scope


def create_app(
    *, store: Store, limits: Limits | None = None, clock: Callable[[], float] = time.monotonic
) -> FastAPI:
    """Build the API around a store; API keys are checked against the same store.

    `clock` exists for tests, which move time forward instead of sleeping.
    """
    limits = limits or Limits()
    app = FastAPI(
        title="Vigil",
        version=__version__,
        description="Threat detection for security logs: send events in, read alerts out.",
    )
    per_key = RateLimiter(burst=limits.burst, per_second=limits.per_second, clock=clock)
    failed_auth = RateLimiter(
        burst=limits.failed_auth_burst, per_second=limits.failed_auth_per_second, clock=clock
    )
    guards = {"per_key": per_key, "failed_auth": failed_auth}
    can_ingest = [Depends(_scope_checker(store, Scope.INGEST, **guards))]
    can_read = [Depends(_scope_checker(store, Scope.READ, **guards))]
    # The last middleware added runs first: security headers wrap even a 413 refusal.
    app.add_middleware(BodySizeLimit, max_bytes=limits.max_body_bytes)
    app.add_middleware(SecurityHeaders)

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
        dependencies=can_ingest,
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
        dependencies=can_read,
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
        dependencies=can_read,
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
