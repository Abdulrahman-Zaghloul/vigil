from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING

import pytest

pytest.importorskip("fastapi", reason="install the api extra: pip install -e '.[api]'")

from factories import DATA, scan
from fastapi.testclient import TestClient

from vigil.api.app import MAX_LINE_LENGTH, MAX_LINES, create_app
from vigil.api.limits import Limits
from vigil.keys import Scope
from vigil.storage.store import Store

if TYPE_CHECKING:
    from httpx import Response

SCENARIO_LINES = (DATA / "attack_scenario.log").read_text(encoding="utf-8").splitlines()


@pytest.fixture
def client(store: Store) -> Iterator[TestClient]:
    with TestClient(create_app(store=store)) as test_client:
        yield test_client


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def shipper(store: Store) -> dict[str, str]:
    """Headers for a log shipper's key: it may send events, nothing else."""
    return bearer(store.create_api_key("web-01-shipper", {Scope.INGEST}))


@pytest.fixture
def analyst(store: Store) -> dict[str, str]:
    """Headers for an analyst's key: it may read alerts, nothing else."""
    return bearer(store.create_api_key("analyst", {Scope.READ}))


def ingest(client: TestClient, headers: dict[str, str], lines: list[str]) -> Response:
    return client.post("/v1/events", json={"lines": lines}, headers=headers)


def test_the_health_check_needs_no_token(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_confirms_the_database_answers(client: TestClient) -> None:
    assert client.get("/health/ready").json() == {"status": "ready"}


def test_readiness_fails_when_the_database_is_down() -> None:
    unreachable = Store.connect("postgresql+psycopg://vigil:vigil@127.0.0.1:1/vigil")
    with TestClient(create_app(store=unreachable)) as client:
        response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer not-a-key"},
        bearer("vigil_0123456789ab_" + "x" * 43),
        {"Authorization": "Basic dXNlcjpwYXNz"},
    ],
    ids=["no-key", "malformed", "unknown-key", "wrong-scheme"],
)
@pytest.mark.parametrize(
    ("method", "path"),
    [("POST", "/v1/events"), ("GET", "/v1/alerts"), ("GET", "/v1/alerts/1")],
)
def test_data_endpoints_require_a_valid_key(
    client: TestClient, headers: dict[str, str], method: str, path: str
) -> None:
    response = client.request(method, path, headers=headers, json={"lines": ["x"]})
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_a_shipper_key_cannot_read_alerts(client: TestClient, shipper: dict[str, str]) -> None:
    response = client.get("/v1/alerts", headers=shipper)
    assert response.status_code == 403
    assert "read" in response.json()["detail"]


def test_an_analyst_key_cannot_send_events(client: TestClient, analyst: dict[str, str]) -> None:
    response = ingest(client, analyst, ["x"])
    assert response.status_code == 403
    assert "ingest" in response.json()["detail"]


def test_a_revoked_key_is_refused_at_once(
    client: TestClient, store: Store, analyst: dict[str, str]
) -> None:
    assert client.get("/v1/alerts", headers=analyst).status_code == 200
    store.revoke_api_key("analyst")
    assert client.get("/v1/alerts", headers=analyst).status_code == 401


def test_ingesting_log_lines_stores_the_login_attempts(
    client: TestClient, store: Store, shipper: dict[str, str]
) -> None:
    response = ingest(client, shipper, SCENARIO_LINES)

    assert response.status_code == 200
    assert response.json() == {"received": 29, "parsed": 19, "stored": 19}
    assert (
        ingest(client, shipper, SCENARIO_LINES).json()["stored"] == 0
    )  # shippers may resend safely
    assert store.counts() == (19, 0)


@pytest.mark.parametrize(
    "body",
    [
        {"lines": []},
        {"lines": ["x"] * (MAX_LINES + 1)},
        {"lines": ["x" * (MAX_LINE_LENGTH + 1)]},
        {"lines": ["fine"], "admin": True},
        {"lines": "not a list"},
    ],
    ids=["empty", "too-many-lines", "line-too-long", "unknown-field", "wrong-type"],
)
def test_malformed_or_oversized_batches_are_rejected(
    client: TestClient, shipper: dict[str, str], body: dict[str, object]
) -> None:
    assert client.post("/v1/events", json=body, headers=shipper).status_code == 422


def test_alerts_are_listed_newest_first(
    client: TestClient, store: Store, analyst: dict[str, str]
) -> None:
    store.save(*scan("attack_scenario.log"))

    response = client.get("/v1/alerts", headers=analyst)

    assert response.status_code == 200
    assert [a["rule_id"] for a in response.json()] == [
        "ssh-success-after-failures",
        "ssh-brute-force",
        "ssh-password-spray",
    ]


def test_alerts_can_be_filtered_and_paged(
    client: TestClient, store: Store, analyst: dict[str, str]
) -> None:
    store.save(*scan("attack_scenario.log"))

    critical = client.get("/v1/alerts", params={"min_severity": "critical"}, headers=analyst)
    first_page = client.get("/v1/alerts", params={"limit": 1}, headers=analyst)

    assert [a["severity"] for a in critical.json()] == ["critical"]
    assert len(first_page.json()) == 1


@pytest.mark.parametrize(
    "params",
    [{"min_severity": "apocalyptic"}, {"limit": 0}, {"limit": 1_001}],
    ids=["unknown-severity", "zero-limit", "huge-limit"],
)
def test_invalid_query_values_are_rejected(
    client: TestClient, analyst: dict[str, str], params: dict[str, object]
) -> None:
    assert client.get("/v1/alerts", params=params, headers=analyst).status_code == 422


def test_an_alert_comes_with_its_evidence(
    client: TestClient, store: Store, analyst: dict[str, str]
) -> None:
    store.save(*scan("attack_scenario.log"))
    [summary] = client.get(
        "/v1/alerts", params={"min_severity": "critical"}, headers=analyst
    ).json()

    alert = client.get(f"/v1/alerts/{summary['id']}", headers=analyst).json()

    assert alert["technique"] == "T1110"
    assert alert["technique_name"] == "Brute Force"
    assert alert["source_ip"] == "198.51.100.23"
    assert len(alert["evidence"]) == 7
    assert "Accepted password for root" in alert["evidence"][-1]


def test_an_unknown_alert_is_not_found(client: TestClient, analyst: dict[str, str]) -> None:
    assert client.get("/v1/alerts/999999", headers=analyst).status_code == 404


def test_the_api_documents_itself(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    assert {"/v1/events", "/v1/alerts", "/v1/alerts/{alert_id}"} <= set(paths)


# --- Abuse limits -------------------------------------------------------------------------


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def strict_client(store: Store, clock: FakeClock) -> Iterator[TestClient]:
    """An API with tiny limits, so tests can reach them in a few requests."""
    limits = Limits(
        burst=3,
        per_second=0.1,
        failed_auth_burst=3,
        failed_auth_per_second=0.1,
        max_body_bytes=1_024,
    )
    with TestClient(create_app(store=store, limits=limits, clock=clock)) as test_client:
        yield test_client


def test_each_key_has_its_own_rate_limit(
    strict_client: TestClient, analyst: dict[str, str], shipper: dict[str, str]
) -> None:
    statuses = [strict_client.get("/v1/alerts", headers=analyst).status_code for _ in range(4)]
    limited = strict_client.get("/v1/alerts", headers=analyst)

    assert statuses == [200, 200, 200, 429]
    assert int(limited.headers["retry-after"]) >= 1
    assert ingest(strict_client, shipper, ["x"]).status_code == 200  # other keys unaffected


def test_a_limited_key_recovers_as_time_passes(
    strict_client: TestClient, analyst: dict[str, str], clock: FakeClock
) -> None:
    for _ in range(4):
        strict_client.get("/v1/alerts", headers=analyst)
    clock.now += 10  # 0.1 tokens per second: one new request after 10 seconds
    assert strict_client.get("/v1/alerts", headers=analyst).status_code == 200


def test_repeated_bad_keys_from_one_address_are_throttled(
    strict_client: TestClient, analyst: dict[str, str], clock: FakeClock
) -> None:
    bad = bearer("vigil_0123456789ab_" + "x" * 43)
    statuses = [strict_client.get("/v1/alerts", headers=bad).status_code for _ in range(4)]

    assert statuses == [401, 401, 401, 429]
    # While throttled, the address is refused before any key is even looked up...
    assert strict_client.get("/v1/alerts", headers=analyst).status_code == 429
    clock.now += 10
    # ...and it recovers once its budget refills.
    assert strict_client.get("/v1/alerts", headers=analyst).status_code == 200


def test_oversized_bodies_are_refused_before_anything_reads_them(
    strict_client: TestClient, shipper: dict[str, str]
) -> None:
    response = ingest(strict_client, shipper, ["x" * 2_000])

    assert response.status_code == 413
    assert "1024 bytes" in response.json()["detail"]


def test_oversized_bodies_without_a_declared_length_are_refused_too(
    strict_client: TestClient, shipper: dict[str, str]
) -> None:
    def stream() -> Iterator[bytes]:  # chunked upload: no Content-Length header at all
        yield b'{"lines": ["'
        for _ in range(100):
            yield b"x" * 100
        yield b'"]}'

    response = strict_client.post(
        "/v1/events", content=stream(), headers={**shipper, "content-type": "application/json"}
    )
    assert response.status_code == 413


def test_responses_carry_protective_headers(client: TestClient) -> None:
    headers = client.get("/health").headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["cache-control"] == "no-store"
