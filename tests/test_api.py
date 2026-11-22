from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING

import pytest

pytest.importorskip("fastapi", reason="install the api extra: pip install -e '.[api]'")

from factories import DATA, scan
from fastapi.testclient import TestClient

from vigil.api.app import MAX_LINE_LENGTH, MAX_LINES, create_app
from vigil.storage.store import Store

if TYPE_CHECKING:
    from httpx import Response

TOKEN = "test-token-" + "x" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}
SCENARIO_LINES = (DATA / "attack_scenario.log").read_text(encoding="utf-8").splitlines()


@pytest.fixture
def client(store: Store) -> Iterator[TestClient]:
    with TestClient(create_app(store=store, api_token=TOKEN)) as test_client:
        yield test_client


def ingest(client: TestClient, lines: list[str]) -> Response:
    return client.post("/v1/events", json={"lines": lines}, headers=AUTH)


def test_the_health_check_needs_no_token(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_confirms_the_database_answers(client: TestClient) -> None:
    assert client.get("/health/ready").json() == {"status": "ready"}


def test_readiness_fails_when_the_database_is_down() -> None:
    unreachable = Store.connect("postgresql+psycopg://vigil:vigil@127.0.0.1:1/vigil")
    with TestClient(create_app(store=unreachable, api_token=TOKEN)) as client:
        response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}


@pytest.mark.parametrize(
    "headers",
    [{}, {"Authorization": "Bearer wrong-token"}, {"Authorization": f"Basic {TOKEN}"}],
    ids=["no-token", "wrong-token", "wrong-scheme"],
)
@pytest.mark.parametrize(
    ("method", "path"),
    [("POST", "/v1/events"), ("GET", "/v1/alerts"), ("GET", "/v1/alerts/1")],
)
def test_data_endpoints_require_the_token(
    client: TestClient, headers: dict[str, str], method: str, path: str
) -> None:
    response = client.request(method, path, headers=headers, json={"lines": ["x"]})
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_ingesting_log_lines_stores_the_login_attempts(client: TestClient, store: Store) -> None:
    response = ingest(client, SCENARIO_LINES)

    assert response.status_code == 200
    assert response.json() == {"received": 29, "parsed": 19, "stored": 19}
    assert ingest(client, SCENARIO_LINES).json()["stored"] == 0  # shippers may resend safely
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
    client: TestClient, body: dict[str, object]
) -> None:
    assert client.post("/v1/events", json=body, headers=AUTH).status_code == 422


def test_alerts_are_listed_newest_first(client: TestClient, store: Store) -> None:
    store.save(*scan("attack_scenario.log"))

    response = client.get("/v1/alerts", headers=AUTH)

    assert response.status_code == 200
    assert [a["rule_id"] for a in response.json()] == [
        "ssh-success-after-failures",
        "ssh-brute-force",
        "ssh-password-spray",
    ]


def test_alerts_can_be_filtered_and_paged(client: TestClient, store: Store) -> None:
    store.save(*scan("attack_scenario.log"))

    critical = client.get("/v1/alerts", params={"min_severity": "critical"}, headers=AUTH)
    first_page = client.get("/v1/alerts", params={"limit": 1}, headers=AUTH)

    assert [a["severity"] for a in critical.json()] == ["critical"]
    assert len(first_page.json()) == 1


@pytest.mark.parametrize(
    "params",
    [{"min_severity": "apocalyptic"}, {"limit": 0}, {"limit": 1_001}],
    ids=["unknown-severity", "zero-limit", "huge-limit"],
)
def test_invalid_query_values_are_rejected(client: TestClient, params: dict[str, object]) -> None:
    assert client.get("/v1/alerts", params=params, headers=AUTH).status_code == 422


def test_an_alert_comes_with_its_evidence(client: TestClient, store: Store) -> None:
    store.save(*scan("attack_scenario.log"))
    [summary] = client.get("/v1/alerts", params={"min_severity": "critical"}, headers=AUTH).json()

    alert = client.get(f"/v1/alerts/{summary['id']}", headers=AUTH).json()

    assert alert["technique"] == "T1110"
    assert alert["technique_name"] == "Brute Force"
    assert alert["source_ip"] == "198.51.100.23"
    assert len(alert["evidence"]) == 7
    assert "Accepted password for root" in alert["evidence"][-1]


def test_an_unknown_alert_is_not_found(client: TestClient) -> None:
    assert client.get("/v1/alerts/999999", headers=AUTH).status_code == 404


def test_a_weak_token_is_refused_at_startup(store: Store) -> None:
    with pytest.raises(ValueError, match="at least 32"):
        create_app(store=store, api_token="password123")


def test_the_api_documents_itself(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    assert {"/v1/events", "/v1/alerts", "/v1/alerts/{alert_id}"} <= set(paths)
