"""Shared pytest fixtures.

Database tests need PostgreSQL. They run when VIGIL_TEST_DATABASE_URL is set (CI always
sets it) and are skipped otherwise, so `pytest` still works on a machine without Docker.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:  # imported only by type checkers: the db extra may not be installed
    from vigil.storage.store import Store

TEST_DATABASE_URL = os.environ.get("VIGIL_TEST_DATABASE_URL")


@pytest.fixture(scope="session")
def database_url() -> str:
    """A database migrated down to nothing and back up, proving both directions work."""
    if not TEST_DATABASE_URL:
        pytest.skip("set VIGIL_TEST_DATABASE_URL to run the database tests")
    from vigil.storage.migrate import downgrade, upgrade

    downgrade(TEST_DATABASE_URL)
    upgrade(TEST_DATABASE_URL)
    return TEST_DATABASE_URL


@pytest.fixture
def store(database_url: str) -> Iterator[Store]:
    """A Store over empty tables, so every test starts from a clean slate."""
    from sqlalchemy import text

    from vigil.storage.store import Store

    store = Store.connect(database_url)
    with store.engine.begin() as connection:
        connection.execute(text("TRUNCATE events, alerts, alert_evidence RESTART IDENTITY"))
    yield store
    store.close()
