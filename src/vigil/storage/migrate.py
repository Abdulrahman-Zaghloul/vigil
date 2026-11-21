"""Run database migrations from code, so `vigil db upgrade` works on any machine.

The migration scripts ship inside the package, which means an installed Vigil can
always build or update its own database, with no project checkout required.
"""

from __future__ import annotations

from importlib.resources import files

from alembic import command
from alembic.config import Config


def alembic_config(database_url: str) -> Config:
    config = Config()
    config.set_main_option("script_location", str(files("vigil.storage") / "migrations"))
    # Alembic's config format treats "%" as special, and passwords may contain one.
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


def upgrade(database_url: str, revision: str = "head") -> None:
    command.upgrade(alembic_config(database_url), revision)


def downgrade(database_url: str, revision: str = "base") -> None:
    command.downgrade(alembic_config(database_url), revision)


def check(database_url: str) -> None:
    """Fail if the tables in code differ from what the migrations build."""
    command.check(alembic_config(database_url))
