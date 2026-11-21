"""Alembic's entry point: connects to the database and runs the migration scripts."""

import os

from alembic import context
from sqlalchemy import engine_from_config, pool

from vigil.storage.schema import metadata

config = context.config
if not config.get_main_option("sqlalchemy.url"):
    # Developers running the `alembic` command directly supply the URL this way.
    config.set_main_option("sqlalchemy.url", os.environ["VIGIL_DATABASE_URL"].replace("%", "%%"))


def run_migrations_offline() -> None:
    """Print the SQL instead of running it (`alembic upgrade head --sql`)."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=metadata,
        literal_binds=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
