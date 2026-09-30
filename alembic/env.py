"""Alembic environment.

Deliberately model-free. Alembic is used here as a *migration runner*, not as
an ORM: every migration is hand-written SQL. That keeps the schema under
version control -- so a column change no longer means dropping 127MB of audit
history -- without an ORM layer sitting between the code and the query plans
that matter (bulk COPY, the scoring cursor, hybrid retrieval).

The DSN comes from the same Settings object the application uses, so there is
exactly one place that knows where the database is.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from sentinel.config import get_settings

config = context.config
# SQLAlchemy defaults bare `postgresql://` to psycopg2. This project uses
# psycopg 3, so name the driver rather than relying on whichever happens to be
# importable.
_dsn = get_settings().pg_dsn
if _dsn.startswith("postgresql://"):
    _dsn = _dsn.replace("postgresql://", "postgresql+psycopg://", 1)
config.set_main_option("sqlalchemy.url", _dsn)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# No model metadata: autogenerate is intentionally unavailable. Migrations are
# written by hand because the interesting DDL here (partial indexes, generated
# columns, HNSW parameters, CHECK constraints) is not what autogenerate emits.
target_metadata = None


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
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
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
