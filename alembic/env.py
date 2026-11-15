import asyncio
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context
from app.models.base import Base
import app.models  # noqa: F401 — registers all models with Base.metadata

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    """Same source as the app: DATABASE_URL from the environment, else from .env.

    Only database_url is read, so migrations don't require the GitHub/admin settings.
    Falls back to alembic.ini only if neither is set.
    """
    from pydantic_settings import BaseSettings, SettingsConfigDict

    class _DbSettings(BaseSettings):
        model_config = SettingsConfigDict(env_file=".env", extra="ignore")
        database_url: str | None = None

    return _DbSettings().database_url or config.get_main_option("sqlalchemy.url")


def run_migrations_offline() -> None:
    url = _database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        version_table="alembic_cloud_version",
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    # Use a dedicated version table to avoid conflicts when sharing a DB with other services
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        version_table="alembic_cloud_version",
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = _database_url()
    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
