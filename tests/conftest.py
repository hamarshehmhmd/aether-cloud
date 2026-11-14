"""Shared test fixtures for aether-cloud.

Strategy:
- Set env vars before any app imports so Settings() picks them up
- Override get_db / get_redis FastAPI dependencies with mocks
- Patch the lifespan to a no-op so tests don't need a real DB/Redis/GitHub
"""

import os
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest

# ── Env vars must be set before any app import ─────────────────────────────
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("GITHUB_APP_ID", "99999")
os.environ.setdefault("GITHUB_PRIVATE_KEY", "dGVzdA==")   # base64("test")
os.environ.setdefault("GITHUB_WEBHOOK_SECRET", "test-webhook-secret")
# Must be ≥32 chars or startup validation raises
os.environ.setdefault("ADMIN_API_KEY", "test-admin-key-that-is-32-chars!!")
os.environ.setdefault("ENVIRONMENT", "test")


def make_mock_db():
    """AsyncMock session that auto-commits and has a usable execute stub."""
    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    # execute() is awaited, but the Result it returns is synchronous in SQLAlchemy.
    # Left as an AsyncMock child, result.scalar_one_or_none() would return a
    # (truthy) coroutine instead of a value.
    db.execute.return_value = MagicMock()
    return db


def make_mock_redis():
    """MagicMock Redis client with async get/set/incr/expire/ping."""
    redis = AsyncMock()
    redis.get.return_value = None       # cache miss by default
    redis.set.return_value = True
    redis.incr.return_value = 1
    redis.expire.return_value = True
    redis.ping.return_value = True
    return redis


@pytest.fixture
def mock_db():
    return make_mock_db()


@pytest.fixture
def mock_redis():
    return make_mock_redis()


@pytest.fixture
def app(mock_db, mock_redis):
    """FastAPI test app with lifespan bypassed and DB/Redis overridden."""
    from app.main import create_app
    from app.dependencies import get_db, get_redis

    @asynccontextmanager
    async def _noop_lifespan(app):
        yield  # skip real DB/Redis/GitHub connectivity checks

    _app = create_app()
    _app.router.lifespan_context = _noop_lifespan

    async def _override_db():
        yield mock_db

    async def _override_redis():
        return mock_redis

    _app.dependency_overrides[get_db] = _override_db
    _app.dependency_overrides[get_redis] = _override_redis

    yield _app

    _app.dependency_overrides.clear()


@pytest.fixture
async def client(app):
    """Async HTTP client wired to the test app."""
    from httpx import ASGITransport, AsyncClient

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        yield c


ADMIN_KEY = os.environ["ADMIN_API_KEY"]
ADMIN_HEADERS = {"Authorization": f"Bearer {ADMIN_KEY}"}
