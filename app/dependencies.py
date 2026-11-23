"""FastAPI dependencies: DB session, Redis, admin key verification."""

import hmac
from typing import Any

import structlog
from fastapi import Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db as _get_db, get_redis as _get_redis

log = structlog.get_logger(__name__)


async def get_db() -> AsyncSession:
    async for session in _get_db():
        yield session


async def get_redis() -> Any:
    return await _get_redis()


async def verify_admin_key(
    authorization: str = Header(..., description="Bearer {admin_api_key}"),
) -> None:
    """FastAPI dependency that rejects requests with wrong admin API key.

    Uses hmac.compare_digest for timing-safe comparison, on bytes: comparing
    str raises TypeError for non-ASCII input, which would surface as a 500.
    A wrong key or wrong scheme gets 401; a missing header gets FastAPI's 422.
    """
    settings = get_settings()
    scheme, _, key = authorization.partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(
        key.encode(), settings.admin_api_key.encode()
    ):
        log.warning("admin_auth_failed")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
