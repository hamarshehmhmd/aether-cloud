"""FastAPI application factory for aether-cloud."""

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.middleware.logging import LoggingMiddleware

logger = structlog.get_logger(__name__)


def _validate_admin_key(settings) -> None:
    """Fail fast if admin key is too short — enforce minimum security."""
    if len(settings.admin_api_key) < 32:
        raise RuntimeError(
            "ADMIN_API_KEY must be at least 32 characters. "
            "Generate one: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: validate config, verify DB + Redis connectivity."""
    settings = get_settings()
    logger.info("aether_cloud_starting", env=settings.environment)

    _validate_admin_key(settings)

    # Verify DB connection
    from app.database import async_engine
    import sqlalchemy
    async with async_engine.connect() as conn:
        await conn.execute(sqlalchemy.text("SELECT 1"))
    logger.info("db_connected")

    # Verify Redis
    from app.database import get_redis_pool
    redis = get_redis_pool()
    await redis.ping()
    logger.info("redis_connected")

    logger.info("aether_cloud_ready")
    yield

    await async_engine.dispose()
    logger.info("aether_cloud_shutdown")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="Aether Cloud",
        description="License validation, token proxy, and webhook relay for Aether self-hosted",
        version="1.0.0",
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-GitHub-Event",
                       "X-Hub-Signature-256"],
    )
    app.add_middleware(LoggingMiddleware)

    from app.routers import admin, installations, licenses, token, webhooks

    app.include_router(licenses.router)
    app.include_router(token.router)
    app.include_router(installations.router)
    app.include_router(webhooks.router)
    app.include_router(admin.router)

    @app.get("/health", tags=["health"])
    async def health():
        return {"status": "ok", "version": "1.0.0"}

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error("unhandled_exception", error=str(exc), path=request.url.path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error"},
        )

    return app


app = create_app()
