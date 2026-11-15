# Stage 1: build + install deps
FROM python:3.12-slim AS builder

WORKDIR /app

# Install uv (fast dependency installer)
RUN pip install --no-cache-dir uv

# Install dependencies from pyproject.toml via uv
COPY pyproject.toml ./
# uv needs a lockfile or will resolve from pyproject.toml
RUN uv pip install --system \
    fastapi \
    "uvicorn[standard]" \
    pydantic \
    "pydantic[email]" \
    pydantic-settings \
    "sqlalchemy[asyncio]" \
    asyncpg \
    alembic \
    "redis[asyncio]" \
    httpx \
    "python-jose[cryptography]" \
    structlog

# Stage 2: runtime
FROM python:3.12-slim AS runtime

WORKDIR /app

# Non-root user
RUN useradd -m -u 1000 aether

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY app/ ./app/
COPY alembic/ ./alembic/
COPY alembic.ini ./

RUN chown -R aether:aether /app
USER aether

EXPOSE 8001

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8001/health').raise_for_status()"

# Apply migrations before serving. Runs once per container start, before the
# workers fork. exec makes uvicorn PID 1 so it receives SIGTERM directly.
# Note: with several replicas starting at once, run migrations as a separate
# one-off job instead (alembic takes no lock).
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8001 --workers 2"]
