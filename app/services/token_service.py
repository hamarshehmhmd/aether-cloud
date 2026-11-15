"""GitHub installation token service with Redis caching and rate limiting."""

import json
from datetime import datetime, timezone
from typing import Any

import structlog

from app.github.app import mint_installation_token

log = structlog.get_logger(__name__)

_TOKEN_TTL = 55 * 60          # seconds; upper bound on caching (GitHub tokens last 60 min)
_TOKEN_EXPIRY_MARGIN = 5 * 60  # never hand out a cached token with less than this left
_RATE_LIMIT_WINDOW = 60       # seconds
_RATE_LIMIT_KEY_PREFIX = "rate:token:"


def _cache_ttl(expires_at: str) -> int:
    """Seconds to cache a token: until 5 min before it expires, at most 55 min.

    Returns 0 (do not cache) if expires_at is unparseable or too close.
    """
    try:
        expiry = datetime.fromisoformat(expires_at)
    except (TypeError, ValueError):
        return 0
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    remaining = (expiry - datetime.now(timezone.utc)).total_seconds() - _TOKEN_EXPIRY_MARGIN
    return max(0, min(_TOKEN_TTL, int(remaining)))


async def get_cached_token(installation_id: int, redis: Any) -> dict[str, str]:
    """Return a GitHub installation token, from cache when possible.

    Cache key: gh_install_token:{installation_id}
    Value:     JSON {"token", "expires_at"}, so cache hits return the same shape
               as a fresh mint (callers can trust expires_at either way).
    TTL:       until 5 minutes before the token expires, at most 55 minutes.
    """
    cache_key = f"gh_install_token:{installation_id}"
    cached = await redis.get(cache_key)
    if cached:
        try:
            data = json.loads(cached)
            token, expires_at = data["token"], data["expires_at"]
        except (ValueError, TypeError, KeyError):
            # Old plain-string entry or corrupt value: treat as a miss and re-mint.
            log.warning("token_cache_invalid_entry", installation_id=installation_id)
        else:
            log.debug("token_cache_hit", installation_id=installation_id)
            return {"token": token, "expires_at": expires_at}

    log.debug("token_cache_miss", installation_id=installation_id)
    result = await mint_installation_token(installation_id)
    ttl = _cache_ttl(result["expires_at"])
    if ttl > 0:
        await redis.set(cache_key, json.dumps(result), ex=ttl)
    return result


async def check_rate_limit(license_key_hash: str, redis: Any, limit: int) -> bool:
    """Fixed-window rate limiter. Returns True if the request is allowed.

    Allows up to `limit` requests per 60-second window, counted per license.
    The window starts at the first request, so a client can make up to
    2 x limit requests across a window boundary. That is acceptable here
    because tokens are cached and the limit only guards against abuse.

    INCR and EXPIRE run in one MULTI/EXEC transaction. As two separate calls,
    a crash between them would leave a counter with no TTL, and the license
    would be locked out permanently once it passed the limit. EXPIRE NX sets
    the TTL only when none exists, so later requests don't extend the window.
    Requires Redis >= 7.0 (for EXPIRE NX).
    """
    rate_key = f"{_RATE_LIMIT_KEY_PREFIX}{license_key_hash}"
    async with redis.pipeline(transaction=True) as pipe:
        pipe.incr(rate_key)
        pipe.expire(rate_key, _RATE_LIMIT_WINDOW, nx=True)
        count, _ = await pipe.execute()
    return count <= limit
