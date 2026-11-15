"""Token cache and rate limiter."""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.services import token_service as ts


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat().replace("+00:00", "Z")


class FakeRedis:
    """Just enough Redis for these tests: get/set with TTL, and a MULTI pipeline."""

    def __init__(self):
        self.data: dict[str, object] = {}
        self.ttl: dict[str, int] = {}
        self.pipelines: list["FakePipeline"] = []

    async def get(self, key):
        return self.data.get(key)

    async def set(self, key, value, ex=None):
        self.data[key] = value
        if ex is not None:
            self.ttl[key] = ex

    def pipeline(self, transaction=True):
        pipe = FakePipeline(self, transaction)
        self.pipelines.append(pipe)
        return pipe


class FakePipeline:
    def __init__(self, redis: FakeRedis, transaction: bool):
        self.redis, self.transaction, self.ops = redis, transaction, []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def incr(self, key):
        self.ops.append(("incr", key))

    def expire(self, key, seconds, nx=False):
        self.ops.append(("expire", key, seconds, nx))

    async def execute(self):
        results = []
        for op in self.ops:
            if op[0] == "incr":
                self.redis.data[op[1]] = int(self.redis.data.get(op[1], 0)) + 1
                results.append(self.redis.data[op[1]])
            else:
                _, key, seconds, nx = op
                if nx and key in self.redis.ttl:
                    results.append(False)
                else:
                    self.redis.ttl[key] = seconds
                    results.append(True)
        return results


# ─────────────────────────────────────────────────────────────────────────────
# Token cache
# ─────────────────────────────────────────────────────────────────────────────

class TestTokenCache:
    @pytest.mark.asyncio
    async def test_cache_hit_returns_real_expires_at(self):
        redis = FakeRedis()
        minted = {"token": "ghs_abc", "expires_at": _iso(timedelta(hours=1))}
        mint = AsyncMock(return_value=minted)

        with patch.object(ts, "mint_installation_token", new=mint):
            first = await ts.get_cached_token(1, redis)
            second = await ts.get_cached_token(1, redis)

        assert first == second == minted  # same shape on miss and hit
        assert second["expires_at"] != ""
        mint.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_ttl_follows_token_expiry_minus_margin(self):
        redis = FakeRedis()
        minted = {"token": "t", "expires_at": _iso(timedelta(minutes=20))}
        with patch.object(ts, "mint_installation_token", new=AsyncMock(return_value=minted)):
            await ts.get_cached_token(1, redis)

        # 20 min left - 5 min margin ≈ 15 min (allow a second of test runtime)
        assert 15 * 60 - 2 <= redis.ttl["gh_install_token:1"] <= 15 * 60

    @pytest.mark.asyncio
    async def test_ttl_is_capped_at_55_minutes(self):
        redis = FakeRedis()
        minted = {"token": "t", "expires_at": _iso(timedelta(hours=2))}
        with patch.object(ts, "mint_installation_token", new=AsyncMock(return_value=minted)):
            await ts.get_cached_token(1, redis)

        assert redis.ttl["gh_install_token:1"] == 55 * 60

    @pytest.mark.parametrize("expires_at", [_iso(timedelta(minutes=3)), "not-a-date", ""])
    @pytest.mark.asyncio
    async def test_short_lived_or_unparseable_tokens_not_cached(self, expires_at):
        redis = FakeRedis()
        minted = {"token": "t", "expires_at": expires_at}
        with patch.object(ts, "mint_installation_token", new=AsyncMock(return_value=minted)):
            assert await ts.get_cached_token(1, redis) == minted

        assert "gh_install_token:1" not in redis.data

    @pytest.mark.parametrize("stale", ["ghs_plain_old_format", "{bad json", json.dumps({"x": 1})])
    @pytest.mark.asyncio
    async def test_invalid_cache_entry_is_treated_as_miss(self, stale):
        redis = FakeRedis()
        redis.data["gh_install_token:1"] = stale
        minted = {"token": "fresh", "expires_at": _iso(timedelta(hours=1))}
        mint = AsyncMock(return_value=minted)

        with patch.object(ts, "mint_installation_token", new=mint):
            assert await ts.get_cached_token(1, redis) == minted

        mint.assert_awaited_once()
        assert json.loads(redis.data["gh_install_token:1"]) == minted


# ─────────────────────────────────────────────────────────────────────────────
# Rate limiter
# ─────────────────────────────────────────────────────────────────────────────

class TestRateLimit:
    @pytest.mark.asyncio
    async def test_allows_up_to_limit_then_blocks(self):
        redis = FakeRedis()
        results = [await ts.check_rate_limit("h", redis, limit=3) for _ in range(5)]
        assert results == [True, True, True, False, False]

    @pytest.mark.asyncio
    async def test_incr_and_expire_run_in_one_transaction(self):
        redis = FakeRedis()
        await ts.check_rate_limit("h", redis, limit=3)

        pipe = redis.pipelines[0]
        assert pipe.transaction is True
        assert pipe.ops == [("incr", "rate:token:h"), ("expire", "rate:token:h", 60, True)]

    @pytest.mark.asyncio
    async def test_counter_without_ttl_gets_one(self):
        """A counter left without a TTL must not lock the license out forever."""
        redis = FakeRedis()
        redis.data["rate:token:h"] = 999  # e.g. written before this fix, no TTL
        assert await ts.check_rate_limit("h", redis, limit=3) is False
        assert redis.ttl["rate:token:h"] == 60

    @pytest.mark.asyncio
    async def test_limits_are_per_license(self):
        redis = FakeRedis()
        for _ in range(3):
            await ts.check_rate_limit("a", redis, limit=3)
        assert await ts.check_rate_limit("a", redis, limit=3) is False
        assert await ts.check_rate_limit("b", redis, limit=3) is True
