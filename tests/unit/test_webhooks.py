"""Tests for the GitHub webhook receiver and for GitHub failures on the token proxy."""

import hashlib
import hmac
import os
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.models.license import License, LicenseStatus

WEBHOOK_SECRET = os.environ["GITHUB_WEBHOOK_SECRET"]


def _signature(body: bytes) -> str:
    return "sha256=" + hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()


def _headers(body: bytes, event: str) -> dict[str, str]:
    return {"X-Hub-Signature-256": _signature(body), "X-GitHub-Event": event}


class TestGithubWebhook:
    async def test_event_without_installation_is_accepted(self, client):
        """Regression: logging this case passed event= to structlog and raised TypeError."""
        body = b'{"zen": "Keep it logically awesome.", "hook_id": 1}'

        with patch("app.routers.webhooks._relay_to_self_hosted", new=AsyncMock()) as relay:
            resp = await client.post("/webhooks/github", content=body, headers=_headers(body, "ping"))

        assert resp.status_code == 200
        assert resp.json() == {"status": "accepted", "event": "ping"}
        relay.assert_not_awaited()

    async def test_event_with_installation_is_relayed(self, client):
        body = b'{"installation": {"id": 12345}}'
        headers = {**_headers(body, "push"), "X-GitHub-Delivery": "delivery-1"}

        with patch("app.routers.webhooks._relay_to_self_hosted", new=AsyncMock()) as relay:
            resp = await client.post("/webhooks/github", content=body, headers=headers)

        assert resp.status_code == 200
        relay.assert_awaited_once_with(
            installation_id=12345, event="push", body=body, delivery_id="delivery-1"
        )

    async def test_bad_signature_returns_401(self, client):
        body = b'{"installation": {"id": 12345}}'
        headers = {"X-Hub-Signature-256": "sha256=" + "0" * 64, "X-GitHub-Event": "push"}

        resp = await client.post("/webhooks/github", content=body, headers=headers)

        assert resp.status_code == 401


def _license() -> License:
    lic = MagicMock(spec=License)
    lic.id = uuid.uuid4()
    lic.status = LicenseStatus.active
    return lic


def _github_status_error(status_code: int) -> httpx.HTTPStatusError:
    request = httpx.Request("POST", "https://api.github.com/app/installations/1/access_tokens")
    response = httpx.Response(status_code, request=request)
    return httpx.HTTPStatusError(f"{status_code}", request=request, response=response)


class TestTokenProxyGithubFailures:
    """GitHub errors while minting must not surface as a bare 500."""

    async def _get_token(self, client, mock_db, mint_error: Exception):
        mock_db.execute.return_value.scalar_one_or_none.return_value = MagicMock()
        with patch(
            "app.routers.token.validate_license", new=AsyncMock(return_value=_license())
        ), patch(
            "app.routers.token.check_rate_limit", new=AsyncMock(return_value=True)
        ), patch(
            "app.services.token_service.mint_installation_token",
            new=AsyncMock(side_effect=mint_error),
        ):
            return await client.get(
                "/github/token?installation_id=12345",
                headers={"Authorization": "Bearer aeth_key"},
            )

    async def test_installation_gone_on_github_returns_404(self, client, mock_db):
        resp = await self._get_token(client, mock_db, _github_status_error(404))
        assert resp.status_code == 404
        assert "no longer exists" in resp.json()["detail"]

    @pytest.mark.parametrize("github_status", [401, 403, 500, 503])
    async def test_other_github_rejections_return_502(self, client, mock_db, github_status):
        resp = await self._get_token(client, mock_db, _github_status_error(github_status))
        assert resp.status_code == 502

    async def test_github_unreachable_returns_502(self, client, mock_db):
        resp = await self._get_token(client, mock_db, httpx.ConnectTimeout("timed out"))
        assert resp.status_code == 502


def test_engine_hides_sql_parameters():
    """DB errors are logged via str(exc); parameters there would leak relay secrets."""
    from app.database import async_engine

    assert async_engine.sync_engine.hide_parameters is True
