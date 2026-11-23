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


class TestWebhookBodyShapes:
    """A valid signature says nothing about the body's shape; none of these may 500."""

    @pytest.mark.parametrize("body", [b"not json", b"payload=%7B%7D", b"\xff\xfe"])
    async def test_non_json_body_returns_400(self, client, body):
        resp = await client.post("/webhooks/github", content=body, headers=_headers(body, "push"))
        assert resp.status_code == 400

    @pytest.mark.parametrize(
        "body",
        [b'{"installation": null}', b"[1]", b'"text"', b'{"installation": {"id": "7"}}'],
    )
    async def test_json_without_usable_installation_is_accepted_not_relayed(self, client, body):
        with patch("app.routers.webhooks._relay_to_self_hosted", new=AsyncMock()) as relay:
            resp = await client.post(
                "/webhooks/github", content=body, headers=_headers(body, "push")
            )

        assert resp.status_code == 200
        relay.assert_not_awaited()

    async def test_non_ascii_signature_returns_401(self, client):
        """Regression: hmac.compare_digest on str raised TypeError -> 500."""
        resp = await client.post(
            "/webhooks/github",
            content=b"{}",
            headers=[
                (b"x-hub-signature-256", "sha256=é".encode("latin-1")),
                (b"x-github-event", b"push"),
            ],
        )
        assert resp.status_code == 401


class TestRelayRespectsLicense:
    """The background relay must stop delivering once a license is revoked or expired."""

    @staticmethod
    def _session_returning(row):
        result = MagicMock()
        result.one_or_none.return_value = row
        session = AsyncMock()
        session.execute.return_value = result
        factory = MagicMock()
        factory.return_value.__aenter__.return_value = session
        return factory

    @staticmethod
    def _row(status=LicenseStatus.active, expires_at=None):
        registry = MagicMock(relay_url="https://relay.example.com/hook", relay_secret="s")
        lic = _license()
        lic.status = status
        lic.expires_at = expires_at
        return registry, lic

    async def _relay(self, row):
        from app.routers.webhooks import _relay_to_self_hosted

        with patch("app.routers.webhooks.AsyncSessionLocal", new=self._session_returning(row)), \
             patch("app.routers.webhooks.forward_event", new=AsyncMock()) as forward:
            await _relay_to_self_hosted(
                installation_id=1, event="push", body=b"{}", delivery_id="d"
            )
        return forward

    async def test_active_license_is_forwarded(self):
        forward = await self._relay(self._row())
        forward.assert_awaited_once()
        assert forward.await_args.kwargs["relay_url"] == "https://relay.example.com/hook"

    async def test_revoked_license_is_not_forwarded(self):
        forward = await self._relay(self._row(status=LicenseStatus.revoked))
        forward.assert_not_awaited()

    async def test_expired_license_is_not_forwarded(self):
        from datetime import datetime, timedelta, timezone

        past = datetime.now(timezone.utc) - timedelta(days=1)
        forward = await self._relay(self._row(expires_at=past))
        forward.assert_not_awaited()

    async def test_unregistered_installation_is_not_forwarded(self):
        forward = await self._relay(None)
        forward.assert_not_awaited()
