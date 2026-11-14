"""Installation registration: ownership must be verified against GitHub."""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.models.license import License, LicenseStatus
from app.utils.security import generate_license_key

OWNER_ACCOUNT_ID = 1111
OTHER_ACCOUNT_ID = 2222
BODY = {"installation_id": 12345, "relay_url": "https://relay.example.com/hook"}


def _license(github_account_id: int | None = OWNER_ACCOUNT_ID) -> License:
    lic = MagicMock(spec=License)
    lic.id = uuid.uuid4()
    lic.status = LicenseStatus.active
    lic.expires_at = None
    lic.github_account_id = github_account_id
    return lic


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {generate_license_key()}"}


@pytest.fixture
def fresh_db(mock_db):
    """No existing registration; db.add assigns an id like a real flush would."""
    mock_db.execute.return_value = MagicMock()
    mock_db.execute.return_value.scalar_one_or_none.return_value = None
    mock_db.add.side_effect = lambda obj: setattr(obj, "id", uuid.uuid4())
    return mock_db


async def _register(client, lic, lookup):
    with patch(
        "app.routers.installations.validate_license", new=AsyncMock(return_value=lic)
    ), patch(
        "app.routers.installations.get_installation_account_id", new=lookup
    ):
        return await client.post("/installations/register", json=BODY, headers=_auth())


class TestRegisterOwnership:
    @pytest.mark.asyncio
    async def test_owned_installation_registers(self, client, fresh_db):
        lookup = AsyncMock(return_value=OWNER_ACCOUNT_ID)
        resp = await _register(client, _license(), lookup)

        assert resp.status_code == 201
        assert resp.json()["installation_id"] == 12345
        assert resp.json()["relay_secret"]
        lookup.assert_awaited_once_with(12345)
        fresh_db.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_installation_of_another_account_is_rejected(self, client, fresh_db):
        resp = await _register(client, _license(), AsyncMock(return_value=OTHER_ACCOUNT_ID))

        assert resp.status_code == 403
        fresh_db.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_nonexistent_installation_is_rejected_like_foreign_one(
        self, client, fresh_db
    ):
        missing = await _register(client, _license(), AsyncMock(return_value=None))
        foreign = await _register(client, _license(), AsyncMock(return_value=OTHER_ACCOUNT_ID))

        assert missing.status_code == foreign.status_code == 403
        assert missing.json() == foreign.json()  # no existence oracle
        fresh_db.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_unbound_license_is_rejected_without_calling_github(
        self, client, fresh_db
    ):
        lookup = AsyncMock(return_value=OWNER_ACCOUNT_ID)
        resp = await _register(client, _license(github_account_id=None), lookup)

        assert resp.status_code == 403
        lookup.assert_not_awaited()
        fresh_db.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_github_failure_returns_502_and_registers_nothing(self, client, fresh_db):
        lookup = AsyncMock(side_effect=httpx.ConnectError("boom"))
        resp = await _register(client, _license(), lookup)

        assert resp.status_code == 502
        fresh_db.add.assert_not_called()


class TestGetInstallationAccountId:
    """The GitHub lookup itself, with GitHub replaced by an httpx MockTransport."""

    @staticmethod
    def _patch_github(handler):
        real_client = httpx.AsyncClient
        return patch(
            "app.github.app.httpx.AsyncClient",
            side_effect=lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw),
        )

    @pytest.mark.asyncio
    async def test_returns_owner_account_id(self):
        from app.github import app as gh

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/app/installations/12345"
            assert request.headers["Authorization"] == "Bearer jwt"
            return httpx.Response(200, json={"account": {"id": OWNER_ACCOUNT_ID}})

        with patch.object(gh, "create_jwt", return_value="jwt"), self._patch_github(handler):
            assert await gh.get_installation_account_id(12345) == OWNER_ACCOUNT_ID

    @pytest.mark.asyncio
    async def test_returns_none_when_installation_missing(self):
        from app.github import app as gh

        with patch.object(gh, "create_jwt", return_value="jwt"), self._patch_github(
            lambda r: httpx.Response(404)
        ):
            assert await gh.get_installation_account_id(12345) is None

    @pytest.mark.asyncio
    async def test_raises_on_other_errors(self):
        from app.github import app as gh

        with patch.object(gh, "create_jwt", return_value="jwt"), self._patch_github(
            lambda r: httpx.Response(500)
        ), pytest.raises(httpx.HTTPStatusError):
            await gh.get_installation_account_id(12345)
