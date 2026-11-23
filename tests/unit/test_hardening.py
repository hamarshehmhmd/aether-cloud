"""Input validation and edge cases that used to surface as 500s or wrong behaviour."""

import ipaddress
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from sqlalchemy.exc import IntegrityError

from app.models.installation_registry import InstallationRegistry
from app.models.license import License, LicenseStatus
from tests.conftest import ADMIN_HEADERS

TOO_BIG = 2**63  # one past Postgres BIGINT
LICENSE_BODY = {"customer_email": "user@example.com", "github_account_id": 1111}
REGISTER_BODY = {"installation_id": 12345, "relay_url": "https://relay.example.com/hook"}
OWNER_ACCOUNT_ID = 1111


def _license(status=LicenseStatus.active, expires_at=None) -> License:
    lic = MagicMock(spec=License)
    lic.id = uuid.uuid4()
    lic.status = status
    lic.expires_at = expires_at
    lic.github_account_id = OWNER_ACCOUNT_ID
    return lic


class TestAdminValidation:
    async def test_non_ascii_admin_key_returns_401(self, client):
        """Regression: hmac.compare_digest on str raised TypeError -> 500."""
        resp = await client.get(
            "/admin/licenses",
            headers=[(b"authorization", "Bearer café".encode("latin-1"))],
        )
        assert resp.status_code == 401

    async def test_revoke_with_malformed_id_returns_422(self, client, mock_db):
        resp = await client.delete("/admin/licenses/not-a-uuid", headers=ADMIN_HEADERS)
        assert resp.status_code == 422
        mock_db.execute.assert_not_awaited()

    @pytest.mark.parametrize(
        "override",
        [
            {"notes": "x" * 1001},
            {"github_account_id": TOO_BIG},
            {"expires_at": "2099-01-01T00:00:00"},  # naive: no UTC offset
            {"expires_at": "2020-01-01T00:00:00Z"},  # already past
        ],
    )
    async def test_create_license_rejects_bad_fields(self, client, mock_db, override):
        resp = await client.post(
            "/admin/licenses", json={**LICENSE_BODY, **override}, headers=ADMIN_HEADERS
        )
        assert resp.status_code == 422
        mock_db.add.assert_not_called()

    async def test_create_license_accepts_future_aware_expiry(self, client, mock_db):
        lic = _license()
        lic.customer_email = "user@example.com"
        lic.created_at = datetime.now(timezone.utc)
        lic.expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        with patch(
            "app.routers.admin.create_license", new=AsyncMock(return_value=(lic, "aeth_k"))
        ) as create:
            resp = await client.post(
                "/admin/licenses",
                json={**LICENSE_BODY, "expires_at": "2099-01-01T00:00:00+02:00"},
                headers=ADMIN_HEADERS,
            )
        assert resp.status_code == 201
        assert create.await_args.kwargs["expires_at"].utcoffset() == timedelta(hours=2)


class TestTokenValidation:
    @pytest.mark.parametrize("installation_id", [0, -1, TOO_BIG])
    async def test_out_of_range_installation_id_returns_422(self, client, installation_id):
        resp = await client.get(
            f"/github/token?installation_id={installation_id}",
            headers={"Authorization": "Bearer aeth_key"},
        )
        assert resp.status_code == 422


async def _register(client, lic, body=REGISTER_BODY):
    with patch(
        "app.routers.installations.validate_license", new=AsyncMock(return_value=lic)
    ), patch(
        "app.routers.installations.get_installation_account_id",
        new=AsyncMock(return_value=OWNER_ACCOUNT_ID),
    ), patch(
        "app.routers.installations.check_relay_url", new=AsyncMock(return_value=None)
    ):
        return await client.post(
            "/installations/register", json=body, headers={"Authorization": "Bearer aeth_key"}
        )


def _existing_registration(mock_db, holder: License) -> InstallationRegistry:
    """Make the DB return an installation already registered under `holder`."""
    existing = MagicMock(spec=InstallationRegistry)
    existing.id = uuid.uuid4()
    existing.installation_id = REGISTER_BODY["installation_id"]
    existing.license_id = holder.id
    existing.relay_url = "https://old.example.com/hook"
    existing.relay_secret = "old-secret"
    mock_db.execute.return_value.scalar_one_or_none.return_value = existing
    mock_db.get.return_value = holder
    return existing


class TestRegisterValidation:
    @pytest.mark.parametrize(
        "override",
        [
            {"installation_id": TOO_BIG},
            {"installation_id": 0},
            {"relay_url": "https://relay.example.com/" + "a" * 600},
        ],
    )
    async def test_bad_fields_return_422(self, client, mock_db, override):
        resp = await _register(client, _license(), body={**REGISTER_BODY, **override})
        assert resp.status_code == 422
        mock_db.add.assert_not_called()

    async def test_concurrent_first_registration_returns_409(self, client, mock_db):
        mock_db.execute.return_value.scalar_one_or_none.return_value = None
        mock_db.flush.side_effect = IntegrityError("INSERT", {}, Exception("duplicate key"))

        resp = await _register(client, _license())

        assert resp.status_code == 409


class TestRegisterTakeover:
    """A replacement license must be able to take over its account's installation."""

    async def test_active_holder_blocks_other_license(self, client, mock_db):
        existing = _existing_registration(mock_db, holder=_license())
        holder_id = existing.license_id

        resp = await _register(client, _license())

        assert resp.status_code == 409
        assert existing.license_id == holder_id
        assert existing.relay_secret == "old-secret"

    @pytest.mark.parametrize(
        "holder",
        [
            _license(status=LicenseStatus.revoked),
            _license(expires_at=datetime.now(timezone.utc) - timedelta(days=1)),
        ],
        ids=["revoked", "expired"],
    )
    async def test_unusable_holder_is_replaced(self, client, mock_db, holder):
        existing = _existing_registration(mock_db, holder=holder)
        new_license = _license()

        resp = await _register(client, new_license)

        assert resp.status_code == 201
        assert existing.license_id == new_license.id
        assert existing.relay_url == REGISTER_BODY["relay_url"]
        assert existing.relay_secret != "old-secret"  # old holder's secret is dead

    async def test_same_license_reregisters_without_holder_lookup(self, client, mock_db):
        lic = _license()
        _existing_registration(mock_db, holder=lic)

        resp = await _register(client, lic)

        assert resp.status_code == 201
        mock_db.get.assert_not_awaited()


class TestLicenseIsUsable:
    def test_states(self):
        from app.services.license_service import license_is_usable

        now = datetime.now(timezone.utc)
        assert license_is_usable(_license()) is True
        assert license_is_usable(_license(expires_at=now + timedelta(days=1))) is True
        assert license_is_usable(_license(expires_at=now - timedelta(seconds=1))) is False
        assert license_is_usable(_license(status=LicenseStatus.revoked)) is False
        assert license_is_usable(_license(status=LicenseStatus.expired)) is False


class TestNat64:
    @pytest.mark.parametrize("address", ["64:ff9b::a00:1", "64:ff9b::7f00:1", "64:ff9b:1::1"])
    def test_nat64_addresses_are_not_public(self, address):
        from app.utils.url_safety import _is_public

        assert _is_public(ipaddress.ip_address(address)) is False

    def test_ordinary_global_ipv6_still_public(self):
        from app.utils.url_safety import _is_public

        assert _is_public(ipaddress.ip_address("2606:4700:4700::1111")) is True


class TestRelayStatusHandling:
    @staticmethod
    async def _forward(response: httpx.Response):
        from app.services.relay_service import forward_event
        from app.utils.url_safety import RelayTarget

        seen = []

        def handler(request):
            seen.append(request)
            return response

        real_client = httpx.AsyncClient
        target = RelayTarget(
            url="https://93.184.216.34/hook",
            host_header="relay.example.com",
            sni_hostname="relay.example.com",
        )
        with patch(
            "app.services.relay_service.resolve_relay_target", new=AsyncMock(return_value=target)
        ), patch(
            "app.services.relay_service.httpx.AsyncClient",
            side_effect=lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw),
        ), patch("app.services.relay_service.asyncio.sleep", new=AsyncMock()):
            delivered = await forward_event(
                relay_url="https://relay.example.com/hook",
                relay_secret="s",
                event="push",
                body=b"{}",
                delivery_id="d-1",
                installation_id=1,
            )
        return delivered, len(seen)

    @pytest.mark.parametrize("status_code", [200, 202, 204])
    async def test_2xx_is_delivered(self, status_code):
        assert await self._forward(httpx.Response(status_code)) == (True, 1)

    @pytest.mark.parametrize("status_code", [302, 401, 404, 422])
    async def test_3xx_4xx_is_not_delivered_and_not_retried(self, status_code):
        assert await self._forward(httpx.Response(status_code)) == (False, 1)

    async def test_5xx_is_retried_then_fails(self):
        assert await self._forward(httpx.Response(503)) == (False, 3)
