"""API integration tests — FastAPI TestClient with mocked DB/Redis, no real infra."""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.license import License, LicenseStatus
from app.utils.security import generate_license_key, hash_key

ADMIN_KEY = "test-admin-key-that-is-32-chars!!"
ADMIN_HEADERS = {"Authorization": f"Bearer {ADMIN_KEY}"}


def _active_license(plain_key: str, email: str = "user@example.com") -> License:
    lic = MagicMock(spec=License)
    lic.id = uuid.uuid4()
    lic.key_hash = hash_key(plain_key)
    lic.customer_email = email
    lic.status = LicenseStatus.active
    lic.expires_at = None
    lic.notes = None
    lic.github_account_id = 1111
    lic.created_at = datetime.now(timezone.utc)
    return lic


# ─────────────────────────────────────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────────────────────────────────────

class TestHealth:
    @pytest.mark.asyncio
    async def test_health_returns_ok(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


# ─────────────────────────────────────────────────────────────────────────────
# Admin: license CRUD
# ─────────────────────────────────────────────────────────────────────────────

class TestAdminLicenses:
    @pytest.mark.asyncio
    async def test_create_license_returns_201_with_key(self, client, mock_db):
        from app.services import license_service

        plain_key = generate_license_key()
        lic = _active_license(plain_key)

        with __import__("unittest.mock", fromlist=["patch"]).patch(
            "app.routers.admin.create_license",
            new=AsyncMock(return_value=(lic, plain_key)),
        ):
            resp = await client.post(
                "/admin/licenses",
                json={"customer_email": "user@example.com", "github_account_id": 1111},
                headers=ADMIN_HEADERS,
            )

        assert resp.status_code == 201
        data = resp.json()
        assert data["license_key"].startswith("aeth_")
        assert data["customer_email"] == "user@example.com"
        assert data["status"] == "active"

    @pytest.mark.asyncio
    async def test_create_license_rejects_missing_admin_key(self, client):
        resp = await client.post(
            "/admin/licenses",
            json={"customer_email": "user@example.com"},
        )
        assert resp.status_code == 422  # missing required header

    @pytest.mark.asyncio
    async def test_create_license_rejects_wrong_admin_key(self, client):
        resp = await client.post(
            "/admin/licenses",
            json={"customer_email": "user@example.com"},
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_list_licenses_returns_empty(self, client, mock_db):
        with __import__("unittest.mock", fromlist=["patch"]).patch(
            "app.routers.admin.list_licenses",
            new=AsyncMock(return_value=[]),
        ):
            resp = await client.get("/admin/licenses", headers=ADMIN_HEADERS)

        assert resp.status_code == 200
        assert resp.json() == []

    @pytest.mark.asyncio
    async def test_revoke_unknown_license_returns_404(self, client, mock_db):
        with __import__("unittest.mock", fromlist=["patch"]).patch(
            "app.routers.admin.revoke_license",
            new=AsyncMock(side_effect=ValueError("not found")),
        ):
            resp = await client.delete(
                f"/admin/licenses/{uuid.uuid4()}",
                headers=ADMIN_HEADERS,
            )

        assert resp.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# License validation endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestLicenseValidate:
    @pytest.mark.asyncio
    async def test_valid_key_returns_200(self, client):
        plain_key = generate_license_key()
        lic = _active_license(plain_key)

        with __import__("unittest.mock", fromlist=["patch"]).patch(
            "app.routers.licenses.validate_license",
            new=AsyncMock(return_value=lic),
        ):
            resp = await client.get(
                "/licenses/validate",
                headers={"Authorization": f"Bearer {plain_key}"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["customer_email"] == "user@example.com"

    @pytest.mark.asyncio
    async def test_invalid_key_returns_401(self, client):
        with __import__("unittest.mock", fromlist=["patch"]).patch(
            "app.routers.licenses.validate_license",
            new=AsyncMock(side_effect=ValueError("Invalid")),
        ):
            resp = await client.get(
                "/licenses/validate",
                headers={"Authorization": "Bearer aeth_badkey"},
            )

        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_auth_header_returns_422(self, client):
        resp = await client.get("/licenses/validate")
        assert resp.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
# Token proxy endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestTokenProxy:
    @pytest.mark.asyncio
    async def test_valid_request_returns_token(self, client, mock_db):
        from app.models.installation_registry import InstallationRegistry

        plain_key = generate_license_key()
        lic = _active_license(plain_key)
        reg = MagicMock(spec=InstallationRegistry)
        reg.installation_id = 12345

        # mock_db is the session the app receives (see conftest)
        mock_db.execute.return_value.scalar_one_or_none.return_value = reg

        with __import__("unittest.mock", fromlist=["patch"]).patch(
            "app.routers.token.validate_license",
            new=AsyncMock(return_value=lic),
        ), __import__("unittest.mock", fromlist=["patch"]).patch(
            "app.routers.token.get_cached_token",
            new=AsyncMock(return_value={"token": "ghs_test_token", "expires_at": "2026-08-08T00:00:00Z"}),
        ), __import__("unittest.mock", fromlist=["patch"]).patch(
            "app.routers.token.check_rate_limit",
            new=AsyncMock(return_value=True),
        ):
            resp = await client.get(
                "/github/token?installation_id=12345",
                headers={"Authorization": f"Bearer {plain_key}"},
            )

        assert resp.status_code == 200
        assert resp.json()["token"] == "ghs_test_token"

    @pytest.mark.asyncio
    async def test_unregistered_installation_returns_403(self, client, mock_db):
        plain_key = generate_license_key()
        lic = _active_license(plain_key)

        # DB returns None → installation not registered under this license
        mock_db.execute.return_value.scalar_one_or_none.return_value = None

        with __import__("unittest.mock", fromlist=["patch"]).patch(
            "app.routers.token.validate_license",
            new=AsyncMock(return_value=lic),
        ), __import__("unittest.mock", fromlist=["patch"]).patch(
            "app.routers.token.check_rate_limit",
            new=AsyncMock(return_value=True),
        ):
            resp = await client.get(
                "/github/token?installation_id=99999",
                headers={"Authorization": f"Bearer {plain_key}"},
            )

        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_invalid_license_returns_401(self, client):
        with __import__("unittest.mock", fromlist=["patch"]).patch(
            "app.routers.token.validate_license",
            new=AsyncMock(side_effect=ValueError("Invalid")),
        ):
            resp = await client.get(
                "/github/token?installation_id=12345",
                headers={"Authorization": "Bearer aeth_bad"},
            )

        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_rate_limited_returns_429(self, client):
        plain_key = generate_license_key()
        lic = _active_license(plain_key)

        with __import__("unittest.mock", fromlist=["patch"]).patch(
            "app.routers.token.validate_license",
            new=AsyncMock(return_value=lic),
        ), __import__("unittest.mock", fromlist=["patch"]).patch(
            "app.routers.token.check_rate_limit",
            new=AsyncMock(return_value=False),  # rate limit exceeded
        ):
            resp = await client.get(
                "/github/token?installation_id=12345",
                headers={"Authorization": f"Bearer {plain_key}"},
            )

        assert resp.status_code == 429
