"""Unit tests for license_service — mocked DB, no Postgres needed."""

import os
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://t:t@localhost/t")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("GITHUB_APP_ID", "1")
os.environ.setdefault("GITHUB_PRIVATE_KEY", "dGVzdA==")
os.environ.setdefault("GITHUB_WEBHOOK_SECRET", "s")
os.environ.setdefault("ADMIN_API_KEY", "test-admin-key-that-is-32-chars!!")

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.license import License, LicenseStatus
from app.utils.security import generate_license_key, hash_key


def _active_license(email="test@example.com", expires_at=None):
    lic = MagicMock(spec=License)
    lic.id = uuid.uuid4()
    lic.key_hash = hash_key("aeth_test")
    lic.customer_email = email
    lic.status = LicenseStatus.active
    lic.expires_at = expires_at
    return lic


def _mock_db(scalar_result=None):
    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = scalar_result
    db.execute.return_value = result
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    return db


class TestCreateLicense:
    @pytest.mark.asyncio
    async def test_returns_license_and_plain_key(self):
        from app.services.license_service import create_license

        db = _mock_db()
        license_, plain_key = await create_license(db, "user@example.com", github_account_id=1111)

        assert plain_key.startswith("aeth_")
        assert db.add.called
        assert db.flush.called

    @pytest.mark.asyncio
    async def test_plain_key_hashes_to_stored_hash(self):
        from app.services.license_service import create_license
        from app.utils.security import verify_key

        db = _mock_db()
        license_, plain_key = await create_license(db, "user@example.com", github_account_id=1111)

        # The License object was created with hash_key(plain_key)
        # We can verify indirectly: re-hash should match what was passed to License()
        add_call_args = db.add.call_args[0][0]
        assert verify_key(plain_key, add_call_args.key_hash)


class TestValidateLicense:
    @pytest.mark.asyncio
    async def test_valid_active_license_passes(self):
        from app.services.license_service import validate_license

        lic = _active_license()
        db = _mock_db(scalar_result=lic)

        result = await validate_license(db, "aeth_test")
        assert result is lic

    @pytest.mark.asyncio
    async def test_missing_key_raises(self):
        from app.services.license_service import validate_license

        db = _mock_db(scalar_result=None)

        with pytest.raises(ValueError, match="Invalid license key"):
            await validate_license(db, "aeth_nonexistent")

    @pytest.mark.asyncio
    async def test_revoked_license_raises(self):
        from app.services.license_service import validate_license

        lic = _active_license()
        lic.status = LicenseStatus.revoked
        db = _mock_db(scalar_result=lic)

        with pytest.raises(ValueError, match="not active"):
            await validate_license(db, "aeth_test")

    @pytest.mark.asyncio
    async def test_expired_license_raises(self):
        from app.services.license_service import validate_license

        lic = _active_license(expires_at=datetime.now(timezone.utc) - timedelta(days=1))
        db = _mock_db(scalar_result=lic)

        with pytest.raises(ValueError, match="expired"):
            await validate_license(db, "aeth_test")

    @pytest.mark.asyncio
    async def test_future_expiry_passes(self):
        from app.services.license_service import validate_license

        lic = _active_license(expires_at=datetime.now(timezone.utc) + timedelta(days=365))
        db = _mock_db(scalar_result=lic)

        result = await validate_license(db, "aeth_test")
        assert result is lic


class TestRevokeLicense:
    @pytest.mark.asyncio
    async def test_sets_status_revoked(self):
        from app.services.license_service import revoke_license

        lic = _active_license()
        db = _mock_db(scalar_result=lic)

        result = await revoke_license(db, str(lic.id))
        assert result.status == LicenseStatus.revoked

    @pytest.mark.asyncio
    async def test_missing_id_raises(self):
        from app.services.license_service import revoke_license

        db = _mock_db(scalar_result=None)

        with pytest.raises(ValueError, match="not found"):
            await revoke_license(db, str(uuid.uuid4()))
