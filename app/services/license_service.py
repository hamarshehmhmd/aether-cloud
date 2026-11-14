"""License CRUD and validation logic."""

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.license import License, LicenseStatus
from app.utils.security import generate_license_key, hash_key, verify_key

log = structlog.get_logger(__name__)


async def create_license(
    db: AsyncSession,
    customer_email: str,
    github_account_id: int,
    expires_at=None,
    notes: str | None = None,
) -> tuple[License, str]:
    """Create a new license. Returns (License, plain_key).

    The plain key is returned ONCE and never stored. The DB stores only the hash.
    """
    plain_key = generate_license_key()
    key_hash = hash_key(plain_key)

    license_ = License(
        key_hash=key_hash,
        customer_email=customer_email,
        github_account_id=github_account_id,
        status=LicenseStatus.active,
        expires_at=expires_at,
        notes=notes,
    )
    db.add(license_)
    await db.flush()
    log.info("license_created", license_id=str(license_.id), email=customer_email)
    return license_, plain_key


async def get_license_by_key(db: AsyncSession, plain_key: str) -> License | None:
    """Look up a License by plain key. Returns None if not found or hash mismatch."""
    key_hash = hash_key(plain_key)
    result = await db.execute(select(License).where(License.key_hash == key_hash))
    return result.scalar_one_or_none()


async def validate_license(db: AsyncSession, plain_key: str) -> License:
    """Validate a license key. Raises ValueError with a safe message on failure.

    Checks:
    - Key exists in DB
    - Status is active
    - Not expired (if expires_at set)
    """
    from datetime import datetime, timezone

    license_ = await get_license_by_key(db, plain_key)
    if license_ is None:
        log.warning("license_not_found")
        raise ValueError("Invalid license key")

    if license_.status != LicenseStatus.active:
        log.warning("license_inactive", license_id=str(license_.id), status=license_.status)
        raise ValueError("License is not active")

    if license_.expires_at and license_.expires_at < datetime.now(timezone.utc):
        log.warning("license_expired", license_id=str(license_.id))
        raise ValueError("License has expired")

    return license_


async def revoke_license(db: AsyncSession, license_id: str) -> License:
    """Revoke a license by ID."""
    result = await db.execute(select(License).where(License.id == license_id))
    license_ = result.scalar_one_or_none()
    if not license_:
        raise ValueError(f"License {license_id} not found")
    license_.status = LicenseStatus.revoked
    log.info("license_revoked", license_id=license_id)
    return license_


async def list_licenses(db: AsyncSession) -> list[License]:
    result = await db.execute(select(License).order_by(License.created_at.desc()))
    return list(result.scalars().all())
