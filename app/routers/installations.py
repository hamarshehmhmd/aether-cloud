"""Installation registration — self-hosters register their relay endpoint here."""

import httpx
import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db
from app.github.app import get_installation_account_id
from app.models.installation_registry import InstallationRegistry
from app.schemas.installation import RegisterRequest, RegisterResponse
from app.services.license_service import validate_license
from app.utils.security import generate_relay_secret

log = structlog.get_logger(__name__)
router = APIRouter(prefix="/installations", tags=["installations"])


@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register_installation(
    body: RegisterRequest,
    authorization: str = Header(..., description="Bearer {license_key}"),
    db: AsyncSession = Depends(get_db),
):
    """Register a GitHub App installation and set the webhook relay URL.

    Auth: Bearer {license_key}

    Idempotent: re-registering an existing installation updates relay_url and
    rotates the relay_secret. Operator must update AETHER_RELAY_SECRET after rotation.

    Returns relay_secret — set this as AETHER_RELAY_SECRET on the self-hosted instance.
    """
    scheme, _, key = authorization.partition(" ")
    if scheme.lower() != "bearer" or not key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    try:
        license_ = await validate_license(db, key)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Ownership check: the installation must belong to the GitHub account this
    # license was issued for. Without this, any license holder could register
    # another org's installation_id and then mint tokens for its repos.
    if license_.github_account_id is None:
        log.warning("register_denied_unbound_license", license_id=str(license_.id))
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="License is not bound to a GitHub account. Contact support.",
        )

    try:
        account_id = await get_installation_account_id(body.installation_id)
    except httpx.HTTPError as exc:
        log.error("github_installation_lookup_failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Could not verify installation with GitHub. Try again later.",
        )

    # Same response for "does not exist" and "belongs to someone else" so the
    # endpoint cannot be used to probe which installation IDs exist.
    if account_id is None or account_id != license_.github_account_id:
        log.warning(
            "register_denied_installation_not_owned",
            installation_id=body.installation_id,
            license_id=str(license_.id),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Installation does not belong to the GitHub account on this license.",
        )

    relay_url = str(body.relay_url)

    # Upsert: update if already registered under this license, else create
    result = await db.execute(
        select(InstallationRegistry).where(
            InstallationRegistry.installation_id == body.installation_id
        )
    )
    existing = result.scalar_one_or_none()

    if existing:
        if existing.license_id != license_.id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Installation is already registered under a different license",
            )
        existing.relay_url = relay_url
        existing.relay_secret = generate_relay_secret()
        registry = existing
        log.info("installation_updated", installation_id=body.installation_id)
    else:
        registry = InstallationRegistry(
            installation_id=body.installation_id,
            license_id=license_.id,
            relay_url=relay_url,
            relay_secret=generate_relay_secret(),
        )
        db.add(registry)
        log.info("installation_registered", installation_id=body.installation_id)

    await db.flush()
    return RegisterResponse(
        id=registry.id,
        installation_id=registry.installation_id,
        relay_url=registry.relay_url,
        relay_secret=registry.relay_secret,
    )
