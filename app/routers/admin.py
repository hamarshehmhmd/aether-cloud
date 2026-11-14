"""Admin endpoints — protected by ADMIN_API_KEY. Internal use only."""

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db, verify_admin_key
from app.schemas.license import LicenseCreateRequest, LicenseCreateResponse, LicenseListItem
from app.services.license_service import create_license, list_licenses, revoke_license

log = structlog.get_logger(__name__)
router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(verify_admin_key)])


@router.post("/licenses", response_model=LicenseCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_new_license(
    body: LicenseCreateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Generate a new license key. Returns plain key ONCE — store it securely.

    Requires: Authorization: Bearer {admin_api_key}
    """
    license_, plain_key = await create_license(
        db,
        customer_email=body.customer_email,
        github_account_id=body.github_account_id,
        expires_at=body.expires_at,
        notes=body.notes,
    )
    return LicenseCreateResponse(
        id=license_.id,
        customer_email=license_.customer_email,
        status=license_.status,
        expires_at=license_.expires_at,
        created_at=license_.created_at,
        github_account_id=license_.github_account_id,
        license_key=plain_key,
    )


@router.get("/licenses", response_model=list[LicenseListItem])
async def get_all_licenses(db: AsyncSession = Depends(get_db)):
    """List all licenses. Requires: Authorization: Bearer {admin_api_key}"""
    licenses = await list_licenses(db)
    return [LicenseListItem.model_validate(lic) for lic in licenses]


@router.delete("/licenses/{license_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke(license_id: str, db: AsyncSession = Depends(get_db)):
    """Revoke a license by ID. Requires: Authorization: Bearer {admin_api_key}"""
    try:
        await revoke_license(db, license_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
