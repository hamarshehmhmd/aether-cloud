"""Pydantic schemas for license endpoints."""

import uuid
from datetime import datetime

from datetime import timezone

from pydantic import AwareDatetime, BaseModel, EmailStr, Field, field_validator

from app.models.license import LicenseStatus

# Columns are Postgres BIGINT; anything larger fails at the driver, not validation.
MAX_BIGINT = 2**63 - 1


class LicenseCreateRequest(BaseModel):
    customer_email: EmailStr
    # Numeric GitHub account ID of the customer's org/user.
    # Look it up: curl https://api.github.com/orgs/{org}  (or /users/{user}) → "id"
    github_account_id: int = Field(gt=0, le=MAX_BIGINT)
    # Must carry a UTC offset. A naive value would be stored as the server's
    # local time, silently shifting the expiry.
    expires_at: AwareDatetime | None = None
    notes: str | None = Field(default=None, max_length=1000)

    @field_validator("expires_at")
    @classmethod
    def _expiry_in_future(cls, value: datetime | None) -> datetime | None:
        if value is not None and value <= datetime.now(timezone.utc):
            raise ValueError("expires_at must be in the future")
        return value


class LicenseCreateResponse(BaseModel):
    id: uuid.UUID
    customer_email: str
    status: LicenseStatus
    expires_at: datetime | None
    created_at: datetime
    github_account_id: int | None
    # Returned ONCE — never stored in plain form
    license_key: str

    model_config = {"from_attributes": True}


class LicenseListItem(BaseModel):
    id: uuid.UUID
    customer_email: str
    status: LicenseStatus
    expires_at: datetime | None
    created_at: datetime
    github_account_id: int | None

    model_config = {"from_attributes": True}


class ValidateResponse(BaseModel):
    valid: bool
    customer_email: str
    expires_at: datetime | None
