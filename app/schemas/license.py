"""Pydantic schemas for license endpoints."""

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from app.models.license import LicenseStatus


class LicenseCreateRequest(BaseModel):
    customer_email: EmailStr
    # Numeric GitHub account ID of the customer's org/user.
    # Look it up: curl https://api.github.com/orgs/{org}  (or /users/{user}) → "id"
    github_account_id: int = Field(gt=0)
    expires_at: datetime | None = None
    notes: str | None = None


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
