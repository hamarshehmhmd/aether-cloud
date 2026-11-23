"""Pydantic schemas for installation registration."""

import uuid

from pydantic import AnyHttpUrl, BaseModel, Field, field_validator

from app.schemas.license import MAX_BIGINT

RELAY_URL_MAX_LENGTH = 512  # installation_registry.relay_url is VARCHAR(512)


class RegisterRequest(BaseModel):
    installation_id: int = Field(gt=0, le=MAX_BIGINT)
    relay_url: AnyHttpUrl

    @field_validator("relay_url")
    @classmethod
    def _relay_url_fits_column(cls, value: AnyHttpUrl) -> AnyHttpUrl:
        if len(str(value)) > RELAY_URL_MAX_LENGTH:
            raise ValueError(f"relay_url must be at most {RELAY_URL_MAX_LENGTH} characters")
        return value


class RegisterResponse(BaseModel):
    id: uuid.UUID
    installation_id: int
    relay_url: str
    # Operator sets this as AETHER_RELAY_SECRET on their self-hosted instance
    relay_secret: str
