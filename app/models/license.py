"""License model.

Keys are stored as SHA-256 hex digests. The plain key is shown to the customer
once on creation and never stored.
"""

import enum
import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Enum, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin


class LicenseStatus(str, enum.Enum):
    active = "active"
    expired = "expired"
    revoked = "revoked"


class License(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "licenses"

    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    customer_email: Mapped[str] = mapped_column(String(320), nullable=False)
    status: Mapped[LicenseStatus] = mapped_column(
        Enum(LicenseStatus), nullable=False, default=LicenseStatus.active
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    notes: Mapped[str | None] = mapped_column(String(1000), nullable=True)

    # GitHub account (org or user) this license may register installations for.
    # Numeric ID, not login: logins can be renamed and then claimed by someone else.
    # Nullable only for licenses created before this column existed; those cannot
    # register installations until an admin binds them to an account.
    github_account_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # Relationships
    installations: Mapped[list["InstallationRegistry"]] = relationship(
        back_populates="license", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<License id={self.id} email={self.customer_email} status={self.status}>"
