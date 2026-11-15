"""InstallationRegistry — maps a GitHub installation to a license + relay endpoint."""

import uuid

from sqlalchemy import BigInteger, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin


class InstallationRegistry(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "installation_registry"

    # GitHub App installation ID (unique per org/user that installs the app)
    installation_id: Mapped[int] = mapped_column(BigInteger, unique=True, nullable=False)

    # License that owns this installation
    license_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("licenses.id", ondelete="CASCADE"), nullable=False
    )

    # Where to forward GitHub webhook events for this installation
    relay_url: Mapped[str] = mapped_column(String(512), nullable=False)

    # HMAC key for signing relayed events (see app/utils/relay_signing.py).
    # Never sent over the wire. Stored in plaintext because signing needs it.
    # Generated once on registration; operator puts this in their AETHER_RELAY_SECRET env
    relay_secret: Mapped[str] = mapped_column(String(128), nullable=False)

    # Relationships
    license: Mapped["License"] = relationship(back_populates="installations")

    def __repr__(self) -> str:
        return (
            f"<InstallationRegistry installation_id={self.installation_id} "
            f"relay_url={self.relay_url}>"
        )
