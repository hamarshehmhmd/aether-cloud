"""GitHub webhook receiver + relay dispatcher."""

import json
import uuid

import structlog
from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request, status
from sqlalchemy import select

from app.config import get_settings
from app.database import AsyncSessionLocal
from app.models.installation_registry import InstallationRegistry
from app.models.license import License
from app.services.license_service import license_is_usable
from app.services.relay_service import forward_event
from app.utils.github_webhook import verify_signature

log = structlog.get_logger(__name__)
router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.post("/github", status_code=status.HTTP_200_OK)
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: str = Header(...),
    x_github_event: str = Header(...),
    x_github_delivery: str | None = Header(default=None),
):
    """Receive all GitHub App webhook events.

    Validates HMAC-SHA256 signature synchronously.
    Relay forwarding runs as a background task so GitHub gets 200 OK immediately.
    """
    settings = get_settings()
    body = await request.body()

    if not verify_signature(body, x_hub_signature_256, settings.github_webhook_secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )

    # The signature only proves GitHub sent these bytes, not what shape they have.
    # A webhook configured as application/x-www-form-urlencoded lands here too.
    try:
        payload = json.loads(body)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Body is not valid JSON. Set the webhook content type to application/json.",
        )

    # Extract installation ID from payload; tolerate a missing or null object.
    installation = payload.get("installation") if isinstance(payload, dict) else None
    installation_id = installation.get("id") if isinstance(installation, dict) else None
    if not isinstance(installation_id, int) or isinstance(installation_id, bool):
        installation_id = None

    if installation_id:
        # GitHub's delivery GUID identifies this event across retries; the receiver
        # uses it to reject replays. Fall back to a fresh ID if absent or malformed.
        delivery_id = x_github_delivery
        if not delivery_id or ":" in delivery_id or len(delivery_id) > 128:
            delivery_id = str(uuid.uuid4())
        background_tasks.add_task(
            _relay_to_self_hosted,
            installation_id=installation_id,
            event=x_github_event,
            body=body,  # raw bytes exactly as GitHub sent them
            delivery_id=delivery_id,
        )
    else:
        # Not `event=`: that is structlog's own first parameter and raises TypeError.
        log.info("webhook_no_installation_id", github_event=x_github_event)

    return {"status": "accepted", "event": x_github_event}


async def _relay_to_self_hosted(
    installation_id: int, event: str, body: bytes, delivery_id: str
) -> None:
    """Background task: look up relay config and forward the event."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(InstallationRegistry, License)
            .join(License, License.id == InstallationRegistry.license_id)
            .where(InstallationRegistry.installation_id == installation_id)
        )
        row = result.one_or_none()

    if row is None:
        # This installation is not self-hosted — it's a hosted SaaS installation.
        # The hosted processing path would go here in future.
        log.debug("no_relay_for_installation", installation_id=installation_id)
        return

    registry, license_ = row
    if not license_is_usable(license_):
        # Revoked or expired: the token proxy already refuses this license, so
        # stop delivering its events as well.
        log.warning(
            "relay_skipped_inactive_license",
            installation_id=installation_id,
            license_id=str(license_.id),
        )
        return

    await forward_event(
        relay_url=registry.relay_url,
        relay_secret=registry.relay_secret,
        event=event,
        body=body,
        delivery_id=delivery_id,
        installation_id=installation_id,
    )
