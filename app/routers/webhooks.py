"""GitHub webhook receiver + relay dispatcher."""

import uuid

import structlog
from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import AsyncSessionLocal
from app.models.installation_registry import InstallationRegistry
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

    payload = await request.json()

    # Extract installation ID from payload
    installation_id: int | None = None
    if "installation" in payload:
        installation_id = payload["installation"].get("id")

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
        log.info("webhook_no_installation_id", event=x_github_event)

    return {"status": "accepted", "event": x_github_event}


async def _relay_to_self_hosted(
    installation_id: int, event: str, body: bytes, delivery_id: str
) -> None:
    """Background task: look up relay config and forward the event."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(InstallationRegistry).where(
                InstallationRegistry.installation_id == installation_id
            )
        )
        registry = result.scalar_one_or_none()

    if registry is None:
        # This installation is not self-hosted — it's a hosted SaaS installation.
        # The hosted processing path would go here in future.
        log.debug("no_relay_for_installation", installation_id=installation_id)
        return

    await forward_event(
        relay_url=registry.relay_url,
        relay_secret=registry.relay_secret,
        event=event,
        body=body,
        delivery_id=delivery_id,
        installation_id=installation_id,
    )
