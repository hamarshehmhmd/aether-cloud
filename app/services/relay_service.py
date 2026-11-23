"""Webhook relay service — forwards GitHub events to self-hosted instances."""

import asyncio

import httpx
import structlog

from app.utils.relay_signing import signature_headers
from app.utils.url_safety import UnsafeURLError, resolve_relay_target

log = structlog.get_logger(__name__)

_RELAY_TIMEOUT = 10.0     # seconds per attempt
_RETRY_DELAYS = [1, 3]    # seconds; 3 attempts total (1 initial + 2 retries)


async def forward_event(
    relay_url: str,
    relay_secret: str,
    event: str,
    body: bytes,
    delivery_id: str,
    installation_id: int,
) -> bool:
    """Forward a GitHub webhook event to a self-hosted instance.

    Sends POST {relay_url} with:
      X-GitHub-Event: {event}
      X-Aether-Timestamp / X-Aether-Delivery / X-Aether-Signature-256
        (HMAC over timestamp, delivery ID and body; see app/utils/relay_signing.py)
      Content-Type: application/json
      body: GitHub's original raw bytes, unmodified

    The relay secret itself is never sent.

    Retries up to 2 times on network/5xx errors. A 3xx/4xx answer is not retried.
    Returns True only if the receiver answered 2xx.
    """
    # SSRF guard: resolve once, refuse non-public addresses, and pin every attempt
    # to the vetted IP so DNS cannot be switched to an internal address mid-flight.
    try:
        target = await resolve_relay_target(relay_url)
    except UnsafeURLError as exc:
        log.error(
            "relay_blocked_unsafe_url",
            installation_id=installation_id,
            relay_url=relay_url,
            reason=str(exc),
        )
        return False

    headers = {
        "Host": target.host_header,
        "X-GitHub-Event": event,
        "Content-Type": "application/json",
        "User-Agent": "Aether-Relay/1.0",
    }

    attempts = [0.0] + _RETRY_DELAYS  # first attempt is immediate

    for attempt_num, delay in enumerate(attempts):
        if delay:
            await asyncio.sleep(delay)
        try:
            # follow_redirects=False: a redirect could point at an internal address.
            async with httpx.AsyncClient(
                timeout=_RELAY_TIMEOUT, follow_redirects=False
            ) as client:
                # Re-sign each attempt: fresh timestamp, same delivery ID (receiver dedupes).
                resp = await client.post(
                    target.url,
                    content=body,
                    headers={**headers, **signature_headers(relay_secret, delivery_id, body)},
                    # TLS SNI + certificate check against the real hostname, not the IP.
                    extensions={"sni_hostname": target.sni_hostname},
                )
                if resp.is_success:
                    log.info(
                        "relay_delivered",
                        installation_id=installation_id,
                        relay_url=relay_url,
                        status=resp.status_code,
                        attempt=attempt_num + 1,
                    )
                    return True
                if resp.status_code < 500:
                    # 3xx/4xx: the receiver answered and refused (bad signature,
                    # wrong path, redirect). Retrying the same request won't help.
                    log.warning(
                        "relay_rejected",
                        installation_id=installation_id,
                        relay_url=relay_url,
                        status=resp.status_code,
                        attempt=attempt_num + 1,
                    )
                    return False
                log.warning(
                    "relay_server_error",
                    installation_id=installation_id,
                    relay_url=relay_url,
                    status=resp.status_code,
                    attempt=attempt_num + 1,
                )
        except httpx.RequestError as exc:
            log.warning(
                "relay_request_error",
                installation_id=installation_id,
                relay_url=relay_url,
                error=str(exc),
                attempt=attempt_num + 1,
            )

    log.error(
        "relay_failed_all_attempts",
        installation_id=installation_id,
        relay_url=relay_url,
    )
    return False
