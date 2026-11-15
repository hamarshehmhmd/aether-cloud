"""Webhook relay service — forwards GitHub events to self-hosted instances."""

import asyncio

import httpx
import structlog

from app.utils.url_safety import UnsafeURLError, resolve_relay_target

log = structlog.get_logger(__name__)

_RELAY_TIMEOUT = 10.0     # seconds per attempt
_RETRY_DELAYS = [1, 3]    # seconds; 3 attempts total (1 initial + 2 retries)


async def forward_event(
    relay_url: str,
    relay_secret: str,
    event: str,
    payload: dict,
    installation_id: int,
) -> bool:
    """Forward a GitHub webhook event to a self-hosted instance.

    Sends POST {relay_url} with:
      X-GitHub-Event: {event}
      X-Aether-Relay-Secret: {relay_secret}
      Content-Type: application/json
      body: original payload

    Retries up to 2 times on network/5xx errors.
    Returns True if delivered, False if all attempts failed.
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
        "X-Aether-Relay-Secret": relay_secret,
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
                resp = await client.post(
                    target.url,
                    json=payload,
                    headers=headers,
                    # TLS SNI + certificate check against the real hostname, not the IP.
                    extensions={"sni_hostname": target.sni_hostname},
                )
                if resp.status_code < 500:
                    log.info(
                        "relay_delivered",
                        installation_id=installation_id,
                        relay_url=relay_url,
                        status=resp.status_code,
                        attempt=attempt_num + 1,
                    )
                    return True
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
