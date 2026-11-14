"""GitHub App JWT generation and installation token minting.

The GitHub App private key lives ONLY in this service.
All other services (bangalore self-hosted) obtain tokens by calling
GET /github/token — they never touch the key directly.
"""

import time

import httpx
from jose import jwt

from app.config import get_settings

GITHUB_API = "https://api.github.com"
_TOKEN_TTL = 55 * 60  # 55 minutes; GitHub tokens last 60 min


def create_jwt() -> str:
    """Create a short-lived RS256 JWT signed with the GitHub App private key."""
    settings = get_settings()
    now = int(time.time())
    payload = {
        "iat": now - 60,          # issued 60s ago for clock-drift tolerance
        "exp": now + 9 * 60,      # valid 9 minutes
        "iss": settings.github_app_id,
    }
    return jwt.encode(payload, settings.github_private_key_pem, algorithm="RS256")


def _app_headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {create_jwt()}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


async def get_installation_account_id(installation_id: int) -> int | None:
    """Return the GitHub account ID (org or user) that owns an installation.

    Authenticates as the App itself (JWT), so the answer comes from GitHub,
    not from the caller. Returns None if the installation does not exist
    for this App. Raises httpx.HTTPError on any other failure.
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(
            f"{GITHUB_API}/app/installations/{installation_id}",
            headers=_app_headers(),
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()["account"]["id"]


async def mint_installation_token(installation_id: int) -> dict[str, str]:
    """Mint a GitHub installation access token.

    Returns a dict with keys: token, expires_at (ISO-8601 string).
    Caller is responsible for caching.
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            f"{GITHUB_API}/app/installations/{installation_id}/access_tokens",
            headers=_app_headers(),
        )
        resp.raise_for_status()
        data = resp.json()
        return {"token": data["token"], "expires_at": data["expires_at"]}
