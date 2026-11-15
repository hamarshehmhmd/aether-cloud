"""SSRF protection for relay URLs: URL checks, DNS vetting, IP pinning, relay behaviour."""

import ipaddress
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.utils import url_safety
from app.utils.url_safety import UnsafeURLError, check_relay_url, resolve_relay_target

PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:4700::1111"


def _resolves_to(*addrs: str):
    """Patch DNS so every hostname resolves to the given addresses."""
    return patch.object(
        url_safety,
        "_resolve",
        new=AsyncMock(return_value=[ipaddress.ip_address(a) for a in addrs]),
    )


# ─────────────────────────────────────────────────────────────────────────────
# URL shape
# ─────────────────────────────────────────────────────────────────────────────

class TestUrlShape:
    @pytest.mark.parametrize(
        "url",
        [
            "http://relay.example.com/hook",       # not https
            "ftp://relay.example.com/hook",
            "https://user:pass@relay.example.com",  # embedded credentials
            "https:///nohost",
            "https://relay.example.com:99999/",     # invalid port
            "not a url",
        ],
    )
    @pytest.mark.asyncio
    async def test_rejected(self, url):
        with _resolves_to(PUBLIC_V4), pytest.raises(UnsafeURLError):
            await check_relay_url(url)

    @pytest.mark.parametrize(
        "url",
        [
            "https://127.0.0.1/hook",
            "https://10.0.0.5/hook",
            "https://172.16.0.1/hook",
            "https://192.168.1.1/hook",
            "https://169.254.169.254/latest/meta-data/",  # cloud metadata
            "https://100.64.0.1/",                         # CGNAT
            "https://0.0.0.0/",
            "https://224.0.0.1/",                          # multicast
            "https://[::1]/",
            "https://[fd00::1]/",                          # IPv6 unique-local
            "https://[fe80::1]/",                          # IPv6 link-local
            "https://[::ffff:127.0.0.1]/",                 # IPv4-mapped loopback
        ],
    )
    @pytest.mark.asyncio
    async def test_private_ip_literal_rejected_without_dns(self, url):
        resolver = AsyncMock()
        with patch.object(url_safety, "_resolve", new=resolver), pytest.raises(UnsafeURLError):
            await check_relay_url(url)
        resolver.assert_not_awaited()


# ─────────────────────────────────────────────────────────────────────────────
# DNS vetting
# ─────────────────────────────────────────────────────────────────────────────

class TestDnsVetting:
    @pytest.mark.asyncio
    async def test_public_hostname_accepted(self):
        with _resolves_to(PUBLIC_V4, PUBLIC_V6):
            await check_relay_url("https://relay.example.com/hook")

    @pytest.mark.parametrize("internal", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1"])
    @pytest.mark.asyncio
    async def test_hostname_resolving_to_internal_rejected(self, internal):
        with _resolves_to(internal), pytest.raises(UnsafeURLError):
            await check_relay_url("https://sneaky.example.com/hook")

    @pytest.mark.asyncio
    async def test_mixed_public_and_internal_records_rejected(self):
        with _resolves_to(PUBLIC_V4, "10.0.0.1"), pytest.raises(UnsafeURLError):
            await check_relay_url("https://sneaky.example.com/hook")

    @pytest.mark.asyncio
    async def test_unresolvable_hostname_rejected(self):
        with patch.object(
            url_safety, "_resolve", new=AsyncMock(side_effect=OSError("NXDOMAIN"))
        ), pytest.raises(UnsafeURLError, match="could not be resolved"):
            await check_relay_url("https://nope.invalid/hook")

    @pytest.mark.asyncio
    async def test_empty_resolution_rejected(self):
        with _resolves_to(), pytest.raises(UnsafeURLError):
            await check_relay_url("https://relay.example.com/hook")


# ─────────────────────────────────────────────────────────────────────────────
# IP pinning
# ─────────────────────────────────────────────────────────────────────────────

class TestPinning:
    @pytest.mark.asyncio
    async def test_pins_to_vetted_ipv4(self):
        with _resolves_to(PUBLIC_V4):
            t = await resolve_relay_target("https://relay.example.com/hook?x=1")
        assert t.url == f"https://{PUBLIC_V4}/hook?x=1"
        assert t.host_header == "relay.example.com"
        assert t.sni_hostname == "relay.example.com"

    @pytest.mark.asyncio
    async def test_pins_ipv6_with_brackets_and_keeps_port(self):
        with _resolves_to(PUBLIC_V6):
            t = await resolve_relay_target("https://relay.example.com:8443/hook")
        assert t.url == f"https://[{PUBLIC_V6}]:8443/hook"
        assert t.host_header == "relay.example.com:8443"

    @pytest.mark.asyncio
    async def test_drops_fragment(self):
        with _resolves_to(PUBLIC_V4):
            t = await resolve_relay_target("https://relay.example.com/hook#frag")
        assert "#" not in t.url


# ─────────────────────────────────────────────────────────────────────────────
# Relay service: what actually goes over the wire
# ─────────────────────────────────────────────────────────────────────────────

def _capture_transport(response: httpx.Response):
    """Patch the relay's httpx client so requests go to a MockTransport we inspect."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return response

    real_client = httpx.AsyncClient
    p = patch(
        "app.services.relay_service.httpx.AsyncClient",
        side_effect=lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw),
    )
    return p, seen


async def _forward(url: str):
    from app.services.relay_service import forward_event

    return await forward_event(
        relay_url=url, relay_secret="s3cret", event="push", payload={"a": 1}, installation_id=1
    )


class TestRelayService:
    @pytest.mark.asyncio
    async def test_request_goes_to_pinned_ip_with_real_host_and_sni(self):
        p, seen = _capture_transport(httpx.Response(200))
        with _resolves_to(PUBLIC_V4), p:
            assert await _forward("https://relay.example.com/hook") is True

        assert len(seen) == 1
        req = seen[0]
        assert req.url.host == PUBLIC_V4
        assert req.headers["Host"] == "relay.example.com"
        assert req.extensions["sni_hostname"] == "relay.example.com"
        assert req.headers["X-Aether-Relay-Secret"] == "s3cret"

    @pytest.mark.asyncio
    async def test_hostname_now_resolving_internal_is_blocked_and_never_sent(self):
        # DNS rebinding: URL passed at registration, now points inside.
        p, seen = _capture_transport(httpx.Response(200))
        with _resolves_to("169.254.169.254"), p, patch(
            "app.services.relay_service.asyncio.sleep", new=AsyncMock()
        ) as sleep:
            assert await _forward("https://relay.example.com/hook") is False

        assert seen == []
        sleep.assert_not_awaited()  # no pointless retries

    @pytest.mark.asyncio
    async def test_redirect_is_not_followed(self):
        redirect = httpx.Response(302, headers={"Location": "http://169.254.169.254/"})
        p, seen = _capture_transport(redirect)
        with _resolves_to(PUBLIC_V4), p:
            await _forward("https://relay.example.com/hook")

        assert len(seen) == 1
        assert seen[0].url.host == PUBLIC_V4
