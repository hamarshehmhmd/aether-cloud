"""Relay delivery signing: HMAC, timestamps, delivery IDs, and what goes over the wire."""

import hashlib
import hmac
import ipaddress
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.utils import relay_signing as rs
from app.utils import url_safety

SECRET = "relay-secret"
BODY = b'{"action":"opened","installation":{"id":42}}'
DELIVERY = "72d3162e-cc78-11e3-81ab-4c9367dc0958"
NOW = 1_800_000_000


def _headers(**kw) -> dict[str, str]:
    return rs.signature_headers(SECRET, kw.get("delivery", DELIVERY), kw.get("body", BODY), now=NOW)


def _verify(h: dict[str, str], *, body=BODY, secret=SECRET, now=NOW) -> bool:
    return rs.verify_signature(
        secret,
        h[rs.TIMESTAMP_HEADER],
        h[rs.DELIVERY_HEADER],
        h[rs.SIGNATURE_HEADER],
        body,
        now=now,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Signing and verification
# ─────────────────────────────────────────────────────────────────────────────

class TestSigning:
    def test_round_trip(self):
        assert _verify(_headers()) is True

    def test_matches_documented_construction(self):
        """Receivers in other languages implement this exact formula."""
        h = _headers()
        msg = f"v1:{NOW}:{DELIVERY}:".encode() + BODY
        expected = "sha256=" + hmac.new(SECRET.encode(), msg, hashlib.sha256).hexdigest()
        assert h[rs.SIGNATURE_HEADER] == expected
        assert h[rs.TIMESTAMP_HEADER] == str(NOW)
        assert h[rs.DELIVERY_HEADER] == DELIVERY

    def test_secret_is_not_in_headers(self):
        assert all(SECRET not in v for v in _headers().values())

    def test_tampered_body_rejected(self):
        assert _verify(_headers(), body=BODY + b" ") is False

    def test_wrong_secret_rejected(self):
        assert _verify(_headers(), secret="other") is False

    def test_swapped_delivery_id_rejected(self):
        h = _headers()
        h[rs.DELIVERY_HEADER] = "another-delivery"
        assert _verify(h) is False

    def test_altered_timestamp_rejected(self):
        h = _headers()
        h[rs.TIMESTAMP_HEADER] = str(NOW + 1)
        assert _verify(h) is False

    @pytest.mark.parametrize("offset", [rs.MAX_SKEW_SECONDS + 1, -(rs.MAX_SKEW_SECONDS + 1)])
    def test_stale_or_future_timestamp_rejected(self, offset):
        assert _verify(_headers(), now=NOW + offset) is False

    @pytest.mark.parametrize("offset", [rs.MAX_SKEW_SECONDS, -rs.MAX_SKEW_SECONDS, 0])
    def test_within_skew_window_accepted(self, offset):
        assert _verify(_headers(), now=NOW + offset) is True

    @pytest.mark.parametrize("ts", ["", "abc", "-5", "1.5", " 1800000000"])
    def test_malformed_timestamp_rejected(self, ts):
        h = _headers()
        h[rs.TIMESTAMP_HEADER] = ts
        assert _verify(h) is False

    def test_signature_without_prefix_rejected(self):
        h = _headers()
        h[rs.SIGNATURE_HEADER] = h[rs.SIGNATURE_HEADER].removeprefix("sha256=")
        assert _verify(h) is False

    @pytest.mark.parametrize("bad", ["", "has:colon", "x" * 129])
    def test_invalid_delivery_id_refused_when_signing(self, bad):
        with pytest.raises(ValueError):
            rs.sign(SECRET, str(NOW), bad, BODY)


# ─────────────────────────────────────────────────────────────────────────────
# Relay service: signed, raw bytes, secret never sent
# ─────────────────────────────────────────────────────────────────────────────

def _capture(*responses: httpx.Response):
    seen: list[httpx.Request] = []
    queue = list(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return queue.pop(0) if len(queue) > 1 else queue[0]

    real_client = httpx.AsyncClient
    p = patch(
        "app.services.relay_service.httpx.AsyncClient",
        side_effect=lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw),
    )
    return p, seen


def _public_dns():
    return patch.object(
        url_safety,
        "_resolve",
        new=AsyncMock(return_value=[ipaddress.ip_address("93.184.216.34")]),
    )


async def _forward():
    from app.services.relay_service import forward_event

    return await forward_event(
        relay_url="https://relay.example.com/hook",
        relay_secret=SECRET,
        event="pull_request",
        body=BODY,
        delivery_id=DELIVERY,
        installation_id=42,
    )


class TestRelayWire:
    @pytest.mark.asyncio
    async def test_sends_raw_body_signed_without_secret(self):
        p, seen = _capture(httpx.Response(200))
        with _public_dns(), p:
            assert await _forward() is True

        req = seen[0]
        assert req.content == BODY  # byte-for-byte, not re-serialized
        assert "X-Aether-Relay-Secret" not in req.headers
        assert all(SECRET not in v for v in req.headers.values())
        assert req.headers["X-GitHub-Event"] == "pull_request"
        assert rs.verify_signature(
            SECRET,
            req.headers[rs.TIMESTAMP_HEADER],
            req.headers[rs.DELIVERY_HEADER],
            req.headers[rs.SIGNATURE_HEADER],
            req.content,
        )

    @pytest.mark.asyncio
    async def test_retries_keep_delivery_id_and_are_each_validly_signed(self):
        p, seen = _capture(httpx.Response(503), httpx.Response(503), httpx.Response(200))
        with _public_dns(), p, patch(
            "app.services.relay_service.asyncio.sleep", new=AsyncMock()
        ):
            assert await _forward() is True

        assert len(seen) == 3
        assert {r.headers[rs.DELIVERY_HEADER] for r in seen} == {DELIVERY}
        for r in seen:
            assert rs.verify_signature(
                SECRET,
                r.headers[rs.TIMESTAMP_HEADER],
                r.headers[rs.DELIVERY_HEADER],
                r.headers[rs.SIGNATURE_HEADER],
                r.content,
            )


# ─────────────────────────────────────────────────────────────────────────────
# Webhook router: hands raw bytes and GitHub's delivery ID to the relay
# ─────────────────────────────────────────────────────────────────────────────

def _github_sig(body: bytes) -> str:
    from app.config import get_settings

    key = get_settings().github_webhook_secret.encode()
    return "sha256=" + hmac.new(key, body, hashlib.sha256).hexdigest()


class TestWebhookRouter:
    @pytest.mark.asyncio
    async def test_relays_raw_body_and_github_delivery_id(self, client):
        relay = AsyncMock()
        # Unusual spacing proves the bytes are forwarded untouched, not re-encoded.
        body = b'{ "installation" : { "id" : 42 } ,"x":1}'
        with patch("app.routers.webhooks._relay_to_self_hosted", new=relay):
            resp = await client.post(
                "/webhooks/github",
                content=body,
                headers={
                    "X-Hub-Signature-256": _github_sig(body),
                    "X-GitHub-Event": "push",
                    "X-GitHub-Delivery": DELIVERY,
                    "Content-Type": "application/json",
                },
            )

        assert resp.status_code == 200
        relay.assert_awaited_once_with(
            installation_id=42, event="push", body=body, delivery_id=DELIVERY
        )

    @pytest.mark.parametrize("delivery", [None, "bad:id"])
    @pytest.mark.asyncio
    async def test_missing_or_malformed_delivery_id_is_replaced(self, client, delivery):
        relay = AsyncMock()
        body = json.dumps({"installation": {"id": 42}}).encode()
        headers = {
            "X-Hub-Signature-256": _github_sig(body),
            "X-GitHub-Event": "push",
            "Content-Type": "application/json",
        }
        if delivery:
            headers["X-GitHub-Delivery"] = delivery
        with patch("app.routers.webhooks._relay_to_self_hosted", new=relay):
            resp = await client.post("/webhooks/github", content=body, headers=headers)

        assert resp.status_code == 200
        sent = relay.await_args.kwargs["delivery_id"]
        assert sent and ":" not in sent

    @pytest.mark.asyncio
    async def test_bad_github_signature_relays_nothing(self, client):
        relay = AsyncMock()
        body = b'{"installation":{"id":42}}'
        with patch("app.routers.webhooks._relay_to_self_hosted", new=relay):
            resp = await client.post(
                "/webhooks/github",
                content=body,
                headers={"X-Hub-Signature-256": "sha256=" + "0" * 64, "X-GitHub-Event": "push"},
            )

        assert resp.status_code == 401
        relay.assert_not_awaited()
