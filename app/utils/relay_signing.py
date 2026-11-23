"""Signing for relayed webhook deliveries (aether-cloud → self-hosted instance).

Previously the relay sent the shared secret itself in a header. Anyone who saw
one request (a proxy log, a misconfigured TLS terminator) had the secret, could
forge arbitrary events forever, and could replay captured requests.

Now the secret never leaves this service. Each delivery carries:

    X-Aether-Timestamp:     unix seconds when the request was signed
    X-Aether-Delivery:      unique delivery ID (GitHub's X-GitHub-Delivery)
    X-Aether-Signature-256: sha256=HMAC_SHA256(relay_secret, message)

    message = b"v1:" + timestamp + b":" + delivery_id + b":" + raw_body

The receiver MUST, in this order:
  1. reject if |now - timestamp| > MAX_SKEW_SECONDS        (stale replay)
  2. recompute the HMAC and compare in constant time        (forgery/tampering)
  3. reject a delivery ID it has already processed within
     the skew window                                        (replay inside window)

Retries are re-signed with a fresh timestamp but keep the same delivery ID, so
step 3 also deduplicates retries. verify_signature() below is the reference
implementation of steps 1 and 2.
"""

import hashlib
import hmac
import time

TIMESTAMP_HEADER = "X-Aether-Timestamp"
DELIVERY_HEADER = "X-Aether-Delivery"
SIGNATURE_HEADER = "X-Aether-Signature-256"

MAX_SKEW_SECONDS = 300
_VERSION = "v1"
_PREFIX = "sha256="


def _message(timestamp: str, delivery_id: str, body: bytes) -> bytes:
    return f"{_VERSION}:{timestamp}:{delivery_id}:".encode() + body


def _valid_delivery_id(delivery_id: str) -> bool:
    # ":" is the field separator; forbidding it keeps the message unambiguous.
    return bool(delivery_id) and ":" not in delivery_id and len(delivery_id) <= 128


def sign(secret: str, timestamp: str, delivery_id: str, body: bytes) -> str:
    if not _valid_delivery_id(delivery_id):
        raise ValueError("invalid delivery id")
    mac = hmac.new(secret.encode(), _message(timestamp, delivery_id, body), hashlib.sha256)
    return _PREFIX + mac.hexdigest()


def signature_headers(
    secret: str, delivery_id: str, body: bytes, now: int | None = None
) -> dict[str, str]:
    """Headers to attach to one delivery attempt."""
    timestamp = str(int(time.time()) if now is None else now)
    return {
        TIMESTAMP_HEADER: timestamp,
        DELIVERY_HEADER: delivery_id,
        SIGNATURE_HEADER: sign(secret, timestamp, delivery_id, body),
    }


def verify_signature(
    secret: str,
    timestamp: str,
    delivery_id: str,
    signature: str,
    body: bytes,
    now: int | None = None,
    max_skew: int = MAX_SKEW_SECONDS,
) -> bool:
    """Reference receiver check (steps 1 and 2). Delivery-ID dedupe is the caller's job."""
    if not timestamp.isdigit() or not _valid_delivery_id(delivery_id):
        return False
    current = int(time.time()) if now is None else now
    if abs(current - int(timestamp)) > max_skew:
        return False
    if not signature.startswith(_PREFIX):
        return False
    expected = sign(secret, timestamp, delivery_id, body)
    # Compare bytes: compare_digest on str raises TypeError for non-ASCII input.
    return hmac.compare_digest(expected.encode(), signature.encode())
