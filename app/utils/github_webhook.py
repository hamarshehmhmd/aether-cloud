"""HMAC-SHA256 webhook signature verification."""

import hashlib
import hmac


def verify_signature(payload: bytes, signature_header: str, secret: str) -> bool:
    """Verify a GitHub webhook HMAC-SHA256 signature."""
    if not signature_header.startswith("sha256="):
        return False
    expected = hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()
    provided = signature_header[len("sha256="):]
    # Compare bytes: compare_digest on str raises TypeError for non-ASCII input.
    return hmac.compare_digest(expected.encode(), provided.encode())
