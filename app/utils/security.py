"""Security utilities: key generation, hashing, timing-safe comparison."""

import hashlib
import hmac
import secrets


def generate_license_key() -> str:
    """Generate a cryptographically random license key.

    Format: aeth_{urlsafe_base64_48_chars}
    Example: aeth_K3mP9xQ2vR...
    """
    return f"aeth_{secrets.token_urlsafe(36)}"


def generate_relay_secret() -> str:
    """Generate a relay secret for webhook forwarding authentication."""
    return secrets.token_urlsafe(32)


def hash_key(key: str) -> str:
    """SHA-256 hex digest of a key. Used to store license keys safely.

    SHA-256 is appropriate here because:
    - Keys are cryptographically random (not user-chosen passwords)
    - Brute force is computationally infeasible against random 48-char tokens
    - Fast verification is desirable (every API call checks the key)
    """
    return hashlib.sha256(key.encode()).hexdigest()


def verify_key(provided: str, stored_hash: str) -> bool:
    """Timing-safe comparison of a provided key against its stored hash."""
    return hmac.compare_digest(hash_key(provided), stored_hash)


def verify_admin_key(provided: str, expected: str) -> bool:
    """Timing-safe comparison for admin API key."""
    return hmac.compare_digest(provided.encode(), expected.encode())
