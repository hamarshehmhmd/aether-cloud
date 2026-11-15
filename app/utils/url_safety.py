"""SSRF protection for customer-supplied relay URLs.

Customers choose their relay_url and this service POSTs webhook payloads to it.
Without checks, a customer could point it at internal targets (cloud metadata at
169.254.169.254, Redis, Postgres, other private services) and use this server to
reach them.

Two layers:
  1. check_relay_url()      at registration: reject obviously bad URLs early.
  2. resolve_relay_target() at send time: resolve DNS, require every address to
     be public, and return a target pinned to the vetted IP. Checking only at
     registration is not enough: DNS can change afterwards (DNS rebinding), so
     the address actually connected to must be the one that was checked.

Redirects must never be followed (the relay client disables them), or a public
URL could bounce the request to an internal one.
"""

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class UnsafeURLError(ValueError):
    """The URL is not an acceptable relay target. Message is safe to show the caller."""


@dataclass(frozen=True)
class RelayTarget:
    """A request target pinned to a vetted IP.

    url:          original URL with the host replaced by the vetted IP
    host_header:  original Host header value (hostname[:port])
    sni_hostname: hostname for TLS SNI and certificate verification
    """

    url: str
    host_header: str
    sni_hostname: str


def _is_public(ip: IPAddress) -> bool:
    # ::ffff:10.0.0.1 is really 10.0.0.1. Judge the embedded IPv4 address.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    # is_global excludes private, loopback, link-local, reserved, shared (CGNAT),
    # unspecified, and documentation ranges. Multicast can still count as
    # "global", so exclude it explicitly.
    return ip.is_global and not ip.is_multicast


def _parse(url: str) -> tuple[str, int]:
    """Validate URL shape. Returns (hostname, port)."""
    try:
        parts = urlsplit(url)
        port = parts.port  # raises ValueError on a malformed port
    except ValueError:
        raise UnsafeURLError("relay_url is not a valid URL")

    if parts.scheme != "https":
        raise UnsafeURLError("relay_url must use https")
    if parts.username is not None or parts.password is not None:
        raise UnsafeURLError("relay_url must not contain credentials")

    host = parts.hostname
    if not host:
        raise UnsafeURLError("relay_url must include a hostname")

    # IP literals are only allowed if public. Hostnames are resolved later.
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None and not _is_public(literal):
        raise UnsafeURLError("relay_url must not point to a private or reserved address")

    return host, port or 443


async def _resolve(host: str, port: int) -> list[IPAddress]:
    """Resolve host to all of its addresses (A and AAAA). Patched in tests."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    # sockaddr[0] is the address; strip an IPv6 zone id like "fe80::1%eth0".
    return [ipaddress.ip_address(info[4][0].split("%", 1)[0]) for info in infos]


async def _resolve_public(host: str, port: int) -> list[IPAddress]:
    try:
        addresses = await _resolve(host, port)
    except (OSError, UnicodeError):
        raise UnsafeURLError("relay_url hostname could not be resolved")
    if not addresses:
        raise UnsafeURLError("relay_url hostname could not be resolved")
    # Reject if ANY address is non-public. Allowing mixed answers would let an
    # attacker publish one public and one internal record and hope for the latter.
    if not all(_is_public(ip) for ip in addresses):
        raise UnsafeURLError("relay_url must not point to a private or reserved address")
    return addresses


async def check_relay_url(url: str) -> None:
    """Registration-time check. Raises UnsafeURLError if the URL is not acceptable."""
    host, port = _parse(url)
    await _resolve_public(host, port)


async def resolve_relay_target(url: str) -> RelayTarget:
    """Send-time check. Resolve, vet, and pin the request to a public IP."""
    host, port = _parse(url)
    ip = (await _resolve_public(host, port))[0]

    parts = urlsplit(url)
    ip_host = f"[{ip}]" if ip.version == 6 else str(ip)
    netloc = ip_host if parts.port is None else f"{ip_host}:{parts.port}"
    header_host = f"[{host}]" if ":" in host else host  # IPv6 literal needs brackets
    host_header = header_host if parts.port is None else f"{header_host}:{parts.port}"

    return RelayTarget(
        url=urlunsplit((parts.scheme, netloc, parts.path, parts.query, "")),
        host_header=host_header,
        sni_hostname=host,
    )
