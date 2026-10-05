"""Target parsing, DNS resolution, and public-address enforcement."""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlsplit

HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_target(value: object) -> str:
    """Return a normalized hostname or IP from a domain, address, or HTTP URL."""
    if not isinstance(value, str):
        raise TypeError("Enter a domain, IP address, or HTTP(S) URL.")
    raw = value.strip()
    if not raw or len(raw) > 253 or any(character.isspace() for character in raw):
        raise ValueError("Enter a valid target no longer than 253 characters.")
    try:
        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        if parsed.scheme and parsed.scheme not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS URLs are accepted.")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Credentials are not allowed in the target.")
        host = parsed.hostname
        if not host:
            raise ValueError("Enter a valid domain, IP address, or HTTP(S) URL.")
        try:
            parsed_port = parsed.port
        except ValueError:
            raise ValueError("The URL contains an invalid port.") from None
        if parsed_port == 0:
            raise ValueError("The URL contains an invalid port.")
    except UnicodeError:
        raise ValueError("Enter a valid domain or IP address.") from None
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        try:
            normalized = host.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise ValueError("Enter a valid domain or IP address.") from None
        if (
            len(normalized) > 253
            or not normalized
            or not all(HOST_LABEL.fullmatch(label) for label in normalized.split("."))
        ):
            raise ValueError("Enter a valid domain or IP address.")
        if re.fullmatch(r"[0-9.]+", normalized):
            raise ValueError("Enter a valid IP address.")
        return normalized


def public_ip(value: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse an address and reject every non-public or special-use range."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("The resolved IP address is invalid.") from None
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    if (
        not address.is_global
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise ValueError("The target must resolve only to public IP addresses.")
    return address


def require_public_ip(value: object, allow_private: bool = False) -> str:
    """Validate an API-supplied IP, with an explicit local-test escape hatch."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("The IP address is invalid.") from None
    if allow_private:
        return str(address)
    return str(public_ip(address))


def resolve_public_target(host: str) -> tuple[str, list[str]]:
    """Resolve once and reject the entire target when any answer is unsafe."""
    try:
        records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError("The target could not be resolved.") from None
    ips: list[str] = []
    for family, _, _, _, sockaddr in records:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        address = str(public_ip(sockaddr[0]))
        if address not in ips:
            ips.append(address)
    if not ips:
        raise ValueError("The target did not resolve to an IPv4 or IPv6 address.")
    return ips[0], ips
