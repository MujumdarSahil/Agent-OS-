"""
Trusted-proxy resolution for AgentOS (3.6b).

When AgentOS is deployed behind a reverse proxy (NGINX, Caddy, Cloudflare, AWS ALB, …) it needs
to know the *real* client IP so that:
  - Login rate-limiting is keyed on the real client, not on the proxy's address.
  - The audit log records the real source address.
  - Webhook rate limits target the real caller.
  - X-Forwarded-Proto drives secure-cookie decisions (HTTPS vs HTTP).
  - X-Forwarded-Host is considered for virtual-host routing (but must still pass the existing
    allowed-hosts check).

Security model
--------------
Only trusted peers may supply forwarding headers.  An untrusted peer (i.e. any direct connection
whose IP is NOT in ``AGENTOS_TRUSTED_PROXIES``) has ALL X-Forwarded-* headers completely stripped
(ignored) — they cannot fake a client IP, force HTTPS, or bypass the Host check.

``AGENTOS_TRUSTED_PROXIES`` is a comma-separated list of IPv4/IPv6 addresses or CIDR ranges, e.g.::

    AGENTOS_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,::1

Default: empty → no proxies trusted → current behaviour unchanged (direct peer IP always used).

X-Forwarded-For handling
------------------------
The right-most address in the XFF chain that is *not itself* a trusted proxy is taken as the
client IP.  This avoids the classic spoofing attack where an attacker prepends a fake IP:

    X-Forwarded-For: 1.2.3.4, 10.0.0.1
    peer: 10.0.0.2 (trusted)

    → walk from right: 10.0.0.1 is trusted, skip; 1.2.3.4 is not trusted → client = 1.2.3.4.

Multi-hop chains and IPv4-mapped addresses (``::ffff:a.b.c.d``) are handled correctly.

Usage
-----
Call ``resolve_client_ip(peer_ip, headers)`` from middleware before any rate-limit or audit call.
Call ``resolve_scheme(peer_ip, headers)`` to determine whether to set ``Secure`` cookies.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CIDR list parsing
# ---------------------------------------------------------------------------

_TRUSTED_NETWORKS: Optional[list[ipaddress.IPv4Network | ipaddress.IPv6Network]] = None
_LOADED_FROM: Optional[str] = None  # the env-var value we parsed


def _load_trusted_proxies() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse AGENTOS_TRUSTED_PROXIES from the environment (cached until the value changes)."""
    global _TRUSTED_NETWORKS, _LOADED_FROM
    raw = os.environ.get("AGENTOS_TRUSTED_PROXIES", "").strip()
    if _TRUSTED_NETWORKS is not None and raw == _LOADED_FROM:
        return _TRUSTED_NETWORKS
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            nets.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            logger.warning("AGENTOS_TRUSTED_PROXIES: ignoring invalid entry %r", token)
    _TRUSTED_NETWORKS = nets
    _LOADED_FROM = raw
    return nets


def _strip_port_and_normalise(token: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Parse and normalise an IP address string, stripping port if present.

    Handles:
      - Plain IPv4: "1.2.3.4"
      - IPv4 with port: "1.2.3.4:5678"
      - Plain IPv6: "2001:db8::1"
      - Bracketed IPv6: "[2001:db8::1]"
      - Bracketed IPv6 with port: "[2001:db8::1]:443"
      - IPv4-mapped IPv6: "::ffff:1.2.3.4" or "[::ffff:1.2.3.4]:8080" (unwrapped to IPv4)

    Returns None on failure or if port/syntax is invalid.
    """
    token = token.strip()
    if not token:
        return None

    # Bracketed IPv6: [2001:db8::1] or [2001:db8::1]:443
    if token.startswith("["):
        close_idx = token.find("]")
        if close_idx == -1:
            return None
        ip_str = token[1:close_idx].strip()
        remainder = token[close_idx + 1:].strip()
        if remainder:
            if not remainder.startswith(":"):
                return None
            port_str = remainder[1:].strip()
            if not (port_str.isdigit() and 0 <= int(port_str) <= 65535):
                return None
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return None
        if not isinstance(ip, ipaddress.IPv6Address):
            return None
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        return ip

    # IPv4 with port: "1.2.3.4:5678" (single colon and dot present)
    if token.count(":") == 1 and "." in token:
        host_str, port_str = token.split(":", 1)
        host_str = host_str.strip()
        port_str = port_str.strip()
        if not (port_str.isdigit() and 0 <= int(port_str) <= 65535):
            return None
        try:
            ip = ipaddress.ip_address(host_str)
        except ValueError:
            return None
        if isinstance(ip, ipaddress.IPv4Address):
            return ip
        return None

    # Plain IP (IPv4 or IPv6 without brackets or port)
    try:
        ip = ipaddress.ip_address(token)
    except ValueError:
        return None

    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _normalise_ip(addr: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Parse and normalise an IP address string; return None on failure."""
    return _strip_port_and_normalise(addr)


def _is_trusted(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    for net in _load_trusted_proxies():
        try:
            if ip in net:
                return True
        except TypeError:
            # IPv4 address vs IPv6 network: not in
            pass
    return False


def peer_is_trusted(peer_ip: str) -> bool:
    """Return True if the direct peer address is in the configured trusted-proxy list."""
    ip = _normalise_ip(peer_ip)
    if ip is None:
        return False
    return _is_trusted(ip)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def resolve_client_ip(peer_ip: str, headers: dict[str, str]) -> str:
    """Return the best-available client IP for the request.

    Parameters
    ----------
    peer_ip:
        The IP of the direct TCP/TLS connection peer (``request.client.host``).
    headers:
        A dict of *lower-cased* header names → values, as decoded from the ASGI scope.

    Returns
    -------
    The resolved client IP string (never empty; falls back to ``peer_ip`` on any parse failure).

    Security guarantee
    ------------------
    If ``peer_ip`` is NOT in ``AGENTOS_TRUSTED_PROXIES``, the ``X-Forwarded-For`` header is
    silently ignored and ``peer_ip`` is returned.  An attacker on an untrusted network cannot
    spoof a different client IP.

    When walking the ``X-Forwarded-For`` chain from right to left:
      - Ports are safely stripped ("1.2.3.4:5678" and "[2001:db8::1]:443").
      - If any entry cannot be parsed (garbage, malformed, empty entry), processing STOPS
        immediately and ``peer_ip`` is returned (never continuing further left to avoid spoofing).
      - The first valid IP that is NOT a trusted proxy is returned.
      - If all addresses in the chain are trusted proxies, the left-most client IP is returned.
    """
    if not peer_is_trusted(peer_ip):
        return peer_ip

    xff = headers.get("x-forwarded-for", "")
    if not xff or not xff.strip():
        return peer_ip

    raw_entries = [a.strip() for a in xff.split(",")]
    if not raw_entries:
        return peer_ip

    # Walk the chain from right to left.
    for candidate in reversed(raw_entries):
        if not candidate:
            # Empty entry in chain -> STOP and return direct peer address
            return peer_ip
        ip = _strip_port_and_normalise(candidate)
        if ip is None:
            # Unparseable entry -> STOP and return direct peer address (never continue further left)
            return peer_ip
        if not _is_trusted(ip):
            return str(ip)

    # Every address in the chain is a trusted proxy. Return the left-most.
    first_ip = _strip_port_and_normalise(raw_entries[0])
    return str(first_ip) if first_ip is not None else peer_ip


def resolve_scheme(peer_ip: str, headers: dict[str, str], conn_scheme: str = "http") -> str:
    """Return the effective request scheme ("https" or "http").

    Considers ``X-Forwarded-Proto`` only when the peer is trusted.
    If the peer is untrusted, returns the real connection scheme ``conn_scheme``.
    """
    if peer_is_trusted(peer_ip):
        proto = headers.get("x-forwarded-proto", "").strip().lower()
        if proto in ("https", "http"):
            return proto
    return conn_scheme


def resolve_host(peer_ip: str, headers: dict[str, str]) -> Optional[str]:
    """Return the X-Forwarded-Host value only when the peer is trusted.

    The returned value MUST still be validated against the existing allowed-hosts list by the
    caller — this function does no host validation of its own.  Returns None when the header
    should be ignored.
    """
    if not peer_is_trusted(peer_ip):
        return None
    fwd_host = headers.get("x-forwarded-host", "").strip()
    return fwd_host if fwd_host else None
