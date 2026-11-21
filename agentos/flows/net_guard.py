"""
SSRF guard and HTTP transport for the http_request node (sub-milestone 2.3).

Pure domain code (no FastAPI). Every outgoing request:
  1. allows only http/https and rejects URLs with embedded credentials;
  2. resolves DNS (injectable resolver) and checks EVERY resolved address against blocked ranges
     (loopback, unspecified, private, unique-local, link-local, CGNAT, multicast, reserved, cloud
     metadata), unwrapping IPv4-mapped / NAT64 / 6to4 IPv6 forms; admin-allowlisted hosts/CIDRs pass;
  3. connects to the CHECKED IP (Host header and TLS SNI keep the hostname), so a second DNS
     answer cannot swap in a private address (DNS rebinding);
  4. follows redirects manually (max 3), re-checking every hop and dropping credential headers
     when the host changes;
  5. streams the body and stops at a size cap; per-request timeout.
"""

from __future__ import annotations

import ipaddress
import json
import socket
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

MAX_REDIRECTS = 3
DEFAULT_TIMEOUT_S = 10.0
MAX_TIMEOUT_S = 30.0
DEFAULT_MAX_BYTES = 1_000_000
MAX_MAX_BYTES = 5_000_000

BLOCKED_NETWORKS: list[tuple[Any, str]] = [
    (ipaddress.ip_network("0.0.0.0/8"), "unspecified/this-network"),
    (ipaddress.ip_network("10.0.0.0/8"), "private"),
    (ipaddress.ip_network("100.64.0.0/10"), "CGNAT"),
    (ipaddress.ip_network("127.0.0.0/8"), "loopback"),
    (ipaddress.ip_network("169.254.0.0/16"), "link-local / cloud metadata"),
    (ipaddress.ip_network("172.16.0.0/12"), "private"),
    (ipaddress.ip_network("192.0.0.0/24"), "IETF protocol assignments"),
    (ipaddress.ip_network("192.168.0.0/16"), "private"),
    (ipaddress.ip_network("198.18.0.0/15"), "benchmarking"),
    (ipaddress.ip_network("224.0.0.0/4"), "multicast"),
    (ipaddress.ip_network("240.0.0.0/4"), "reserved"),
    (ipaddress.ip_network("::/128"), "unspecified"),
    (ipaddress.ip_network("::1/128"), "loopback"),
    (ipaddress.ip_network("fc00::/7"), "unique-local (private)"),
    (ipaddress.ip_network("fe80::/10"), "link-local"),
    (ipaddress.ip_network("ff00::/8"), "multicast"),
]
CLOUD_METADATA_IPS = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("fd00:ec2::254")}
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_6TO4 = ipaddress.ip_network("2002::/16")

CREDENTIAL_HEADERS = {"authorization", "proxy-authorization", "cookie", "x-api-key"}


class SSRFBlockedError(Exception):
    """The destination is not allowed (scheme, credentials, blocked address or too many redirects)."""


Resolver = Callable[[str, int], list[str]]


def default_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({info[4][0] for info in infos})


def _embedded_ipv4(ip: Any) -> ipaddress.IPv4Address | None:
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip in _NAT64:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if ip in _6TO4 and ip.sixtofour is not None:
            return ip.sixtofour
    return None


def blocked_reason(ip_str: str) -> str | None:
    """Why an address is blocked, or None if it is a public unicast address."""
    try:
        ip = ipaddress.ip_address(ip_str.split("%", 1)[0])
    except ValueError:
        return f"unparseable address {ip_str!r}"
    if ip in CLOUD_METADATA_IPS:
        return "cloud metadata"
    inner = _embedded_ipv4(ip)
    if inner is not None:
        inner_reason = blocked_reason(str(inner))
        if inner_reason:
            return f"{inner_reason} (embedded in IPv6 {ip})"
    for net, reason in BLOCKED_NETWORKS:
        if ip.version == net.version and ip in net:
            return reason
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return "non-public address"
    return None


def _normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".").strip("[]")


def host_matches_allowlist(host: str, ips: Iterable[str], allowlist: Iterable[str]) -> bool:
    """Admin allowlist entries: exact hostnames, '*.suffix' wildcards, or IP/CIDR ranges."""
    h = _normalize_host(host)
    parsed_ips = []
    for ip in ips:
        try:
            parsed_ips.append(ipaddress.ip_address(ip.split("%", 1)[0]))
        except ValueError:
            continue
    for entry in allowlist:
        e = entry.strip().lower()
        if not e:
            continue
        if e.startswith("*."):
            if h.endswith(e[1:]) and h != e[2:]:
                return True
            continue
        try:
            net = ipaddress.ip_network(e, strict=False)
        except ValueError:
            if h == _normalize_host(e):
                return True
            continue
        if parsed_ips and all(ip.version == net.version and ip in net for ip in parsed_ips):
            return True
    return False


def url_host(url: str) -> str:
    return _normalize_host(urlsplit(url).hostname or "")


@dataclass
class CheckedTarget:
    url: str
    scheme: str
    host: str
    port: int
    ip: str
    allowlisted: bool
    resolved: list[str] = field(default_factory=list)


def check_url(url: str, allowlist: Iterable[str] = (), resolver: Resolver | None = None) -> CheckedTarget:
    """Validate a URL and pick the IP to connect to. Raises SSRFBlockedError."""
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise SSRFBlockedError(f"scheme {scheme or '(none)'!r} is not allowed; only http/https")
    if parts.username or parts.password:
        raise SSRFBlockedError("URLs with embedded credentials are not allowed")
    host = _normalize_host(parts.hostname or "")
    if not host:
        raise SSRFBlockedError("URL has no host")
    port = parts.port or (443 if scheme == "https" else 80)
    try:
        ips = [str(ipaddress.ip_address(host))]
    except ValueError:
        try:
            ips = (resolver or default_resolver)(host, port)
        except OSError as err:
            raise SSRFBlockedError(f"DNS resolution failed for {host!r}: {err}") from err
    if not ips:
        raise SSRFBlockedError(f"{host!r} did not resolve to any address")
    allowed = host_matches_allowlist(host, ips, list(allowlist))
    if not allowed:
        for ip in ips:
            reason = blocked_reason(ip)
            if reason:
                raise SSRFBlockedError(f"{host!r} resolves to blocked address {ip} ({reason})")
    return CheckedTarget(url=url, scheme=scheme, host=host, port=port, ip=ips[0], allowlisted=allowed, resolved=list(ips))


@dataclass
class RawResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    truncated: bool = False


# A sender performs ONE request to an already-checked IP (no redirects). Injectable for tests.
Sender = Callable[[str, CheckedTarget, str, dict[str, str], "bytes | None", float, int], RawResponse]


def httpx_sender(method: str, target: CheckedTarget, path_and_query: str, headers: dict[str, str],
                 body: bytes | None, timeout_s: float, max_bytes: int) -> RawResponse:
    import httpx

    ip_host = f"[{target.ip}]" if ":" in target.ip else target.ip
    url = f"{target.scheme}://{ip_host}:{target.port}{path_and_query}"
    host_header = target.host if target.port in (80, 443) else f"{target.host}:{target.port}"
    req_headers = {**headers, "Host": host_header}
    extensions = {"sni_hostname": target.host} if target.scheme == "https" else {}
    with httpx.Client(follow_redirects=False, timeout=timeout_s, trust_env=False) as client:
        with client.stream(method, url, headers=req_headers, content=body, extensions=extensions) as resp:
            chunks: list[bytes] = []
            size = 0
            truncated = False
            for chunk in resp.iter_bytes():
                if size + len(chunk) > max_bytes:
                    chunks.append(chunk[: max_bytes - size])
                    truncated = True
                    break
                size += len(chunk)
                chunks.append(chunk)
            return RawResponse(resp.status_code, {k.lower(): v for k, v in resp.headers.items()}, b"".join(chunks), truncated)


def _path_and_query(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit(("", "", p.path or "/", p.query, ""))


class HttpRequestTransport:
    """Executes http_request calls with SSRF checks on every hop. Injectable resolver/sender."""

    def __init__(self, allowlist: Iterable[str] = (), resolver: Resolver | None = None, sender: Sender | None = None):
        self.allowlist = list(allowlist)
        self.resolver = resolver
        self.sender = sender or httpx_sender
        self.sent_calls: list[dict[str, Any]] = []

    def request(self, method: str, url: str, headers: dict[str, str] | None = None, query: dict[str, Any] | None = None,
                body: Any = None, timeout_s: float = DEFAULT_TIMEOUT_S, max_bytes: int = DEFAULT_MAX_BYTES,
                credential_headers: dict[str, str] | None = None) -> dict[str, Any]:
        method = (method or "GET").upper()
        timeout_s = max(0.1, min(float(timeout_s or DEFAULT_TIMEOUT_S), MAX_TIMEOUT_S))
        max_bytes = max(1, min(int(max_bytes or DEFAULT_MAX_BYTES), MAX_MAX_BYTES))
        if query:
            sep = "&" if urlsplit(url).query else "?"
            url = f"{url}{sep}{urlencode({k: v if isinstance(v, str) else json.dumps(v) for k, v in query.items()})}"
        plain_headers = {k: str(v) for k, v in (headers or {}).items()}
        data: bytes | None
        if body is None or body == "":
            data = None
        elif isinstance(body, (bytes, bytearray)):
            data = bytes(body)
        elif isinstance(body, str):
            data = body.encode("utf-8")
        else:
            data = json.dumps(body).encode("utf-8")
            plain_headers.setdefault("Content-Type", "application/json")
        creds = dict(credential_headers or {})

        target = check_url(url, self.allowlist, self.resolver)
        origin_host = target.host
        hops: list[str] = []
        for hop in range(MAX_REDIRECTS + 1):
            send_headers = dict(plain_headers)
            if target.host == origin_host:
                send_headers.update(creds)  # credentials never follow a redirect to another host
            self.sent_calls.append({
                "method": method, "url": target.url, "ip": target.ip, "host": target.host,
                "credential_headers": sorted(k for k in send_headers if k in creds or k.lower() in CREDENTIAL_HEADERS),
            })
            raw = self.sender(method, target, _path_and_query(target.url), send_headers, data, timeout_s, max_bytes)
            location = raw.headers.get("location")
            if raw.status in (301, 302, 303, 307, 308) and location:
                if hop == MAX_REDIRECTS:
                    raise SSRFBlockedError(f"too many redirects (max {MAX_REDIRECTS})")
                next_url = urljoin(target.url, location)
                hops.append(next_url)
                target = check_url(next_url, self.allowlist, self.resolver)
                if raw.status == 303 or (raw.status in (301, 302) and method == "POST"):
                    method, data = "GET", None
                continue
            return {
                "status": raw.status,
                "headers": {k: v for k, v in raw.headers.items() if k in ("content-type", "content-length")},
                "body": raw.body.decode("utf-8", errors="replace"),
                "final_url": target.url,
                "redirects": hops,
                "truncated": raw.truncated,
            }
        raise SSRFBlockedError(f"too many redirects (max {MAX_REDIRECTS})")
