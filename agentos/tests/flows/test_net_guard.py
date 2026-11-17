"""SSRF guard for the http_request node (2.3). MOCK: fake resolver/sender; one test uses a local
loopback HTTP server (allowlisted) to exercise the real httpx sender without external network."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agentos.flows.net_guard import (
    HttpRequestTransport,
    RawResponse,
    SSRFBlockedError,
    blocked_reason,
    check_url,
)

BLOCKED = [
    ("127.0.0.1", "loopback"), ("127.255.0.9", "loopback"), ("::1", "loopback"),
    ("0.0.0.0", "unspecified"), ("::", "unspecified"),
    ("10.1.2.3", "private"), ("172.16.5.4", "private"), ("172.31.255.255", "private"), ("192.168.1.10", "private"),
    ("fc00::1", "unique-local"), ("fd12:3456::1", "unique-local"),
    ("169.254.10.10", "link-local"), ("fe80::1", "link-local"),
    ("100.64.0.1", "CGNAT"), ("100.127.255.254", "CGNAT"),
    ("224.0.0.1", "multicast"), ("239.255.255.250", "multicast"), ("ff02::1", "multicast"),
    ("169.254.169.254", "cloud metadata"), ("fd00:ec2::254", "cloud metadata"),
    ("::ffff:127.0.0.1", "IPv4-mapped loopback"), ("::ffff:169.254.169.254", "IPv4-mapped metadata"),
    ("64:ff9b::a00:1", "NAT64 private"), ("2002:a00:1::1", "6to4 private"),
    ("240.0.0.1", "reserved"),
]


@pytest.mark.parametrize("ip,label", BLOCKED, ids=[f"{ip}-{label}" for ip, label in BLOCKED])
def test_blocked_ranges(ip, label):
    assert blocked_reason(ip) is not None
    host = f"[{ip}]" if ":" in ip else ip
    with pytest.raises(SSRFBlockedError):
        check_url(f"http://{host}/x")


@pytest.mark.parametrize("ip", ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses_pass(ip):
    assert blocked_reason(ip) is None


@pytest.mark.parametrize("url", ["file:///etc/passwd", "gopher://x/", "ftp://example.com/", "javascript:alert(1)", "//example.com"])
def test_only_http_https(url):
    with pytest.raises(SSRFBlockedError, match="scheme"):
        check_url(url, resolver=lambda h, p: ["93.184.216.34"])


def test_embedded_credentials_rejected():
    with pytest.raises(SSRFBlockedError, match="credentials"):
        check_url("http://user:pw@example.com/", resolver=lambda h, p: ["93.184.216.34"])


def test_dns_rebinding_name_resolving_to_private_ip_is_blocked():
    with pytest.raises(SSRFBlockedError, match="10.0.0.5"):
        check_url("https://innocent.example.com/", resolver=lambda h, p: ["10.0.0.5"])


def test_any_private_record_among_public_ones_is_blocked():
    with pytest.raises(SSRFBlockedError, match="127.0.0.1"):
        check_url("https://mixed.example.com/", resolver=lambda h, p: ["93.184.216.34", "127.0.0.1"])


def test_admin_allowlist_permits_internal_host_and_cidr():
    t = check_url("http://wiki.corp.internal/a", allowlist=["wiki.corp.internal"], resolver=lambda h, p: ["10.2.3.4"])
    assert t.allowlisted and t.ip == "10.2.3.4"
    t2 = check_url("http://svc.corp.internal/a", allowlist=["*.corp.internal"], resolver=lambda h, p: ["10.2.3.5"])
    assert t2.allowlisted
    t3 = check_url("http://10.9.0.7/a", allowlist=["10.9.0.0/16"])
    assert t3.allowlisted
    with pytest.raises(SSRFBlockedError):
        check_url("http://other.corp.example/a", allowlist=["*.corp.internal"], resolver=lambda h, p: ["10.2.3.6"])


def _sender_from(routes):
    calls = []

    def sender(method, target, path, headers, body, timeout_s, max_bytes):
        calls.append({"method": method, "host": target.host, "ip": target.ip, "path": path, "headers": dict(headers)})
        return routes[(target.host, path)]

    return sender, calls


def test_connects_to_checked_ip_not_a_second_dns_answer():
    answers = iter([["93.184.216.34"], ["10.0.0.9"]])  # a rebinding resolver would answer private the 2nd time
    sender, calls = _sender_from({("example.com", "/"): RawResponse(200, {}, b"ok")})
    tr = HttpRequestTransport(resolver=lambda h, p: next(answers), sender=sender)
    out = tr.request("GET", "https://example.com/")
    assert out["status"] == 200 and calls[0]["ip"] == "93.184.216.34"


def test_redirect_to_private_ip_is_blocked():
    sender, _ = _sender_from({("example.com", "/r"): RawResponse(302, {"location": "http://169.254.169.254/latest/meta-data/"}, b"")})
    tr = HttpRequestTransport(resolver=lambda h, p: ["93.184.216.34"], sender=sender)
    with pytest.raises(SSRFBlockedError, match="169.254.169.254"):
        tr.request("GET", "https://example.com/r")


def test_redirect_to_name_resolving_private_is_blocked():
    resolve = {"example.com": ["93.184.216.34"], "evil.example.net": ["192.168.0.10"]}
    sender, _ = _sender_from({("example.com", "/r"): RawResponse(301, {"location": "https://evil.example.net/x"}, b"")})
    tr = HttpRequestTransport(resolver=lambda h, p: resolve[h], sender=sender)
    with pytest.raises(SSRFBlockedError, match="192.168.0.10"):
        tr.request("GET", "https://example.com/r")


def test_more_than_three_redirects_is_blocked():
    routes = {("example.com", f"/{i}"): RawResponse(302, {"location": f"/{i + 1}"}, b"") for i in range(5)}
    sender, calls = _sender_from(routes)
    tr = HttpRequestTransport(resolver=lambda h, p: ["93.184.216.34"], sender=sender)
    with pytest.raises(SSRFBlockedError, match="too many redirects"):
        tr.request("GET", "https://example.com/0")
    assert len(calls) == 4  # original + 3 redirects


def test_three_redirects_allowed_and_credentials_dropped_on_host_change():
    resolve = {"api.example.com": ["93.184.216.34"], "cdn.example.org": ["93.184.216.35"]}
    routes = {
        ("api.example.com", "/a"): RawResponse(302, {"location": "/b"}, b""),
        ("api.example.com", "/b"): RawResponse(302, {"location": "https://cdn.example.org/c"}, b""),
        ("cdn.example.org", "/c"): RawResponse(200, {"content-type": "text/plain"}, b"done"),
    }
    sender, calls = _sender_from(routes)
    tr = HttpRequestTransport(resolver=lambda h, p: resolve[h], sender=sender)
    out = tr.request("GET", "https://api.example.com/a", credential_headers={"Authorization": "Bearer s3"})
    assert out["body"] == "done" and len(out["redirects"]) == 2
    assert "Authorization" in calls[0]["headers"] and "Authorization" in calls[1]["headers"]
    assert "Authorization" not in calls[2]["headers"]


def test_real_httpx_sender_pins_ip_keeps_host_and_caps_size():
    seen = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            seen["host"] = self.headers.get("Host")
            body = b"x" * 5000
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        tr = HttpRequestTransport(allowlist=["intranet.test"], resolver=lambda h, p: ["127.0.0.1"])
        out = tr.request("GET", f"http://intranet.test:{port}/big", max_bytes=1000, timeout_s=5)
    finally:
        server.shutdown()
        server.server_close()
    assert seen["host"] == f"intranet.test:{port}"
    assert out["truncated"] is True and len(out["body"]) == 1000
