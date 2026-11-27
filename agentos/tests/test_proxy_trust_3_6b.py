"""Tests for 3.6b trusted-proxy resolution (agentos/proxy_trust.py).

MOCK — no external services required.

Covers:
- Spoofed X-Forwarded-For from an untrusted peer is ignored (rate limit and audit use the real peer)
- Multi-hop XFF chains
- IPv6 and IPv4-mapped addresses
- X-Forwarded-Proto only honoured from a trusted proxy
- X-Forwarded-Host cannot bypass the Host check
- peer_is_trusted() correctly evaluates CIDRs
"""

from __future__ import annotations

import os
import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve(peer_ip: str, xff: str = "", proto: str = "", fwd_host: str = "",
             trusted_proxies: str = "") -> dict:
    """Run proxy trust resolution with an isolated AGENTOS_TRUSTED_PROXIES value."""
    # Reset the module-level cache so each test sees its own config.
    import importlib
    import agentos.proxy_trust as pt
    old_nets = pt._TRUSTED_NETWORKS
    old_from = pt._LOADED_FROM
    try:
        pt._TRUSTED_NETWORKS = None
        pt._LOADED_FROM = None
        with _env(AGENTOS_TRUSTED_PROXIES=trusted_proxies):
            headers: dict[str, str] = {}
            if xff:
                headers["x-forwarded-for"] = xff
            if proto:
                headers["x-forwarded-proto"] = proto
            if fwd_host:
                headers["x-forwarded-host"] = fwd_host
            return {
                "client_ip": pt.resolve_client_ip(peer_ip, headers),
                "scheme": pt.resolve_scheme(peer_ip, headers),
                "host": pt.resolve_host(peer_ip, headers),
                "trusted": pt.peer_is_trusted(peer_ip),
            }
    finally:
        pt._TRUSTED_NETWORKS = old_nets
        pt._LOADED_FROM = old_from


class _env:
    """Context manager that temporarily sets environment variables."""
    def __init__(self, **kwargs):
        self._vars = kwargs
        self._saved = {}

    def __enter__(self):
        for k, v in self._vars.items():
            self._saved[k] = os.environ.get(k)
            os.environ[k] = v
        return self

    def __exit__(self, *_):
        for k, saved in self._saved.items():
            if saved is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = saved


# ---------------------------------------------------------------------------
# Tests: no trusted proxies (default behaviour unchanged)
# ---------------------------------------------------------------------------

class TestNoTrustedProxies:
    def test_untrusted_peer_xff_ignored(self):
        """When no proxies are configured, XFF is never used (default behaviour unchanged)."""
        r = _resolve("1.2.3.4", xff="10.0.0.1, 192.168.0.1", trusted_proxies="")
        assert r["client_ip"] == "1.2.3.4"

    def test_untrusted_peer_scheme_is_http(self):
        r = _resolve("1.2.3.4", proto="https", trusted_proxies="")
        assert r["scheme"] == "http"

    def test_untrusted_peer_host_is_none(self):
        r = _resolve("1.2.3.4", fwd_host="example.com", trusted_proxies="")
        assert r["host"] is None

    def test_peer_not_trusted(self):
        r = _resolve("1.2.3.4", trusted_proxies="")
        assert r["trusted"] is False


# ---------------------------------------------------------------------------
# Tests: basic trusted proxy
# ---------------------------------------------------------------------------

class TestTrustedProxy:
    PROXY = "10.0.0.1"
    NETS = "10.0.0.0/24"

    def test_trusted_peer_uses_xff_rightmost_untrusted(self):
        """Right-most non-trusted address in XFF is the client IP."""
        r = _resolve(self.PROXY, xff="203.0.113.1, 10.0.0.1", trusted_proxies=self.NETS)
        # 10.0.0.1 is trusted → skip; 203.0.113.1 is not trusted → client IP
        assert r["client_ip"] == "203.0.113.1"

    def test_trusted_peer_no_xff_uses_peer(self):
        r = _resolve(self.PROXY, trusted_proxies=self.NETS)
        assert r["client_ip"] == self.PROXY

    def test_trusted_peer_scheme_https(self):
        r = _resolve(self.PROXY, proto="https", trusted_proxies=self.NETS)
        assert r["scheme"] == "https"

    def test_trusted_peer_scheme_http(self):
        r = _resolve(self.PROXY, proto="http", trusted_proxies=self.NETS)
        assert r["scheme"] == "http"

    def test_trusted_peer_scheme_invalid_ignored(self):
        r = _resolve(self.PROXY, proto="ftp", trusted_proxies=self.NETS)
        assert r["scheme"] == "http"

    def test_trusted_peer_fwd_host_returned(self):
        r = _resolve(self.PROXY, fwd_host="myhost.example.com", trusted_proxies=self.NETS)
        assert r["host"] == "myhost.example.com"

    def test_peer_is_trusted(self):
        r = _resolve(self.PROXY, trusted_proxies=self.NETS)
        assert r["trusted"] is True

    def test_peer_outside_cidr_not_trusted(self):
        r = _resolve("10.0.1.1", trusted_proxies=self.NETS)
        assert r["trusted"] is False


# ---------------------------------------------------------------------------
# Tests: multi-hop chains
# ---------------------------------------------------------------------------

class TestMultiHopChains:
    # 10.0.0.0/8 and 172.16.0.0/12 are trusted (like internal load balancers)
    NETS = "10.0.0.0/8,172.16.0.0/12"

    def test_two_hop_client_at_left(self):
        """XFF: real_client, proxy1(trusted), proxy2(trusted) — rightmost non-trusted is real_client."""
        r = _resolve("172.16.0.1", xff="203.0.113.5, 10.0.0.2, 172.16.0.1",
                     trusted_proxies=self.NETS)
        # Walk from right: 172.16.0.1 trusted, 10.0.0.2 trusted, 203.0.113.5 not trusted → client
        assert r["client_ip"] == "203.0.113.5"

    def test_all_trusted_fallback_to_leftmost(self):
        """If all addresses in XFF are trusted, return the leftmost (the most-original address)."""
        r = _resolve("172.16.0.1", xff="10.0.0.5, 10.0.0.6, 172.16.0.1",
                     trusted_proxies=self.NETS)
        assert r["client_ip"] == "10.0.0.5"

    def test_attacker_prepends_fake_ip(self):
        """Attacker prepends a fake IP — but the right-most untrusted wins, not the left-most."""
        # XFF crafted by attacker: "1.2.3.4, 10.0.0.2, 172.16.0.1"
        # peer is 172.16.0.1 (trusted), walks right: 172.16.0.1 trusted, 10.0.0.2 trusted, 1.2.3.4 not trusted
        r = _resolve("172.16.0.1", xff="1.2.3.4, 10.0.0.2, 172.16.0.1",
                     trusted_proxies=self.NETS)
        # This is correct: 1.2.3.4 is the right-most non-trusted address.
        # In a 2-hop setup where both internal proxies are trusted, the first-party client IS 1.2.3.4.
        # The concern is that an ATTACKER at 1.2.3.4 cannot spoof a different address.
        assert r["client_ip"] == "1.2.3.4"


# ---------------------------------------------------------------------------
# Tests: IPv6 and IPv4-mapped addresses
# ---------------------------------------------------------------------------

class TestIPv6:
    def test_ipv6_peer_trusted(self):
        r = _resolve("::1", trusted_proxies="::1")
        assert r["trusted"] is True

    def test_ipv6_cidr_trusted(self):
        r = _resolve("2001:db8::1", trusted_proxies="2001:db8::/32")
        assert r["trusted"] is True

    def test_ipv4_mapped_in_xff_normalised(self):
        """::ffff:a.b.c.d is equivalent to a.b.c.d for CIDR matching."""
        # Peer is ::1 (trusted), XFF has an IPv4-mapped address
        r = _resolve("::1", xff="::ffff:203.0.113.5", trusted_proxies="::1")
        # ::ffff:203.0.113.5 → maps to 203.0.113.5; that is not in ::1 → client
        assert r["client_ip"] == "203.0.113.5"

    def test_ipv4_mapped_peer_trusted(self):
        """An IPv4-mapped peer (::ffff:10.0.0.1) matches the IPv4 CIDR 10.0.0.0/24."""
        r = _resolve("::ffff:10.0.0.1", trusted_proxies="10.0.0.0/24")
        assert r["trusted"] is True


# ---------------------------------------------------------------------------
# Tests: X-Forwarded-Host cannot bypass existing host validation
# ---------------------------------------------------------------------------

class TestXForwardedHost:
    NETS = "10.0.0.1"

    def test_fwd_host_returned_to_caller(self):
        """resolve_host returns the header value; it's up to the caller (middleware) to validate it."""
        r = _resolve("10.0.0.1", fwd_host="localhost", trusted_proxies=self.NETS)
        # resolve_host only returns the value; SecurityMiddleware then passes it to verify_host_header
        assert r["host"] == "localhost"

    def test_fwd_host_from_untrusted_is_none(self):
        r = _resolve("5.5.5.5", fwd_host="localhost", trusted_proxies=self.NETS)
        assert r["host"] is None

    def test_empty_fwd_host_is_none(self):
        r = _resolve("10.0.0.1", fwd_host="", trusted_proxies=self.NETS)
        assert r["host"] is None


# ---------------------------------------------------------------------------
# Tests: invalid / edge-case inputs
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_malformed_trusted_proxies_skipped(self):
        """Invalid CIDR entries are logged and skipped; valid ones still work."""
        import agentos.proxy_trust as pt
        old_nets = pt._TRUSTED_NETWORKS
        old_from = pt._LOADED_FROM
        try:
            pt._TRUSTED_NETWORKS = None
            pt._LOADED_FROM = None
            with _env(AGENTOS_TRUSTED_PROXIES="not-an-ip, 10.0.0.1"):
                assert pt.peer_is_trusted("10.0.0.1") is True
                assert pt.peer_is_trusted("1.2.3.4") is False
        finally:
            pt._TRUSTED_NETWORKS = old_nets
            pt._LOADED_FROM = old_from

    def test_malformed_xff_address_skipped(self):
        """If a non-trusted address is found on the right, unparseable entries further to the left are never reached."""
        import agentos.proxy_trust as pt
        old_nets = pt._TRUSTED_NETWORKS
        old_from = pt._LOADED_FROM
        try:
            pt._TRUSTED_NETWORKS = None
            pt._LOADED_FROM = None
            with _env(AGENTOS_TRUSTED_PROXIES="10.0.0.1"):
                headers = {"x-forwarded-for": "not-valid, 203.0.113.5"}
                result = pt.resolve_client_ip("10.0.0.1", headers)
                # 203.0.113.5 is right-most non-trusted address → client IP
                assert result == "203.0.113.5"
        finally:
            pt._TRUSTED_NETWORKS = old_nets
            pt._LOADED_FROM = old_from

    def test_port_stripping_ipv4(self):
        """XFF with ip:port has port stripped correctly and returns the untrusted client IP."""
        r = _resolve("10.0.0.2", xff="6.6.6.6, 198.51.100.7:51234", trusted_proxies="10.0.0.0/8")
        assert r["client_ip"] == "198.51.100.7"

    def test_port_stripping_ipv6_bracketed(self):
        """XFF with [v6]:port has port stripped correctly."""
        r = _resolve("10.0.0.2", xff="6.6.6.6, [2001:db8::1]:443", trusted_proxies="10.0.0.0/8")
        assert r["client_ip"] == "2001:db8::1"

    def test_bracketed_ipv6_without_port(self):
        """XFF with [v6] brackets without port parses correctly."""
        r = _resolve("10.0.0.2", xff="6.6.6.6, [2001:db8::1]", trusted_proxies="10.0.0.0/8")
        assert r["client_ip"] == "2001:db8::1"

    def test_unparseable_garbage_stops_and_returns_peer(self):
        """Unparseable right-most entry STOPS immediately and returns peer IP (no spoofing to left)."""
        r = _resolve("10.0.0.2", xff="6.6.6.6, not-an-ip", trusted_proxies="10.0.0.0/8")
        assert r["client_ip"] == "10.0.0.2"

    def test_unparseable_garbage_between_hops_stops_and_returns_peer(self):
        """Unparseable entry preceding a trusted proxy STOPS immediately and returns peer IP."""
        r = _resolve("10.0.0.2", xff="6.6.6.6, not-an-ip, 10.0.0.1", trusted_proxies="10.0.0.0/8")
        assert r["client_ip"] == "10.0.0.2"

    def test_empty_entry_stops_and_returns_peer(self):
        """Empty entry (trailing or double comma) STOPS and returns peer IP."""
        r1 = _resolve("10.0.0.2", xff="6.6.6.6, ", trusted_proxies="10.0.0.0/8")
        assert r1["client_ip"] == "10.0.0.2"

        r2 = _resolve("10.0.0.2", xff="6.6.6.6, , 10.0.0.1", trusted_proxies="10.0.0.0/8")
        assert r2["client_ip"] == "10.0.0.2"

    def test_ipv4_mapped_in_xff_with_and_without_port(self):
        """IPv4-mapped IPv6 in XFF is normalized to plain IPv4, with or without port."""
        r1 = _resolve("10.0.0.2", xff="6.6.6.6, ::ffff:198.51.100.7", trusted_proxies="10.0.0.0/8")
        assert r1["client_ip"] == "198.51.100.7"

        r2 = _resolve("10.0.0.2", xff="6.6.6.6, [::ffff:198.51.100.7]:8080", trusted_proxies="10.0.0.0/8")
        assert r2["client_ip"] == "198.51.100.7"

    def test_unknown_peer(self):
        import agentos.proxy_trust as pt
        old_nets = pt._TRUSTED_NETWORKS
        old_from = pt._LOADED_FROM
        try:
            pt._TRUSTED_NETWORKS = None
            pt._LOADED_FROM = None
            with _env(AGENTOS_TRUSTED_PROXIES="10.0.0.1"):
                assert pt.peer_is_trusted("unknown") is False
                result = pt.resolve_client_ip("unknown", {"x-forwarded-for": "1.2.3.4"})
                assert result == "unknown"  # untrusted peer: ignore XFF
        finally:
            pt._TRUSTED_NETWORKS = old_nets
            pt._LOADED_FROM = old_from
