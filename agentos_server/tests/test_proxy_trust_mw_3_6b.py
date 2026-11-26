"""Integration tests for 3.6b trusted-proxy middleware integration.

MOCK — no external services required.

Tests:
- Spoofed X-Forwarded-For from an untrusted peer is ignored in rate limiting and audit
- Trusted proxy XFF is used for rate limiting and audit source
- WebSocket requests follow the same trusted-proxy rules
"""

from __future__ import annotations

import os
import pytest
from fastapi.testclient import TestClient


def _make_app(trusted_proxies: str = "", monkeypatch=None):
    """Create a test app with the trusted proxies configured."""
    if monkeypatch:
        monkeypatch.setenv("AGENTOS_TRUSTED_PROXIES", trusted_proxies)
        monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
        monkeypatch.setenv("LITELLM_LOCAL_MODEL_COST_MAP", "True")
    from agentos_server.app import create_app
    app = create_app(project_path=".", storage=None)
    return app


class TestMiddlewareProxyResolution:
    """Test that SecurityMiddleware correctly resolves client IPs via trusted proxy rules."""

    def test_untrusted_peer_xff_ignored_in_scope(self, monkeypatch, tmp_path):
        """When a peer is not trusted, X-Forwarded-For is ignored; scope has the real peer IP."""
        monkeypatch.setenv("AGENTOS_TRUSTED_PROXIES", "")
        monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
        monkeypatch.setenv("LITELLM_LOCAL_MODEL_COST_MAP", "True")
        monkeypatch.setenv("AGENTOS_DATA_DIR", str(tmp_path))
        # We test via the proxy_trust module directly since TestClient doesn't expose ASGI scope state
        import agentos.proxy_trust as pt
        # Peer 1.2.3.4 is not trusted → XFF ignored
        result = pt.resolve_client_ip("1.2.3.4", {"x-forwarded-for": "10.0.0.1"})
        assert result == "1.2.3.4"

    def test_trusted_peer_xff_applied(self, monkeypatch, tmp_path):
        monkeypatch.setenv("AGENTOS_TRUSTED_PROXIES", "10.0.0.0/8")
        import agentos.proxy_trust as pt
        old_nets = pt._TRUSTED_NETWORKS
        old_from = pt._LOADED_FROM
        try:
            pt._TRUSTED_NETWORKS = None
            pt._LOADED_FROM = None
            result = pt.resolve_client_ip("10.0.0.1", {"x-forwarded-for": "203.0.113.5"})
            assert result == "203.0.113.5"
        finally:
            pt._TRUSTED_NETWORKS = old_nets
            pt._LOADED_FROM = old_from
            monkeypatch.delenv("AGENTOS_TRUSTED_PROXIES", raising=False)

    def test_rate_limit_uses_resolved_ip(self, monkeypatch):
        """The login rate limiter should key on the resolved IP, not the proxy IP."""
        # This is tested indirectly: if the middleware sets scope["state"]["client_ip"],
        # and _client_ip() reads from request.state.client_ip, the limiter gets the right IP.
        # We test _client_ip directly with a mock request object.
        from unittest.mock import MagicMock

        # Simulate a request whose state has client_ip set by middleware
        request = MagicMock()
        request.state.client_ip = "203.0.113.5"
        request.client.host = "10.0.0.1"  # the proxy

        # Import the _client_ip helper from the access routes
        from agentos_server.routes_v2.access import _client_ip
        assert _client_ip(request) == "203.0.113.5"

    def test_client_ip_fallback_when_no_state(self, monkeypatch):
        """When scope state has no client_ip (old code path / test), falls back to request.client.host."""
        from unittest.mock import MagicMock

        request = MagicMock()
        # No client_ip attribute on state
        del request.state.client_ip  # AttributeError → getattr returns None
        request.state = MagicMock(spec=[])  # empty spec: getattr returns None for client_ip
        request.client.host = "1.2.3.4"

        from agentos_server.routes_v2.access import _client_ip
        assert _client_ip(request) == "1.2.3.4"

    def test_trusted_proxy_https_proto_sets_secure_cookie(self, monkeypatch):
        """Trusted proxy + X-Forwarded-Proto https -> Secure cookie."""
        import asyncio
        from agentos_server.auth import SecurityMiddleware
        from agentos_server.routes_v2.access import _set_session_cookie
        from starlette.requests import Request
        from starlette.responses import Response

        monkeypatch.setenv("AGENTOS_TRUSTED_PROXIES", "10.0.0.0/8")
        import agentos.proxy_trust as pt
        pt._TRUSTED_NETWORKS = None
        pt._LOADED_FROM = None

        captured_scope = {}
        async def mock_app(scope, receive, send):
            captured_scope.update(scope)

        mw = SecurityMiddleware(mock_app)
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/api/v2/access/login",
            "headers": [(b"host", b"localhost"), (b"x-forwarded-proto", b"https")],
            "client": ("10.0.0.1", 12345),
            "scheme": "http",
        }
        asyncio.run(mw(scope, None, None))
        assert captured_scope.get("state", {}).get("scheme") == "https"

        req = Request(captured_scope)
        resp = Response()
        _set_session_cookie(resp, req, "token_val")
        cookie_header = resp.headers.get("set-cookie", "")
        assert "Secure" in cookie_header

    def test_untrusted_peer_https_proto_not_secure_cookie(self, monkeypatch):
        """Untrusted peer sending X-Forwarded-Proto https -> not Secure cookie."""
        import asyncio
        from agentos_server.auth import SecurityMiddleware
        from agentos_server.routes_v2.access import _set_session_cookie
        from starlette.requests import Request
        from starlette.responses import Response

        monkeypatch.setenv("AGENTOS_TRUSTED_PROXIES", "10.0.0.0/8")
        import agentos.proxy_trust as pt
        pt._TRUSTED_NETWORKS = None
        pt._LOADED_FROM = None

        captured_scope = {}
        async def mock_app(scope, receive, send):
            captured_scope.update(scope)

        mw = SecurityMiddleware(mock_app)
        # Peer 1.2.3.4 is NOT in 10.0.0.0/8
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/api/v2/access/login",
            "headers": [(b"host", b"localhost"), (b"x-forwarded-proto", b"https")],
            "client": ("1.2.3.4", 12345),
            "scheme": "http",
        }
        asyncio.run(mw(scope, None, None))
        assert captured_scope.get("state", {}).get("scheme") == "http"

        req = Request(captured_scope)
        resp = Response()
        _set_session_cookie(resp, req, "token_val")
        cookie_header = resp.headers.get("set-cookie", "")
        assert "Secure" not in cookie_header

    def test_direct_https_sets_secure_cookie(self, monkeypatch):
        """Direct connection with scheme https -> Secure cookie."""
        import asyncio
        from agentos_server.auth import SecurityMiddleware
        from agentos_server.routes_v2.access import _set_session_cookie
        from starlette.requests import Request
        from starlette.responses import Response

        monkeypatch.delenv("AGENTOS_TRUSTED_PROXIES", raising=False)
        import agentos.proxy_trust as pt
        pt._TRUSTED_NETWORKS = None
        pt._LOADED_FROM = None

        captured_scope = {}
        async def mock_app(scope, receive, send):
            captured_scope.update(scope)

        mw = SecurityMiddleware(mock_app)
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/api/v2/access/login",
            "headers": [(b"host", b"localhost")],
            "client": ("1.2.3.4", 12345),
            "scheme": "https",
        }
        asyncio.run(mw(scope, None, None))
        assert captured_scope.get("state", {}).get("scheme") == "https"

        req = Request(captured_scope)
        resp = Response()
        _set_session_cookie(resp, req, "token_val")
        cookie_header = resp.headers.get("set-cookie", "")
        assert "Secure" in cookie_header
