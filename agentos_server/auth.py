"""
Authentication and security utilities for AgentOS server.

Provides:
- Local API token management (stored outside the repository, e.g. ~/.agentos/api.token).
- Constant-time token verification (hmac.compare_digest).
- Host header validation (DNS rebinding defense: localhost and 127.0.0.1 only).
- Deprecation warning for AGENTOS_V1_NO_AUTH=1 compatibility mode.
"""

from __future__ import annotations

import hmac
import logging
import os
from pathlib import Path
import secrets
from typing import Optional
import warnings

from fastapi import Request

logger = logging.getLogger(__name__)

_PRINTED_STARTUP_BANNER = False
_EMITTED_V1_NO_AUTH_WARNING = False

ALLOWED_HOSTS = {"localhost", "127.0.0.1"}


def default_token_path() -> Path:
    """Return the filesystem location where the local API token is stored."""
    override = os.environ.get("AGENTOS_API_TOKEN_FILE")
    if override:
        return Path(override)
    return Path.home() / ".agentos" / "api.token"


def get_or_create_api_token() -> str:
    """
    Get the existing local API token or generate a new 256-bit cryptographically
    secure token on first start.
    """
    # 1. Environment variable override
    env_token = os.environ.get("AGENTOS_API_TOKEN")
    if env_token and env_token.strip():
        return env_token.strip()

    # 2. File storage outside repository
    path = default_token_path()
    if path.exists():
        try:
            token = path.read_text(encoding="ascii").strip()
            if token:
                return token
        except Exception as e:
            logger.warning(f"Failed to read existing token from {path}: {e}")

    # 3. Generate fresh token and store with restricted permissions
    token = secrets.token_urlsafe(32)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # On POSIX, use 0600 permissions
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        mode = 0o600
        fd = os.open(path, flags, mode)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(token + "\n")
    except Exception as e:
        logger.warning(f"Could not persist API token to {path}: {e}")

    return token


def verify_api_token(provided_token: Optional[str], expected_token: Optional[str] = None) -> bool:
    """
    Constant-time comparison of the provided token against the server's token.
    """
    if not provided_token:
        return False
    expected = expected_token or get_or_create_api_token()
    return hmac.compare_digest(provided_token.strip(), expected.strip())


def extract_token_from_request(request: Request) -> Optional[str]:
    """Extract token from Authorization: Bearer <token> or X-AgentOS-Token: <token>."""
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    x_token = request.headers.get("x-agentos-token")
    if x_token:
        return x_token.strip()
    return None


def verify_host_header(host_header: Optional[str]) -> bool:
    """
    DNS-rebinding defense: only localhost or 127.0.0.1 (with optional port)
    are accepted.
    """
    if not host_header:
        return False
    # Strip port if present
    hostname = host_header.split(":")[0].strip().lower()
    return hostname in ALLOWED_HOSTS


def verify_origin(origin: Optional[str]) -> bool:
    """
    Validate WebSocket Origin header against allowed localhost/127.0.0.1 origins.
    """
    if not origin:
        return False
    import urllib.parse
    parsed = urllib.parse.urlparse(origin)
    hostname = (parsed.hostname or "").lower()
    return hostname in ALLOWED_HOSTS


def check_request_auth(request: Request, expected_token: Optional[str] = None) -> tuple[bool, Optional[str]]:
    """
    Verify Host header and token authentication.
    Returns (is_authorized, error_detail).
    """
    global _EMITTED_V1_NO_AUTH_WARNING

    # 1. Host header validation (DNS-rebinding defense)
    host = request.headers.get("host")
    if not verify_host_header(host):
        return False, "Invalid Host header (DNS-rebinding protection: localhost and 127.0.0.1 only)"

    path = request.url.path

    # 2. /api/health is always unauthenticated
    if path == "/api/health":
        return True, None

    # 3. Static assets and non-api routes do not require API token
    if not path.startswith("/api"):
        return True, None

    # 4. Token validation
    token = extract_token_from_request(request)
    if token and verify_api_token(token, expected_token):
        return True, None

    # 5. v1 compatibility flag
    if not path.startswith("/api/v2"):
        if os.environ.get("AGENTOS_V1_NO_AUTH") == "1":
            if not _EMITTED_V1_NO_AUTH_WARNING:
                warnings.warn(
                    "AGENTOS_V1_NO_AUTH=1 is deprecated; all /api routes will require authentication in 2.0",
                    DeprecationWarning,
                    stacklevel=2,
                )
                _EMITTED_V1_NO_AUTH_WARNING = True
            return True, None

    return False, "Unauthorized: valid local API token required"


class SecurityMiddleware:
    """
    Pure ASGI middleware enforcing:
    1. Host header validation for both HTTP and WebSocket scopes.
    2. Origin header validation for WebSocket scope (must match allowed UI origins).
    3. Token authentication:
       - HTTP: Bearer or X-AgentOS-Token on all /api/* routes (except /api/health).
         Compatibility mode: AGENTOS_V1_NO_AUTH=1 allows v1 routes with DeprecationWarning.
       - WebSocket: Sec-WebSocket-Protocol header with subprotocol "agentos.token.<token>",
         echoing "agentos.v1"; refused with close code 4401 on missing/invalid token or bad origin/host.
    """

    def __init__(self, app, api_token: Optional[str] = None):
        self.app = app
        self.api_token = api_token

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            await self._handle_http(scope, receive, send)
        elif scope["type"] == "websocket":
            await self._handle_websocket(scope, receive, send)
        else:
            await self.app(scope, receive, send)

    async def _handle_http(self, scope, receive, send):
        raw_headers = scope.get("headers", [])
        headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in raw_headers}
        host = headers.get("host", "")

        # 1. Host header validation
        if not verify_host_header(host):
            body = b'{"detail":"Invalid Host header (DNS-rebinding protection: localhost and 127.0.0.1 only)"}'
            await send({
                "type": "http.response.start",
                "status": 400,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            })
            await send({"type": "http.response.body", "body": body})
            return

        path = scope.get("path", "")

        # 2. /api/health is always unauthenticated, and non-/api static/UI routes
        if path == "/api/health" or not path.startswith("/api"):
            await self.app(scope, receive, send)
            return

        # 3. Token validation
        token = None
        auth_header = headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()
        if not token:
            x_token = headers.get("x-agentos-token")
            if x_token:
                token = x_token.strip()

        app_obj = scope.get("app")
        expected_token = (
            self.api_token
            or (getattr(app_obj.state, "api_token", None) if hasattr(app_obj, "state") else None)
            or get_or_create_api_token()
        )

        if token and verify_api_token(token, expected_token):
            await self.app(scope, receive, send)
            return

        # 4. v1 compatibility flag
        if not path.startswith("/api/v2") and os.environ.get("AGENTOS_V1_NO_AUTH") == "1":
            global _EMITTED_V1_NO_AUTH_WARNING
            if not _EMITTED_V1_NO_AUTH_WARNING:
                warnings.warn(
                    "AGENTOS_V1_NO_AUTH=1 is deprecated; all /api routes will require authentication in 2.0",
                    DeprecationWarning,
                    stacklevel=2,
                )
                _EMITTED_V1_NO_AUTH_WARNING = True
            await self.app(scope, receive, send)
            return

        body = b'{"detail":"Unauthorized: valid local API token required"}'
        await send({
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        })
        await send({"type": "http.response.body", "body": body})

    async def _handle_websocket(self, scope, receive, send):
        raw_headers = scope.get("headers", [])
        headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in raw_headers}
        host = headers.get("host", "")
        origin = headers.get("origin")

        # 1. Host header validation
        if not verify_host_header(host):
            await self._reject_ws(receive, send, code=4401)
            return

        # 2. Origin validation
        if not verify_origin(origin):
            await self._reject_ws(receive, send, code=4401)
            return

        # 3. Sec-WebSocket-Protocol token validation
        protocols = headers.get("sec-websocket-protocol", "")
        subprotocols = [p.strip() for p in protocols.split(",") if p.strip()]
        token_subprotocol = next((p for p in subprotocols if p.startswith("agentos.token.")), None)
        if not token_subprotocol:
            await self._reject_ws(receive, send, code=4401)
            return

        provided_token = token_subprotocol[len("agentos.token."):].strip()
        app_obj = scope.get("app")
        expected_token = (
            self.api_token
            or (getattr(app_obj.state, "api_token", None) if hasattr(app_obj, "state") else None)
            or get_or_create_api_token()
        )

        if not verify_api_token(provided_token, expected_token):
            await self._reject_ws(receive, send, code=4401)
            return

        await self.app(scope, receive, send)

    @staticmethod
    async def _reject_ws(receive, send, code: int = 4401):
        event = await receive()
        if event["type"] == "websocket.connect":
            await send({"type": "websocket.close", "code": code})


def get_ui_port(server_port: int = 8000) -> int:
    """
    Determine the port of the UI being served.
    In dev mode (AGENTOS_DEV=1 or built UI dist not found), UI is on Vite dev server (5173).
    When built UI is present (packaged static or ui/dist), UI is served directly on the server port.
    """
    if os.environ.get("AGENTOS_DEV") == "1":
        return 5173
    package_static = os.path.join(os.path.dirname(__file__), "static")
    checkout_dist = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ui", "dist")
    has_built_ui = (
        os.path.isfile(os.path.join(package_static, "index.html"))
        or os.path.isfile(os.path.join(checkout_dist, "index.html"))
    )
    if not has_built_ui:
        return 5173
    return server_port


def print_startup_auth_banner(token: str, server_port: int = 8000) -> None:
    """Print the one-time access link with token fragment on startup."""
    global _PRINTED_STARTUP_BANNER
    if _PRINTED_STARTUP_BANNER:
        return
    _PRINTED_STARTUP_BANNER = True
    port = get_ui_port(server_port)
    print("\n" + "=" * 60)
    print("AgentOS Local Server Ready")
    print(f"One-Time UI Access Link: http://localhost:{port}/#token={token}")
    print(f"Direct API Access: Authorization: Bearer {token}")
    print("=" * 60 + "\n")
