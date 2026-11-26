"""
Authentication and security utilities for AgentOS server.

Provides:
- Local API token management (stored outside the repository, e.g. ~/.agentos/api.token).
- Constant-time token verification (hmac.compare_digest).
- Host header validation (DNS rebinding defense: localhost and 127.0.0.1 only).
- Deprecation warning for AGENTOS_V1_NO_AUTH=1 compatibility mode.
- 3.6b: Trusted-proxy header resolution (X-Forwarded-For / Proto / Host from AGENTOS_TRUSTED_PROXIES).
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

from agentos.access.permissions import allows
from agentos.proxy_trust import resolve_client_ip, resolve_host, resolve_scheme, peer_is_trusted
from agentos_server.access_mw import (
    LEGACY, LOCAL_HOSTS, UNSAFE_METHODS, bearer_token, capability, csrf_ok, origin_host, principal_from_session,
    principal_from_token, route_template, session_cookie,
)
from agentos_server.permissions_table import PERMISSIONS, permission_for

logger = logging.getLogger(__name__)

_PRINTED_STARTUP_BANNER = False
_EMITTED_V1_NO_AUTH_WARNING = False

ALLOWED_HOSTS = {"localhost", "127.0.0.1"}


def get_public_hosts() -> set[str]:
    """Return configured public hosts from AGENTOS_PUBLIC_HOSTS (comma-separated)."""
    raw = os.environ.get("AGENTOS_PUBLIC_HOSTS", "").strip()
    if not raw:
        return set()
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def default_token_path() -> Path:
    """Return the filesystem location where the local API token is stored."""
    from agentos.core.home_guard import checked

    override = os.environ.get("AGENTOS_API_TOKEN_FILE")
    if override:
        return checked(Path(override), "API token file")
    return checked(Path.home() / ".agentos" / "api.token", "API token file")


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
        # Temp file + fsync + os.replace (0600 on POSIX): a crash never leaves a half-written token file.
        from agentos.storage.atomic import atomic_write_text
        atomic_write_text(path, token + "\n", private=True, encoding="ascii")
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


def verify_host_header(host_header: Optional[str], is_hook: bool = False) -> bool:
    """
    DNS-rebinding defense:
    - By default, only localhost or 127.0.0.1 (with optional port) are accepted.
    - If is_hook=True, hosts in AGENTOS_PUBLIC_HOSTS are also accepted for /hooks/* routes.
    - All other routes (including /api and the UI) keep the localhost-only rule.
    """
    if not host_header:
        return False
    # Strip port if present
    hostname = host_header.split(":")[0].strip().lower()
    if hostname in ALLOWED_HOSTS:
        return True
    if is_hook and hostname in get_public_hosts():
        return True
    return False


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

    path = request.url.path
    is_hook = path.startswith("/hooks/") or path == "/hooks"

    # 1. Host header validation (DNS-rebinding defense)
    host = request.headers.get("host")
    if not verify_host_header(host, is_hook=is_hook):
        return False, "Invalid Host header (DNS-rebinding protection: localhost and 127.0.0.1 only)"

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
        path = scope.get("path", "")
        is_hook = path.startswith("/hooks/") or path == "/hooks"

        # 3.6b: resolve the real client IP early so all downstream handlers (rate limit, audit) use it.
        peer_ip = (scope.get("client") or ("unknown", 0))[0]
        resolved_ip = resolve_client_ip(peer_ip, headers)
        scope.setdefault("state", {})["client_ip"] = resolved_ip

        # 3.6b: X-Forwarded-Host is considered only from a trusted peer and must still pass allowed-hosts.
        effective_host = host
        fwd_host = resolve_host(peer_ip, headers)
        if fwd_host:
            # Strip port and normalise; must still pass the existing host check below.
            fwd_hostname = fwd_host.split(":")[0].strip().lower()
            is_fwd_hook = is_hook  # same path, same routing context
            if verify_host_header(fwd_host, is_hook=is_fwd_hook):
                effective_host = fwd_host  # the forwarded host passes the existing rules

        # 1. Host header validation
        if not verify_host_header(effective_host, is_hook=is_hook):
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

        # 2. Non-/api paths (UI, /hooks/* with their own HMAC) are not handled here
        if not path.startswith("/api"):
            await self.app(scope, receive, send)
            return

        # 3. 3.4 access: route capability (deny by default) -> principal -> CSRF -> role check
        app_obj = scope.get("app")
        state = getattr(app_obj, "state", None)
        method = scope.get("method", "GET")
        template = route_template(app_obj, scope)
        if template is None:  # no route at all: the app answers 404
            await self.app(scope, receive, send)
            return
        cap = permission_for(method, template)
        if cap is None and any(k[1] == template for k in PERMISSIONS):
            await self.app(scope, receive, send)  # declared route, other method: the app answers 405
            return

        expected_token = (getattr(state, "api_token", None) if state is not None else None) or self.api_token \
            or get_or_create_api_token()
        principal = None
        token = bearer_token(headers)
        if token:
            principal = await principal_from_token(state, token, expected_token)
        else:
            principal = await principal_from_session(state, session_cookie(headers))

        # v1 compatibility flag (deprecated): unauthenticated v1 routes act as the local admin
        if principal is None and not token and not path.startswith("/api/v2") \
                and os.environ.get("AGENTOS_V1_NO_AUTH") == "1":
            global _EMITTED_V1_NO_AUTH_WARNING
            if not _EMITTED_V1_NO_AUTH_WARNING:
                warnings.warn(
                    "AGENTOS_V1_NO_AUTH=1 is deprecated; all /api routes will require authentication in 2.0",
                    DeprecationWarning,
                    stacklevel=2,
                )
                _EMITTED_V1_NO_AUTH_WARNING = True
            principal = LEGACY

        if cap == "public":
            host = origin_host(headers)
            if method in UNSAFE_METHODS and host is not None and host not in LOCAL_HOSTS:
                await _json(send, 403, b'{"detail":"Cross-site request refused"}')
                return
            scope.setdefault("state", {})["principal"] = principal
            await self.app(scope, receive, send)
            return

        if principal is None:
            if token or session_cookie(headers):
                await _note_auth_failure(app_obj, "ui" if headers.get("x-agentos-client", "").lower() == "ui" else "api")
            await _json(send, 401, b'{"detail":"Unauthorized: log in, or send a valid API token"}')
            return
        if cap is None:
            await _json(send, 403, b'{"detail":"Forbidden: this route declares no permission (deny by default)"}')
            return
        if principal.kind == "session" and method in UNSAFE_METHODS and not csrf_ok(state, principal, headers):
            await _json(send, 403, b'{"detail":"Forbidden: CSRF check failed (Origin and X-AgentOS-CSRF required)"}')
            return
        if not allows(principal.role, cap):
            detail = f'{{"detail":"Forbidden: requires the {cap} permission (your role: {principal.role})"}}'
            await _json(send, 403, detail.encode("utf-8"))
            return
        scope.setdefault("state", {})["principal"] = principal
        await self.app(scope, receive, send)

    async def _handle_websocket(self, scope, receive, send):
        raw_headers = scope.get("headers", [])
        headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in raw_headers}
        host = headers.get("host", "")
        origin = headers.get("origin")

        # 3.6b: resolve the real client IP for WebSocket requests (same rules as HTTP).
        peer_ip = (scope.get("client") or ("unknown", 0))[0]
        resolved_ip = resolve_client_ip(peer_ip, headers)
        scope.setdefault("state", {})["client_ip"] = resolved_ip

        # 1. Host header validation
        if not verify_host_header(host):
            await self._reject_ws(receive, send, code=4401)
            return

        # 2. Origin validation
        if not verify_origin(origin):
            await self._reject_ws(receive, send, code=4401)
            return

        # 3. Principal: subprotocol "agentos.token.<legacy token or PAT>", else the session cookie
        app_obj = scope.get("app")
        state = getattr(app_obj, "state", None)
        protocols = headers.get("sec-websocket-protocol", "")
        subprotocols = [p.strip() for p in protocols.split(",") if p.strip()]
        token_subprotocol = next((p for p in subprotocols if p.startswith("agentos.token.")), None)
        expected_token = (getattr(state, "api_token", None) if state is not None else None) or self.api_token \
            or get_or_create_api_token()
        if token_subprotocol:
            principal = await principal_from_token(state, token_subprotocol[len("agentos.token."):].strip(),
                                                   expected_token)
        else:
            principal = await principal_from_session(state, session_cookie(headers))
        if principal is None:
            if token_subprotocol:
                await _note_auth_failure(app_obj, "ui")
            await self._reject_ws(receive, send, code=4401)
            return

        # 4. Capability of the WebSocket route (deny by default)
        cap = capability(app_obj, scope)
        if cap is None or not allows(principal.role, cap):
            await self._reject_ws(receive, send, code=4403)
            return
        scope.setdefault("state", {})["principal"] = principal
        await self.app(scope, receive, send)

    @staticmethod
    async def _reject_ws(receive, send, code: int = 4401):
        event = await receive()
        if event["type"] == "websocket.connect":
            await send({"type": "websocket.close", "code": code})


async def _json(send, status: int, body: bytes) -> None:
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode("ascii"))],
    })
    await send({"type": "http.response.body", "body": body})


async def _note_auth_failure(app_obj, source: str) -> None:
    """3.1: count a failed authentication for the aggregated audit entry (never raises, never blocks the 401)."""
    agg = getattr(getattr(app_obj, "state", None), "auth_failures", None)
    if agg is None:
        return
    try:
        await agg.note(app_obj, source)
    except Exception:  # auditing must not change the auth response
        pass


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
    """3.4: print where to log in. The token value is never printed (rule 6); scripts read it from its file."""
    global _PRINTED_STARTUP_BANNER
    if _PRINTED_STARTUP_BANNER:
        return
    _PRINTED_STARTUP_BANNER = True
    port = get_ui_port(server_port)
    source = "the AGENTOS_API_TOKEN environment variable" if os.environ.get("AGENTOS_API_TOKEN") \
        else str(default_token_path())
    print("\n" + "=" * 60)
    print("AgentOS Local Server Ready")
    print(f"Open http://localhost:{port}/ and log in.")
    print("First start (no users yet): the setup page asks for the local API token to create the first admin")
    print("(or run: agentos users create-admin).")
    print(f"Local API token for scripts (legacy, admin): {source}")
    print("=" * 60 + "\n")
