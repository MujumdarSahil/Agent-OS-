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
    if hostname in ALLOWED_HOSTS:
        return True
    # Test client compatibility (httpx ASGITransport defaults to 'test', starlette TestClient to 'testserver')
    if hostname in {"test", "testserver"} and (
        "PYTEST_CURRENT_TEST" in os.environ or os.environ.get("AGENTOS_TEST_MODE") == "1"
    ):
        return True
    return False


def check_request_auth(request: Request, expected_token: Optional[str] = None) -> tuple[bool, Optional[str]]:
    """
    Verify Host header and token authentication.
    Returns (is_authorized, error_detail).
    """
    global _EMITTED_V1_NO_AUTH_WARNING

    # 1. Host header validation
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


def print_startup_auth_banner(token: str, port: int = 8000) -> None:
    """Print the one-time access link with token fragment on startup."""
    global _PRINTED_STARTUP_BANNER
    if _PRINTED_STARTUP_BANNER:
        return
    _PRINTED_STARTUP_BANNER = True
    print("\n" + "=" * 60)
    print("AgentOS Local Server Ready")
    print(f"One-Time UI Access Link: http://localhost:5173/#token={token}")
    print(f"Direct API Access: Authorization: Bearer {token}")
    print("=" * 60 + "\n")
