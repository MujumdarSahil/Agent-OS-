"""3.4 access enforcement helpers for SecurityMiddleware (agentos_server/auth.py). Design: docs/evidence/3.4.md.

Order for an /api request: Host check (unchanged) -> route template -> declared capability (none = 403 for
everyone) -> principal (Bearer: legacy local token or PAT; else the session cookie) -> CSRF for cookie sessions
on state-changing methods -> role allows capability (else 403). The principal is put on ``request.state.principal``.
"""

from __future__ import annotations

import hmac
import re
import urllib.parse
from http.cookies import CookieError, SimpleCookie
from typing import Any, Optional

from starlette.routing import Mount

from agentos.access.service import TOKEN_PREFIX, Principal
from agentos_server.permissions_table import permission_for

SESSION_COOKIE = "agentos_session"
CSRF_HEADER = "x-agentos-csrf"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
LOCAL_HOSTS = {"localhost", "127.0.0.1"}
LEGACY = Principal("legacy", "admin")

_template_cache: dict[tuple[int, str, str, str], Optional[str]] = {}
_route_index: dict[int, tuple[int, list[tuple[re.Pattern[str], str, frozenset[str]]]]] = {}


def _iter_routes(routes: Any, prefix: str = "") -> Any:
    """Flatten the app's routes (FastAPI may keep included routers as wrappers): yields (full template, route)."""
    for r in routes:
        if isinstance(r, Mount) and not hasattr(r, "original_router"):
            continue  # the UI static mount at "/" is never an /api route
        if hasattr(r, "original_router"):
            p = prefix + getattr(getattr(r, "include_context", None), "prefix", "")
            yield from _iter_routes(r.original_router.routes, p)
        elif hasattr(r, "routes"):
            yield from _iter_routes(r.routes, prefix + getattr(r, "path", ""))
        else:
            raw = getattr(r, "path", "")
            yield (raw if raw.startswith(prefix) else prefix + raw), r


def _index(app: Any) -> list[tuple[re.Pattern[str], str, frozenset[str]]]:
    routes = getattr(app, "routes", [])
    cached = _route_index.get(id(app))
    if cached is not None and cached[0] == len(routes):
        return cached[1]
    out = []
    for template, r in _iter_routes(routes):
        methods = frozenset(getattr(r, "methods", None) or {"WS"})
        pattern = re.compile("^" + re.sub(r"\\\{[^}]+\\\}", "[^/]+", re.escape(template)) + "$")
        out.append((pattern, template, methods))
    _route_index[id(app)] = (len(routes), out)
    return out


def route_template(app: Any, scope: dict[str, Any]) -> Optional[str]:
    """The route template (e.g. /api/v2/flows/{flow_id}) the request matches, or None.

    A path that matches only with another method returns that template (the app answers 405)."""
    kind = scope.get("type", "http")
    method = scope.get("method", "GET") if kind == "http" else "WS"
    path = scope.get("path", "")
    key = (id(app), kind, method, path)
    if key in _template_cache:
        return _template_cache[key]
    found: Optional[str] = None
    partial: Optional[str] = None
    want = {"GET", "HEAD"} if method in ("GET", "HEAD") else {method}
    for pattern, template, methods in _index(app):
        if not pattern.match(path):
            continue
        if methods & want:
            found = template
            break
        if partial is None and ("WS" in methods) == (kind == "websocket"):
            partial = template
    found = found or partial
    if len(_template_cache) > 4096:
        _template_cache.clear()
    _template_cache[key] = found
    return found


def capability(app: Any, scope: dict[str, Any]) -> Optional[str]:
    method = scope.get("method", "GET") if scope.get("type") == "http" else "WS"
    return permission_for(method, route_template(app, scope))


def session_cookie(headers: dict[str, str]) -> Optional[str]:
    raw = headers.get("cookie")
    if not raw:
        return None
    try:
        c = SimpleCookie()
        c.load(raw)
    except CookieError:
        return None
    m = c.get(SESSION_COOKIE)
    return m.value if m else None


def bearer_token(headers: dict[str, str]) -> Optional[str]:
    auth = headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip() or None
    x = headers.get("x-agentos-token")
    return x.strip() if x and x.strip() else None


async def principal_from_token(app_state: Any, token: str, expected_legacy: Optional[str]) -> Optional[Principal]:
    """Legacy local token (unless an admin disabled it) or a personal access token."""
    access = getattr(app_state, "access", None)
    if token.startswith(TOKEN_PREFIX):
        return await access.resolve_token(token) if access is not None else None
    if expected_legacy and hmac.compare_digest(token.strip(), expected_legacy.strip()):
        if access is not None and await access.legacy_token_disabled():
            return None
        return LEGACY
    return None


async def principal_from_session(app_state: Any, raw: Optional[str]) -> Optional[Principal]:
    access = getattr(app_state, "access", None)
    if access is None or not raw:
        return None
    return await access.resolve_session(raw)


def origin_host(headers: dict[str, str]) -> Optional[str]:
    """Host of the Origin header, or of the Referer when Origin is absent (None if neither)."""
    for name in ("origin", "referer"):
        value = headers.get(name)
        if value and value != "null":
            return (urllib.parse.urlparse(value).hostname or "").lower()
    return None


def csrf_ok(app_state: Any, principal: Principal, headers: dict[str, str]) -> bool:
    """Cookie session + state-changing request: allowed local Origin AND the per-session CSRF header."""
    host = origin_host(headers)
    if host is None or host not in LOCAL_HOSTS:
        return False
    access = getattr(app_state, "access", None)
    return access is not None and principal.session_hash is not None and \
        access.check_csrf(principal.session_hash, headers.get(CSRF_HEADER))
