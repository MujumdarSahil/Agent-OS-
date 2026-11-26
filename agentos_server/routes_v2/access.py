"""3.4 access routes: setup, login/logout, me, own password and API tokens, users (admin), legacy token (admin).

Permissions are declared in agentos_server/permissions_table.py and enforced by SecurityMiddleware; handlers only
add the checks that depend on WHO is calling (a browser session vs an API token vs the legacy token).
Audited actions validate first, then write the audit entry (503 = not applied), then apply (3.1 rule).
Design: docs/evidence/3.4.md.
"""

from __future__ import annotations

import asyncio
import secrets
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel

from agentos.access import passwords as pw
from agentos.access.permissions import ROLE_DESCRIPTIONS, ROLES
from agentos.access.service import (
    SESSION_ABSOLUTE_S, TOKEN_DEFAULT_DAYS, AccessError, AccessService, Principal,
)
from agentos_server.access_mw import SESSION_COOKIE
from agentos_server.audit_support import audit, audit_best_effort, source_of

router = APIRouter(tags=["v2-access"])

GENERIC_LOGIN_ERROR = "Invalid username or password"


class SetupBody(BaseModel):
    username: str
    display_name: Optional[str] = None
    password: str


class LoginBody(BaseModel):
    username: str
    password: str


class PasswordChangeBody(BaseModel):
    current_password: str
    new_password: str


class PasswordResetBody(BaseModel):
    new_password: str


class TokenBody(BaseModel):
    name: str
    expires_in_days: int = TOKEN_DEFAULT_DAYS


class UserCreateBody(BaseModel):
    username: str
    display_name: Optional[str] = None
    role: str
    password: str


class UserUpdateBody(BaseModel):
    display_name: Optional[str] = None
    role: Optional[str] = None
    disabled: Optional[bool] = None


class LegacyTokenBody(BaseModel):
    enabled: bool


# ------------------------------------------------------------------ helpers


def _svc(request: Request) -> AccessService:
    return request.app.state.access


def _principal(request: Request) -> Optional[Principal]:
    return getattr(request.state, "principal", None)


def _user_principal(request: Request, *, session_only: bool = False, why: str = "") -> Principal:
    p = _principal(request)
    if p is None or p.user_id is None:
        raise HTTPException(status_code=400, detail="This needs a user account (the legacy local token has none)")
    if session_only and p.kind != "session":
        raise HTTPException(status_code=403, detail=why or "Only possible from a logged-in browser session")
    return p


def _err(e: AccessError) -> HTTPException:
    return HTTPException(status_code=e.status, detail=str(e))


def _client_ip(request: Request) -> str:
    """Return the resolved client IP (real client, respecting trusted proxies).

    Part 0 / 3.6b: SecurityMiddleware resolves the IP early and stores it in request.state.client_ip;
    we fall back to the direct peer address for requests that bypass middleware (e.g. tests that use
    the FastAPI TestClient directly against a bare app).
    """
    resolved = getattr(request.state, "client_ip", None)
    if resolved:
        return resolved
    return request.client.host if request.client else "unknown"


def _is_secure(request: Request) -> bool:
    scheme = getattr(request.state, "scheme", None)
    if scheme:
        return scheme == "https"
    return request.url.scheme == "https"


def _set_session_cookie(response: Response, request: Request, raw: str) -> None:
    response.set_cookie(SESSION_COOKIE, raw, max_age=SESSION_ABSOLUTE_S, path="/", httponly=True,
                        samesite="strict", secure=_is_secure(request))


def _clear_session_cookie(response: Response, request: Request) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, samesite="strict",
                           secure=_is_secure(request))


def _me(request: Request, p: Principal) -> dict[str, Any]:
    out = p.public()
    out["csrf_token"] = _svc(request).csrf_token(p.session_hash) if p.session_hash else None
    out["separation_of_duties"] = bool(getattr(request.app.state, "separation_of_duties", False))
    return out


async def _login_response(request: Request, response: Response, user: dict[str, Any]) -> dict[str, Any]:
    svc = _svc(request)
    raw = await svc.create_session(user, _client_ip(request), request.headers.get("user-agent", ""))
    _set_session_cookie(response, request, raw)
    p = await svc.resolve_session(raw)
    return {"user": svc.public_user(user), "me": _me(request, p)}


# ------------------------------------------------------------------ setup, login, logout, me


@router.get("/auth/status")
async def auth_status(request: Request) -> dict[str, Any]:
    from agentos.__version__ import __version__

    return {"setup_required": await _svc(request).user_count() == 0, "version": __version__,
            "roles": {r: ROLE_DESCRIPTIONS[r] for r in ROLES}}


@router.post("/auth/setup")
async def auth_setup(body: SetupBody, request: Request, response: Response) -> dict[str, Any]:
    """First admin. Only while no user exists, and only with the local API token (nobody else on the network
    can claim admin)."""
    p = _principal(request)
    if p is None or p.kind != "legacy":
        raise HTTPException(status_code=401, detail="The local API token is required to create the first admin")
    svc = _svc(request)
    lock: asyncio.Lock = request.app.state.access_setup_lock
    async with lock:
        if await svc.user_count() > 0:
            raise HTTPException(status_code=409, detail="Setup is already done; log in instead")
        try:
            svc.validate_new_user(body.username, body.display_name, "admin", body.password)
        except AccessError as e:
            raise _err(e)
        await audit(request, "user.create", "user", body.username.strip().lower(),
                    details={"role": "admin", "via": "setup"}, actor=p.actor)
        try:
            created = await svc.create_user(body.username, body.display_name, "admin", body.password)
        except AccessError as e:
            await audit_best_effort(request.app, "user.create", "user", body.username.strip().lower(),
                                    outcome="failed", actor=p.actor, source=source_of(request))
            raise _err(e)
    return await _login_response(request, response, await svc.get_user(created["id"]))


@router.post("/auth/login")
async def auth_login(body: LoginBody, request: Request, response: Response) -> dict[str, Any]:
    svc, limiter = _svc(request), request.app.state.login_limiter
    ip = _client_ip(request)
    wait = limiter.retry_after(ip, body.username)
    if wait > 0:
        secs = int(wait) + 1
        raise HTTPException(status_code=429, detail=f"Too many failed logins; try again in {secs} s",
                            headers={"Retry-After": str(secs)})
    user = await svc.check_login(body.username, body.password)
    if user is None:
        limiter.failure(ip, body.username)
        agg = getattr(request.app.state, "auth_failures", None)
        if agg is not None:
            try:
                await agg.note(request.app, f"login-{source_of(request)}")  # per minute, no username (3.1 style)
            except Exception:
                pass
        raise HTTPException(status_code=401, detail=GENERIC_LOGIN_ERROR)
    limiter.success(ip, body.username)
    await audit(request, "auth.login", "user", user["id"], details={"username": user["username"]},
                actor=user["username"])
    return await _login_response(request, response, user)


@router.post("/auth/logout")
async def auth_logout(request: Request, response: Response) -> dict[str, bool]:
    p = _user_principal(request, session_only=True, why="Logout ends a browser session; revoke API tokens instead")
    await audit(request, "auth.logout", "user", p.user_id)
    await _svc(request).revoke_session(p.session_hash)
    _clear_session_cookie(response, request)
    return {"ok": True}


@router.get("/auth/me")
async def auth_me(request: Request) -> dict[str, Any]:
    p = _principal(request)
    if p is None:
        raise HTTPException(status_code=401, detail="Not logged in")
    return _me(request, p)


@router.post("/auth/password")
async def change_own_password(body: PasswordChangeBody, request: Request) -> dict[str, Any]:
    p = _user_principal(request, session_only=True, why="Change your password from the web UI")
    svc = _svc(request)
    if not await svc.verify_user_password(p.user_id, body.current_password):
        raise HTTPException(status_code=400, detail="Current password is not correct")
    try:
        pw.check_password_rules(body.new_password, p.username)
    except pw.PasswordRuleError as e:
        raise HTTPException(status_code=400, detail=str(e))
    await audit(request, "user.password_change", "user", p.user_id)
    revoked = await svc.set_password(p.user_id, body.new_password, keep_session_hash=p.session_hash)
    return {"ok": True, "other_sessions_revoked": revoked}


# ------------------------------------------------------------------ own API tokens


@router.get("/auth/tokens")
async def list_own_tokens(request: Request) -> list[dict[str, Any]]:
    p = _user_principal(request)
    return await _svc(request).list_tokens(p.user_id)


@router.post("/auth/tokens", status_code=201)
async def create_own_token(body: TokenBody, request: Request) -> dict[str, Any]:
    p = _user_principal(request, session_only=True,
                        why="Create API tokens from the web UI (a token cannot make tokens)")
    svc = _svc(request)
    try:
        svc.validate_token_request(body.name, body.expires_in_days)
    except AccessError as e:
        raise _err(e)
    await audit(request, "token.create", "user", p.user_id,
                details={"name": body.name.strip(), "expires_in_days": body.expires_in_days})
    try:
        raw, view = await svc.create_token(p.user_id, body.name, body.expires_in_days)
    except AccessError as e:
        raise _err(e)
    return {**view, "token": raw, "note": "Shown once. Store it now; AgentOS keeps only a hash."}


@router.delete("/auth/tokens/{token_id}")
async def revoke_own_token(token_id: str, request: Request) -> dict[str, Any]:
    p = _user_principal(request)
    svc = _svc(request)
    if not any(t["token_id"] == token_id for t in await svc.list_tokens(p.user_id)):
        raise HTTPException(status_code=404, detail="Token not found")
    await audit(request, "token.revoke", "api_token", token_id, details={"owner": p.user_id})
    return await svc.revoke_token(token_id, user_id=p.user_id)


# ------------------------------------------------------------------ users (admin)


@router.get("/users")
async def list_users(request: Request) -> list[dict[str, Any]]:
    svc = _svc(request)
    return [svc.public_user(u) for u in await svc.list_users()]


@router.post("/users", status_code=201)
async def create_user(body: UserCreateBody, request: Request) -> dict[str, Any]:
    svc = _svc(request)
    try:
        svc.validate_new_user(body.username, body.display_name, body.role, body.password)
    except AccessError as e:
        raise _err(e)
    if await svc.find_user(body.username) is not None:
        raise HTTPException(status_code=409, detail="A user with this username already exists")
    await audit(request, "user.create", "user", body.username.strip().lower(), details={"role": body.role})
    try:
        return await svc.create_user(body.username, body.display_name, body.role, body.password)
    except AccessError as e:
        await audit_best_effort(request.app, "user.create", "user", body.username.strip().lower(), outcome="failed",
                                actor=_principal(request).actor, source=source_of(request))
        raise _err(e)


@router.put("/users/{user_id}")
async def update_user(user_id: str, body: UserUpdateBody, request: Request) -> dict[str, Any]:
    svc = _svc(request)
    try:
        before, after = await svc.update_user(user_id, display_name=body.display_name, role=body.role,
                                              disabled=body.disabled, dry_run=True)
    except AccessError as e:
        raise _err(e)
    if before["role"] != after["role"]:
        await audit(request, "user.role_change", "user", user_id,
                    details={"from": before["role"], "to": after["role"]})
    if before["disabled"] != after["disabled"]:
        await audit(request, "user.disable" if after["disabled"] else "user.enable", "user", user_id)
    if before["display_name"] != after["display_name"]:
        await audit(request, "user.update", "user", user_id, details={"field": "display_name"})
    try:
        return (await svc.update_user(user_id, display_name=body.display_name, role=body.role,
                                      disabled=body.disabled))[1]
    except AccessError as e:
        raise _err(e)


@router.post("/users/{user_id}/password")
async def reset_password(user_id: str, body: PasswordResetBody, request: Request) -> dict[str, Any]:
    svc = _svc(request)
    u = await svc.get_user(user_id)
    if u is None:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        pw.check_password_rules(body.new_password, u["username"])
    except pw.PasswordRuleError as e:
        raise HTTPException(status_code=400, detail=str(e))
    await audit(request, "user.password_reset", "user", user_id)
    revoked = await svc.set_password(user_id, body.new_password)
    return {"ok": True, "sessions_revoked": revoked}


@router.get("/users/{user_id}/tokens")
async def list_user_tokens(user_id: str, request: Request) -> list[dict[str, Any]]:
    if await _svc(request).get_user(user_id) is None:
        raise HTTPException(status_code=404, detail="User not found")
    return await _svc(request).list_tokens(user_id)


@router.delete("/users/{user_id}/tokens/{token_id}")
async def revoke_user_token(user_id: str, token_id: str, request: Request) -> dict[str, Any]:
    svc = _svc(request)
    if not any(t["token_id"] == token_id for t in await svc.list_tokens(user_id)):
        raise HTTPException(status_code=404, detail="Token not found")
    await audit(request, "token.revoke", "api_token", token_id, details={"owner": user_id})
    return await svc.revoke_token(token_id, user_id=user_id)


# ------------------------------------------------------------------ legacy local token (admin)


def _legacy_source() -> dict[str, Any]:
    import os

    from agentos_server.auth import default_token_path

    if os.environ.get("AGENTOS_API_TOKEN", "").strip():
        return {"source": "env", "path": None, "can_rotate": False}
    return {"source": "file", "path": str(default_token_path()), "can_rotate": True}


@router.get("/access/legacy-token")
async def legacy_token_status(request: Request) -> dict[str, Any]:
    """Status only; the token value is never returned here."""
    return {"enabled": not await _svc(request).legacy_token_disabled(max_age_s=0), **_legacy_source()}


@router.put("/access/legacy-token")
async def set_legacy_token(body: LegacyTokenBody, request: Request) -> dict[str, Any]:
    svc = _svc(request)
    if not body.enabled and not await svc.has_enabled_admin():
        raise HTTPException(status_code=409, detail="Create an enabled admin user before disabling the legacy token")
    await audit(request, "legacy_token.enable" if body.enabled else "legacy_token.disable", "api",
                "legacy-local-token")
    try:
        await svc.set_legacy_token_disabled(not body.enabled)
    except AccessError as e:
        raise _err(e)
    return await legacy_token_status(request)


@router.post("/access/legacy-token/rotate")
async def rotate_legacy_token(request: Request) -> dict[str, Any]:
    info = _legacy_source()
    if not info["can_rotate"]:
        raise HTTPException(status_code=409,
                            detail="The token comes from AGENTOS_API_TOKEN; change that variable instead")
    from pathlib import Path

    from agentos.storage.atomic import atomic_write_text

    new = secrets.token_urlsafe(32)
    await audit(request, "legacy_token.rotate", "api", "legacy-local-token")
    atomic_write_text(Path(info["path"]), new + "\n", private=True, encoding="ascii")
    request.app.state.api_token = new
    return {"token": new, "path": info["path"],
            "note": "Shown once. Scripts that read the token file pick it up; the old token no longer works."}
