"""AccessService: users, password login, server-side sessions, personal access tokens (3.4).

Design: docs/evidence/3.4.md. No FastAPI or Mongo imports (ports and adapters); the server wires it up.

- Sessions: the raw id (256 bits) goes to the browser in an HttpOnly cookie; only its sha256 is stored.
  Idle timeout 12 h, absolute 7 days; ``last_seen`` is written at most once a minute.
- PATs: ``aos_pat_`` + 256 random bits, shown once, stored as sha256. The token acts with its owner's CURRENT role.
- Login: an unknown or disabled user is checked against a dummy hash, so every failed login costs one scrypt.
- CSRF token: HMAC-SHA256(key derived from the server secret, session hash). Never stored.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import hashlib
import hmac
import re
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Optional

from agentos.access import passwords as pw
from agentos.access.permissions import ROLES, capabilities_of

USERNAME_RE = re.compile(r"^[a-z0-9._-]{3,64}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
SESSION_IDLE_S = 12 * 3600
SESSION_ABSOLUTE_S = 7 * 24 * 3600
TOUCH_EVERY_S = 60
TOKEN_PREFIX = "aos_pat_"
TOKEN_DEFAULT_DAYS = 90
TOKEN_MAX_DAYS = 365
LEGACY_PRINCIPAL = "legacy-local-token"
HASH_CONCURRENCY = 2  # scrypt uses ~128 MiB each: bound the memory a burst of logins can take


class AccessError(Exception):
    status = 400


class NotFound(AccessError):
    status = 404


class Conflict(AccessError):
    status = 409


@dataclass(frozen=True)
class Principal:
    """Who is calling: a logged-in user (session), a user's API token (pat), or the legacy local token."""

    kind: str  # "session" | "pat" | "legacy"
    role: str
    user_id: Optional[str] = None
    username: Optional[str] = None
    display_name: Optional[str] = None
    token_name: Optional[str] = None
    token_id: Optional[str] = None
    session_hash: Optional[str] = None

    @property
    def actor(self) -> str:
        """The audit-log actor."""
        if self.kind == "legacy":
            return LEGACY_PRINCIPAL
        if self.kind == "pat":
            return f"token:{self.token_name}@{self.username}"
        return self.username or "unknown"

    @property
    def actor_id(self) -> str:
        """Stable id for published_by / decided_by / separation of duties."""
        return self.user_id or LEGACY_PRINCIPAL

    def public(self) -> dict[str, Any]:
        return {"kind": self.kind, "role": self.role, "user_id": self.user_id, "username": self.username,
                "display_name": self.display_name or (LEGACY_PRINCIPAL if self.kind == "legacy" else None),
                "token_name": self.token_name, "capabilities": capabilities_of(self.role)}


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def iso(ts: Optional[float]) -> Optional[str]:
    return None if ts is None else _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc).isoformat()


def _clean_text(value: Any, field: str, max_len: int) -> str:
    if not isinstance(value, str):
        raise AccessError(f"{field} must be text")
    value = value.strip()
    if not value or len(value) > max_len or _CONTROL.search(value):
        raise AccessError(f"{field} must be 1-{max_len} printable characters")
    return value


class AccessService:
    def __init__(self, store: Any, secret_key: bytes, clock: Callable[[], float] = time.time) -> None:
        self.store = store
        self._clock = clock
        self._csrf_key = hmac.new(secret_key, b"agentos-csrf-v1", hashlib.sha256).digest()
        self._sem: Optional[asyncio.Semaphore] = None
        self._dummy_hash: Optional[str] = None
        self._legacy_cache: Optional[tuple[float, bool]] = None

    # ------------------------------------------------------------------ hashing

    def _semaphore(self) -> asyncio.Semaphore:
        if self._sem is None:
            self._sem = asyncio.Semaphore(HASH_CONCURRENCY)
        return self._sem

    async def _hash(self, password: str) -> str:
        async with self._semaphore():
            return await asyncio.to_thread(pw.hash_password, password)

    async def _verify(self, password: str, encoded: str) -> bool:
        async with self._semaphore():
            return await asyncio.to_thread(pw.verify_password, password, encoded)

    async def warm(self) -> None:
        """Make the dummy hash used for unknown users (call at startup so the first login is not slower)."""
        if self._dummy_hash is None:
            self._dummy_hash = await self._hash(secrets.token_urlsafe(16))

    # ------------------------------------------------------------------ users

    @staticmethod
    def public_user(u: dict[str, Any]) -> dict[str, Any]:
        return {"id": u["id"], "username": u["username"], "display_name": u.get("display_name") or u["username"],
                "role": u["role"], "disabled": bool(u.get("disabled")), "created_at": iso(u.get("created_ts")),
                "updated_at": iso(u.get("updated_ts")), "password_changed_at": iso(u.get("password_changed_ts"))}

    async def list_users(self) -> list[dict[str, Any]]:
        return sorted(await self.store.users.list(), key=lambda u: u.get("username_lower", ""))

    async def user_count(self) -> int:
        return len(await self.store.users.list())

    async def get_user(self, user_id: str) -> Optional[dict[str, Any]]:
        return await self.store.users.get(user_id) if isinstance(user_id, str) and user_id else None

    async def find_user(self, username: Any) -> Optional[dict[str, Any]]:
        if not isinstance(username, str) or not username or len(username) > 128:
            return None
        claim = await self.store.usernames.get(username.strip().lower())
        return await self.get_user(claim["user_id"]) if claim else None

    async def has_enabled_admin(self, excluding: Optional[str] = None) -> bool:
        return any(u["role"] == "admin" and not u.get("disabled") and u["id"] != excluding
                   for u in await self.store.users.list())

    @staticmethod
    def validate_new_user(username: Any, display_name: Any, role: Any, password: Any) -> tuple[str, str]:
        """Checks a new user without side effects; returns (username, display name)."""
        uname = _clean_text(username, "Username", 64)
        if not USERNAME_RE.fullmatch(uname.lower()):
            raise AccessError("Username must be 3-64 characters: letters, digits, '.', '_' or '-'")
        if role not in ROLES:
            raise AccessError(f"Role must be one of: {', '.join(ROLES)}")
        dname = _clean_text(display_name, "Display name", 100) if display_name else uname
        try:
            pw.check_password_rules(password, uname)
        except pw.PasswordRuleError as e:
            raise AccessError(str(e)) from None
        return uname, dname

    @staticmethod
    def validate_token_request(name: Any, days: Any) -> None:
        _clean_text(name, "Token name", 64)
        if not isinstance(days, int) or isinstance(days, bool) or not (1 <= days <= TOKEN_MAX_DAYS):
            raise AccessError(f"Expiry must be 1-{TOKEN_MAX_DAYS} days")

    async def verify_user_password(self, user_id: str, password: Any) -> bool:
        u = await self.get_user(user_id)
        if u is None or not isinstance(password, str) or len(password) > pw.MAX_LENGTH:
            return False
        return await self._verify(password, u["password_hash"])

    async def create_user(self, username: Any, display_name: Any, role: Any, password: Any) -> dict[str, Any]:
        uname, dname = self.validate_new_user(username, display_name, role, password)
        lower = uname.lower()
        password_hash = await self._hash(password)
        uid = uuid.uuid4().hex
        if not await self.store.usernames.insert_if_absent({"id": lower, "user_id": uid}):
            raise Conflict("A user with this username already exists")
        now = self._clock()
        doc = {"id": uid, "username": uname, "username_lower": lower, "display_name": dname, "role": role,
               "disabled": False, "created_ts": now, "updated_ts": now, "password_hash": password_hash,
               "password_changed_ts": now}
        await self.store.users.put(doc)
        return self.public_user(doc)

    async def update_user(self, user_id: str, *, display_name: Any = None, role: Any = None,
                          disabled: Any = None, dry_run: bool = False) -> tuple[dict[str, Any], dict[str, Any]]:
        """Returns (before, after) public views. Refuses to remove the last enabled admin. ``dry_run``: all checks,
        nothing saved (the route audits between the check and the change)."""
        u = await self.get_user(user_id)
        if u is None:
            raise NotFound("User not found")
        new = dict(u)
        if display_name is not None:
            new["display_name"] = _clean_text(display_name, "Display name", 100)
        if role is not None:
            if role not in ROLES:
                raise AccessError(f"Role must be one of: {', '.join(ROLES)}")
            new["role"] = role
        if disabled is not None:
            if not isinstance(disabled, bool):
                raise AccessError("disabled must be true or false")
            new["disabled"] = disabled
        was_admin = u["role"] == "admin" and not u.get("disabled")
        still_admin = new["role"] == "admin" and not new.get("disabled")
        if was_admin and not still_admin and not await self.has_enabled_admin(excluding=user_id):
            raise Conflict("At least one enabled admin is required")
        new["updated_ts"] = self._clock()
        if dry_run:
            return self.public_user(u), self.public_user(new)
        await self.store.users.put(new)
        if new.get("disabled") and not u.get("disabled"):
            await self.revoke_user_sessions(user_id)
            await self.revoke_user_tokens(user_id)
        return self.public_user(u), self.public_user(new)

    async def set_password(self, user_id: str, new_password: Any, *, current_password: Any = None,
                           keep_session_hash: Optional[str] = None, require_current: bool = False) -> int:
        """Change (``require_current``: the user's own change) or reset (admin) a password. Revokes every session
        of the user except ``keep_session_hash``. Returns the number of sessions revoked."""
        u = await self.get_user(user_id)
        if u is None:
            raise NotFound("User not found")
        if require_current and not (isinstance(current_password, str)
                                    and await self._verify(current_password, u["password_hash"])):
            raise AccessError("Current password is not correct")
        try:
            pw.check_password_rules(new_password, u["username"])
        except pw.PasswordRuleError as e:
            raise AccessError(str(e)) from None
        new_hash = await self._hash(new_password)
        now = self._clock()
        await self.store.users.put({**u, "password_hash": new_hash, "password_changed_ts": now, "updated_ts": now})
        return await self.revoke_user_sessions(user_id, except_hash=keep_session_hash)

    async def check_login(self, username: Any, password: Any) -> Optional[dict[str, Any]]:
        """The user for a correct username + password, else None. Same cost for every failure (no enumeration)."""
        u = await self.find_user(username)
        if not isinstance(password, str) or len(password) > pw.MAX_LENGTH:
            password = ""
        if u is None or u.get("disabled"):
            await self.warm()
            await self._verify(password, self._dummy_hash or "")
            return None
        return u if await self._verify(password, u["password_hash"]) else None

    # ------------------------------------------------------------------ sessions

    async def create_session(self, user: dict[str, Any], ip: str = "", user_agent: str = "") -> str:
        """New session for ``user``; returns the raw id (for the cookie only; never stored)."""
        raw = secrets.token_urlsafe(32)
        now = self._clock()
        await self.store.sessions.put({"id": sha256_hex(raw), "user_id": user["id"], "created_ts": now,
                                       "last_seen_ts": now, "ip": (ip or "")[:64],
                                       "user_agent": (user_agent or "")[:200]})
        await self._prune_sessions(now)
        return raw

    def _expired(self, s: dict[str, Any], now: float) -> bool:
        return now - s["created_ts"] > SESSION_ABSOLUTE_S or now - s["last_seen_ts"] > SESSION_IDLE_S

    async def _prune_sessions(self, now: float) -> None:
        for s in await self.store.sessions.list():
            if self._expired(s, now):
                await self.store.sessions.delete(s["id"])

    async def resolve_session(self, raw: Any) -> Optional[Principal]:
        if not isinstance(raw, str) or not raw or len(raw) > 128:
            return None
        h = sha256_hex(raw)
        s = await self.store.sessions.get(h)
        if s is None:
            return None
        now = self._clock()
        if self._expired(s, now):
            await self.store.sessions.delete(h)
            return None
        u = await self.get_user(s["user_id"])
        if u is None or u.get("disabled"):
            return None
        if now - s["last_seen_ts"] > TOUCH_EVERY_S:
            await self.store.sessions.put({**s, "last_seen_ts": now})
        return Principal("session", u["role"], u["id"], u["username"], u.get("display_name"), session_hash=h)

    async def revoke_session(self, session_hash: str) -> bool:
        return await self.store.sessions.delete(session_hash)

    async def revoke_user_sessions(self, user_id: str, except_hash: Optional[str] = None) -> int:
        n = 0
        for s in await self.store.sessions.list():
            if s["user_id"] == user_id and s["id"] != except_hash:
                n += int(await self.store.sessions.delete(s["id"]))
        return n

    def csrf_token(self, session_hash: str) -> str:
        return hmac.new(self._csrf_key, session_hash.encode("ascii"), hashlib.sha256).hexdigest()

    def check_csrf(self, session_hash: str, provided: Any) -> bool:
        return isinstance(provided, str) and hmac.compare_digest(self.csrf_token(session_hash), provided)

    # ------------------------------------------------------------------ API tokens

    def public_token(self, t: dict[str, Any]) -> dict[str, Any]:
        now = self._clock()
        return {"token_id": t["token_id"], "user_id": t["user_id"], "name": t["name"], "prefix": t["prefix"],
                "created_at": iso(t["created_ts"]), "expires_at": iso(t["expires_ts"]),
                "last_used_at": iso(t.get("last_used_ts")), "revoked_at": iso(t.get("revoked_ts")),
                "active": t.get("revoked_ts") is None and t["expires_ts"] > now}

    async def create_token(self, user_id: str, name: Any, days: Any = TOKEN_DEFAULT_DAYS) -> tuple[str, dict[str, Any]]:
        """Returns (the token, shown once; its public view)."""
        self.validate_token_request(name, days)
        tname = _clean_text(name, "Token name", 64)
        u = await self.get_user(user_id)
        if u is None or u.get("disabled"):
            raise NotFound("User not found")
        raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
        h = sha256_hex(raw)
        now = self._clock()
        doc = {"id": h, "token_id": h[:16], "user_id": user_id, "name": tname, "prefix": raw[:len(TOKEN_PREFIX) + 4],
               "created_ts": now, "expires_ts": now + days * 86400, "last_used_ts": None, "revoked_ts": None}
        await self.store.tokens.put(doc)
        return raw, self.public_token(doc)

    async def resolve_token(self, raw: Any) -> Optional[Principal]:
        if not isinstance(raw, str) or not raw.startswith(TOKEN_PREFIX) or len(raw) > 128:
            return None
        t = await self.store.tokens.get(sha256_hex(raw))
        now = self._clock()
        if t is None or t.get("revoked_ts") is not None or t["expires_ts"] <= now:
            return None
        u = await self.get_user(t["user_id"])
        if u is None or u.get("disabled"):
            return None
        if now - (t.get("last_used_ts") or 0) > TOUCH_EVERY_S:
            await self.store.tokens.put({**t, "last_used_ts": now})
        return Principal("pat", u["role"], u["id"], u["username"], u.get("display_name"), token_name=t["name"],
                         token_id=t["token_id"])

    async def list_tokens(self, user_id: Optional[str] = None) -> list[dict[str, Any]]:
        docs = [t for t in await self.store.tokens.list() if user_id is None or t["user_id"] == user_id]
        return [self.public_token(t) for t in sorted(docs, key=lambda t: t["created_ts"])]

    async def revoke_token(self, token_id: str, user_id: Optional[str] = None) -> dict[str, Any]:
        """Revoke by public token id; with ``user_id`` only that user's token (own-token management)."""
        for t in await self.store.tokens.list():
            if t["token_id"] == token_id and (user_id is None or t["user_id"] == user_id):
                if t.get("revoked_ts") is None:
                    t = {**t, "revoked_ts": self._clock()}
                    await self.store.tokens.put(t)
                return self.public_token(t)
        raise NotFound("Token not found")

    async def revoke_user_tokens(self, user_id: str) -> int:
        n = 0
        for t in await self.store.tokens.list():
            if t["user_id"] == user_id and t.get("revoked_ts") is None:
                await self.store.tokens.put({**t, "revoked_ts": self._clock()})
                n += 1
        return n

    # ------------------------------------------------------------------ legacy token setting

    async def legacy_token_disabled(self, max_age_s: float = 5.0) -> bool:
        now = self._clock()
        if self._legacy_cache is not None and now - self._legacy_cache[0] < max_age_s:
            return self._legacy_cache[1]
        doc = await self.store.settings.get("legacy_token")
        value = bool(doc and doc.get("disabled"))
        self._legacy_cache = (now, value)
        return value

    async def set_legacy_token_disabled(self, disabled: bool) -> None:
        if disabled and not await self.has_enabled_admin():
            raise Conflict("Create an enabled admin user before disabling the legacy local token")
        await self.store.settings.put({"id": "legacy_token", "disabled": bool(disabled),
                                       "updated_ts": self._clock()})
        self._legacy_cache = (self._clock(), bool(disabled))
