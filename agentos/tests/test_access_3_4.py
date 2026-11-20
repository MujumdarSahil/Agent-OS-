"""3.4 access domain (MOCK, file store in a temp dir, fake clock): passwords, users, sessions, API tokens, limiter.

scrypt cost is lowered for speed by monkeypatching the module constant (the only way; there is no env knob).
"""

from __future__ import annotations

import pytest

from agentos.access import passwords as pw
from agentos.access.permissions import ROLE_CAPABILITIES, allows
from agentos.access.ratelimit import FREE_FAILURES, MAX_BACKOFF_S, LoginLimiter
from agentos.access.service import (
    SESSION_ABSOLUTE_S, SESSION_IDLE_S, TOKEN_PREFIX, AccessError, AccessService, Conflict, NotFound,
)
from agentos.access.store import AccessStore
from agentos.notify.store import FileDocs

GOOD = "violet-harbor-lantern-42"


class Clock:
    def __init__(self) -> None:
        self.t = 1_800_000_000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture(autouse=True)
def cheap_scrypt(monkeypatch):
    monkeypatch.setattr(pw, "LOG_N", 10)


@pytest.fixture
def svc(tmp_path):
    clock = Clock()
    store = AccessStore(*(FileDocs(tmp_path / f"{n}.json") for n in ("u", "n", "s", "t", "x")))
    service = AccessService(store, b"k" * 32, clock=clock)
    service.clock = clock
    return service


# ------------------------------------------------------------------ passwords


def test_hash_format_and_verify():
    h = pw.hash_password(GOOD)
    assert h.startswith("scrypt$10$8$1$") and GOOD not in h
    assert pw.verify_password(GOOD, h) and not pw.verify_password(GOOD + "x", h)
    assert not pw.verify_password(GOOD, "scrypt$99$8$1$AA$AA")  # absurd parameters refused
    assert not pw.verify_password(GOOD, "garbage")


def test_production_parameters_are_owasp():
    import ast
    import inspect

    src = inspect.getsource(pw)
    consts = {t.targets[0].id: t.value.value for t in ast.parse(src).body
              if isinstance(t, ast.Assign) and isinstance(t.targets[0], ast.Name) and isinstance(t.value, ast.Constant)}
    assert (consts["LOG_N"], consts["R"], consts["P"]) == (17, 8, 1)
    assert "os.environ" not in src and "getenv" not in src  # no environment knob can weaken hashing


@pytest.mark.parametrize("bad,msg", [("short-pass1", "at least 12"), ("password1234", "too common"),
                                     ("PASSWORD1234", "too common"), ("alice.admin12", "username"),
                                     ("x" * 257, "at most")])
def test_password_rules(bad, msg):
    with pytest.raises(pw.PasswordRuleError, match=msg):
        pw.check_password_rules(bad, "alice.admin12")
    pw.check_password_rules(GOOD, "alice")


# ------------------------------------------------------------------ roles


def test_role_matrix():
    assert allows("viewer", "read") and not allows("viewer", "approve") and not allows("viewer", "build")
    assert allows("approver", "approve") and not allows("approver", "build")
    assert allows("builder", "build") and not allows("builder", "approve") and not allows("builder", "admin")
    assert all(allows("admin", c) for c in ("read", "approve", "build", "admin", "self"))
    assert allows(None, "public") and not allows(None, "read") and not allows("admin", None)
    assert not allows("root", "read")  # unknown role: deny
    assert set(ROLE_CAPABILITIES) == {"viewer", "approver", "builder", "admin"}


# ------------------------------------------------------------------ users


@pytest.mark.asyncio
async def test_users_unique_case_insensitive_and_last_admin(svc):
    a = await svc.create_user("Alice", "Alice A", "admin", GOOD)
    assert "password_hash" not in a and a["role"] == "admin"
    with pytest.raises(Conflict):
        await svc.create_user("ALICE", None, "viewer", GOOD)
    with pytest.raises(AccessError, match="Role"):
        await svc.create_user("bob", None, "root", GOOD)
    with pytest.raises(AccessError, match="Username"):
        await svc.create_user("b", None, "viewer", GOOD)
    assert (await svc.find_user("aLiCe"))["id"] == a["id"]
    with pytest.raises(Conflict, match="enabled admin"):
        await svc.update_user(a["id"], role="viewer")
    with pytest.raises(Conflict, match="enabled admin"):
        await svc.update_user(a["id"], disabled=True)
    b = await svc.create_user("bob", None, "admin", GOOD)
    _, after = await svc.update_user(a["id"], role="viewer")
    assert after["role"] == "viewer" and b["role"] == "admin"


@pytest.mark.asyncio
async def test_login_generic_and_disabled(svc):
    u = await svc.create_user("carol", None, "builder", GOOD)
    assert (await svc.check_login("CAROL", GOOD))["id"] == u["id"]
    assert await svc.check_login("carol", "wrong-password-123") is None
    assert await svc.check_login("nobody", GOOD) is None
    await svc.create_user("admin1", None, "admin", GOOD)
    await svc.update_user(u["id"], disabled=True)
    assert await svc.check_login("carol", GOOD) is None


# ------------------------------------------------------------------ sessions


@pytest.mark.asyncio
async def test_session_idle_expiry_and_hash_only_storage(svc):
    u = await svc.create_user("dave", None, "viewer", GOOD)
    raw = await svc.create_session(await svc.get_user(u["id"]))
    assert len(raw) >= 43 and raw not in str(await svc.store.sessions.list())  # only the hash is stored
    assert (await svc.resolve_session(raw)).username == "dave"
    svc.clock.t += SESSION_IDLE_S - 10
    assert await svc.resolve_session(raw) is not None  # used: the idle timer restarts
    svc.clock.t += SESSION_IDLE_S + 1
    assert await svc.resolve_session(raw) is None  # idle timeout


@pytest.mark.asyncio
async def test_session_absolute_expiry_even_when_active(svc):
    u = await svc.create_user("dora", None, "viewer", GOOD)
    raw = await svc.create_session(await svc.get_user(u["id"]))
    start = svc.clock.t
    while svc.clock.t + 6 * 3600 < start + SESSION_ABSOLUTE_S:
        svc.clock.t += 6 * 3600  # active every 6 h (below the idle limit)
        assert await svc.resolve_session(raw) is not None
    svc.clock.t = start + SESSION_ABSOLUTE_S + 1
    assert await svc.resolve_session(raw) is None


@pytest.mark.asyncio
async def test_password_change_revokes_other_sessions_and_role_is_live(svc):
    await svc.create_user("root1", None, "admin", GOOD)
    u = await svc.create_user("erin", None, "viewer", GOOD)
    user = await svc.get_user(u["id"])
    keep, other = await svc.create_session(user), await svc.create_session(user)
    keep_p = await svc.resolve_session(keep)
    with pytest.raises(AccessError, match="Current password"):
        await svc.set_password(u["id"], "new-river-stone-77", current_password="nope", require_current=True)
    n = await svc.set_password(u["id"], "new-river-stone-77", current_password=GOOD, require_current=True,
                               keep_session_hash=keep_p.session_hash)
    assert n == 1 and await svc.resolve_session(other) is None and await svc.resolve_session(keep) is not None
    await svc.update_user(u["id"], role="approver")
    assert (await svc.resolve_session(keep)).role == "approver"  # role read live, not frozen in the session
    await svc.update_user(u["id"], disabled=True)
    assert await svc.resolve_session(keep) is None


def test_csrf_token_bound_to_session(svc):
    t = svc.csrf_token("a" * 64)
    assert svc.check_csrf("a" * 64, t) and not svc.check_csrf("b" * 64, t) and not svc.check_csrf("a" * 64, None)


# ------------------------------------------------------------------ API tokens


@pytest.mark.asyncio
async def test_pat_lifecycle(svc):
    await svc.create_user("root2", None, "admin", GOOD)
    u = await svc.create_user("frank", None, "builder", GOOD)
    raw, view = await svc.create_token(u["id"], "ci", 30)
    assert raw.startswith(TOKEN_PREFIX) and raw not in str(await svc.store.tokens.list())
    p = await svc.resolve_token(raw)
    assert (p.kind, p.role, p.actor) == ("pat", "builder", "token:ci@frank")
    with pytest.raises(AccessError):
        await svc.create_token(u["id"], "x", 400)
    other = await svc.create_user("gina", None, "viewer", GOOD)
    with pytest.raises(NotFound):
        await svc.revoke_token(view["token_id"], user_id=other["id"])  # not hers
    await svc.revoke_token(view["token_id"], user_id=u["id"])
    assert await svc.resolve_token(raw) is None
    raw2, _ = await svc.create_token(u["id"], "short", 1)
    svc.clock.t += 86401
    assert await svc.resolve_token(raw2) is None  # expired
    raw3, _ = await svc.create_token(u["id"], "live", 5)
    await svc.update_user(u["id"], disabled=True)
    assert await svc.resolve_token(raw3) is None
    assert await svc.resolve_token("aos_pat_forged") is None and await svc.resolve_token("no-prefix") is None


@pytest.mark.asyncio
async def test_legacy_disable_needs_an_admin(svc):
    with pytest.raises(Conflict):
        await svc.set_legacy_token_disabled(True)
    await svc.create_user("root3", None, "admin", GOOD)
    await svc.set_legacy_token_disabled(True)
    assert await svc.legacy_token_disabled()


# ------------------------------------------------------------------ limiter


def test_limiter_backoff_and_reset():
    clock = Clock()
    lim = LoginLimiter(clock=clock)
    for _ in range(FREE_FAILURES):
        assert lim.retry_after("1.2.3.4", "alice") == 0
        lim.failure("1.2.3.4", "alice")
    assert lim.retry_after("1.2.3.4", "alice") == pytest.approx(1.0)
    lim.failure("1.2.3.4", "alice")
    assert lim.retry_after("1.2.3.4", "ALICE") == pytest.approx(2.0)  # case-insensitive key
    assert lim.retry_after("5.6.7.8", "alice") == 0  # other IP unaffected
    for _ in range(30):
        lim.failure("1.2.3.4", "alice")
    assert lim.retry_after("1.2.3.4", "alice") <= MAX_BACKOFF_S
    assert lim.retry_after("1.2.3.4", "bob") > 0  # per-IP limit across usernames
    lim.success("1.2.3.4", "alice")
    clock.t += MAX_BACKOFF_S + 1
    assert lim.retry_after("1.2.3.4", "alice") == 0
