"""3.4: LIVE Mongo tests for access (users, username claims, sessions, API tokens, settings) on MongoDocs.

Runs in CI's mongo-live job (AGENTOS_REQUIRE_LIVE_MONGO=1 turns a skip into a failure); skipped locally without
AGENTOS_MONGO_URI. Each test uses a throwaway database that is dropped afterwards.
"""

from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio

from agentos.access import passwords as pw
from agentos.access.service import SESSION_IDLE_S, AccessService, Conflict
from agentos.access.store import access_store_for
from agentos.tests.test_storage_contract_1_2 import _live_mongo_storage

pytestmark = pytest.mark.asyncio
GOOD = "violet-harbor-lantern-42"


class Clock:
    def __init__(self) -> None:
        self.t = 1_800_000_000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture(autouse=True)
def cheap_scrypt(monkeypatch):
    monkeypatch.setattr(pw, "LOG_N", 10)


@pytest_asyncio.fixture
async def svc():
    async for storage in _live_mongo_storage():
        clock = Clock()
        service = AccessService(access_store_for(storage), b"k" * 32, clock=clock)
        service.clock = clock
        yield service


async def test_mongo_store_is_the_mongo_backend(svc):
    assert type(svc.store.users).__name__ == "MongoDocs"


async def test_concurrent_creates_of_one_username_one_wins(svc):
    results = await asyncio.gather(*(svc.create_user(n, None, "viewer", GOOD) for n in ("Dup", "dup", "DUP")),
                                   return_exceptions=True)
    assert sum(isinstance(r, dict) for r in results) == 1
    assert sum(isinstance(r, Conflict) for r in results) == 2
    assert len(await svc.list_users()) == 1


async def test_sessions_live(svc):
    await svc.create_user("root", None, "admin", GOOD)
    u = await svc.create_user("mia", None, "builder", GOOD)
    user = await svc.get_user(u["id"])
    a, b = await svc.create_session(user), await svc.create_session(user)
    assert (await svc.resolve_session(a)).username == "mia"
    assert a not in str(await svc.store.sessions.list())  # only hashes stored
    keep = (await svc.resolve_session(a)).session_hash
    assert await svc.set_password(u["id"], "new-river-stone-77", keep_session_hash=keep) == 1
    assert await svc.resolve_session(b) is None and await svc.resolve_session(a) is not None
    svc.clock.t += SESSION_IDLE_S + 1
    assert await svc.resolve_session(a) is None


async def test_tokens_and_settings_live(svc):
    await svc.create_user("root", None, "admin", GOOD)
    u = await svc.create_user("ned", None, "viewer", GOOD)
    raw, view = await svc.create_token(u["id"], "ci", 5)
    assert (await svc.resolve_token(raw)).actor == "token:ci@ned"
    await svc.revoke_token(view["token_id"], user_id=u["id"])
    assert await svc.resolve_token(raw) is None
    await svc.set_legacy_token_disabled(True)
    assert await svc.legacy_token_disabled(max_age_s=0) is True
