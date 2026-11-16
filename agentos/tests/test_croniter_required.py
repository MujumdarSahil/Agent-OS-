"""
2.0 cleanup: a missing croniter must fail loudly, never silently skip schedules (MOCK).
  - Server startup fails with CroniterMissingError when schedules exist.
  - Startup is unaffected when there are no schedules.
  - FlowScheduler.tick raises instead of returning [].
  - The schedules API rejects (503) instead of storing an unvalidated cron expression.
"""

from __future__ import annotations

import os

import pytest
from httpx import ASGITransport, AsyncClient

import agentos.triggers.scheduler as scheduler_mod
import agentos_server.routes_v2.schedules as schedules_routes
from agentos.queue.in_process import InProcessQueueBackend
from agentos.storage.file import open_file_storage
from agentos.storage.models import ScheduleRecord
from agentos.triggers.scheduler import CroniterMissingError, FlowScheduler, InProcessLeaderLock
from agentos_server.app import create_app

TOKEN = "test-token-croniter"


def _schedule() -> ScheduleRecord:
    return ScheduleRecord(
        schedule_id="s1", name="nightly", flow_id="f1", cron_expression="0 2 * * *", timezone="UTC", enabled=True
    )


@pytest.fixture
def no_croniter(monkeypatch):
    monkeypatch.setattr(scheduler_mod, "croniter", None)
    monkeypatch.setattr(schedules_routes, "croniter", None)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTOS_API_TOKEN", TOKEN)
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    (tmp_path / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    return tmp_path


@pytest.mark.asyncio
async def test_startup_fails_when_schedules_exist_and_croniter_missing(env, no_croniter):
    storage = open_file_storage(str(env))
    await storage.schedules.put(_schedule())
    app = create_app(project_path=str(env), storage=storage)
    with pytest.raises(CroniterMissingError, match="croniter"):
        async with app.router.lifespan_context(app):
            pass


@pytest.mark.asyncio
async def test_startup_ok_without_schedules_even_if_croniter_missing(env, no_croniter):
    app = create_app(project_path=str(env), storage=open_file_storage(str(env)))
    async with app.router.lifespan_context(app):
        assert app.state.scheduler is not None


@pytest.mark.asyncio
async def test_tick_raises_instead_of_skipping(env, no_croniter):
    storage = open_file_storage(str(env))
    await storage.schedules.put(_schedule())
    sched = FlowScheduler(storage=storage, queue=InProcessQueueBackend(storage=storage), leader_lock=InProcessLeaderLock())
    with pytest.raises(CroniterMissingError):
        await sched.tick()


@pytest.mark.asyncio
async def test_schedule_route_rejects_when_croniter_missing(env, no_croniter):
    app = create_app(project_path=str(env), storage=open_file_storage(str(env)))
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://localhost",
        headers={"Authorization": f"Bearer {TOKEN}", "Host": "localhost"},
    ) as c:
        r = await c.post(
            "/api/v2/schedules",
            json={"name": "n", "flow_id": "f1", "cron_expression": "not a cron", "timezone": "UTC"},
        )
    assert r.status_code == 503
    assert "croniter" in r.json()["detail"]
    assert os.environ.get("AGENTOS_API_TOKEN") == TOKEN
