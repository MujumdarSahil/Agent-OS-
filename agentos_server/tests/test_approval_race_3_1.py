"""3.1 Part 0: approval race (CI run 44483492284). MOCK (in-process worker, MockTransport); the Mongo variant
is LIVE (AGENTOS_MONGO_URI, mongo-live CI job) and skips without Mongo unless AGENTOS_REQUIRE_LIVE_MONGO=1.

The worker makes the run visible as waiting (node_waiting) while its queue job is still leased, and releases
the lease right after. These tests hold the worker exactly in that window (release_for_waiting blocks on an
event) and approve there:
  - released within the endpoint's short wait -> 200, run succeeds, the decision is applied exactly once;
  - not released in time -> 409 "retry", NO decision written; the retry after the release succeeds;
  - two concurrent approvals -> one decision, one email.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from agentos.flows.proxy import MockTransport
from agentos_server.app import create_app
import agentos_server.routes_v2.flows as flow_routes

TOKEN = "test-token-approval-race"
MONGO_URI = os.environ.get("AGENTOS_MONGO_URI")

FLOW = {
    "id": "race_flow", "name": "race", "entrypoint": "trig",
    "nodes": {
        "trig": {"id": "trig", "type": "manual_trigger", "config": {}},
        "gate": {"id": "gate", "type": "approval",
                 "config": {"prompt": "Review", "approves": {"sink_node": "send", "args": ["body"]}}},
        "send": {"id": "send", "type": "send_email", "config": {},
                 "pinned_args": {"to": "support@corp.local", "subject": "Ticket"}},
    },
    "edges": [{"source": "trig", "target": "gate", "arg_mapping": {"body": "payload"}},
              {"source": "gate", "target": "send", "arg_mapping": {"body": "body"}}],
}


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTOS_API_TOKEN", TOKEN)
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    monkeypatch.setenv("AGENTOS_INPROCESS_WORKER", "1")
    monkeypatch.setenv("AGENTOS_INTERNAL_DOMAINS", "corp.local")
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    project = tmp_path / "project"
    project.mkdir()
    (project / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    return str(project)


@pytest_asyncio.fixture(params=["file", "mongo"])
async def backend(request, env):
    if request.param == "file":
        yield env, None
        return
    if not MONGO_URI:
        if os.environ.get("AGENTOS_REQUIRE_LIVE_MONGO") == "1":
            pytest.fail("LIVE Mongo required (AGENTOS_MONGO_URI not set)")
        pytest.skip("LIVE: set AGENTOS_MONGO_URI (docker/compose.mongo.yml) to run the Mongo variant")
    from agentos.storage import open_storage

    db_name = f"agentos_test_{uuid.uuid4().hex[:12]}"
    storage = await open_storage(backend="mongo", mongo_uri=MONGO_URI, db_name=db_name)
    yield env, storage
    await storage.close()
    from pymongo import AsyncMongoClient

    client = AsyncMongoClient(MONGO_URI)
    await client.drop_database(db_name)
    await client.close()


def _client(app) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost",
                       headers={"Authorization": f"Bearer {TOKEN}", "Host": "localhost"})


class Parking:
    """Hold the worker between 'waiting visible' and 'lease released'."""

    def __init__(self, queue):
        self.entered = asyncio.Event()
        self.gate = asyncio.Event()
        self._orig = queue.release_for_waiting

    async def __call__(self, *args, **kwargs):
        self.entered.set()
        await self.gate.wait()
        return await self._orig(*args, **kwargs)


async def _start_parked(app, c):
    parking = Parking(app.state.queue)
    app.state.queue.release_for_waiting = parking
    assert (await c.post("/api/v2/flows", json=FLOW)).status_code == 201
    assert (await c.post("/api/v2/flows/race_flow/publish", json={"note": "test publish"})).status_code == 200
    r = await c.post("/api/v2/flows/race_flow/runs", json={"inputs": {"text": "please review"}})
    assert r.status_code == 201
    run_id = r.json()["run_id"]
    await asyncio.wait_for(parking.entered.wait(), timeout=15)
    # exactly the race window: visible as waiting, lease still held
    events = (await c.get(f"/api/v2/flows/race_flow/runs/{run_id}/events")).json()
    assert any(e["type"] == "node_waiting" for e in events)
    assert (await app.state.queue.get_job_by_run_id(run_id)).status == "leased"
    return run_id, parking


async def _decisions(c, run_id) -> int:
    events = (await c.get(f"/api/v2/flows/race_flow/runs/{run_id}/events")).json()
    return sum(1 for e in events if e["type"] == "approval_decision")


def _app(env, storage, mt):
    app = create_app(project_path=env, storage=storage) if storage is not None else create_app(project_path=env)
    app.state.transport_registry = {"send_email": mt}
    return app


@pytest.mark.asyncio
async def test_approve_inside_the_window_waits_and_is_applied_once(backend):
    env, storage = backend
    mt = MockTransport()
    app = _app(env, storage, mt)
    async with app.router.lifespan_context(app):
        app.state.transport_registry = {"send_email": mt}
        async with _client(app) as c:
            run_id, parking = await _start_parked(app, c)
            approve = asyncio.create_task(
                c.post(f"/api/v2/flows/race_flow/runs/{run_id}/approve", json={"node_id": "gate", "decision": True}))
            await asyncio.sleep(0.3)  # the endpoint is now waiting for the release
            assert not approve.done()
            parking.gate.set()
            r = await approve
            assert r.status_code == 200, r.text
            assert r.json()["status"] == "succeeded"
            assert await _decisions(c, run_id) == 1
    assert len(mt.sent_calls) == 1


@pytest.mark.asyncio
async def test_approve_returns_409_retry_and_writes_nothing_then_retry_succeeds(backend, monkeypatch):
    env, storage = backend
    monkeypatch.setattr(flow_routes, "PARK_WAIT_S", 0.2)
    mt = MockTransport()
    app = _app(env, storage, mt)
    async with app.router.lifespan_context(app):
        app.state.transport_registry = {"send_email": mt}
        async with _client(app) as c:
            run_id, parking = await _start_parked(app, c)
            r = await c.post(f"/api/v2/flows/race_flow/runs/{run_id}/approve", json={"node_id": "gate", "decision": True})
            assert r.status_code == 409
            detail = r.json()["detail"]
            assert detail["retry"] is True and "retry" in detail["detail"]
            assert await _decisions(c, run_id) == 0  # the decision was not applied, and not lost silently
            parking.gate.set()
            for _ in range(100):
                if (await app.state.queue.get_job_by_run_id(run_id)).status != "leased":
                    break
                await asyncio.sleep(0.05)
            r2 = await c.post(f"/api/v2/flows/race_flow/runs/{run_id}/approve", json={"node_id": "gate", "decision": True})
            assert r2.status_code == 200 and r2.json()["status"] == "succeeded"
            assert await _decisions(c, run_id) == 1
    assert len(mt.sent_calls) == 1


@pytest.mark.asyncio
async def test_concurrent_approvals_apply_one_decision(backend):
    env, storage = backend
    mt = MockTransport()
    app = _app(env, storage, mt)
    async with app.router.lifespan_context(app):
        app.state.transport_registry = {"send_email": mt}
        async with _client(app) as c:
            run_id, parking = await _start_parked(app, c)
            url = f"/api/v2/flows/race_flow/runs/{run_id}/approve"
            tasks = [asyncio.create_task(c.post(url, json={"node_id": "gate", "decision": True})) for _ in range(3)]
            await asyncio.sleep(0.2)
            parking.gate.set()
            results = await asyncio.gather(*tasks)
            assert [r.status_code for r in results] == [200, 200, 200]
            assert await _decisions(c, run_id) == 1
    assert len(mt.sent_calls) == 1
