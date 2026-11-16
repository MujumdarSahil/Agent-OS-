"""
2.4 backend tests (MOCK, FileStorage, MockTransport):
  - AGENTOS_INPROCESS_WORKER is off by default; when on, runs enqueued via the API execute
    and the worker task is stopped on shutdown.
  - Approval: approve -> succeeded with 1 send; reject -> failed with 0 sends.
  - WebSocket after_seq replays only events with seq > after_seq, gap-free.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.testclient import TestClient

from agentos.flows.proxy import MockTransport
from agentos_server.app import create_app

TOKEN = "test-token-inprocess-worker"

BENIGN = {
    "id": "notify_flow",
    "name": "notify",
    "entrypoint": "trig",
    "nodes": {
        "trig": {"id": "trig", "type": "manual_trigger", "config": {}},
        "notify": {
            "id": "notify",
            "type": "send_email",
            "config": {},
            "pinned_args": {"to": "support@corp.local", "subject": "Ticket"},
        },
    },
    "edges": [{"source": "trig", "target": "notify", "arg_mapping": {"body": "payload"}}],
}

APPROVAL = {
    "id": "approval_flow",
    "name": "approval",
    "entrypoint": "hook",
    "nodes": {
        "hook": {"id": "hook", "type": "webhook_trigger", "config": {}},
        "gate": {
            "id": "gate",
            "type": "approval",
            "config": {"prompt": "Review", "approves": {"sink_node": "send", "args": ["to", "body"]}},
        },
        "send": {"id": "send", "type": "send_email", "config": {}},
    },
    "edges": [
        {"source": "hook", "target": "gate", "arg_mapping": {"to": "payload", "body": "payload"}},
        {"source": "gate", "target": "send", "arg_mapping": {"to": "to", "body": "body"}},
    ],
}


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTOS_API_TOKEN", TOKEN)
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    project = tmp_path / "project"
    project.mkdir()
    (project / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    return str(project)


def _app(project: str, transport: MockTransport | None = None):
    app = create_app(project_path=project)
    if transport is not None:
        app.state.transport_registry = {"send_email": transport}
    return app


def _client(app) -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://localhost",
        headers={"Authorization": f"Bearer {TOKEN}", "Host": "localhost"},
    )


async def _wait_status(client: AsyncClient, flow_id: str, run_id: str, want: set[str]) -> str:
    status = ""
    for _ in range(200):
        status = (await client.get(f"/api/v2/flows/{flow_id}/runs/{run_id}")).json()["status"]
        if status in want:
            return status
        await asyncio.sleep(0.05)
    return status


async def _publish_and_run(c: AsyncClient, flow: dict, inputs: dict) -> str:
    assert (await c.post("/api/v2/flows", json=flow)).status_code == 201
    assert (await c.post(f"/api/v2/flows/{flow['id']}/publish")).status_code == 200
    r = await c.post(f"/api/v2/flows/{flow['id']}/runs", json={"inputs": inputs})
    assert r.status_code == 201
    return r.json()["run_id"]


@pytest.mark.asyncio
async def test_worker_off_by_default(env, monkeypatch):
    monkeypatch.delenv("AGENTOS_INPROCESS_WORKER", raising=False)
    app = _app(env)
    async with app.router.lifespan_context(app):
        assert app.state.inprocess_worker is None
        async with _client(app) as c:
            run_id = await _publish_and_run(c, BENIGN, {"text": "hi"})
            await asyncio.sleep(0.3)
            rec = (await c.get(f"/api/v2/flows/notify_flow/runs/{run_id}")).json()
            assert rec["status"] == "queued"


@pytest.mark.asyncio
async def test_worker_runs_benign_flow_and_stops_on_shutdown(env, monkeypatch):
    monkeypatch.setenv("AGENTOS_INPROCESS_WORKER", "1")
    mt = MockTransport()
    app = _app(env, mt)
    async with app.router.lifespan_context(app):
        worker = app.state.inprocess_worker
        assert worker is not None
        task = worker._task
        async with _client(app) as c:
            run_id = await _publish_and_run(c, BENIGN, {"text": "hi"})
            assert await _wait_status(c, "notify_flow", run_id, {"succeeded", "failed"}) == "succeeded"
    assert len(mt.sent_calls) == 1
    assert task is not None and task.done()
    assert app.state.inprocess_worker is None


@pytest.mark.asyncio
async def test_worker_uses_mock_transport_when_none_configured(env, monkeypatch):
    monkeypatch.setenv("AGENTOS_INPROCESS_WORKER", "1")
    app = _app(env)
    async with app.router.lifespan_context(app):
        assert isinstance(app.state.transport_registry["send_email"], MockTransport)


@pytest.mark.asyncio
@pytest.mark.parametrize("decision,final,sends", [(True, "succeeded", 1), ("reject", "failed", 0)])
async def test_approval_approve_and_reject(env, monkeypatch, decision, final, sends):
    monkeypatch.setenv("AGENTOS_INPROCESS_WORKER", "1")
    mt = MockTransport()
    app = _app(env, mt)
    async with app.router.lifespan_context(app):
        async with _client(app) as c:
            run_id = await _publish_and_run(c, APPROVAL, {"text": "memo"})
            assert await _wait_status(c, "approval_flow", run_id, {"waiting", "failed"}) == "waiting"
            r = await c.post(
                f"/api/v2/flows/approval_flow/runs/{run_id}/approve",
                json={"node_id": "gate", "decision": decision},
            )
            assert r.status_code == 200, r.text
            assert await _wait_status(c, "approval_flow", run_id, {"succeeded", "failed"}) == final
            events = (await c.get(f"/api/v2/flows/approval_flow/runs/{run_id}/events")).json()
    types = [e["type"] for e in events]
    assert len(mt.sent_calls) == sends
    assert ("sink_committed" in types) is (sends == 1)


def test_websocket_after_seq_replays_only_missing_events(env, monkeypatch):
    monkeypatch.setenv("AGENTOS_INPROCESS_WORKER", "1")
    app = _app(env, MockTransport())
    headers = {"Authorization": f"Bearer {TOKEN}", "Host": "localhost"}
    with TestClient(app, base_url="http://localhost") as client:
        client.post("/api/v2/flows", json=BENIGN, headers=headers)
        client.post("/api/v2/flows/notify_flow/publish", headers=headers)
        run_id = client.post(
            "/api/v2/flows/notify_flow/runs", json={"inputs": {"text": "hi"}}, headers=headers
        ).json()["run_id"]

        def stream(after_seq: int) -> list[dict]:
            msgs = []
            with client.websocket_connect(
                f"/api/v2/flows/notify_flow/runs/{run_id}/events?after_seq={after_seq}",
                subprotocols=[f"agentos.token.{TOKEN}", "agentos.v1"],
                headers={"Host": "localhost", "Origin": "http://localhost:5173"},
            ) as ws:
                while True:
                    m = json.loads(ws.receive_text())
                    msgs.append(m)
                    if m.get("event") == "run_finished":
                        return msgs

        full = [m["seq"] for m in stream(0) if "seq" in m]
        assert full == list(range(1, len(full) + 1)) and len(full) > 3
        resumed = [m["seq"] for m in stream(3) if "seq" in m]
        assert resumed == full[3:]
