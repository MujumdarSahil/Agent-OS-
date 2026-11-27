"""4.1b Part 0: the approve endpoint refuses a look-alike destination without the extra confirmation. MOCK
(in-process worker, MockTransport; nothing is sent anywhere)."""

from __future__ import annotations

import asyncio

import pytest
from httpx import ASGITransport, AsyncClient

from agentos.flows.proxy import MockTransport
from agentos_server.app import create_app

TOKEN = "test-token-lookalike-4-1b"
LOOK = "support@corp.lоcal"
FLOW = {
    "id": "gated_to", "name": "gated_to", "entrypoint": "trig",
    "nodes": {"trig": {"id": "trig", "type": "manual_trigger", "config": {}},
              "gate": {"id": "gate", "type": "approval",
                       "config": {"prompt": "Review", "approves": {"sink_node": "send", "args": ["to", "body"]}}},
              "send": {"id": "send", "type": "send_email", "config": {}, "pinned_args": {"subject": "S"}}},
    "edges": [{"source": "trig", "target": "gate", "arg_mapping": {"to": "payload", "body": "payload"}},
              {"source": "gate", "target": "send", "arg_mapping": {"to": "to", "body": "body"}}],
}


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTOS_API_TOKEN", TOKEN)
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    monkeypatch.setenv("AGENTOS_INPROCESS_WORKER", "1")
    monkeypatch.setenv("AGENTOS_INTERNAL_DOMAINS", "corp.local")
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    p = tmp_path / "project"
    p.mkdir()
    (p / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    return p


@pytest.mark.asyncio
async def test_approve_lookalike_needs_confirmation(project):
    app = create_app(project_path=str(project))
    mt = MockTransport()
    async with app.router.lifespan_context(app):
        app.state.transport_registry = {"send_email": mt}
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost",
                               headers={"Authorization": f"Bearer {TOKEN}", "Host": "localhost"}) as c:
            assert (await c.post("/api/v2/flows", json=FLOW)).status_code == 201
            assert (await c.post("/api/v2/flows/gated_to/publish")).status_code == 200
            rid = (await c.post("/api/v2/flows/gated_to/runs", json={"inputs": {"to": LOOK}})).json()["run_id"]
            for _ in range(200):
                if (await c.get(f"/api/v2/flows/gated_to/runs/{rid}")).json()["status"] == "waiting":
                    break
                await asyncio.sleep(0.05)
            url = f"/api/v2/flows/gated_to/runs/{rid}/approve"
            refused = await c.post(url, json={"node_id": "gate", "decision": True})
            assert refused.status_code == 400 and "look-alike" in refused.text
            assert mt.sent_calls == []
            ok = await c.post(url, json={"node_id": "gate", "decision": True, "confirm_lookalike": True})
            assert ok.status_code == 200
            for _ in range(200):
                if (await c.get(f"/api/v2/flows/gated_to/runs/{rid}")).json()["status"] == "succeeded":
                    break
                await asyncio.sleep(0.05)
    assert len(mt.sent_calls) == 1
    decided = [e for e in await app.state.audit.entries() if e["action"] == "approval.decide"]
    assert [e["details"].get("confirm_lookalike") for e in decided] == [False, True]
