"""2.5a (MOCK): /api/v2/mcp-servers discovery and review API, agent and publish integration.

Uses the local fixture server agentos/tests/fixtures/mcp/good_tools.py (stdio). Every server started is
stopped at the end of each test.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from agentos_server.app import create_app

TOKEN = "test-token-mcp-api-0001"
FIX = Path(__file__).resolve().parents[2] / "agentos" / "tests" / "fixtures" / "mcp"


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTOS_API_TOKEN", TOKEN)
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    monkeypatch.setenv("AGENTOS_VAULT_PATH", str(tmp_path / "home" / "vault.json"))
    monkeypatch.setenv("AGENTOS_MASTER_KEY_FILE", str(tmp_path / "home" / "master.key"))
    monkeypatch.delenv("AGENTOS_MASTER_KEY", raising=False)
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    project = tmp_path / "project"
    project.mkdir()
    (project / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    return create_app(project_path=str(project))


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost",
                           headers={"Authorization": f"Bearer {TOKEN}", "Host": "localhost"}) as c:
        yield c
    await app.state.mcp_manager.stop_all()


GOOD = {"name": "good", "transport": "stdio", "command": sys.executable, "args": [str(FIX / "good_tools.py")],
        "env": {"NOTES_MODE": "demo"}, "secret_env": {"SERVICE_TOKEN": "fake_vault_name"}}


@pytest.mark.asyncio
async def test_requires_token(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as c:
        assert (await c.get("/api/v2/mcp-servers")).status_code == 401
        assert (await c.post("/api/v2/mcp-servers/x/discover")).status_code == 401


@pytest.mark.asyncio
async def test_env_names_validated_on_save(client):
    bad = {**GOOD, "env": {"GROQ_API_KEY": "fake-value"}}
    r = await client.post("/api/v2/mcp-servers", json=bad)
    assert r.status_code == 400 and "secret_env" in r.json()["detail"]
    r = await client.post("/api/v2/mcp-servers", json={**GOOD, "env": {"AGENTOS_API_TOKEN": "x"}})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_preview_enable_discover_approve_and_save_keeps_approvals(client, app):
    r = await client.post("/api/v2/mcp-servers", json={**GOOD, "secret_env": {}})
    assert r.status_code == 200 and r.json()["enabled"] is False

    # discovery only for enabled servers
    assert (await client.post("/api/v2/mcp-servers/good/discover")).status_code == 409

    prev = (await client.get("/api/v2/mcp-servers/good/launch-preview")).json()
    assert prev["argv"] == [sys.executable, str(FIX / "good_tools.py")]
    assert prev["inherits_parent_env"] is False
    assert "NOTES_MODE" in prev["env_names"] and "demo" not in str(prev)  # names only, never values

    r = await client.post("/api/v2/mcp-servers/good/enable", json={"enabled": True})
    assert r.status_code == 200 and r.json()["launch_preview"]["command_line"]

    r = await client.post("/api/v2/mcp-servers/good/discover")
    assert r.status_code == 200, r.text
    t = r.json()["tools"]["save_draft"]
    assert t["status"] == "unreviewed" and t["snapshot"]["label"] == "untrusted"
    assert t["canonical_name"] == "mcp.good.save_draft" and t["wire_name"] == "mcp__good__save_draft"

    # approval must name the exact snapshot the admin reviewed
    bad = await client.post("/api/v2/mcp-servers/good/tools/save_draft/approve",
                            json={"expected_sha256": "0" * 64, "side_effect": "write"})
    assert bad.status_code == 409
    unk = await client.post("/api/v2/mcp-servers/good/tools/save_draft/approve",
                            json={"expected_sha256": t["snapshot"]["sha256"], "side_effect": "write",
                                  "untrusted_ok_args": ["nope"]})
    assert unk.status_code == 400
    ok = await client.post("/api/v2/mcp-servers/good/tools/save_draft/approve",
                           json={"expected_sha256": t["snapshot"]["sha256"], "side_effect": "write",
                                 "untrusted_ok_args": ["body"], "replacement_description": "Save a draft."})
    assert ok.status_code == 200 and ok.json()["tools"]["save_draft"]["status"] == "approved"

    # a plain save never overwrites approvals; the same target keeps the approval
    again = await client.post("/api/v2/mcp-servers", json={**GOOD, "secret_env": {}, "enabled": True, "tools": {}})
    assert again.json()["tools"]["save_draft"]["status"] == "approved"
    # a different launch target disables the server and puts the approval back under review
    moved = await client.post("/api/v2/mcp-servers", json={**GOOD, "secret_env": {},
                                                           "args": [str(FIX / "envdump.py")], "enabled": True})
    mv = moved.json()
    assert mv["enabled"] is False and mv["tools"]["save_draft"]["status"] == "changed"

    assert (await client.post("/api/v2/mcp-servers/good/tools/save_draft/revoke")).status_code == 200
    # 3.1: server events are audit entries now (the mcp-server-<name> pseudo-run stream is no longer written)
    actions = [e["action"] for e in await app.state.audit.entries()]
    for a in ("mcp.server.enable", "mcp.server.started", "mcp.server.discover", "mcp.server.discovered",
              "mcp.tool.approve", "mcp.tool.revoke", "mcp.server.create", "mcp.server.update"):
        assert a in actions, a
    assert await app.state.storage.events.list("mcp-server-good") == []
    assert (await app.state.audit.verify())["status"] == "ok"


@pytest.mark.asyncio
async def test_agents_and_publish_accept_only_approved_mcp_tools(client):
    await client.post("/api/v2/mcp-servers", json={**GOOD, "secret_env": {}})
    await client.post("/api/v2/mcp-servers/good/enable", json={"enabled": True})
    tools = (await client.post("/api/v2/mcp-servers/good/discover")).json()["tools"]

    agent = {"name": "notes_agent", "role": "r", "goal": "g", "backstory": "b", "tools": ["mcp.good.read_note"]}
    r = await client.post("/api/v2/agents", json=agent)
    assert r.status_code == 400 and "not been reviewed" in r.json()["detail"]

    flow = {
        "id": "uses_mcp", "name": "uses_mcp", "entrypoint": "start",
        "nodes": {
            "start": {"id": "start", "type": "manual_trigger", "config": {}, "pinned_args": {}},
            "agent": {"id": "agent", "type": "agent", "config": {"role": "r", "tools": ["mcp.good.read_note"]},
                      "pinned_args": {}},
        },
        "edges": [{"source": "start", "target": "agent", "arg_mapping": {"task": "payload"}}],
        "loops": {},
    }
    assert (await client.post("/api/v2/flows", json=flow)).status_code == 201
    refused = await client.post("/api/v2/flows/uses_mcp/publish")
    assert refused.status_code == 400
    assert any("not been reviewed" in v["reason"] for v in refused.json()["detail"]["violations"])

    await client.post("/api/v2/mcp-servers/good/tools/read_note/approve",
                      json={"expected_sha256": tools["read_note"]["snapshot"]["sha256"], "side_effect": "read"})
    assert (await client.post("/api/v2/agents", json=agent)).status_code == 200
    published = await client.post("/api/v2/flows/uses_mcp/publish")
    assert published.status_code == 200, published.text
    assert published.json()["analysis"]["mcp_tools"] == {"mcp.good.read_note": tools["read_note"]["snapshot"]["sha256"]}
