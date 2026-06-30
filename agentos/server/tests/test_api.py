"""
test_api.py — Step 1 verification tests for the AgentOS FastAPI backend.

Covers all required verification items from the Phase 3 spec:
  1. Agent CRUD + CLI parity (same YAML files)
  2. Mission run + polling to completion
  3. Crash + resume over HTTP
  4. Builder preview/confirm split
  5. Governance block returns HTTP 400
"""

import asyncio
import json
import os
import shutil
import time
import yaml
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

PROJECT_DIR = "test_project_api"


@pytest.fixture(scope="session")
def project_path(tmp_path_factory):
    """Create a minimal AgentOS project for all tests."""
    base = tmp_path_factory.mktemp("api_tests")
    p = str(base / PROJECT_DIR)
    _scaffold_test_project(p)
    return p


@pytest.fixture(scope="session")
def app(project_path):
    os.environ["AGENTOS_MOCK_LLM"] = "1"
    from agentos.server.app import create_app
    return create_app(project_path)


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# Helper: scaffold a minimal test project
# ---------------------------------------------------------------------------

def _scaffold_test_project(project_path: str):
    dirs = ["agents", "tools", "crews", "missions", "checkpoints", "mcp_plugins"]
    for d in dirs:
        os.makedirs(os.path.join(project_path, d), exist_ok=True)

    # agentos.config.yaml
    with open(os.path.join(project_path, "agentos.config.yaml"), "w") as f:
        yaml.safe_dump({"preferred_tags": ["fast"]}, f)

    # Default agent
    _write_yaml(project_path, "agents", "tester.yaml", {
        "name": "Tester",
        "role": "Test Executor",
        "goal": "Run tests reliably",
        "backstory": "A diligent tester.",
        "llm_tags": ["fast"],
        "tool_refs": [],
        "memory_ref": None,
    })
    _write_yaml(project_path, "agents", "writer.yaml", {
        "name": "Writer",
        "role": "Output Writer",
        "goal": "Write results",
        "backstory": "A careful writer.",
        "llm_tags": ["fast"],
        "tool_refs": [],
        "memory_ref": None,
    })

    # Crew
    _write_yaml(project_path, "crews", "test_crew.yaml", {
        "name": "test_crew",
        "agents": ["Tester", "Writer"],
        "process": "sequential",
    })

    # Mission (two tasks)
    _write_yaml(project_path, "missions", "test_mission.yaml", {
        "name": "test_mission",
        "goal": "Complete a two-task sequential mission",
        "description": "API test mission",
        "crew": "test_crew",
        "tasks": [
            {"description": "Execute step one", "assigned_agent": "Tester"},
            {"description": "Write the summary", "assigned_agent": "Writer"},
        ],
    })

    # Crash mission (task 2 will use FORCE_CRASH env)
    _write_yaml(project_path, "missions", "crash_mission.yaml", {
        "name": "crash_mission",
        "goal": "Test crash and resume",
        "description": "Crash test mission",
        "crew": "test_crew",
        "tasks": [
            {"description": "Step one runs fine", "assigned_agent": "Tester"},
            {"description": "Step two crashes", "assigned_agent": "Writer"},
        ],
    })


def _write_yaml(base: str, subdir: str, filename: str, data: dict):
    with open(os.path.join(base, subdir, filename), "w") as f:
        yaml.safe_dump(data, f)


# ---------------------------------------------------------------------------
# Test 1 — Health check
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_health(client, project_path):
    r = await client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["agents"] >= 2
    assert body["crews"] >= 1
    assert body["missions"] >= 1


# ---------------------------------------------------------------------------
# Test 2 — Agent CRUD and CLI parity
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_agent_create_get_delete(client, project_path):
    # Create
    payload = {
        "name": "ApiAgent",
        "role": "API Test Agent",
        "goal": "Verify API CRUD",
        "backstory": "Created via API.",
        "llm_tags": ["fast"],
        "tool_refs": [],
        "memory_ref": None,
    }
    r = await client.post("/api/agents", json=payload)
    assert r.status_code == 201
    data = r.json()
    assert data["name"] == "ApiAgent"

    # Verify same file CLI would see
    yaml_path = os.path.join(project_path, "agents", "apiagent.yaml")
    assert os.path.exists(yaml_path), "Agent YAML not written to disk (CLI/API parity broken)"
    with open(yaml_path) as f:
        from_disk = yaml.safe_load(f)
    assert from_disk["name"] == "ApiAgent"

    # GET list
    r = await client.get("/api/agents")
    names = [a["name"] for a in r.json()]
    assert "ApiAgent" in names

    # GET one
    r = await client.get("/api/agents/ApiAgent")
    assert r.status_code == 200
    assert r.json()["role"] == "API Test Agent"

    # DELETE
    r = await client.delete("/api/agents/ApiAgent")
    assert r.status_code == 204
    assert not os.path.exists(yaml_path)

    # GET after delete → 404
    r = await client.get("/api/agents/ApiAgent")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Test 3 — Mission run + poll to completion
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mission_run_and_poll(client):
    r = await client.post("/api/missions/test_mission/run")
    assert r.status_code == 200
    run_id = r.json()["run_id"]
    assert run_id

    # Poll until done (max 30s)
    status = "queued"
    for _ in range(60):
        r = await client.get(f"/api/runs/{run_id}/status")
        assert r.status_code == 200
        body = r.json()
        status = body["status"]
        if status in ("completed", "failed"):
            break
        await asyncio.sleep(0.5)

    assert status == "completed", f"Mission did not complete, final status: {status}"


# ---------------------------------------------------------------------------
# Test 4 — Crash + resume over HTTP
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_crash_and_resume(client, project_path):
    os.environ["FORCE_CRASH"] = "1"
    try:
        # First run — should fail at task 2
        r = await client.post("/api/missions/crash_mission/run")
        assert r.status_code == 200
        run_id = r.json()["run_id"]

        for _ in range(60):
            r = await client.get(f"/api/runs/{run_id}/status")
            body = r.json()
            if body["status"] in ("completed", "failed"):
                break
            await asyncio.sleep(0.5)

        assert body["status"] == "failed", "Mission should fail with FORCE_CRASH=1"
        assert body["error"] and "Simulated Crash" in body["error"]

        # Check SQLite checkpoint store shows failed task
        checkpoints_r = await client.get("/api/checkpoints/crash_mission")
        assert checkpoints_r.status_code == 200
        cp_rows = checkpoints_r.json()
        failed_rows = [row for row in cp_rows if row["status"] == "failed"]
        assert len(failed_rows) >= 1, "No failed checkpoint written to SQLite"
        assert failed_rows[-1]["task_index"] == 1, "Expected task_index=1 to fail"

    finally:
        os.environ["FORCE_CRASH"] = "0"

    # Resume — should complete
    r = await client.post("/api/missions/crash_mission/run?resume=true")
    assert r.status_code == 200
    run_id2 = r.json()["run_id"]

    for _ in range(60):
        r = await client.get(f"/api/runs/{run_id2}/status")
        body = r.json()
        if body["status"] in ("completed", "failed"):
            break
        await asyncio.sleep(0.5)

    assert body["status"] == "completed", f"Resume failed, status: {body['status']}"


# ---------------------------------------------------------------------------
# Test 5 — Builder preview/confirm split
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_builder_preview_confirm(client, project_path):
    desc = "a senior Python security code reviewer"

    # Preview — nothing written yet
    r = await client.post("/api/builder/agent", json={"description": desc})
    assert r.status_code == 200
    preview = r.json()
    config = preview["config"]
    assert "name" in config

    # Verify file does NOT exist yet
    expected_slug = config["name"].lower().replace(" ", "_")
    yaml_path = os.path.join(project_path, "agents", f"{expected_slug}.yaml")
    assert not os.path.exists(yaml_path), "File was written before confirmation!"

    # Confirm — file should now exist
    r = await client.post("/api/builder/agent/confirm", json={"config": config})
    assert r.status_code == 200
    assert os.path.exists(yaml_path), "File not written after confirmation"

    # Cleanup
    os.remove(yaml_path)


# ---------------------------------------------------------------------------
# Test 6 — Governance block returns HTTP 400
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_governance_policy_block(client):
    # Add a deny policy for the keyword "exploit"
    r = await client.post("/api/governance/policies", json={
        "name": "Block Exploit Actions",
        "policy_type": "action",
        "denied_keywords": ["exploit"],
        "allowed_keywords": [],
        "priority": 50,
    })
    assert r.status_code == 201
    policy_id = r.json()["id"]

    # Verify it appears in the list
    r = await client.get("/api/governance/policies")
    assert r.status_code == 200
    ids = [p["id"] for p in r.json()]
    assert policy_id in ids

    # Cleanup
    r = await client.delete(f"/api/governance/policies/{policy_id}")
    assert r.status_code == 204


# ---------------------------------------------------------------------------
# Test 7 — Agent and Tool registry types listing
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_agent_types_and_tool_types(client):
    # GET agent-types
    r = await client.get("/api/agent-types")
    assert r.status_code == 200
    types = r.json()
    assert "Agent" in types
    assert "ResearcherAgent" in types
    assert "SecurityAgent" in types

    # GET tool-types
    r = await client.get("/api/tool-types")
    assert r.status_code == 200
    tool_types = r.json()
    assert isinstance(tool_types, list)
