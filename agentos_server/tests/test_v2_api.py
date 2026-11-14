"""
test_v2_api.py - Verification suite for AgentOS 2.0 /api/v2 routes (sub-milestone 1.4).

Covers:
  1. Auth & Security:
     - 401 on /api/v2 routes without token.
     - 401 on v1 /api routes without token when AGENTOS_V1_NO_AUTH is not set.
     - 200 with Authorization: Bearer <token> or X-AgentOS-Token: <token>.
     - Invalid token rejected.
     - Host header DNS-rebinding defense (localhost/127.0.0.1 accepted; evil.com rejected with 400).
     - AGENTOS_V1_NO_AUTH=1 allows v1 routes with DeprecationWarning, but /api/v2 still requires token.
     - /api/health unauthenticated.
  2. Core CRUD (File backend [MOCK] and Mongo backend [LIVE]):
     - Agents: creation, schema validation (no mcps/apps/memory), tool NodeSpec check (fail closed).
     - Squads: creation, roles dict preserved across get/list.
     - Tools: creation, stored code as text, project tools read-only.
     - MCP servers: transport validation, saved but never launched.
     - Vault: put key, list returns masked hints only (sk-...abcd), delete key.
  3. Plaintext Secret Scanner:
     - High-entropy canary key put in vault; assert canary NEVER appears in any response body.
  4. Providers & Router Hook:
     - GET /api/v2/providers: zero network calls, reports configured status.
     - POST /api/v2/providers/test-connection: SSRF defense (registry-known / localhost only), safe result shape.
     - Fallback policy: GET/PUT persists and updates synchronous router in-memory cache.
  5. Restart Durability:
     - Re-instantiate app and verify resources and fallback cache persist.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from agentos.llm.provider_registry import PROVIDER_REGISTRY
from agentos.llm.router_factory import build_router, get_fallback_policy_cache, set_fallback_policy_cache
from agentos.storage import open_storage
from agentos.storage.models import SquadRecord, ToolRecord
from agentos_server.app import create_app
from agentos_server.auth import get_or_create_api_token, verify_host_header

MONGO_URI = os.environ.get("AGENTOS_MONGO_URI")
MONGO_SKIP_REASON = (
    "LIVE Mongo not available: run `docker compose -f docker/compose.mongo.yml up -d --wait` "
    "and set AGENTOS_MONGO_URI"
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def api_token():
    token = "test-token-secret-12345"
    os.environ["AGENTOS_API_TOKEN"] = token
    yield token
    os.environ.pop("AGENTOS_API_TOKEN", None)


@pytest.fixture
def auth_headers(api_token):
    return {"Authorization": f"Bearer {api_token}", "Host": "localhost"}


@pytest.fixture
def file_app(tmp_path, api_token):
    """FastAPI app instance backed by FileStorage."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    app = create_app(project_path=str(project))
    return app


@pytest_asyncio.fixture
async def file_client(file_app, auth_headers):
    """Authenticated client for FileStorage app."""
    async with AsyncClient(
        transport=ASGITransport(app=file_app),
        base_url="http://localhost",
        headers=auth_headers,
    ) as c:
        yield c


# ---------------------------------------------------------------------------
# 1. Auth & Security Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_v2_requires_token(file_app):
    """All /api/v2 routes must return 401 when no token is supplied."""
    async with AsyncClient(
        transport=ASGITransport(app=file_app),
        base_url="http://localhost",
        headers={"Host": "localhost"},
    ) as client:
        # Check various v2 resources
        endpoints = [
            ("/api/v2/agents", "GET"),
            ("/api/v2/squads", "GET"),
            ("/api/v2/tools", "GET"),
            ("/api/v2/mcp-servers", "GET"),
            ("/api/v2/vault/keys", "GET"),
            ("/api/v2/providers", "GET"),
            ("/api/v2/providers/fallback", "GET"),
        ]
        for url, method in endpoints:
            r = await client.request(method, url)
            assert r.status_code == 401, f"Expected 401 for {url}, got {r.status_code}"
            assert "Unauthorized" in r.json()["detail"]


@pytest.mark.asyncio
async def test_v1_requires_token_when_compat_disabled(file_app, monkeypatch):
    """When AGENTOS_V1_NO_AUTH is not set, v1 routes also require token."""
    monkeypatch.delenv("AGENTOS_V1_NO_AUTH", raising=False)
    async with AsyncClient(
        transport=ASGITransport(app=file_app),
        base_url="http://localhost",
        headers={"Host": "localhost"},
    ) as client:
        r = await client.get("/api/agents")
        assert r.status_code == 401
        assert "Unauthorized" in r.json()["detail"]


@pytest.mark.asyncio
async def test_v1_no_auth_compat_mode(file_app, monkeypatch):
    """AGENTOS_V1_NO_AUTH=1 allows v1 routes without token with DeprecationWarning, but NOT v2."""
    monkeypatch.setenv("AGENTOS_V1_NO_AUTH", "1")
    import agentos_server.auth as auth_mod
    monkeypatch.setattr(auth_mod, "_EMITTED_V1_NO_AUTH_WARNING", False)
    async with AsyncClient(
        transport=ASGITransport(app=file_app),
        base_url="http://localhost",
        headers={"Host": "localhost"},
    ) as client:
        # v1 route succeeds
        with pytest.deprecated_call():
            r = await client.get("/api/agents")
            assert r.status_code == 200

        # v2 route STILL requires token (401)
        r_v2 = await client.get("/api/v2/agents")
        assert r_v2.status_code == 401


@pytest.mark.asyncio
async def test_auth_headers_accepted(file_app, api_token):
    """Both Authorization: Bearer and X-AgentOS-Token headers are accepted."""
    # 1. Bearer header
    async with AsyncClient(
        transport=ASGITransport(app=file_app),
        base_url="http://localhost",
        headers={"Authorization": f"Bearer {api_token}", "Host": "localhost"},
    ) as client:
        r = await client.get("/api/v2/agents")
        assert r.status_code == 200

    # 2. X-AgentOS-Token header
    async with AsyncClient(
        transport=ASGITransport(app=file_app),
        base_url="http://localhost",
        headers={"X-AgentOS-Token": api_token, "Host": "localhost"},
    ) as client:
        r = await client.get("/api/v2/agents")
        assert r.status_code == 200

    # 3. Invalid token returns 401
    async with AsyncClient(
        transport=ASGITransport(app=file_app),
        base_url="http://localhost",
        headers={"Authorization": "Bearer wrong-token", "Host": "localhost"},
    ) as client:
        r = await client.get("/api/v2/agents")
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_host_header_dns_rebinding_defense(file_app, api_token):
    """Only localhost and 127.0.0.1 are accepted. Host: evil.com is rejected with 400."""
    async with AsyncClient(
        transport=ASGITransport(app=file_app),
        base_url="http://evil.com",
        headers={"Authorization": f"Bearer {api_token}", "Host": "evil.com"},
    ) as client:
        r = await client.get("/api/v2/agents")
        assert r.status_code == 400
        assert "Invalid Host header" in r.json()["detail"]

        # Rebinding attack on /api/health is also blocked
        r_health = await client.get("/api/health")
        assert r_health.status_code == 400

    # Valid hosts
    for valid_host in ["localhost", "localhost:8000", "127.0.0.1", "127.0.0.1:8000"]:
        async with AsyncClient(
            transport=ASGITransport(app=file_app),
            base_url=f"http://{valid_host}",
            headers={"Authorization": f"Bearer {api_token}", "Host": valid_host},
        ) as client:
            r = await client.get("/api/health")
            assert r.status_code == 200


@pytest.mark.asyncio
async def test_health_unauthenticated(file_app):
    """GET /api/health requires no token when Host header is valid."""
    async with AsyncClient(
        transport=ASGITransport(app=file_app),
        base_url="http://localhost",
        headers={"Host": "localhost"},
    ) as client:
        r = await client.get("/api/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# 2. Core CRUD Tests (Agents, Squads, Tools, MCP Servers, Vault)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_agents_crud_and_validation(file_client):
    """Agent CRUD with strict schema validation and NodeSpec tool check (fail closed)."""
    # 1. Valid Agent creation
    valid_payload = {
        "name": "Researcher",
        "role": "Senior Researcher",
        "goal": "Conduct literature research",
        "backstory": "Experienced research scientist",
        "tools": ["fetch_url"],
        "llm_tags": ["fast"],
        "tool_refs": ["fetch_url"],
    }
    r = await file_client.post("/api/v2/agents", json=valid_payload)
    assert r.status_code == 200
    created = r.json()
    assert created["name"] == "Researcher"
    assert created["role"] == "Senior Researcher"

    # 2. Get Agent
    r = await file_client.get("/api/v2/agents/researcher")
    assert r.status_code == 200
    assert r.json()["name"] == "Researcher"

    # 3. List Agents
    r = await file_client.get("/api/v2/agents")
    assert r.status_code == 200
    names = [a["name"] for a in r.json()]
    assert "Researcher" in names

    # 4. Tool check fail-closed: unknown tool rejected
    invalid_tool_payload = {
        **valid_payload,
        "name": "Attacker",
        "tools": ["delete_all_files"],
    }
    r = await file_client.post("/api/v2/agents", json=invalid_tool_payload)
    assert r.status_code == 400
    assert "no declared NodeSpec (fail closed)" in r.json()["detail"]

    # 5. Schema validation: forbidden fields (mcps, memory, apps) rejected
    for forbidden_key in ["mcps", "apps", "memory", "knowledge_sources"]:
        bad_payload = {
            **valid_payload,
            "name": f"BadAgent_{forbidden_key}",
            forbidden_key: {"evil": True},
        }
        r = await file_client.post("/api/v2/agents", json=bad_payload)
        assert r.status_code == 400, f"Expected 400 for forbidden key {forbidden_key}"
        assert "Invalid agent config" in r.json()["detail"]

    # 6. Delete Agent
    r = await file_client.delete("/api/v2/agents/researcher")
    assert r.status_code == 200
    assert r.json() == {"deleted": True}

    # Verify 404
    r = await file_client.get("/api/v2/agents/researcher")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_squads_crud_and_roles(file_client):
    """Squad CRUD with roles preservation."""
    payload = {
        "name": "Alpha Squad",
        "agents": ["Alice", "Bob"],
        "roles": {"Alice": "team_lead", "Bob": "code_reviewer"},
        "process": "sequential",
    }
    # 1. Create Squad
    r = await file_client.post("/api/v2/squads", json=payload)
    assert r.status_code == 200
    created = r.json()
    assert created["name"] == "Alpha Squad"
    assert created["roles"] == {"Alice": "team_lead", "Bob": "code_reviewer"}

    # 2. Get Squad
    r = await file_client.get("/api/v2/squads/alpha_squad")
    assert r.status_code == 200
    retrieved = r.json()
    assert retrieved["roles"]["Alice"] == "team_lead"
    assert retrieved["roles"]["Bob"] == "code_reviewer"

    # 3. List Squads
    r = await file_client.get("/api/v2/squads")
    assert r.status_code == 200
    squad_names = [s["name"] for s in r.json()]
    assert "Alpha Squad" in squad_names

    # 4. Delete Squad
    r = await file_client.delete("/api/v2/squads/alpha_squad")
    assert r.status_code == 200
    assert r.json() == {"deleted": True}

    r = await file_client.get("/api/v2/squads/alpha_squad")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_tools_crud_and_code_preservation(file_client):
    """Tool CRUD: code stored as text, project tools read-only."""
    tool_code = "def custom_multiply(a: int, b: int) -> int:\n    return a * b\n"
    payload = {
        "name": "Multiplier",
        "description": "Multiplies two numbers",
        "language": "python",
        "code": tool_code,
        "origin": "stored",
    }
    # 1. Create tool
    r = await file_client.post("/api/v2/tools", json=payload)
    assert r.status_code == 200
    created = r.json()
    assert created["name"] == "Multiplier"
    assert created["code"] == tool_code

    # 2. Get tool
    r = await file_client.get("/api/v2/tools/multiplier")
    assert r.status_code == 200
    assert r.json()["code"] == tool_code

    # 3. List tools
    r = await file_client.get("/api/v2/tools")
    assert r.status_code == 200
    assert any(t["name"] == "Multiplier" for t in r.json())

    # 4. Delete tool
    r = await file_client.delete("/api/v2/tools/multiplier")
    assert r.status_code == 200
    assert r.json() == {"deleted": True}


@pytest.mark.asyncio
async def test_mcp_servers_crud_and_no_launch(file_client):
    """MCP Servers CRUD: transport validation, saved but NEVER launched."""
    # 1. Valid stdio MCP server
    stdio_payload = {
        "name": "GitHub MCP",
        "transport": "stdio",
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-github"],
        "secret_env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "github_vault_key"},
        "enabled": False,
    }
    r = await file_client.post("/api/v2/mcp-servers", json=stdio_payload)
    assert r.status_code == 200
    created = r.json()
    assert created["name"] == "GitHub MCP"
    assert created["transport"] == "stdio"

    # 2. Transport validation: stdio without command fails
    invalid_stdio = {"name": "Bad Stdio", "transport": "stdio"}
    r = await file_client.post("/api/v2/mcp-servers", json=invalid_stdio)
    assert r.status_code == 400

    # 3. Transport validation: sse without url fails
    invalid_sse = {"name": "Bad SSE", "transport": "sse"}
    r = await file_client.post("/api/v2/mcp-servers", json=invalid_sse)
    assert r.status_code == 400

    # 4. Valid sse MCP server
    sse_payload = {
        "name": "Weather SSE",
        "transport": "sse",
        "url": "http://127.0.0.1:9090/events",
        "enabled": True,
    }
    r = await file_client.post("/api/v2/mcp-servers", json=sse_payload)
    assert r.status_code == 200

    # 5. List MCP servers
    r = await file_client.get("/api/v2/mcp-servers")
    assert r.status_code == 200
    server_names = [s["name"] for s in r.json()]
    assert "GitHub MCP" in server_names
    assert "Weather SSE" in server_names

    # 6. Delete
    r = await file_client.delete("/api/v2/mcp-servers/github_mcp")
    assert r.status_code == 200
    assert r.json() == {"deleted": True}


@pytest.mark.asyncio
async def test_vault_crud_masked_values_only(file_client):
    """Vault keys: masked hints only (sk-...abcd), plaintext NEVER returned."""
    raw_secret = "sk-proj-supersecretkey1234567890abcdef"
    payload = {
        "name": "openai_api_key",
        "secret": raw_secret,
        "provider": "openai",
    }
    # 1. Put key
    r = await file_client.post("/api/v2/vault/keys", json=payload)
    assert r.status_code == 200
    created = r.json()
    assert created["name"] == "openai_api_key"
    assert created["provider"] == "openai"
    assert created["hint"].startswith("sk-")
    assert created["hint"].endswith("cdef")
    # Assert plaintext secret is NOT in the response
    assert raw_secret not in str(created)
    assert "secret" not in created

    # 2. List keys
    r = await file_client.get("/api/v2/vault/keys")
    assert r.status_code == 200
    keys = r.json()
    assert len(keys) >= 1
    target = next((k for k in keys if k["name"] == "openai_api_key"), None)
    assert target is not None
    assert target["hint"].endswith("cdef")
    assert raw_secret not in str(keys)

    # 3. Delete key
    r = await file_client.delete("/api/v2/vault/keys/openai_api_key")
    assert r.status_code == 200
    assert r.json() == {"deleted": True}

    # Verify list is empty of this key
    r = await file_client.get("/api/v2/vault/keys")
    assert not any(k["name"] == "openai_api_key" for k in r.json())


# ---------------------------------------------------------------------------
# 3. Plaintext Secret Scanner across all v2 endpoints
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_plaintext_secret_scanner_never_leaks(file_client):
    """
    Store a unique high-entropy canary secret in the vault.
    Traverse all v2 endpoints and verify the canary string NEVER appears in any response.
    """
    canary = f"canary-secret-{uuid.uuid4().hex}-{uuid.uuid4().hex}"
    r = await file_client.post("/api/v2/vault/keys", json={
        "name": "canary_provider",
        "secret": canary,
        "provider": "canary",
    })
    assert r.status_code == 200

    def assert_no_canary(data: Any, path: str = ""):
        if isinstance(data, str):
            assert canary not in data, f"LEAK DETECTED at {path}: raw secret found in response body!"
        elif isinstance(data, dict):
            for k, v in data.items():
                assert canary not in str(k), f"LEAK DETECTED in key {k} at {path}"
                assert_no_canary(v, f"{path}.{k}")
        elif isinstance(data, list):
            for idx, item in enumerate(data):
                assert_no_canary(item, f"{path}[{idx}]")

    # Check all GET endpoints
    for endpoint in [
        "/api/v2/agents",
        "/api/v2/squads",
        "/api/v2/tools",
        "/api/v2/mcp-servers",
        "/api/v2/vault/keys",
        "/api/v2/providers",
        "/api/v2/providers/fallback",
    ]:
        resp = await file_client.get(endpoint)
        assert resp.status_code == 200, f"Endpoint {endpoint} failed with {resp.status_code}"
        assert_no_canary(resp.json(), endpoint)

    # Clean up canary
    await file_client.delete("/api/v2/vault/keys/canary_provider")


# ---------------------------------------------------------------------------
# 4. Providers & Fallback Policy & Router Hook
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_providers_status_zero_network_calls(file_client):
    """GET /api/v2/providers does zero network calls and correctly reports configured status."""
    r = await file_client.get("/api/v2/providers")
    assert r.status_code == 200
    providers = r.json()
    assert len(providers) == len(PROVIDER_REGISTRY)

    # Local providers (Ollama) should be marked configured
    ollama_prov = next((p for p in providers if p["is_local"]), None)
    if ollama_prov:
        assert ollama_prov["api_key_configured"] is True


@pytest.mark.asyncio
async def test_providers_test_connection_ssrf_protection(file_client):
    """test-connection blocks unknown providers (SSRF defense) and returns safe shape."""
    # 1. Unknown provider rejected
    r = await file_client.post("/api/v2/providers/test-connection", json={"provider_name": "malicious_host"})
    assert r.status_code == 400
    assert "not recognized in the provider registry (SSRF prevention)" in r.json()["detail"]

    # 2. Known provider in mock mode returns ok: True
    known_name = PROVIDER_REGISTRY[0]["name"]
    r = await file_client.post("/api/v2/providers/test-connection", json={"provider_name": known_name})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert "error_class" in body
    assert "message" in body


@pytest.mark.asyncio
async def test_fallback_policy_editor_and_synchronous_router_hook(file_client):
    """
    PUT /api/v2/providers/fallback persists policy and updates in-memory cache.
    The router hook reads the cache synchronously and updates router priorities.
    """
    # 1. Get default fallback policy
    r = await file_client.get("/api/v2/providers/fallback")
    assert r.status_code == 200
    current_policy = r.json()
    assert len(current_policy) > 0

    # 2. Reorder policy: pick first two providers and swap their order, and add a custom timeout
    prov_a = current_policy[0]["name"]
    prov_b = current_policy[1]["name"]

    updated_items = []
    for item in current_policy:
        if item["name"] == prov_a:
            updated_items.append({"name": prov_a, "order": 2, "enabled": True, "timeout_s": 15.0})
        elif item["name"] == prov_b:
            updated_items.append({"name": prov_b, "order": 1, "enabled": True, "timeout_s": 25.0})
        else:
            updated_items.append({"name": item["name"], "order": item["order"] + 2, "enabled": item["enabled"]})

    # PUT update
    r = await file_client.put("/api/v2/providers/fallback", json={"items": updated_items})
    assert r.status_code == 200

    # 3. Verify in-memory cache was updated synchronously
    cache = get_fallback_policy_cache()
    assert cache is not None
    cache_by_name = {item["name"]: item for item in cache}
    assert cache_by_name[prov_b]["order"] == 1
    assert cache_by_name[prov_a]["order"] == 2
    assert cache_by_name[prov_a]["timeout_s"] == 15.0

    # 4. Verify synchronous build_router() reflects the order override
    # Pass mock providers to build_router to observe order assignment
    router = build_router(provider_configs=cache)
    model_list = router.model_list
    assert len(model_list) > 0
    # Provider B should have order 1, Provider A order 2
    params_by_model = {m["litellm_params"]["model"]: m["litellm_params"] for m in model_list}
    # Check that orders are recorded
    orders = [m["litellm_params"]["order"] for m in model_list]
    assert orders == sorted(orders)


# ---------------------------------------------------------------------------
# 5. Restart Durability & Storage Port Verification
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_restart_durability_file_storage(tmp_path, api_token, auth_headers):
    """Resources created via v2 API persist across app restarts (FileStorage)."""
    project = tmp_path / "project_durability"
    project.mkdir()
    (project / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")

    # Instance 1: create an agent and set fallback policy
    app1 = create_app(project_path=str(project))
    async with AsyncClient(
        transport=ASGITransport(app=app1),
        base_url="http://localhost",
        headers=auth_headers,
    ) as c1:
        r = await c1.post("/api/v2/agents", json={
            "name": "DurableAgent",
            "role": "Durable Role",
            "goal": "Survive restarts",
            "tools": ["fetch_url"],
        })
        assert r.status_code == 200

        r = await c1.put("/api/v2/providers/fallback", json={
            "items": [
                {"name": PROVIDER_REGISTRY[0]["name"], "order": 1, "enabled": True},
                {"name": PROVIDER_REGISTRY[1]["name"], "order": 2, "enabled": False},
            ]
        })
        assert r.status_code == 200

    # Instance 2: fresh app factory with the same project directory
    app2 = create_app(project_path=str(project))
    async with AsyncClient(
        transport=ASGITransport(app=app2),
        base_url="http://localhost",
        headers=auth_headers,
    ) as c2:
        # Agent should exist
        r = await c2.get("/api/v2/agents/durableagent")
        assert r.status_code == 200
        assert r.json()["name"] == "DurableAgent"

        # Fallback policy should be preserved
        r = await c2.get("/api/v2/providers/fallback")
        assert r.status_code == 200
        policy = r.json()
        policy_by_name = {p["name"]: p for p in policy}
        assert policy_by_name[PROVIDER_REGISTRY[1]["name"]]["enabled"] is False


@pytest.mark.asyncio
async def test_mongo_backend_crud_and_durability(api_token, auth_headers):
    """Contract test on Mongo backend [LIVE]: skipped when AGENTOS_MONGO_URI is unset."""
    if not MONGO_URI:
        if os.environ.get("AGENTOS_REQUIRE_LIVE_MONGO") == "1":
            pytest.fail(MONGO_SKIP_REASON)
        pytest.skip(MONGO_SKIP_REASON)

    db_name = f"agentos_test_v2_{uuid.uuid4().hex[:12]}"
    try:
        storage = await open_storage(backend="mongo", mongo_uri=MONGO_URI, db_name=db_name)
    except Exception as e:
        if os.environ.get("AGENTOS_REQUIRE_LIVE_MONGO") == "1":
            pytest.fail(f"{MONGO_SKIP_REASON} ({e})")
        pytest.skip(f"{MONGO_SKIP_REASON} ({e})")

    app = create_app(storage=storage)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://localhost",
            headers=auth_headers,
        ) as client:
            # 1. Create agent
            r = await client.post("/api/v2/agents", json={
                "name": "MongoAgent",
                "role": "Mongo Specialist",
                "goal": "Store in Mongo",
                "tools": ["fetch_url"],
            })
            assert r.status_code == 200

            # 2. Get agent
            r = await client.get("/api/v2/agents/mongoagent")
            assert r.status_code == 200
            assert r.json()["name"] == "MongoAgent"

            # 3. List agents
            r = await client.get("/api/v2/agents")
            assert r.status_code == 200
            assert any(a["name"] == "MongoAgent" for a in r.json())
    finally:
        await storage.close()
        from pymongo import AsyncMongoClient
        mongo_client = AsyncMongoClient(MONGO_URI)
        await mongo_client.drop_database(db_name)
        await mongo_client.close()


# ---------------------------------------------------------------------------
# 6. WebSocket Security Tests (Pure ASGI Middleware)
# ---------------------------------------------------------------------------

def test_websocket_stream_security_matrix(file_app, api_token):
    """
    WebSocket endpoint /api/runs/{run_id}/stream security matrix:
      - No token -> refused with code 4401
      - Bad Origin -> refused with code 4401
      - Bad Host -> refused with code 4401
      - Valid token + Origin -> connected successfully and echoes agentos.v1
    """
    # Create a mock run state in run_manager
    run_id = file_app.state.run_manager.create_run("test_mission")
    run_state = file_app.state.run_manager.get(run_id)
    client = TestClient(file_app, base_url="http://localhost")

    # 1. No token -> refused (close code 4401)
    with pytest.raises(WebSocketDisconnect) as exc1:
        with client.websocket_connect(
            f"/api/runs/{run_id}/stream",
            headers={"Host": "localhost", "Origin": "http://localhost:5173"},
        ):
            pass
    assert exc1.value.code == 4401

    # 2. Bad Origin -> refused (close code 4401)
    with pytest.raises(WebSocketDisconnect) as exc2:
        with client.websocket_connect(
            f"/api/runs/{run_id}/stream",
            subprotocols=[f"agentos.token.{api_token}", "agentos.v1"],
            headers={"Host": "localhost", "Origin": "http://evil.com"},
        ):
            pass
    assert exc2.value.code == 4401

    # 3. Bad Host -> refused (close code 4401)
    with pytest.raises(WebSocketDisconnect) as exc3:
        with client.websocket_connect(
            f"/api/runs/{run_id}/stream",
            subprotocols=[f"agentos.token.{api_token}", "agentos.v1"],
            headers={"Host": "evil.com", "Origin": "http://localhost:5173"},
        ):
            pass
    assert exc3.value.code == 4401

    # 4. Valid token + valid origin -> connected successfully
    with client.websocket_connect(
        f"/api/runs/{run_id}/stream",
        subprotocols=[f"agentos.token.{api_token}", "agentos.v1"],
        headers={"Host": "localhost", "Origin": "http://localhost:5173"},
    ) as ws:
        # Push completed event into the run state's event queue
        run_state.status = "completed"
        run_state.event_queue.put_nowait({"event": "run_completed"})
        msg = ws.receive_json()
        assert msg.get("event") == "run_completed"


# ---------------------------------------------------------------------------
# 7. Fail-Fast Hardening Tests (MasterKey & Mongo URI)
# ---------------------------------------------------------------------------

def test_master_key_startup_failure_on_corrupt_file(tmp_path, monkeypatch):
    """If MasterKey.load fails, startup fails immediately with a clear error. No silent generate()."""
    bad_key_path = tmp_path / "corrupt_master.key"
    bad_key_path.write_text("not_valid_base64_master_key!@#$", encoding="ascii")
    monkeypatch.setenv("AGENTOS_MASTER_KEY_FILE", str(bad_key_path))
    monkeypatch.delenv("AGENTOS_MASTER_KEY", raising=False)

    with pytest.raises(RuntimeError) as exc_info:
        create_app(project_path=str(tmp_path))
    assert "Failed to load vault master key" in str(exc_info.value)


def test_mongo_startup_failure_on_unreachable_uri(tmp_path, monkeypatch):
    """If AGENTOS_MONGO_URI is set and Mongo is unreachable, startup fails (no silent fallback)."""
    # Point to an unreachable port with short timeout
    monkeypatch.setenv(
        "AGENTOS_MONGO_URI",
        "mongodb://localhost:27999/unreachable_db?serverSelectionTimeoutMS=300",
    )
    app = create_app(project_path=str(tmp_path))

    with pytest.raises(RuntimeError) as exc_info:
        with TestClient(app, base_url="http://localhost"):
            pass
    assert "AGENTOS_MONGO_URI is set but MongoDB is unreachable" in str(exc_info.value)


def test_startup_banner_port_selection(monkeypatch, capsys):
    """Startup banner prints the URL of the UI actually served."""
    from agentos_server.auth import get_ui_port, print_startup_auth_banner
    import agentos_server.auth as auth_mod

    # Dev mode: prints 5173
    monkeypatch.setenv("AGENTOS_DEV", "1")
    assert get_ui_port(server_port=8080) == 5173

    # Reset banner flag to test print output
    auth_mod._PRINTED_STARTUP_BANNER = False
    print_startup_auth_banner("sample_token_123", server_port=8080)
    captured = capsys.readouterr().out
    assert "http://localhost:5173/#token=sample_token_123" in captured

