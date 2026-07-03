import asyncio
import os
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

PROJECT_DIR = "test_project_providers"


@pytest.fixture(scope="session")
def project_path(tmp_path_factory):
    """Create a minimal project for providers testing."""
    base = tmp_path_factory.mktemp("providers_tests")
    p = str(base / PROJECT_DIR)
    os.makedirs(p, exist_ok=True)
    return p


@pytest.fixture(scope="session")
def app(project_path):
    os.environ["AGENTOS_MOCK_LLM"] = "1"
    # Set a mock project path env
    os.environ["AGENTOS_PROJECT"] = project_path
    from agentos.server.app import create_app
    return create_app(project_path)


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_providers_get(client):
    r = await client.get("/api/providers")
    assert r.status_code == 200
    providers = r.json()
    assert len(providers) > 0
    # Check shape
    first = providers[0]
    assert "name" in first
    assert "litellm_model" in first
    assert "api_key_configured" in first
    assert "status" in first


@pytest.mark.asyncio
async def test_providers_keys_lifecycle(client, project_path):
    # Select a cloud provider to configure
    provider_name = "openai_gpt4o"
    key_env = "OPENAI_API_KEY"

    # Set key
    payload = {
        "provider_name": provider_name,
        "api_key": "sk-mock-key-12345",
    }
    r = await client.post("/api/providers/keys", json=payload)
    assert r.status_code == 200
    assert r.json()["success"] is True
    assert r.json()["provider_name"] == provider_name
    assert r.json()["key_env_var"] == key_env

    # Verify os.environ is updated
    assert os.environ.get(key_env) == "sk-mock-key-12345"

    # Verify fallback chain updates
    r_chain = await client.get("/api/providers/fallback-chain")
    assert r_chain.status_code == 200
    chain = r_chain.json()
    assert len(chain) > 0
    # openai_gpt4o should be in the chain now
    names = [c["name"] for c in chain]
    assert provider_name in names

    # Run direct provider test
    r_test = await client.post(f"/api/providers/test/{provider_name}")
    assert r_test.status_code == 200
    assert r_test.json()["success"] is True
    assert r_test.json()["response"] == "OK"

    # Delete key
    r_delete = await client.delete(f"/api/providers/keys/{provider_name}")
    assert r_delete.status_code == 200
    assert r_delete.json()["success"] is True

    # Verify env var is cleaned up
    assert os.environ.get(key_env) is None
