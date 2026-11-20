"""3.4 Part 0c (MOCK): a local Ollama provider is "healthy" only after a real reachability check.

The probe function is replaced (no Ollama needed); the test proves the routes call it and map its answer, and
that a failed check reads "not running" both on the overview and in the connection test.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

TOKEN = "ollama-health-test-token"


@pytest.fixture
def client_factory(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTOS_API_TOKEN", TOKEN)
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    (tmp_path / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")

    def make(reachable: bool, calls: list):
        import agentos.llm.router_factory as rf
        from agentos_server.app import create_app

        def probe(timeout: float = 1.0) -> bool:
            calls.append(timeout)
            return reachable

        monkeypatch.setattr(rf, "check_ollama_reachable", probe)
        app = create_app(str(tmp_path))
        return AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost",
                           headers={"Authorization": f"Bearer {TOKEN}", "Host": "localhost"})

    return make


@pytest.mark.asyncio
@pytest.mark.parametrize("reachable,state", [(True, "healthy"), (False, "not_running")])
async def test_connection_test_checks_ollama(client_factory, reachable, state):
    calls: list = []
    async with client_factory(reachable, calls) as c:
        r = await c.post("/api/v2/providers/test-connection", json={"provider_name": "ollama_llama"})
    body = r.json()
    assert r.status_code == 200 and body["ok"] is reachable
    assert calls == [1.5]  # a real check with the short timeout, also in MOCK mode
    assert ("not running" in (body.get("message") or "")) is (not reachable)


@pytest.mark.asyncio
async def test_overview_never_says_healthy_without_a_check(client_factory):
    calls: list = []
    async with client_factory(False, calls) as c:
        rows = (await c.get("/api/v2/overview")).json()["providers"]
    local = [r for r in rows if r["name"].startswith("ollama") and r["state"] not in ("disabled", "no_key")]
    assert all(r["state"] == "not_running" for r in local)
    if local:
        assert calls == [1.5]  # one check per request, however many local rows
