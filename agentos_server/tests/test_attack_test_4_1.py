"""4.1 "Attack my flow" API (MOCK, fake sinks): a safe flow scores 100%, the unsafe use case 07 flow reports the
successful path and one-click fixes, permissions per role, audit counts only, nothing saved, no real transport."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from agentos.access import passwords as pw
from agentos_server.app import create_app
from benchmarks.awib import tripwire

UC = Path(__file__).resolve().parents[2] / "examples" / "usecases"
PASSWORD = "violet-harbor-lantern-42"


def _flow(rel: str) -> dict:
    return json.loads((UC / rel).read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def cheap_scrypt(monkeypatch):
    monkeypatch.setattr(pw, "LOG_N", 10)


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTOS_API_TOKEN", "test-token")
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    monkeypatch.setenv("AGENTOS_INTERNAL_DOMAINS", "corp.local,internal.local")
    monkeypatch.setenv("CREWAI_TELEMETRY_OPT_OUT", "1")
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    (tmp_path / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    return tmp_path


def client(app, token: str) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://localhost",
                       headers={"Host": "localhost", "Authorization": f"Bearer {token}"})


async def user_token(app, username: str, role: str) -> str:
    svc = app.state.access
    if await svc.find_user(username) is None:
        await svc.create_user(username, None, role, PASSWORD)
    u = await svc.find_user(username)
    raw, _ = await svc.create_token(u["id"], f"{username}-pat", 30)
    return raw


@pytest.mark.asyncio
async def test_permissions_per_role(project):
    app = create_app(str(project))
    flow = _flow("04-webhook-trigger/flow.json")
    for role, code in {"viewer": 403, "approver": 403, "builder": 200, "admin": 200}.items():
        async with client(app, await user_token(app, f"u_{role}", role)) as c:
            r = await c.post(f"/api/v2/flows/{flow['id']}/attack-test", json={"flow": flow})
            assert r.status_code == code, (role, r.text)


@pytest.mark.asyncio
async def test_safe_flow_scores_100_nothing_saved_audit_counts_only(project, monkeypatch):
    app = create_app(str(project))
    flow = _flow("07-support-desk-copilot/flows/support_desk.flow.json")
    async with client(app, await user_token(app, "bob", "builder")) as c:
        assert (await c.post("/api/v2/flows", json=flow)).status_code == 201
        before = (await app.state.storage.flows.get_draft(flow["id"])).model_dump(mode="json")
        calls = tripwire.install(monkeypatch)
        r = await c.post(f"/api/v2/flows/{flow['id']}/attack-test")  # the stored draft
    rep = r.json()
    assert r.status_code == 200 and rep["tried"] > 10 and rep["score_pct"] == 100.0 and rep["succeeded"] == 0
    assert rep["saved"] is False and rep["sent"] is False and rep["model"] == "mock/adversarial"
    assert rep["furthest"]["outcome"] in ("stopped_at_approval", "blocked_at_runtime", "pinned_only")
    after = (await app.state.storage.flows.get_draft(flow["id"])).model_dump(mode="json")
    assert after == before
    assert await app.state.storage.flows.list_versions(flow["id"]) == []
    entries = [e for e in await app.state.audit.entries() if e["action"] == "flow.attack_test"]
    assert len(entries) == 1
    assert set(entries[0]["details"]) == {"tried", "stopped", "succeeded", "families", "violations"}
    assert all(isinstance(v, int) for v in entries[0]["details"].values())
    assert "attacker" not in json.dumps(entries)
    assert calls == []


@pytest.mark.asyncio
async def test_unsafe_uc07_reports_the_successful_path_and_fixes(project, monkeypatch):
    app = create_app(str(project))
    flow = _flow("07-support-desk-copilot/flows/support_desk_unsafe.flow.json")
    async with client(app, await user_token(app, "bob", "builder")) as c:
        calls = tripwire.install(monkeypatch)
        r = await c.post(f"/api/v2/flows/{flow['id']}/attack-test", json={"flow": flow})
    rep = r.json()
    assert r.status_code == 200 and rep["succeeded"] > 0 and rep["score_pct"] < 100
    worst = rep["furthest"]
    assert worst["outcome"] == "reached_flagged_sink" and "page_oncall" in worst["nodes"]
    assert worst["paths"] and worst["paths"][0][0] == "ticket" and worst["paths"][0][-1] == "page_oncall"
    assert rep["violations"] and (rep["fixes"] or rep["refusals"])
    assert any("page_oncall.to" in x for x in rep["refusals"])  # a recipient from the ticket is never "fixed"
    assert calls == []
