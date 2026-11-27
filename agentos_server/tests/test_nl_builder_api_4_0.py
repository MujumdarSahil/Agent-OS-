"""4.0 natural-language builder API (MOCK): permissions per role, nothing saved or published, audit metadata only,
llm_call events + ledger under the pseudo flow "builder", run limits and budgets, /flows/check."""

from __future__ import annotations

import json

import pytest
from httpx import ASGITransport, AsyncClient

from agentos.access import passwords as pw
from agentos.builder import mock_builder
from agentos.usage.ledger import Budgets, RunLimits, UsageSettings
from agentos.usage.pricing import UNKNOWN
from agentos_server.app import create_app

PASSWORD = "violet-harbor-lantern-42"
SUPPORT = mock_builder.EXAMPLES["support"]


@pytest.fixture(autouse=True)
def cheap_scrypt(monkeypatch):
    monkeypatch.setattr(pw, "LOG_N", 10)


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTOS_API_TOKEN", "test-token")
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    monkeypatch.setenv("AGENTOS_INTERNAL_DOMAINS", "corp.local")
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    monkeypatch.delenv("AGENTOS_V1_NO_AUTH", raising=False)
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
    expected = {"viewer": 403, "approver": 403, "builder": 200, "admin": 200}
    for role, code in expected.items():
        async with client(app, await user_token(app, f"u_{role}", role)) as c:
            r = await c.post("/api/v2/flows/generate", json={"description": SUPPORT})
            assert r.status_code == code, (role, r.text)
            r = await c.post("/api/v2/flows/check", json={"flow": json.loads(mock_builder.support_desk({}))["flow"]})
            assert r.status_code == code, (role, r.text)


@pytest.mark.asyncio
async def test_generate_never_saves_or_publishes_and_audits_metadata_only(project):
    app = create_app(str(project))
    async with client(app, await user_token(app, "bob", "builder")) as c:
        r = await c.post("/api/v2/flows/generate", json={"description": SUPPORT})
        body = r.json()
        assert r.status_code == 200 and body["status"] == "draft" and body["check"]["status"] == "passed"
        assert body["published"] is False and body["saved"] is False
        fid = body["flow"]["id"]
        assert (await c.get(f"/api/v2/flows/{fid}")).status_code == 404  # not saved
        assert await app.state.storage.flows.list_versions(fid) == []    # not published
        # "Create draft" = the normal create route; still nothing published
        rec = {**body["flow"], "status": "draft"}
        assert (await c.post("/api/v2/flows", json=rec)).status_code == 201
        assert await app.state.storage.flows.list_versions(fid) == []
    entries = [e for e in await app.state.audit.entries() if e["action"] == "flow.generate"]
    assert len(entries) == 2 and entries[0]["details"]["description_chars"] == len(SUPPORT)
    assert len(entries[0]["details"]["description_sha256"]) == 64
    dump = json.dumps(entries)
    assert "support ticket" not in dump and "oncall@corp.local" not in dump  # never the description text
    assert entries[1]["details"]["check"] == "passed" and entries[1]["details"]["model_calls"] == 1


@pytest.mark.asyncio
async def test_usage_recorded_under_builder_pseudo_flow(project):
    app = create_app(str(project))
    async with client(app, await user_token(app, "bob", "builder")) as c:
        r = await c.post("/api/v2/flows/generate",
                         json={"description": "Forward every webhook payload by email to partners@external.example"})
    body = r.json()
    assert body["check"]["status"] == "fixed" and body["model_calls"] == 2
    run = await app.state.storage.runs.get(body["run_id"])
    assert run.flow_id == "builder" and run.trigger == "builder" and run.status == "succeeded"
    calls = [e for e in await app.state.storage.events.list(body["run_id"]) if e.type == "llm_call"]
    assert len(calls) == 2 and all(e.data["provider"] == "mock" and e.data["mock"] for e in calls)
    assert all("messages" not in e.data and "content" not in e.data for e in calls)  # metadata only
    rows = [r for r in await app.state.usage.ledger.rows() if r["flow_id"] == "builder"]
    assert sum(r["calls"] for r in rows) == 2


@pytest.mark.asyncio
async def test_run_limit_applies(project):
    app = create_app(str(project))
    await app.state.usage.put_settings(UsageSettings(run_limits=RunLimits(max_model_calls=1)))
    async with client(app, await user_token(app, "bob", "builder")) as c:
        r = await c.post("/api/v2/flows/generate",
                         json={"description": "Forward every webhook payload by email to partners@external.example"})
    assert r.status_code == 429 and "run limit exceeded" in r.json()["detail"]["detail"]
    run_id = r.json()["detail"]["run_id"]
    assert (await app.state.storage.runs.get(run_id)).status == "failed"
    types = [e.type for e in await app.state.storage.events.list(run_id)]
    assert "run_limit_exceeded" in types


@pytest.mark.asyncio
async def test_budget_applies(project, monkeypatch):
    app = create_app(str(project))
    await app.state.usage.put_settings(UsageSettings(budgets=Budgets(flow_daily={"builder": 1.0})))
    monkeypatch.setattr(app.state.usage, "price", lambda *a, **k: UNKNOWN)  # a paid model with no known price
    async with client(app, await user_token(app, "bob", "builder")) as c:
        r = await c.post("/api/v2/flows/generate", json={"description": SUPPORT})
    assert r.status_code == 429 and "budget" in r.json()["detail"]["detail"]
    assert r.json()["detail"]["model_calls"] == 1


@pytest.mark.asyncio
async def test_secret_like_description_refused_and_audited_without_text(project):
    app = create_app(str(project))
    async with client(app, await user_token(app, "bob", "builder")) as c:
        r = await c.post("/api/v2/flows/generate",
                         json={"description": "Use header Authorization: Bearer fixture-not-a-real-token-9"})
    assert r.status_code == 400 and "vault" in r.json()["detail"]
    entries = [e for e in await app.state.audit.entries() if e["action"] == "flow.generate"]
    assert entries[-1]["outcome"] == "refused" and entries[-1]["details"]["reason"] == "secret_like_input"
    assert "fixture-not-a-real-token" not in json.dumps(entries)
    assert not [r for r in await app.state.storage.runs.list() if r.flow_id == "builder"]  # no model call


@pytest.mark.asyncio
async def test_edit_mode_from_stored_draft_and_check_endpoint(project):
    app = create_app(str(project))
    flow = json.loads(mock_builder.support_desk({}))["flow"]
    async with client(app, await user_token(app, "bob", "builder")) as c:
        assert (await c.post("/api/v2/flows", json=flow)).status_code == 201
        r = await c.post("/api/v2/flows/generate",
                         json={"flow_id": flow["id"], "change_request": "also email lead@corp.local"})
        body = r.json()
        assert body["mode"] == "edit" and body["diff"]["nodes_added"] == ["email_lead"], body
        stored = await app.state.storage.flows.get_draft(flow["id"])
        assert "email_lead" not in stored.nodes  # the proposal is not applied by the server
        # /check: an unsafe flow + description gives a passing one-click fix
        unsafe = json.loads(mock_builder.to_sender({}))["flow"]
        r = await c.post("/api/v2/flows/check", json={"flow": unsafe, "description": "send to a@corp.local"})
        chk = r.json()["check"]
        assert chk["status"] == "failing" and chk["fixes"][0]["passes"]
        r = await c.post("/api/v2/flows/check", json={"flow": chk["fixes"][0]["flow"]})
        assert r.json()["check"]["status"] == "passed"
