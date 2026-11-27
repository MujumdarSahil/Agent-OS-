"""4.2 flow tests API (MOCK, fake sinks): permissions per role, admin-only options (live tools, include secret
values), audit entries (counts only), case CRUD and validation, suite runs with history, save-from-run, security
generation, comparison, and the publish gate in both modes (static check first). No real transport is used."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from agentos.access import passwords as pw
from agentos_server.app import create_app
from benchmarks.awib import tripwire

UC07 = Path(__file__).resolve().parents[2] / "examples" / "usecases" / "07-support-desk-copilot"
FLOW = json.loads((UC07 / "flows" / "support_desk.flow.json").read_text(encoding="utf-8"))
UNSAFE = json.loads((UC07 / "flows" / "support_desk_unsafe.flow.json").read_text(encoding="utf-8"))
TICKETS = json.loads((UC07 / "inputs" / "tickets.json").read_text(encoding="utf-8"))
FX = [{"kind": "http", "method": "GET", "url": "https://jsonplaceholder.typicode.com/users/1", "body": {"id": 1}}]
PASSWORD = "violet-harbor-lantern-42"
FID = FLOW["id"]
BASE = f"/api/v2/flows/{FID}/tests"

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def cheap_scrypt(monkeypatch):
    monkeypatch.setattr(pw, "LOG_N", 10)


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTOS_API_TOKEN", "test-token")
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    monkeypatch.setenv("AGENTOS_INTERNAL_DOMAINS", "corp.local")
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


def normal_case(expect: str = "succeeded", **kw) -> dict:
    return {"name": "normal ticket", "tags": ["smoke"], "input": TICKETS["normal"], "fixtures": FX,
            "mock_responses": {"triage": "NORMAL. Billing question."},
            "expectations": [{"kind": "status", "equals": expect},
                             {"kind": "sink", "target": "send_email", "node": "queue_note", "op": "called_with",
                              "arg": "to", "value": "support-queue@corp.local"}], **kw}


async def actions(app, prefix: str) -> list[dict]:
    return [e for e in await app.state.audit.entries() if e["action"].startswith(prefix)]


async def test_permissions_per_role(project):
    app = create_app(str(project))
    async with client(app, await user_token(app, "admin", "admin")) as c:
        assert (await c.post("/api/v2/flows", json=FLOW)).status_code == 201
        case_id = (await c.post(BASE, json=normal_case())).json()["id"]
    reads = [("GET", BASE), ("GET", f"{BASE}/{case_id}"), ("GET", f"{BASE}/runs"), ("GET", f"{BASE}/settings"),
             ("GET", "/api/v2/flow-tests/summary")]
    writes = [("POST", BASE, normal_case()), ("PUT", f"{BASE}/{case_id}", normal_case()),
              ("POST", f"{BASE}/run", {}), ("PUT", f"{BASE}/settings", {"mode": "warn"}),
              ("POST", f"{BASE}/security", None), ("POST", f"{BASE}/from-review", {})]
    for role, can_write in {"viewer": False, "approver": False, "builder": True, "admin": True}.items():
        async with client(app, await user_token(app, f"u_{role}", role)) as c:
            for method, url in reads:
                assert (await c.request(method, url)).status_code == 200, (role, url)
            for method, url, body in writes:
                r = await c.request(method, url, json=body)
                assert (r.status_code in (200, 201)) == can_write and (can_write or r.status_code == 403), \
                    (role, method, url, r.status_code, r.text[:200])
    async with client(app, await user_token(app, "u_viewer", "viewer")) as c:
        assert (await c.delete(f"{BASE}/{case_id}")).status_code == 403


async def test_case_crud_validation_and_audit_counts_only(project):
    app = create_app(str(project))
    async with client(app, await user_token(app, "bob", "builder")) as c:
        assert (await c.post("/api/v2/flows", json=FLOW)).status_code == 201
        bad_node = normal_case(expectations=[{"kind": "output", "node": "nope", "value": 1}])
        assert (await c.post(BASE, json=bad_node)).status_code == 400
        bad_kind = normal_case(expectations=[{"kind": "bogus"}])
        assert (await c.post(BASE, json=bad_kind)).status_code == 422
        r = await c.post(BASE, json=normal_case())
        assert r.status_code == 201
        cid = r.json()["id"]
        r = await c.put(f"{BASE}/{cid}", json={**normal_case(), "name": "renamed"})
        assert r.status_code == 200 and r.json()["name"] == "renamed" and r.json()["id"] == cid
        listing = (await c.get(BASE)).json()
        assert [x["name"] for x in listing["cases"]] == ["renamed"] and listing["gate"]["mode"] == "off"
        assert (await c.delete(f"{BASE}/{cid}")).json() == {"deleted": True}
        assert (await c.get(f"{BASE}/{cid}")).status_code == 404
    entries = await actions(app, "flow_tests.case")
    assert [e["details"]["action"] for e in entries] == ["create", "update", "delete"]
    blob = json.dumps(entries)
    assert "support-queue@corp.local" not in blob and "Billing" not in blob


async def test_extraction_value_must_be_an_allowed_value(project):
    app = create_app(str(project))
    flow = {"id": "ex", "name": "ex", "entrypoint": "t", "loops": {}, "edges": [
        {"source": "t", "target": "x", "arg_mapping": {"text": "payload"}}], "nodes": {
        "t": {"id": "t", "type": "manual_trigger", "config": {}, "pinned_args": {}},
        "x": {"id": "x", "type": "quarantined_extraction", "pinned_args": {}, "config": {
            "fields": [{"name": "severity", "type": "enum", "values": ["low", "high"]}]}}}}
    async with client(app, await user_token(app, "bob", "builder")) as c:
        assert (await c.post("/api/v2/flows", json=flow)).status_code == 201
        ok = {"name": "a", "expectations": [{"kind": "extraction", "node": "x", "field": "severity", "equals": "high"}]}
        bad = {"name": "b", "expectations": [{"kind": "extraction", "node": "x", "field": "severity",
                                              "equals": "urgent"}]}
        assert (await c.post("/api/v2/flows/ex/tests", json=ok)).status_code == 201
        r = await c.post("/api/v2/flows/ex/tests", json=bad)
        assert r.status_code == 400 and "allowed values" in r.text


async def test_run_history_regression_from_run_and_tripwire(project, monkeypatch):
    app = create_app(str(project))
    async with client(app, await user_token(app, "bob", "builder")) as c:
        assert (await c.post("/api/v2/flows", json=FLOW)).status_code == 201
        await c.post(BASE, json=normal_case())
        calls = tripwire.install(monkeypatch)
        s1 = (await c.post(f"{BASE}/run", json={"model": "mock"})).json()
        assert s1["counts"] == {"total": 1, "pass": 1, "fail": 0, "error": 0}
        res = s1["results"][0]
        assert res["run_id"].startswith("test_") and res["models_used"] == ["mock/scripted"]
        run = (await c.get(f"/api/v2/flows/{FID}/runs/{res['run_id']}")).json()
        assert run["trigger"] == "test"
        draft = (await c.post(f"{BASE}/from-run", json={"run_id": res["run_id"]})).json()
        assert draft["source"] == "run" and draft["input"] == TICKETS["normal"] and draft["fixtures"]
        listed = (await c.get(BASE)).json()["cases"]
        assert listed[0]["last_result"]["status"] == "pass"
        await c.put(f"{BASE}/{listed[0]['id']}", json={**normal_case("failed")})
        s2 = (await c.post(f"{BASE}/run", json={})).json()
        assert [x["name"] for x in s2["regression"]["newly_failing"]] == ["normal ticket"]
        assert s2["results"][0]["failures"][0]["message"].startswith("final status: expected failed, got succeeded")
        hist = (await c.get(f"{BASE}/runs")).json()
        assert [h["id"] for h in hist] == [s2["id"], s1["id"]]
        assert (await c.get(f"{BASE}/runs/{s1['id']}")).json()["id"] == s1["id"]
        summary = (await c.get("/api/v2/flow-tests/summary")).json()
        assert summary[FID]["cases"] == 1 and summary[FID]["last_pass_rate"] == 0.0
        assert (await c.post(f"{BASE}/run", json={"target": "published"})).status_code == 404
        assert (await c.post(f"{BASE}/run", json={"model": "nonsense"})).status_code == 400
    assert calls == []
    runs = await actions(app, "flow_tests.run")
    assert len(runs) == 2 and set(runs[0]["details"]) == {"suite_run_id", "target", "version", "model", "total",
                                                         "pass", "fail", "error", "live_tools"}


async def test_admin_only_options_live_tools_and_secret_values(project):
    app = create_app(str(project))
    async with client(app, await user_token(app, "admin", "admin")) as c:
        assert (await c.post("/api/v2/flows", json=FLOW)).status_code == 201
    async with client(app, await user_token(app, "bob", "builder")) as c:
        assert (await c.post(f"{BASE}/run", json={"live_tools": True})).status_code == 403
        assert (await c.post(BASE, json=normal_case(secret_values_included=True))).status_code == 403
        r = await c.post(f"{BASE}/from-run", json={"run_id": "x", "include_secret_values": True})
        assert r.status_code == 403
    async with client(app, await user_token(app, "admin", "admin")) as c:
        await c.post(BASE, json=normal_case())
        r = await c.post(f"{BASE}/run", json={"live_tools": True})  # fixtures exist: still nothing real
        assert r.status_code == 200 and r.json()["live_tools"] is True
        assert (await c.post(BASE, json=normal_case(secret_values_included=True))).status_code == 201
    live = await actions(app, "flow_tests.live_tools")
    sec = await actions(app, "flow_tests.secret_values")
    assert [e["outcome"] for e in live] == ["refused", "ok"]
    assert [e["outcome"] for e in sec] == ["refused", "refused", "ok"]


async def test_security_generation_and_compare(project, monkeypatch):
    from agentos.flowtests import service

    monkeypatch.setattr(service, "check_model_enabled", lambda m: None)
    app = create_app(str(project))
    async with client(app, await user_token(app, "bob", "builder")) as c:
        assert (await c.post("/api/v2/flows", json=FLOW)).status_code == 201
        gen = (await c.post(f"{BASE}/security")).json()
        assert gen["generated"] > 10 and "recipient_swap" in gen["families"]
        again = (await c.post(f"{BASE}/security")).json()  # regenerating replaces, never duplicates
        assert len((await c.get(BASE)).json()["cases"]) == again["generated"] == gen["generated"]
        await c.post(BASE, json=normal_case())
        cmp_ = await c.post(f"{BASE}/compare", json={"models": ["mock", "router"], "tags": ["smoke"]})
        assert cmp_.status_code == 200
        rows = cmp_.json()["rows"]
        assert [r["model"] for r in rows] == ["mock", "router"] and rows[0]["pass_rate"] == 100.0
        assert (await c.post(f"{BASE}/compare", json={"models": ["mock"]})).status_code == 400


async def test_publish_gate_block_and_warn(project):
    app = create_app(str(project))
    async with client(app, await user_token(app, "bob", "builder")) as c:
        assert (await c.post("/api/v2/flows", json=FLOW)).status_code == 201
        # block with no cases: fail closed
        assert (await c.put(f"{BASE}/settings", json={"mode": "block"})).json()["mode"] == "block"
        r = await c.post(f"/api/v2/flows/{FID}/publish")
        assert r.status_code == 400 and r.json()["detail"]["test_gate"]["counts"]["total"] == 0
        # block with a failing case: refused, no version
        cid = (await c.post(BASE, json=normal_case("failed"))).json()["id"]
        r = await c.post(f"/api/v2/flows/{FID}/publish")
        assert r.status_code == 400 and r.json()["detail"]["error"] == "Publish refused: tests failed"
        assert r.json()["detail"]["test_gate"]["failed"] == ["normal ticket"]
        assert await app.state.storage.flows.list_versions(FID) == []
        # warn: published with a warning
        await c.put(f"{BASE}/settings", json={"mode": "warn"})
        r = await c.post(f"/api/v2/flows/{FID}/publish")
        assert r.status_code == 200 and r.json()["published_version"] == 1
        assert r.json()["test_gate"]["mode"] == "warn" and r.json()["test_gate"]["passed"] is False
        # block with passing cases: published, gate passed
        await c.put(f"{BASE}/{cid}", json=normal_case("succeeded"))
        await c.put(f"{BASE}/settings", json={"mode": "block"})
        r = await c.post(f"/api/v2/flows/{FID}/publish")
        assert r.status_code == 200 and r.json()["test_gate"]["passed"] is True
        # gate off: no test run, no field
        await c.put(f"{BASE}/settings", json={"mode": "off"})
        assert (await c.post(f"/api/v2/flows/{FID}/publish")).json()["test_gate"] is None
        # the saved draft never stores the response-only field
        assert (await app.state.storage.flows.get_draft(FID)).test_gate is None
    refused = [e for e in await actions(app, "flow.publish") if e["outcome"] == "refused"]
    assert [e["details"]["reason"] for e in refused] == ["tests_failed", "tests_failed"]
    gates = await actions(app, "flow_tests.gate")
    assert [e["details"]["mode"] for e in gates] == ["block", "warn", "block", "off"]


async def test_static_check_still_runs_first(project):
    app = create_app(str(project))
    async with client(app, await user_token(app, "bob", "builder")) as c:
        assert (await c.post("/api/v2/flows", json=UNSAFE)).status_code == 201
        await c.put(f"/api/v2/flows/{UNSAFE['id']}/tests/settings", json={"mode": "block"})
        r = await c.post(f"/api/v2/flows/{UNSAFE['id']}/publish")
        assert r.status_code == 400 and r.json()["detail"]["error"] == "Publish refused: security violations found"
        assert (await c.get(f"/api/v2/flows/{UNSAFE['id']}/tests/runs")).json() == []  # gate never ran
