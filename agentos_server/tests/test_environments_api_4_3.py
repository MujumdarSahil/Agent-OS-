"""4.3 API (MOCK): publish needs a change note and deploys to staging only (new flows); permissions per role on every
new route; webhooks / schedules run the environment's version at run START and keep it; promotion race over HTTP;
re-check against a changed policy; test gate; second-person rule; staging sends simulated unless mapped (tripwire);
versions summary, archive and diff; audit entries."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time

import pytest
from httpx import ASGITransport, AsyncClient

from agentos.access import passwords as pw
from agentos.flows.worker import FlowWorker
from agentos_server.app import create_app
from benchmarks.awib import tripwire

PASSWORD = "violet-harbor-lantern-42"
FID = "env_api"
F = f"/api/v2/flows/{FID}"


def flow(to: str = "team@corp.local") -> dict:
    return {
        "id": FID, "name": FID, "entrypoint": "trig",
        "nodes": {"trig": {"id": "trig", "type": "manual_trigger", "config": {}},
                  "send": {"id": "send", "type": "send_email", "config": {},
                           "pinned_args": {"to": to, "subject": "S"}}},
        "edges": [{"source": "trig", "target": "send", "arg_mapping": {"body": "payload"}}],
    }


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


async def token(app, username: str, role: str) -> str:
    svc = app.state.access
    if await svc.find_user(username) is None:
        await svc.create_user(username, None, role, PASSWORD)
    u = await svc.find_user(username)
    raw, _ = await svc.create_token(u["id"], f"{username}-pat", 30)
    return raw


async def roles(app) -> dict:
    return {r: client(app, await token(app, f"u_{r}", r)) for r in ("viewer", "builder", "admin")}


async def create_and_publish(c: AsyncClient, to: str = "team@corp.local", note: str = "v") -> dict:
    if (await c.get(F)).status_code == 404:
        assert (await c.post("/api/v2/flows", json=flow(to))).status_code == 201
    else:
        assert (await c.put(F, json=flow(to))).status_code == 200
    r = await c.post(f"{F}/publish", json={"note": note})
    assert r.status_code == 200, r.text
    return r.json()


async def work(app) -> None:
    s = app.state
    w = FlowWorker(queue=s.queue, storage=s.storage, policy=s.security_policy, transport_registry=s.transport_registry,
                   staging_registry=s.staging_registry)
    while await w.run_once():
        pass


async def fire(c: AsyncClient, hook: dict, payload: dict) -> str:
    body, ts = json.dumps(payload), int(time.time())
    sig = "sha256=" + hmac.new(hook["secret_key"].encode(), f"{ts}.{body}".encode(), hashlib.sha256).hexdigest()
    r = await c.post(f"/hooks/{hook['secret_path']}", content=body,
                     headers={"Content-Type": "application/json", "X-AgentOS-Signature": sig,
                              "X-AgentOS-Timestamp": str(ts)})
    assert r.status_code == 202, r.text
    return r.json()["run_id"]


# ------------------------------------------------------------------------------------------------ publish


@pytest.mark.asyncio
async def test_publish_needs_a_note_and_deploys_staging_only(project):
    app = create_app(project_path=str(project))
    r = await roles(app)
    b = r["builder"]
    assert (await b.post("/api/v2/flows", json=flow())).status_code == 201
    assert (await b.post(f"{F}/publish")).status_code == 422
    assert (await b.post(f"{F}/publish", json={"note": ""})).status_code == 422
    assert (await b.post(f"{F}/publish", json={"note": "x" * 501})).status_code == 422
    assert (await b.post(f"{F}/publish", json={"note": "   "})).status_code == 422
    pub = (await b.post(f"{F}/publish", json={"note": "first version"})).json()
    assert pub["deployments"]["staging"] == {"deployed": True, "version": 1}
    assert pub["deployments"]["production"]["deployed"] is False
    assert (await b.get(f"{F}/versions/1")).json()["change_note"] == "first version"
    envs = (await r["viewer"].get(f"{F}/environments")).json()
    assert envs["environments"]["staging"]["version"] == 1 and envs["environments"]["production"] is None
    assert envs["settings"]["auto_deploy_production"] is False and envs["settings"]["legacy"] is False


@pytest.mark.asyncio
async def test_legacy_flow_migrated_on_startup_keeps_auto_deploy_to_production(project):
    from agentos.storage import open_storage
    from agentos.storage.models import FlowRecord

    st = await open_storage(str(project), backend="file")  # a flow from before 4.3 (no environment settings)
    await st.flows.put_draft(FlowRecord(**flow()))
    await st.flows.publish(FID, "sha", "p")
    await st.close()
    app = create_app(project_path=str(project))
    async with app.router.lifespan_context(app):
        r = await roles(app)
        envs = (await r["viewer"].get(f"{F}/environments")).json()
        assert envs["environments"]["production"]["version"] == 1
        assert envs["environments"]["production"]["action"] == "migrate" and envs["settings"]["legacy"]
        pub = await create_and_publish(r["builder"], to="ops@corp.local")
        assert pub["deployments"]["production"] == {"deployed": True, "version": 2}  # today's behaviour


# ------------------------------------------------------------------------------------------------ permissions


ROUTES = [  # (method, path, json body, capability)
    ("GET", f"{F}/environments", None, "read"),
    ("GET", f"{F}/environments/history", None, "read"),
    ("GET", f"{F}/versions/summary", None, "read"),
    ("GET", f"{F}/diff?from=1&to=draft", None, "read"),
    ("POST", f"{F}/environments/staging/promote", {"version": 1}, "build"),
    ("POST", f"{F}/environments/staging/rollback", {"version": 1}, "build"),
    ("PUT", f"{F}/environments/settings/staging", {"auto_deploy_staging": True}, "build"),
    ("POST", f"{F}/versions/1/archive", None, "build"),
    ("POST", f"{F}/environments/production/promote", {"version": 1}, "admin"),
    ("POST", f"{F}/environments/production/rollback", {"version": 1}, "admin"),
    ("PUT", f"{F}/environments/settings/production", {"second_person": False}, "admin"),
    ("GET", "/api/v2/environments/staging-channels", None, "admin"),
    ("PUT", "/api/v2/environments/staging-channels", {"slack_channels": []}, "admin"),
    ("PUT", "/api/v2/webhooks/wh_x/environment", {"environment": "staging"}, "admin"),
    ("PUT", "/api/v2/schedules/sc_x/environment", {"environment": "staging"}, "admin"),
]
ALLOWED = {"viewer": {"read"}, "builder": {"read", "build"}, "admin": {"read", "build", "admin"}}


@pytest.mark.asyncio
async def test_permissions_per_role_on_every_new_route(project):
    from agentos_server.permissions_table import PERMISSIONS

    app = create_app(project_path=str(project))
    r = await roles(app)
    await create_and_publish(r["builder"])
    for method, path, body, cap in ROUTES:
        template = path.split("?")[0].replace(FID, "{flow_id}").replace("/1/archive", "/{version}/archive") \
            .replace("wh_x", "{webhook_id}").replace("sc_x", "{schedule_id}")
        assert PERMISSIONS[(method, template)] == cap, (method, template)
        for role, c in r.items():
            res = await c.request(method, path, json=body)
            if cap in ALLOWED[role]:
                assert res.status_code != 403, (role, method, path, res.text)
            else:
                assert res.status_code == 403, (role, method, path, res.status_code)


# ------------------------------------------------------------------------------------------------ what runs where


@pytest.mark.asyncio
async def test_triggers_run_the_environment_version_at_start_and_keep_it(project):
    app = create_app(project_path=str(project))
    r = await roles(app)
    b, a = r["builder"], r["admin"]
    await create_and_publish(b)  # v1 -> staging
    assert (await a.post(f"{F}/environments/production/promote", json={"version": 1})).status_code == 200
    await create_and_publish(b, to="ops@corp.local")  # v2 -> staging only
    prod_hook = (await b.post("/api/v2/webhooks", json={"name": "p", "flow_id": FID})).json()
    stg_hook = (await b.post("/api/v2/webhooks", json={"name": "s", "flow_id": FID, "environment": "staging"})).json()
    assert prod_hook["environment"] == "production" and stg_hook["environment"] == "staging"
    started = await fire(b, prod_hook, {"payload": "x"})
    # promoted AFTER the run started: the run keeps v1
    assert (await a.post(f"{F}/environments/production/promote", json={"version": 2})).status_code == 200
    await work(app)
    run = await app.state.storage.runs.get(started)
    assert run.flow_version == 1 and run.environment == "production"
    staged = await app.state.storage.runs.get(await fire(b, stg_hook, {"payload": "y"}))
    assert staged.flow_version == 2 and staged.environment == "staging"
    after = await app.state.storage.runs.get(await fire(b, prod_hook, {"payload": "z"}))
    assert after.flow_version == 2  # new runs use the new production version
    # binding changes are admin-only
    hook_id = prod_hook["webhook_id"]
    assert (await b.put(f"/api/v2/webhooks/{hook_id}", json={"environment": "staging"})).status_code == 403
    assert (await b.put(f"/api/v2/webhooks/{hook_id}", json={"name": "renamed"})).status_code == 200
    moved = await a.put(f"/api/v2/webhooks/{hook_id}/environment", json={"environment": "staging"})
    assert moved.status_code == 200 and moved.json()["environment"] == "staging"
    sched = (await b.post("/api/v2/schedules", json={"name": "n", "flow_id": FID, "cron_expression": "0 * * * *"}))
    assert sched.json()["environment"] == "production"
    sid = sched.json()["schedule_id"]
    assert (await a.put(f"/api/v2/schedules/{sid}/environment", json={"environment": "staging"})).json()[
        "environment"] == "staging"
    # manual run: environment choice, draft, version; both environment and version -> 400
    m = (await b.post(f"{F}/runs", json={"environment": "staging"})).json()
    assert m["version"] == 2 and m["environment"] == "staging"
    d = (await b.post(f"{F}/runs", json={"environment": "draft", "inputs": {"payload": "d"}})).json()
    assert d["version"] is None and d["environment"] == "draft"
    await work(app)
    draft_run = await app.state.storage.runs.get(d["run_id"])
    assert draft_run.status == "succeeded" and draft_run.flow_snapshot["target"] == "draft"
    assert (await b.post(f"{F}/runs", json={"environment": "staging", "version": 1})).status_code == 400


@pytest.mark.asyncio
async def test_draft_run_refused_when_the_draft_fails_the_check(project):
    app = create_app(project_path=str(project))
    b = (await roles(app))["builder"]
    unsafe = flow()
    unsafe["nodes"]["send"]["pinned_args"] = {"subject": "S"}
    unsafe["edges"][0]["arg_mapping"] = {"to": "payload", "body": "payload"}
    assert (await b.post("/api/v2/flows", json=unsafe)).status_code == 201
    res = await b.post(f"{F}/runs", json={"environment": "draft"})
    assert res.status_code == 400 and "Draft run refused" in res.json()["detail"]["error"]


# ------------------------------------------------------------------------------------------------ checks


@pytest.mark.asyncio
async def test_promotion_race_over_http_one_wins(project):
    app = create_app(project_path=str(project))
    r = await roles(app)
    await create_and_publish(r["builder"])
    await create_and_publish(r["builder"], to="ops@corp.local")
    a1, a2 = r["admin"], client(app, await token(app, "u_admin2", "admin"))
    res = await asyncio.gather(
        a1.post(f"{F}/environments/production/promote", json={"version": 1, "expected_version": None}),
        a2.post(f"{F}/environments/production/promote", json={"version": 2, "expected_version": None}))
    codes = sorted(x.status_code for x in res)
    assert codes == [200, 409], [x.text for x in res]
    loser = next(x for x in res if x.status_code == 409).json()["detail"]
    assert "changed meanwhile" in loser["error"]


@pytest.mark.asyncio
async def test_changed_policy_refuses_promote_and_rollback_and_is_audited(project):
    app = create_app(project_path=str(project))
    r = await roles(app)
    b, a = r["builder"], r["admin"]
    await create_and_publish(b)
    assert (await a.post(f"{F}/environments/production/promote", json={"version": 1})).status_code == 200
    fixed = flow()
    fixed["edges"][0]["arg_mapping"] = {}
    fixed["nodes"]["send"]["pinned_args"]["body"] = "fixed"
    await b.put(F, json=fixed)
    assert (await b.post(f"{F}/publish", json={"note": "fixed body"})).status_code == 200
    assert (await a.post(f"{F}/environments/production/promote", json={"version": 2})).status_code == 200
    app.state.security_policy.internal_domains = set()  # the admin tightens the policy after v1 was published
    rb = await a.post(f"{F}/environments/production/rollback", json={"version": 1})
    assert rb.status_code == 409
    detail = rb.json()["detail"]
    assert "fails the security check against the current policy" in detail["error"]
    assert detail["checks"][0]["policy_changed"] is True
    assert (await a.post(f"{F}/environments/staging/promote", json={"version": 1})).status_code == 409
    entries = (await a.get("/api/v2/audit", params={"action": "flow.rollback"})).json()["entries"]
    assert entries[0]["outcome"] == "refused" and entries[0]["details"]["to"] == 1
    promotes = (await a.get("/api/v2/audit", params={"action": "flow.promote", "outcome": "ok"})).json()["entries"]
    assert {e["details"].get("to") for e in promotes} >= {1, 2}


@pytest.mark.asyncio
async def test_test_gate_and_second_person_over_http(project):
    app = create_app(project_path=str(project))
    r = await roles(app)
    b, a = r["builder"], r["admin"]
    a2 = client(app, await token(app, "u_admin2", "admin"))
    await create_and_publish(a)  # published by the admin
    assert (await b.put(f"{F}/environments/settings/production", json={"second_person": True})).status_code == 403
    s = await a.put(f"{F}/environments/settings/production", json={"promote_test_gate": "block"})
    assert s.status_code == 200 and s.json()["promote_test_gate"] == "block"
    refused = await a2.post(f"{F}/environments/production/promote", json={"version": 1})
    assert refused.status_code == 409 and "no test cases" in refused.json()["detail"]["error"]
    await a.put(f"{F}/environments/settings/production", json={"promote_test_gate": "warn", "second_person": True})
    same = await a.post(f"{F}/environments/production/promote", json={"version": 1})
    assert same.status_code == 409 and "second-person" in same.json()["detail"]["error"]
    other = await a2.post(f"{F}/environments/production/promote", json={"version": 1})
    assert other.status_code == 200 and other.json()["warnings"]
    settings = (await a.get("/api/v2/audit", params={"action": "flow.env_settings"})).json()["entries"]
    assert len(settings) == 2


# ------------------------------------------------------------------------------------------------ staging sends


@pytest.mark.asyncio
async def test_staging_sends_are_simulated_unless_mapped_tripwire(project, monkeypatch):
    app = create_app(project_path=str(project))
    r = await roles(app)
    b, a = r["builder"], r["admin"]
    ch = await a.post("/api/v2/notify/channels", json={
        "type": "email", "name": "mail", "host": "127.0.0.1", "port": 2525, "security": "none",
        "allow_insecure_local": True, "from_address": "agentos@corp.local", "use_for_flows": True})
    assert ch.status_code == 201, ch.text
    test_box = await a.post("/api/v2/notify/channels", json={
        "type": "email", "name": "testbox", "host": "127.0.0.1", "port": 2526, "security": "none",
        "allow_insecure_local": True, "from_address": "staging@corp.local"})
    assert test_box.status_code == 201, test_box.text
    await create_and_publish(b)
    calls = tripwire.install(monkeypatch)
    run_id = (await b.post(f"{F}/runs", json={"environment": "staging", "inputs": {"payload": "hi"}})).json()["run_id"]
    await work(app)
    assert calls == []  # nothing left the process although a production flow channel exists
    sink = [e for e in await app.state.storage.events.list(run_id) if e.type == "sink_committed"]
    assert sink[0].data["result"]["status"] == "simulated" and "staging" in sink[0].data["result"]["reason"]
    # mapped: the staging run uses the admin's test mailbox (a real delivery attempt, caught by the tripwire)
    assert (await b.put("/api/v2/environments/staging-channels", json={"email_channel": "testbox"})).status_code == 403
    assert (await a.put("/api/v2/environments/staging-channels", json={"email_channel": "nope"})).status_code == 400
    m = await a.put("/api/v2/environments/staging-channels", json={"email_channel": "testbox"})
    assert m.status_code == 200 and m.json()["email_channel"] == "testbox"
    await b.post(f"{F}/runs", json={"environment": "staging", "inputs": {"payload": "hi"}})
    await work(app)
    assert any("SMTP" in c for c in calls)
    audit = (await a.get("/api/v2/audit", params={"action": "env.staging_channels"})).json()["entries"]
    assert audit and audit[0]["details"]["email_channel"] == "testbox"


# ------------------------------------------------------------------------------------------------ versions, diff


@pytest.mark.asyncio
async def test_versions_summary_archive_and_diff(project):
    app = create_app(project_path=str(project))
    r = await roles(app)
    b, a, v = r["builder"], r["admin"], r["viewer"]
    await create_and_publish(b, note="first")
    await create_and_publish(b, to="ops@corp.local", note="ops")
    assert (await a.post(f"{F}/environments/production/promote", json={"version": 1})).status_code == 200
    summary = (await v.get(f"{F}/versions/summary")).json()
    rows = {x["version"]: x for x in summary["versions"]}
    assert rows[1]["environments"] == ["production"] and rows[2]["environments"] == ["staging"]
    assert rows[1]["change_note"] == "first" and rows[1]["security"]["passed"] is True
    assert summary["environments"] == {"staging": 2, "production": 1}
    assert (await b.post(f"{F}/versions/1/archive")).status_code == 409  # deployed
    await b.put(F, json=flow(to="other@corp.local"))
    d = (await v.get(f"{F}/diff", params={"from": "1", "to": "draft"})).json()
    rc = [x for x in d["security"] if x["kind"] == "recipient_changed"]
    assert rc and rc[0]["from"] == "team@corp.local" and rc[0]["to"] == "other@corp.local"
    assert (await v.get(f"{F}/diff", params={"from": "9", "to": "1"})).status_code == 404
    hist = (await v.get(f"{F}/environments/history")).json()
    assert hist[0]["environment"] == "production" and hist[0]["deployed_by"] == "u_admin"
