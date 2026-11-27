"""4.2 review fix: a test run (trigger "test") can only be advanced by the flow test runner (MOCK).

- a waiting test run cannot be approved or rejected through the normal API (409), even one left over by a crash;
- after a suite, no test run is waiting (the runner closes it: cancelled, "test case ended", AFTER evaluating);
- the run stores the exact flow it ran against (never "latest published");
- a security test suite fires no alert and queues no notification, although its runs contain security blocks;
- startup recovery and the wait-timer scheduler ignore test runs; the worker refuses them;
- the Overview (waiting approvals and KPIs) excludes test runs;
- the tripwire records no real transport.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from agentos.access import passwords as pw
from agentos.notify.service import security_block_kind
from agentos.storage.models import RunRecord
from agentos_server.app import create_app
from benchmarks.awib import tripwire

UC07 = Path(__file__).resolve().parents[2] / "examples" / "usecases" / "07-support-desk-copilot"
FLOW = json.loads((UC07 / "flows" / "support_desk.flow.json").read_text(encoding="utf-8"))
UNSAFE = json.loads((UC07 / "flows" / "support_desk_unsafe.flow.json").read_text(encoding="utf-8"))
TICKETS = json.loads((UC07 / "inputs" / "tickets.json").read_text(encoding="utf-8"))
FX = [{"kind": "http", "method": "GET", "url": "https://jsonplaceholder.typicode.com/users/1", "body": {"id": 1}}]
PASSWORD = "violet-harbor-lantern-42"
FID = FLOW["id"]

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


async def admin(app) -> str:
    svc = app.state.access
    if await svc.find_user("root") is None:
        await svc.create_user("root", None, "admin", PASSWORD)
    u = await svc.find_user("root")
    raw, _ = await svc.create_token(u["id"], "root-pat", 30)
    return raw


URGENT = {"name": "urgent waits", "input": TICKETS["urgent"], "fixtures": FX,
          "mock_responses": {"triage": "URGENT. Checkout is down."},
          "expectations": [{"kind": "status", "equals": "waiting_for_approval"},
                           {"kind": "approval_reached", "node": "oncall_approval"}]}


async def leftover_waiting_test_run(storage, run_id: str = "test_leftover") -> str:
    """A test run as a crash would leave it: waiting at the approval (no runner left to close it)."""
    await storage.runs.put(RunRecord(run_id=run_id, mission_name=FID, flow_id=FID, status="waiting",
                                     trigger="test"))
    await storage.events.append(run_id=run_id, type="run_started", data={"flow_id": FID, "inputs": TICKETS["urgent"],
                                                                         "trigger": "test"})
    await storage.events.append(run_id=run_id, type="node_waiting", data={
        "node_id": "oncall_approval", "approves": {"sink_node": "page_oncall"},
        "sink_args": {"to": "oncall@corp.local"}})
    await storage.events.append(run_id=run_id, type="run_waiting", data={"node_id": "oncall_approval"})
    return run_id


async def test_suite_leaves_nothing_waiting_and_stores_the_exact_flow(project, monkeypatch):
    app = create_app(str(project))
    async with client(app, await admin(app)) as c:
        assert (await c.post("/api/v2/flows", json=FLOW)).status_code == 201
        assert (await c.post(f"/api/v2/flows/{FID}/tests", json=URGENT)).status_code == 201
        calls = tripwire.install(monkeypatch)
        suite = (await c.post(f"/api/v2/flows/{FID}/tests/run", json={})).json()
        res = suite["results"][0]
        # evaluated BEFORE closing: the case saw the run waiting at the approval
        assert res["status"] == "pass" and res["run_status"] == "waiting_for_approval"
        run = await app.state.storage.runs.get(res["run_id"])
        assert run.trigger == "test" and run.status == "cancelled" and run.error == "test case ended"
        events = await app.state.storage.events.list(res["run_id"])
        assert events[-1].type == "run_cancelled" and events[-1].data["reason"] == "test case ended"
        snap = run.flow_snapshot
        assert snap["target"] == "draft" and snap["version"] is None and len(snap["content_sha256"]) == 64
        assert snap["flow"]["nodes"]["page_oncall"]["pinned_args"]["to"] == "oncall@corp.local"
        # the closed run cannot be approved either
        r = await c.post(f"/api/v2/flows/{FID}/runs/{res['run_id']}/approve", json={"node_id": "oncall_approval"})
        assert r.status_code == 409 and "test run" in r.text
        waiting = [x for x in await app.state.storage.runs.list(limit=500) if x.status == "waiting"]
        assert waiting == []
    assert calls == []


async def test_waiting_test_run_cannot_be_approved_or_rejected_and_is_not_on_overview(project, monkeypatch):
    app = create_app(str(project))
    async with client(app, await admin(app)) as c:
        assert (await c.post("/api/v2/flows", json=FLOW)).status_code == 201
        assert (await c.post(f"/api/v2/flows/{FID}/publish")).status_code == 200  # a published version exists
        rid = await leftover_waiting_test_run(app.state.storage)
        calls = tripwire.install(monkeypatch)
        for decision in (True, "reject"):
            r = await c.post(f"/api/v2/flows/{FID}/runs/{rid}/approve",
                             json={"node_id": "oncall_approval", "decision": decision})
            assert r.status_code == 409 and r.json()["detail"].startswith("this is a test run")
        assert (await app.state.storage.runs.get(rid)).status == "waiting"  # untouched
        assert not [e for e in await app.state.storage.events.list(rid) if e.type == "approval_decision"]
        ov = (await c.get("/api/v2/overview")).json()
        assert rid not in json.dumps(ov)
    assert calls == []
    refused = [e for e in await app.state.audit.entries() if e["action"] == "approval.decide"]
    assert [e["details"]["reason"] for e in refused] == ["test_run", "test_run"]


async def test_security_suite_fires_no_alert_and_no_notification(project, monkeypatch):
    app = create_app(str(project))
    async with client(app, await admin(app)) as c:
        assert (await c.post("/api/v2/flows", json=UNSAFE)).status_code == 201
        assert (await c.post(f"/api/v2/flows/{UNSAFE['id']}/tests/security")).status_code == 200
        calls = tripwire.install(monkeypatch)
        suite = (await c.post(f"/api/v2/flows/{UNSAFE['id']}/tests/run", json={"tags": ["direct"]})).json()
        assert suite["counts"]["total"] >= 1
        blocks = []
        for res in suite["results"]:
            blocks += [e for e in await app.state.storage.events.list(res["run_id"]) if security_block_kind(e)]
        assert blocks, "the unsafe flow's test runs contain security blocks (they would alert on a real run)"
        alerts = (await c.get("/api/v2/alerts")).json()
        assert alerts["alerts"] == [] and alerts["unacknowledged"] == 0
        assert await app.state.notify.store.outbox.list() == []
    assert calls == []


async def test_startup_recovery_scheduler_and_worker_ignore_test_runs(project):
    from agentos.flows.worker import FlowWorker
    from agentos.triggers.scheduler import FlowScheduler

    app = create_app(str(project))
    st = app.state.storage
    await st.runs.put(RunRecord(run_id="test_crashed", mission_name=FID, flow_id=FID, flow_version=1,
                                status="running", trigger="test"))
    await st.events.append(run_id="test_crashed", type="run_started", data={"inputs": {}})
    await st.runs.put(RunRecord(run_id="test_timer", mission_name=FID, flow_id=FID, flow_version=1,
                                status="waiting", trigger="test", resume_at=1.0))
    async with app.router.lifespan_context(app):
        queue = app.state.queue
        assert await queue.get_job_by_run_id("test_crashed") is None  # startup recovery skipped it
        assert await FlowScheduler(st, queue).resume_due_timers(now_override=10.0) == []
        assert await queue.get_job_by_run_id("test_timer") is None
        # even if a test run reached a queue, a worker refuses it (no engine, no transport)
        await queue.reenqueue(run_id="test_crashed", flow_id=FID, version=1, inputs={})
        processed = await FlowWorker(queue, st).run_once()
        assert processed == "test_crashed"
        job = await queue.get_job_by_run_id("test_crashed")
        assert job.status in ("failed", "dead_letter", "queued") and "test run" in (job.last_error or "")
        assert (await st.runs.get("test_crashed")).status == "running"  # the worker never touched the run
        assert not [e for e in await st.events.list("test_crashed") if e.type != "run_started"]
