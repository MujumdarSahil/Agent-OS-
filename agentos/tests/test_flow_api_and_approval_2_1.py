"""
Tests for Flow API endpoints (/api/v2/flows):
- Publish gate refusal with violation list
- Manual trigger untrusted input labeling
- Approval endpoint idempotency and rejection
- Deletion guard (409) and archive
- Startup recovery of interrupted/queued runs
"""

import asyncio
import os
import uuid
import pytest
from httpx import ASGITransport, AsyncClient

from agentos.flows.models import FlowDefinition
from agentos.flows.proxy import MockTransport
from agentos.flows.state import RunStatus
from agentos.storage import open_storage
from agentos.storage.models import FlowRecord
from agentos_server.app import create_app

MONGO_URI = os.environ.get("AGENTOS_MONGO_URI", "mongodb://127.0.0.1:27017")


@pytest.fixture
def test_app(tmp_path):
    project_dir = tmp_path / "api_test_project"
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    app = create_app(str(project_dir))
    return app


@pytest.fixture
def auth_headers(test_app):
    token = test_app.state.api_token
    return {
        "Authorization": f"Bearer {token}",
        "Host": "localhost:8000",
    }


def _unpinned_sink_flow(flow_id: str = "flow_unpinned") -> dict:
    """Flow where untrusted webhook input feeds directly into unpinned 'to' argument of send_email."""
    return {
        "id": flow_id,
        "name": "Unpinned Sink Flow",
        "entrypoint": "webhook",
        "nodes": {
            "webhook": {
                "id": "webhook",
                "type": "webhook_trigger",
                "config": {"path": "/in"},
            },
            "sink": {
                "id": "sink",
                "type": "send_email",
                "config": {},
                # Note: 'to' is NOT pinned
            },
        },
        "edges": [
            {
                "source": "webhook",
                "target": "sink",
                "arg_mapping": {"to": "payload", "body": "payload"},
            }
        ],
    }


def _pinned_sink_flow(flow_id: str = "flow_pinned") -> dict:
    return {
        "id": flow_id,
        "name": "Pinned Sink Flow",
        "entrypoint": "webhook",
        "nodes": {
            "webhook": {
                "id": "webhook",
                "type": "webhook_trigger",
                "config": {"path": "/in"},
            },
            "sink": {
                "id": "sink",
                "type": "send_email",
                "config": {},
                "pinned_args": {"to": "admin@internal.local"},
            },
        },
        "edges": [
            {
                "source": "webhook",
                "target": "sink",
                "arg_mapping": {"body": "payload"},
            }
        ],
    }


def _approval_flow(flow_id: str = "flow_with_approval") -> dict:
    return {
        "id": flow_id,
        "name": "Approval Sink Flow",
        "entrypoint": "webhook",
        "nodes": {
            "webhook": {
                "id": "webhook",
                "type": "webhook_trigger",
                "config": {"path": "/in"},
            },
            "approval_gate": {
                "id": "approval_gate",
                "type": "approval",
                "config": {
                    "prompt": "Review email",
                    "approves": {"sink_node": "sink", "args": ["to", "body"]},
                },
            },
            "sink": {
                "id": "sink",
                "type": "send_email",
                "config": {},
            },
        },
        "edges": [
            {
                "source": "webhook",
                "target": "approval_gate",
                "arg_mapping": {"to": "payload", "body": "payload"},
            },
            {
                "source": "approval_gate",
                "target": "sink",
                "arg_mapping": {"to": "to", "body": "body"},
            },
        ],
    }


@pytest.mark.asyncio
async def test_publish_gate_refusal_with_violations(test_app, auth_headers):
    """
    Requirement 2: Publishing runs StaticFlowAnalyzer; violations refuse publish with list.
    """
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://localhost:8000") as client:
        # 1. Create draft with unpinned sensitive sink
        res = await client.post(
            "/api/v2/flows",
            headers=auth_headers,
            json=_unpinned_sink_flow("test_pub_refusal"),
        )
        assert res.status_code == 201

        # 2. Publish must be refused (400)
        pub_res = await client.post(
            "/api/v2/flows/test_pub_refusal/publish",
            headers=auth_headers,
        )
        assert pub_res.status_code == 400
        detail = pub_res.json()["detail"]
        assert "Publish refused" in detail["error"]
        violations = detail["violations"]
        assert len(violations) > 0
        assert violations[0]["node_id"] == "sink"
        assert violations[0]["target_arg"] == "to"


@pytest.mark.asyncio
async def test_deletion_guard_and_archive_endpoints(test_app, auth_headers):
    """
    Requirement 7: Flow with published versions cannot be deleted (returns 409).
    POST /flows/{id}/archive marks the flow archived.
    """
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://localhost:8000") as client:
        # Create valid pinned flow
        res = await client.post(
            "/api/v2/flows",
            headers=auth_headers,
            json=_pinned_sink_flow("flow_del_test"),
        )
        assert res.status_code == 201

        # Publish version 1
        pub_res = await client.post(
            "/api/v2/flows/flow_del_test/publish",
            headers=auth_headers,
        )
        assert pub_res.status_code == 200
        assert pub_res.json()["version"] == 1

        # Attempt DELETE -> 409 Conflict
        del_res = await client.delete("/api/v2/flows/flow_del_test", headers=auth_headers)
        assert del_res.status_code == 409
        assert "Cannot delete flow with published versions" in del_res.json()["detail"]

        # Call archive endpoint
        arc_res = await client.post("/api/v2/flows/flow_del_test/archive", headers=auth_headers)
        assert arc_res.status_code == 200
        assert arc_res.json()["status"] == "archived"


@pytest.mark.asyncio
async def test_manual_trigger_inputs_untrusted_by_default(test_app, auth_headers):
    """
    Requirement 5: Manual trigger inputs (POST /flows/{id}/runs) are labeled untrusted by default.
    """
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://localhost:8000") as client:
        # Create and publish pinned flow
        await client.post("/api/v2/flows", headers=auth_headers, json=_pinned_sink_flow("flow_trigger_test"))
        await client.post("/api/v2/flows/flow_trigger_test/publish", headers=auth_headers)

        # Trigger run
        run_res = await client.post(
            "/api/v2/flows/flow_trigger_test/runs",
            headers=auth_headers,
            json={"inputs": {"msg": "hello from manual trigger"}},
        )
        assert run_res.status_code == 201
        run_id = run_res.json()["run_id"]

        # Check job in queue
        job = await test_app.state.queue.get_job_by_run_id(run_id)
        assert job is not None
        assert job.inputs == {"msg": "hello from manual trigger"}


@pytest.mark.asyncio
async def test_approval_idempotency_and_rejection(test_app, auth_headers):
    """
    Requirement 6:
    - Approve only for runs waiting at named approval node
    - Idempotent: second call returns same result
    - Decision 'reject' fails run cleanly without executing sink
    """
    mock_transport = MockTransport()
    test_app.state.transport_registry = {"send_email": mock_transport}

    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://localhost:8000") as client:
        # Create and publish flow with approval gate
        await client.post("/api/v2/flows", headers=auth_headers, json=_approval_flow("flow_appr_api"))
        await client.post("/api/v2/flows/flow_appr_api/publish", headers=auth_headers)

        # Trigger run
        run_res = await client.post(
            "/api/v2/flows/flow_appr_api/runs",
            headers=auth_headers,
            json={"inputs": {"to": "partner@corp.local", "body": "confidential memo"}},
        )
        run_id = run_res.json()["run_id"]

        # Worker processes job until approval gate
        from agentos.flows.worker import FlowWorker
        worker = FlowWorker(
            queue=test_app.state.queue,
            storage=test_app.state.storage,
            transport_registry={"send_email": mock_transport},
        )
        await worker.run_once()

        # Run is now waiting at approval_gate
        rec = await test_app.state.storage.runs.get(run_id)
        assert rec.status == "waiting"

        # 1. Non-existent node -> 400
        bad_node_res = await client.post(
            f"/api/v2/flows/flow_appr_api/runs/{run_id}/approve",
            headers=auth_headers,
            json={"node_id": "wrong_node", "decision": True},
        )
        assert bad_node_res.status_code == 400

        # 2. Rejection decision
        reject_res = await client.post(
            f"/api/v2/flows/flow_appr_api/runs/{run_id}/approve",
            headers=auth_headers,
            json={"node_id": "approval_gate", "decision": "reject"},
        )
        assert reject_res.status_code == 200
        assert reject_res.json()["status"] == "failed"
        assert reject_res.json()["error"] == "rejected_by_operator"

        # Sink was NOT executed
        assert len(mock_transport.sent_calls) == 0

        # 3. Idempotent second call returns same result
        second_reject = await client.post(
            f"/api/v2/flows/flow_appr_api/runs/{run_id}/approve",
            headers=auth_headers,
            json={"node_id": "approval_gate", "decision": "reject"},
        )
        assert second_reject.status_code == 200
        assert second_reject.json()["status"] == "failed"


@pytest.mark.asyncio
async def test_startup_recovery(tmp_path, monkeypatch):
    """
    Requirement 2: Startup recovery (MOCK):
    On start, find runs whose last state is queued/running (from event log) and re-enqueue them.
    """
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    project_dir = tmp_path / "recovery_project"
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")

    # 1. First server session: setup storage and simulate an interrupted running run
    s = await open_storage(str(project_dir), backend="file", vault_path=str(tmp_path / "vault.json"))
    flow_rec = FlowRecord(
        id="flow_recover",
        name="Recover Flow",
        entrypoint="trig",
        nodes={
            "trig": {"id": "trig", "type": "webhook_trigger", "config": {"path": "/in"}},
            "sink": {"id": "sink", "type": "send_email", "config": {}, "pinned_args": {"to": "ops@local"}},
        },
        edges=[{"source": "trig", "target": "sink", "arg_mapping": {"body": "payload"}}],
    )
    await s.flows.put_draft(flow_rec)
    await s.flows.publish("flow_recover", "h1", "p1")

    # Create run and event
    from agentos.storage.models import RunRecord
    run_id = "run_interrupted_42"
    await s.runs.put(RunRecord(run_id=run_id, mission_name="flow_recover", flow_id="flow_recover", flow_version=1, status="running"))
    await s.events.append(run_id, "run_started", {"inputs": {"data": "recover me"}})
    await s.close()

    # 2. Second session (simulated server restart): create app and trigger lifespan
    app = create_app(str(project_dir))
    async with app.router.lifespan_context(app):
        # Startup recovery should have re-enqueued run_interrupted_42
        job = await app.state.queue.get_job_by_run_id(run_id)
        assert job is not None
        assert job.status == "queued"
        assert job.inputs == {"data": "recover me"}
        assert job.flow_id == "flow_recover"
        assert job.version == 1


@pytest.mark.asyncio
async def test_startup_recovery_live_mongo():
    """
    Requirement 2: Startup recovery (LIVE Mongo):
    On start with LIVE Mongo, find runs whose last state is queued/running and re-enqueue them.
    """
    mongo_uri = os.environ.get("AGENTOS_MONGO_URI")
    if not mongo_uri:
        if os.environ.get("AGENTOS_REQUIRE_LIVE_MONGO") == "1":
            pytest.fail("AGENTOS_REQUIRE_LIVE_MONGO=1 set but AGENTOS_MONGO_URI not configured")
        pytest.skip("LIVE Mongo not configured")

    from agentos.storage.mongo import open_mongo_storage
    db_name = f"agentos_test_recov_{uuid.uuid4().hex[:12]}"
    s = await open_mongo_storage(mongo_uri, db_name=db_name)

    flow_rec = FlowRecord(
        id="flow_recover_mongo",
        name="Recover Flow Mongo",
        entrypoint="trig",
        nodes={
            "trig": {"id": "trig", "type": "webhook_trigger", "config": {"path": "/in"}},
            "sink": {"id": "sink", "type": "send_email", "config": {}, "pinned_args": {"to": "ops@local"}},
        },
        edges=[{"source": "trig", "target": "sink", "arg_mapping": {"body": "payload"}}],
    )
    await s.flows.put_draft(flow_rec)
    await s.flows.publish("flow_recover_mongo", "h1", "p1")

    from agentos.storage.models import RunRecord
    run_id = f"run_interrupted_mongo_{uuid.uuid4().hex[:8]}"
    await s.runs.put(RunRecord(run_id=run_id, mission_name="flow_recover_mongo", flow_id="flow_recover_mongo", flow_version=1, status="running"))
    await s.events.append(run_id, "run_started", {"inputs": {"data": "recover me mongo"}})

    # Create app with explicit Mongo storage to simulate server running against Mongo
    app = create_app(project_path=".", storage=s)
    async with app.router.lifespan_context(app):
        job = await app.state.queue.get_job_by_run_id(run_id)
        assert job is not None
        assert job.status == "queued"
        assert job.inputs == {"data": "recover me mongo"}
        assert job.flow_id == "flow_recover_mongo"

    await s.close()
    from pymongo import AsyncMongoClient
    c = AsyncMongoClient(mongo_uri)
    await c.drop_database(db_name)
    await c.close()
