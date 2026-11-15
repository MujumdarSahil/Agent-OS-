"""Tests for Flow queue, worker leasing, heartbeat renewal, and lease fencing safety."""

import asyncio
import pytest
import pytest_asyncio
from unittest.mock import MagicMock

from agentos.flows.engine import FlowEngine
from agentos.flows.models import FlowDefinition
from agentos.flows.policy import SecurityPolicy
from agentos.flows.proxy import AgentOSToolProxy, MockTransport
from agentos.flows.state import RunStatus
from agentos.flows.worker import FlowWorker
from agentos.queue.in_process import InProcessQueueBackend
from agentos.storage import open_storage
from agentos.storage.models import FlowRecord
from agentos.storage.ports import FencingTokenError


@pytest_asyncio.fixture
async def file_storage(tmp_path):
    project = tmp_path / "queue_worker_proj"
    project.mkdir(parents=True, exist_ok=True)
    (project / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    s = await open_storage(str(project), backend="file", vault_path=str(tmp_path / "vault.json"))
    yield s
    await s.close()


def _make_sink_flow(flow_id: str = "flow_email") -> FlowRecord:
    return FlowRecord(
        id=flow_id,
        name="Email Sink Flow",
        entrypoint="trig",
        nodes={
            "trig": {
                "id": "trig",
                "type": "webhook_trigger",
                "config": {"path": "/msg"},
            },
            "sink": {
                "id": "sink",
                "type": "send_email",
                "config": {},
                "pinned_args": {"to": "ops@internal.local"},
            },
        },
        edges=[
            {
                "source": "trig",
                "target": "sink",
                "arg_mapping": {"body": "payload"},
            }
        ],
    )


def _make_approval_flow(flow_id: str = "flow_approval") -> FlowRecord:
    return FlowRecord(
        id=flow_id,
        name="Approval Flow",
        entrypoint="trig",
        nodes={
            "trig": {
                "id": "trig",
                "type": "webhook_trigger",
                "config": {"path": "/req"},
            },
            "gate": {
                "id": "gate",
                "type": "approval",
                "config": {
                    "prompt": "Approve email dispatch",
                    "approves": {"sink_node": "sink", "args": ["to", "body"]},
                },
            },
            "sink": {
                "id": "sink",
                "type": "send_email",
                "config": {},
            },
        },
        edges=[
            {
                "source": "trig",
                "target": "gate",
                "arg_mapping": {"to": "payload", "body": "payload"},
            },
            {
                "source": "gate",
                "target": "sink",
                "arg_mapping": {"to": "to", "body": "body"},
            },
        ],
    )


@pytest.mark.asyncio
async def test_queue_leasing_and_heartbeat_renewal():
    """InProcessQueueBackend supports leasing, expiration detection, and heartbeat renewal."""
    queue = InProcessQueueBackend()
    job = await queue.enqueue(run_id="run_101", flow_id="flow_1", version=1, inputs={"msg": "hello"})
    assert job.status == "queued"

    # Worker 1 leases the job with short timeout (0.2s)
    leased_job = await queue.lease(worker_id="worker_1", lease_timeout_s=0.2)
    assert leased_job is not None
    assert leased_job.worker_id == "worker_1"
    lease_1 = leased_job.lease_id
    assert lease_1 is not None

    # Fencing check should pass for worker 1
    assert queue.validate_lease("run_101", lease_1) is True
    assert queue.validate_lease("run_101", "bad_lease") is False

    # Renew lease
    renewed = await queue.renew_lease(leased_job.job_id, lease_1, lease_timeout_s=0.3)
    assert renewed is True

    # Sleep past expiration without renewal
    await asyncio.sleep(0.35)
    assert queue.validate_lease("run_101", lease_1) is False

    # Worker 2 can now lease the expired job
    leased_by_w2 = await queue.lease(worker_id="worker_2", lease_timeout_s=1.0)
    assert leased_by_w2 is not None
    assert leased_by_w2.worker_id == "worker_2"
    assert leased_by_w2.lease_id != lease_1
    assert queue.validate_lease("run_101", leased_by_w2.lease_id) is True


@pytest.mark.asyncio
async def test_worker_lease_safety_and_fencing(file_storage):
    """
    Requirement 1: Lease safety & fencing test:
    Worker 1 is still running when its lease expires. Worker 2 takes over.
    Worker 1's next write is rejected, and transport records exactly 1 send.
    """
    transport = MockTransport()
    queue = InProcessQueueBackend()
    file_storage.events._fencing_checker = queue.validate_lease

    # Setup published flow
    flow_rec = _make_sink_flow("flow_lease_fence")
    await file_storage.flows.put_draft(flow_rec)
    await file_storage.flows.publish("flow_lease_fence", "hash1", "policy1")

    run_id = "run_fenced_1"
    job = await queue.enqueue(
        run_id=run_id,
        flow_id="flow_lease_fence",
        version=1,
        inputs={"data": "test content"},
    )

    # Worker 1 leases with very short lease (0.1s)
    leased_w1 = await queue.lease(worker_id="worker_1", lease_timeout_s=0.1)
    assert leased_w1 is not None

    # Flow definitions
    flow_def = FlowDefinition(
        id=flow_rec.id,
        name=flow_rec.name,
        entrypoint=flow_rec.entrypoint,
        nodes=flow_rec.nodes,
        edges=flow_rec.edges,
    )

    policy = SecurityPolicy(internal_domains={"internal.local"})

    # Build engine for worker 1
    engine_w1 = FlowEngine(
        flow=flow_def,
        storage=file_storage,
        policy=policy,
        transport_registry={"send_email": transport},
        lease_id=leased_w1.lease_id,
        fencing_checker=queue.validate_lease,
    )

    # Wait for Worker 1's lease to expire
    await asyncio.sleep(0.15)

    # Worker 2 leases the expired job!
    leased_w2 = await queue.lease(worker_id="worker_2", lease_timeout_s=10.0)
    assert leased_w2 is not None
    assert leased_w2.lease_id != leased_w1.lease_id

    # Worker 1 now attempts to execute/write: its write MUST be rejected
    with pytest.raises(FencingTokenError):
        await engine_w1.run(run_id=run_id, inputs={"data": "test content"})

    # Worker 2 executes the job successfully
    engine_w2 = FlowEngine(
        flow=flow_def,
        storage=file_storage,
        policy=policy,
        transport_registry={"send_email": transport},
        lease_id=leased_w2.lease_id,
        fencing_checker=queue.validate_lease,
    )
    state_w2 = await engine_w2.run(run_id=run_id, inputs={"data": "test content"})
    assert state_w2.status == RunStatus.SUCCEEDED

    # Verify that transport records EXACTLY 1 send
    assert len(transport.sent_calls) == 1
    assert transport.sent_calls[0]["to"] == "ops@internal.local"


@pytest.mark.asyncio
async def test_worker_run_vs_resume_from_event_log(file_storage):
    """
    Requirement 3: Run vs resume is decided from the event log (run_started exists -> resume),
    not attempts.
    """
    transport = MockTransport()
    queue = InProcessQueueBackend()
    file_storage.events._fencing_checker = queue.validate_lease

    flow_rec = _make_sink_flow("flow_resume_test")
    await file_storage.flows.put_draft(flow_rec)
    await file_storage.flows.publish("flow_resume_test", "h", "p")

    run_id = "run_resume_1"
    await queue.enqueue(run_id=run_id, flow_id="flow_resume_test", version=1, inputs={"text": "hello"})

    # Manually append a run_started event to simulate an interrupted run
    await file_storage.events.append(
        run_id=run_id,
        type="run_started",
        data={"flow_id": "flow_resume_test", "entrypoint": "trig", "inputs": {"text": "hello"}},
    )

    policy = SecurityPolicy(internal_domains={"internal.local"})
    worker = FlowWorker(
        queue=queue,
        storage=file_storage,
        policy=policy,
        transport_registry={"send_email": transport},
        lease_timeout_s=5.0,
    )

    processed_run = await worker.run_once()
    assert processed_run == run_id

    # Verify run completed and only 1 send recorded
    events = await file_storage.events.list(run_id)
    assert any(e.type == "sink_committed" for e in events)
    assert len(transport.sent_calls) == 1


@pytest.mark.asyncio
async def test_worker_frees_on_approval_waiting(file_storage):
    """
    Requirement 4: Worker: a waiting run (approval) frees the worker.
    """
    transport = MockTransport()
    queue = InProcessQueueBackend()
    file_storage.events._fencing_checker = queue.validate_lease

    flow_rec = _make_approval_flow("flow_approval_worker")
    await file_storage.flows.put_draft(flow_rec)
    await file_storage.flows.publish("flow_approval_worker", "h", "p")

    run_id = "run_approval_1"
    await queue.enqueue(
        run_id=run_id,
        flow_id="flow_approval_worker",
        version=1,
        inputs={"to": "external@evil.corp", "body": "untrusted text"},
    )

    policy = SecurityPolicy(internal_domains={"internal.local", "corp.local"})
    worker = FlowWorker(
        queue=queue,
        storage=file_storage,
        policy=policy,
        transport_registry={"send_email": transport},
        lease_timeout_s=5.0,
    )

    # Worker runs the job
    processed_run = await worker.run_once()
    assert processed_run == run_id

    # Check that job is in waiting status and worker is freed
    job = await queue.get_job_by_run_id(run_id)
    assert job is not None
    assert job.status == "waiting"
    assert job.lease_id is None  # worker released!

    # Transport should not have been called yet
    assert len(transport.sent_calls) == 0


@pytest.mark.asyncio
async def test_fencing_always_active_fail_closed(file_storage):
    """
    Confirm in code: during leased execution the fencing check is always active
    (not optional / 'if configured').
    Any code path attempting to append events or call transport without a lease check fails closed.
    """
    transport = MockTransport()
    flow_rec = _make_sink_flow("flow_fc")
    flow_def = FlowDefinition(
        id=flow_rec.id,
        name=flow_rec.name,
        entrypoint=flow_rec.entrypoint,
        nodes=flow_rec.nodes,
        edges=flow_rec.edges,
    )

    # 1. FlowEngine with lease_id but no fencing_checker fails closed
    engine_no_checker = FlowEngine(
        flow=flow_def,
        storage=file_storage,
        lease_id="lease_xyz",
        fencing_checker=None,
    )
    with pytest.raises(FencingTokenError, match="no fencing_checker configured"):
        await engine_no_checker.run("run_fc_1", inputs={"to": "dev@local", "body": "test"})

    # 2. AgentOSToolProxy with lease_id but no fencing_checker fails closed
    proxy_no_checker = AgentOSToolProxy(
        run_id="run_fc_2",
        agent_node_id="agent_fc",
        storage=file_storage,
        policy=SecurityPolicy(),
        transport_registry={"send_email": transport},
        lease_id="lease_xyz",
        fencing_checker=None,
    )
    with pytest.raises(FencingTokenError, match="no fencing_checker configured"):
        await proxy_no_checker.invoke("agent_fc", "send_email", {"to": "dev@local", "body": "test"})

    assert len(transport.sent_calls) == 0
    events_run2 = await file_storage.events.list("run_fc_2")
    assert len(events_run2) == 0

    # 3. AgentOSToolProxy with expired/superseded lease fails closed
    is_valid = False
    proxy_expired = AgentOSToolProxy(
        run_id="run_fc_3",
        agent_node_id="agent_fc",
        storage=file_storage,
        policy=SecurityPolicy(),
        transport_registry={"send_email": transport},
        lease_id="lease_expired",
        fencing_checker=lambda run_id, lease_id: is_valid,
    )
    with pytest.raises(FencingTokenError, match="expired or been superseded"):
        await proxy_expired.invoke("agent_fc", "send_email", {"to": "dev@local", "body": "test"})

    assert len(transport.sent_calls) == 0
    events_run3 = await file_storage.events.list("run_fc_3")
    assert len(events_run3) == 0


@pytest.mark.asyncio
async def test_agent_path_worker_lease_fencing_safety(file_storage):
    """
    Lease safety in the agent path:
    Worker 1 leases an agent flow. While Worker 1 is paused, its lease expires and Worker 2 takes over.
    Worker 2 sends the email. When Worker 1 resumes and calls the proxy, its invocation fails closed
    with FencingTokenError, and the transport records exactly 1 send.
    """
    transport = MockTransport()
    queue = InProcessQueueBackend()
    file_storage.events._fencing_checker = queue.validate_lease

    run_id = "run_agent_fence"
    job = await queue.enqueue(
        run_id=run_id,
        flow_id="flow_agent_fence",
        version=1,
        inputs={"to": "dev@local", "body": "agent email"},
    )

    # Worker 1 leases job
    job1 = await queue.lease(worker_id="worker_1", lease_timeout_s=0.2)
    assert job1 is not None
    lease_1 = job1.lease_id

    # Create proxy for Worker 1
    proxy_w1 = AgentOSToolProxy(
        run_id=run_id,
        agent_node_id="agent_worker_1",
        storage=file_storage,
        policy=SecurityPolicy(),
        transport_registry={"send_email": transport},
        lease_id=lease_1,
        fencing_checker=queue.validate_lease,
    )

    # Worker 1 appends tool_called (lease still valid)
    await proxy_w1._append_event("tool_called", {"step": 1})

    # Wait for Worker 1's lease to expire
    await asyncio.sleep(0.25)
    assert queue.validate_lease(run_id, lease_1) is False

    # Worker 2 leases the job
    job2 = await queue.lease(worker_id="worker_2", lease_timeout_s=5.0)
    assert job2 is not None
    lease_2 = job2.lease_id

    # Worker 2 creates its proxy and successfully sends email
    proxy_w2 = AgentOSToolProxy(
        run_id=run_id,
        agent_node_id="agent_worker_2",
        storage=file_storage,
        policy=SecurityPolicy(),
        transport_registry={"send_email": transport},
        lease_id=lease_2,
        fencing_checker=queue.validate_lease,
    )
    result_w2 = await proxy_w2.invoke("agent_worker_2", "send_email", {"to": "dev@local", "body": "agent email"})
    assert "successfully dispatched" in result_w2
    assert len(transport.sent_calls) == 1

    # Worker 1 now attempts to invoke send_email or append event: must fail closed!
    with pytest.raises(FencingTokenError):
        await proxy_w1.invoke("agent_worker_1", "send_email", {"to": "dev@local", "body": "stale agent email"})

    # Transport still has exactly 1 send
    assert len(transport.sent_calls) == 1


@pytest.mark.asyncio
async def test_complete_and_fail_check_lease_in_every_state():
    """
    Fix 1: complete() and fail() must check the lease in EVERY state.
    A caller whose lease_id is not the job's current lease gets FencingTokenError,
    including when the job is waiting.
    """
    queue = InProcessQueueBackend()
    job = await queue.enqueue(run_id="run_state_check", flow_id="flow_1", version=1)

    # Worker 1 leases with short timeout
    j1 = await queue.lease(worker_id="w1", lease_timeout_s=0.1)
    assert j1 is not None
    w1_lease = j1.lease_id

    # Wait for w1's lease to expire
    await asyncio.sleep(0.15)

    # Worker 2 takes over and parks the job for approval
    j2 = await queue.lease(worker_id="w2", lease_timeout_s=10.0)
    assert j2 is not None
    w2_lease = j2.lease_id
    assert w2_lease != w1_lease

    await queue.release_for_waiting(j2.job_id, w2_lease, reason="needs_operator")

    check_job = await queue.get_job(j2.job_id)
    assert check_job.status == "waiting"

    # w1 calls fail() and complete() -> both rejected
    with pytest.raises(FencingTokenError):
        await queue.fail(j2.job_id, lease_id=w1_lease, error="w1 failed")

    with pytest.raises(FencingTokenError):
        await queue.complete(j2.job_id, lease_id=w1_lease)

    # Caller with unleased / None lease_id also rejected
    with pytest.raises(FencingTokenError):
        await queue.complete(j2.job_id, lease_id=None)

    # Job remains waiting
    post_job = await queue.get_job(j2.job_id)
    assert post_job.status == "waiting"


def test_validate_lease_no_queue_job_fails_closed():
    """
    Fix 2: validate_lease for a run with no queue job -> False when lease_id is given (fail closed).
    Writes without a queue (direct engine use in tests/CLI) must use lease_id=None explicitly.
    """
    queue = InProcessQueueBackend()

    # Run with no queue job + lease_id given -> False (fail closed)
    assert queue.validate_lease("no_such_run", lease_id="stale_or_fake_lease") is False

    # Run with no queue job + lease_id=None -> True (direct engine test/CLI write)
    assert queue.validate_lease("no_such_run", lease_id=None) is True


@pytest.mark.asyncio
async def test_max_attempts_dead_letter_and_worker_crash(file_storage):
    """
    Fix 3: Max attempts: QueueJob.attempts increments on every lease;
    after max_attempts (default 3, configurable) the job moves to 'dead_letter' with the last error,
    and the run is marked failed with reason 'max_attempts_exceeded'.
    Tested with a worker that crashes every time.
    """
    queue = InProcessQueueBackend(storage=file_storage)
    run_id = "run_crash_loop"

    # Seed run in storage
    from agentos.storage.models import RunRecord
    await file_storage.runs.put(RunRecord(
        run_id=run_id,
        mission_name="flow_crash",
        flow_id="flow_crash",
        flow_version=1,
        status="running",
    ))

    # Enqueue job with max_attempts=3
    job = await queue.enqueue(
        run_id=run_id,
        flow_id="flow_crash",
        version=1,
        inputs={"data": "poison pill"},
        max_attempts=3,
    )
    assert job.attempts == 0
    assert job.max_attempts == 3

    # Attempt 1: Worker 1 leases and crashes (timeout without renewal/complete)
    j1 = await queue.lease(worker_id="worker_1", lease_timeout_s=0.1)
    assert j1 is not None
    assert j1.attempts == 1
    await asyncio.sleep(0.15)  # crash / timeout

    # Attempt 2: Worker 2 leases and crashes
    j2 = await queue.lease(worker_id="worker_2", lease_timeout_s=0.1)
    assert j2 is not None
    assert j2.attempts == 2
    await asyncio.sleep(0.15)  # crash / timeout

    # Attempt 3: Worker 3 leases and crashes
    j3 = await queue.lease(worker_id="worker_3", lease_timeout_s=0.1)
    assert j3 is not None
    assert j3.attempts == 3
    await asyncio.sleep(0.15)  # crash / timeout

    # Next lease attempt: job moves to dead_letter, no worker leases it
    j4 = await queue.lease(worker_id="worker_4", lease_timeout_s=1.0)
    assert j4 is None  # no available jobs

    # Verify queue job state
    dead_job = await queue.get_job_by_run_id(run_id)
    assert dead_job is not None
    assert dead_job.status == "dead_letter"
    assert dead_job.attempts == 3
    assert dead_job.last_error == "max_attempts_exceeded"

    # Verify run record marked failed with reason max_attempts_exceeded
    run_rec = await file_storage.runs.get(run_id)
    assert run_rec is not None
    assert run_rec.status == "failed"
    assert run_rec.error == "max_attempts_exceeded"

    # Verify event log has run_failed
    events = await file_storage.events.list(run_id)
    fail_ev = next((e for e in events if e.type == "run_failed"), None)
    assert fail_ev is not None
    assert fail_ev.data.get("reason") == "max_attempts_exceeded"

