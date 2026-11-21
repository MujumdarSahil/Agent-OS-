#!/usr/bin/env python3
"""
Use Case 03: Flow Lifecycle, Worker Leasing & Fencing, and Dead-Letter Recovery.
Demonstrates:
  1. Benign execution: Draft -> Publish -> Enqueue -> Leased Worker execution -> Exactly-1 send.
  2. Failover & Fencing: Worker 1 lease expires, Worker 2 takes over; Worker 1 late write rejected.
  3. Dead-letter protection: Bounded retries move poison-pill runs to dead_letter after max_attempts.
"""

import argparse
import asyncio
import os
import sys
import tempfile
import uuid
from pathlib import Path

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

os.environ["AGENTOS_MOCK_LLM"] = "1"

from agentos.flows.engine import FlowEngine
from agentos.flows.models import FlowDefinition
from agentos.flows.policy import SecurityPolicy
from agentos.flows.proxy import MockTransport
from agentos.flows.worker import FlowWorker
from agentos.queue.in_process import InProcessQueueBackend
from agentos.storage import open_storage
from agentos.storage.models import FlowRecord
from agentos.storage.ports import FencingTokenError


def _make_notification_flow(flow_id: str = "flow_dispatch") -> FlowRecord:
    return FlowRecord(
        id=flow_id,
        name="External Notification Flow",
        entrypoint="trigger",
        nodes={
            "trigger": {
                "id": "trigger",
                "type": "webhook_trigger",
                "config": {"path": "/alert"},
            },
            "sink": {
                "id": "sink",
                "type": "send_email",
                "config": {},
                "pinned_args": {"to": "ops@internal.local"},
            },
        },
        edges=[
            {"source": "trigger", "target": "sink", "arg_mapping": {"body": "payload"}},
        ],
    )


async def _run_benign_async() -> bool:
    print("\n[1/3] Testing Benign Leased Execution & Exactly-Once Delivery...")
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        storage = await open_storage(tmpdir, backend="file", vault_path=str(Path(tmpdir) / "vault.json"))
        queue = InProcessQueueBackend(storage=storage)
        storage.events._fencing_checker = queue.validate_lease

        policy = SecurityPolicy(
            internal_domains={"internal.local", "corp.local"},
        )
        transport = MockTransport()

        flow_rec = _make_notification_flow("flow_benign_1")
        await storage.flows.put_draft(flow_rec)
        pub = await storage.flows.publish("flow_benign_1", content_sha256="sha_abc", policy_hash="pol_xyz")
        print(f"  Flow published: version {pub.version} (id={pub.id})")

        run_id = f"run_benign_{uuid.uuid4().hex[:8]}"
        job = await queue.enqueue(
            run_id=run_id,
            flow_id="flow_benign_1",
            version=pub.version,
            inputs={"payload": "System alert: CPU threshold exceeded"},
        )
        print(f"  Enqueued job {job.job_id} for run {run_id}")

        worker = FlowWorker(
            queue=queue,
            storage=storage,
            policy=policy,
            transport_registry={"send_email": transport},
            lease_timeout_s=10.0,
        )

        processed = await worker.run_once()
        assert processed == run_id

        # Verify job completed and exactly 1 send
        job_state = await queue.get_job_by_run_id(run_id)
        assert job_state is not None and job_state.status == "completed"
        assert len(transport.sent_calls) == 1
        assert transport.sent_calls[0]["to"] == "ops@internal.local"
        print("  Worker successfully completed job; exactly 1 send verified.")

        await storage.close()
        return True


async def _run_failover_async() -> bool:
    print("\n[2/3] Testing Worker Failover & Fencing Token Safety...")
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        storage = await open_storage(tmpdir, backend="file", vault_path=str(Path(tmpdir) / "vault.json"))
        queue = InProcessQueueBackend(storage=storage)
        storage.events._fencing_checker = queue.validate_lease

        policy = SecurityPolicy(
            internal_domains={"internal.local"},
        )
        transport = MockTransport()

        flow_rec = _make_notification_flow("flow_fence_1")
        await storage.flows.put_draft(flow_rec)
        pub = await storage.flows.publish("flow_fence_1", "sha_1", "pol_1")

        run_id = f"run_fence_{uuid.uuid4().hex[:8]}"
        await queue.enqueue(
            run_id=run_id,
            flow_id="flow_fence_1",
            version=pub.version,
            inputs={"payload": "Urgent alert"},
        )

        # Worker 1 leases with very short timeout
        job_w1 = await queue.lease(worker_id="worker_1", lease_timeout_s=0.1)
        assert job_w1 is not None
        w1_lease = job_w1.lease_id

        # Worker 1 pauses; lease expires
        await asyncio.sleep(0.15)
        print("  Worker 1 lease expired without heartbeat renewal.")

        # Worker 2 takes over and executes to completion
        worker_2 = FlowWorker(
            queue=queue,
            storage=storage,
            worker_id="worker_2",
            policy=policy,
            transport_registry={"send_email": transport},
            lease_timeout_s=10.0,
        )
        processed_w2 = await worker_2.run_once()
        assert processed_w2 == run_id
        assert len(transport.sent_calls) == 1
        print("  Worker 2 leased job and dispatched notification (1 send).")

        # Worker 1 wakes up and attempts a write or complete -> FencingTokenError
        fencing_rejected = False
        try:
            flow_def = FlowDefinition(
                id=pub.id,
                name=pub.name,
                entrypoint=pub.entrypoint,
                nodes=pub.nodes,
                edges=pub.edges,
            )
            engine_w1 = FlowEngine(
                flow=flow_def,
                storage=storage,
                policy=policy,
                transport_registry={"send_email": transport},
                lease_id=w1_lease,
                fencing_checker=queue.validate_lease,
            )
            await engine_w1._append_event(run_id, "sink_intent", {"stale": True})
        except FencingTokenError:
            fencing_rejected = True

        assert fencing_rejected is True
        assert len(transport.sent_calls) == 1
        print("  Worker 1 stale append rejected with FencingTokenError; 0 duplicate sends.")

        await storage.close()
        return True


async def _run_dead_letter_async() -> bool:
    print("\n[3/3] Testing Poison-Pill Bounded Retries & Dead-Letter Isolation...")
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        storage = await open_storage(tmpdir, backend="file", vault_path=str(Path(tmpdir) / "vault.json"))
        queue = InProcessQueueBackend(storage=storage)

        run_id = f"run_poison_{uuid.uuid4().hex[:8]}"
        from agentos.storage.models import RunRecord
        await storage.runs.put(RunRecord(
            run_id=run_id,
            mission_name="flow_crash",
            flow_id="flow_crash",
            flow_version=1,
            status="running",
        ))

        job = await queue.enqueue(
            run_id=run_id,
            flow_id="flow_crash",
            version=1,
            inputs={"poison": True},
            max_attempts=3,
        )
        print(f"  Enqueued job with max_attempts={job.max_attempts}")

        # Simulate 3 worker crashes
        for attempt in range(1, 4):
            leased = await queue.lease(worker_id=f"worker_crash_{attempt}", lease_timeout_s=0.1)
            assert leased is not None
            assert leased.attempts == attempt
            print(f"  Attempt {attempt}: Worker leased job and crashed (lease expired).")
            await asyncio.sleep(0.15)

        # 4th lease attempt moves job to dead_letter
        next_lease = await queue.lease(worker_id="worker_healthy", lease_timeout_s=5.0)
        assert next_lease is None
        print("  Queue halted retry cycle; no further workers leased the failing job.")

        dead_job = await queue.get_job_by_run_id(run_id)
        assert dead_job is not None
        assert dead_job.status == "dead_letter"
        assert dead_job.last_error == "max_attempts_exceeded"

        run_rec = await storage.runs.get(run_id)
        assert run_rec is not None and run_rec.status == "failed"
        assert run_rec.error == "max_attempts_exceeded"
        print("  Run status in storage transitioned to failed (reason: max_attempts_exceeded).")

        await storage.close()
        return True


def run_benign() -> bool:
    return asyncio.run(_run_benign_async())


def run_failover() -> bool:
    return asyncio.run(_run_failover_async())


def run_dead_letter() -> bool:
    return asyncio.run(_run_dead_letter_async())


def main():
    parser = argparse.ArgumentParser(description="Use Case 03: Flow Queue, Leasing & Fencing Safety")
    parser.add_argument("--mode", choices=["all", "benign", "failover", "dead_letter"], default="all")
    args = parser.parse_args()

    print("============================================================")
    print("=== Use Case 03: Flow Queue, Leasing & Fencing Safety ===")
    print("============================================================")

    success = True
    if args.mode in ("all", "benign"):
        success = success and run_benign()
    if args.mode in ("all", "failover"):
        success = success and run_failover()
    if args.mode in ("all", "dead_letter"):
        success = success and run_dead_letter()

    if success:
        print("\n============================================================")
        print("Use Case 03 PASSED in all execution modes.")
        print("============================================================")
        sys.exit(0)
    else:
        print("\nUse Case 03 FAILED.")
        sys.exit(1)


if __name__ == "__main__":
    main()
