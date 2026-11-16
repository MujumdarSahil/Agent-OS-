"""
Tests for Sub-milestone 2.2 Redis QueueBackend and Single Shared Clock Semantics.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any, Dict, Optional
import pytest
import pytest_asyncio

import redis.asyncio as aioredis

from agentos.queue.ports import QueueJob
from agentos.queue.redis import RedisQueueBackend
from agentos.storage.ports import FencingTokenError


async def get_test_redis_client():
    uri = os.environ.get("AGENTOS_REDIS_URI") or os.environ.get("AGENTOS_REDIS_URL")
    if not uri:
        if os.environ.get("AGENTOS_REQUIRE_LIVE_REDIS") == "1":
            pytest.fail("AGENTOS_REQUIRE_LIVE_REDIS=1 but AGENTOS_REDIS_URI is not set")
        pytest.skip("Skipping Redis LIVE tests: AGENTOS_REDIS_URI not set (use docker compose -f docker/compose.redis.yml up -d)")

    client = aioredis.from_url(uri)
    try:
        await client.ping()
        # Flush DB 15 for isolated test runs
        await client.flushdb()
    except Exception as e:
        if os.environ.get("AGENTOS_REQUIRE_LIVE_REDIS") == "1":
            pytest.fail(f"AGENTOS_REQUIRE_LIVE_REDIS=1 but Redis is unreachable at {uri}: {e}")
        pytest.skip(f"Redis unreachable at {uri}: {e}")
    return client


@pytest_asyncio.fixture(params=["mock", "live"])
async def redis_queue(request):
    mode = request.param
    if mode == "mock":
        try:
            import fakeredis.aioredis
            client = fakeredis.aioredis.FakeRedis()
        except ImportError:
            pytest.skip("fakeredis not installed")
    else:
        client = await get_test_redis_client()

    queue = RedisQueueBackend(client, default_max_attempts=3)
    yield queue
    try:
        await client.flushdb()
        await client.aclose()
    except Exception:
        pass


@pytest.mark.asyncio
async def test_redis_queue_leasing_and_heartbeat(redis_queue):
    """RedisQueueBackend supports leasing, expiration detection, and heartbeat renewal."""
    queue = redis_queue
    job = await queue.enqueue(run_id="run_redis_101", flow_id="flow_1", version=1, inputs={"msg": "hello"})
    assert job.status == "queued"

    # Worker 1 leases the job with short timeout (0.3s)
    leased_job = await queue.lease(worker_id="worker_1", lease_timeout_s=0.3)
    assert leased_job is not None
    assert leased_job.worker_id == "worker_1"
    lease_1 = leased_job.lease_id
    assert lease_1 is not None

    # Fencing check should pass for worker 1
    assert queue.validate_lease("run_redis_101", lease_1) is True
    assert queue.validate_lease("run_redis_101", "bad_lease") is False

    # Renew lease
    renewed = await queue.renew_lease(leased_job.job_id, lease_1, lease_timeout_s=0.5)
    assert renewed is True

    # Sleep past expiration without renewal
    await asyncio.sleep(0.6)
    assert queue.validate_lease("run_redis_101", lease_1) is False

    # Worker 2 can now lease the expired job
    leased_by_w2 = await queue.lease(worker_id="worker_2", lease_timeout_s=1.0)
    assert leased_by_w2 is not None
    assert leased_by_w2.worker_id == "worker_2"
    assert leased_by_w2.lease_id != lease_1
    assert queue.validate_lease("run_redis_101", leased_by_w2.lease_id) is True


@pytest.mark.asyncio
async def test_redis_universal_fencing_complete_fail_waiting(redis_queue):
    """
    complete(), fail(), and release_for_waiting() must check lease in every state.
    Caller with invalid lease gets FencingTokenError.
    """
    queue = redis_queue
    job = await queue.enqueue(run_id="run_redis_fence", flow_id="flow_f", version=1)

    # Worker 1 leases
    w1_job = await queue.lease(worker_id="w1", lease_timeout_s=0.2)
    assert w1_job is not None
    w1_lease = w1_job.lease_id

    # Lease expires
    await asyncio.sleep(0.3)

    # Worker 2 takes over and parks job for approval (waiting state)
    w2_job = await queue.lease(worker_id="w2", lease_timeout_s=10.0)
    assert w2_job is not None
    w2_lease = w2_job.lease_id
    await queue.release_for_waiting(w2_job.job_id, w2_lease, reason="approval_required")

    # Worker 1 attempts fail() and complete() -> both rejected with FencingTokenError!
    with pytest.raises(FencingTokenError):
        await queue.fail(w1_job.job_id, lease_id=w1_lease, error="late worker 1 error")

    with pytest.raises(FencingTokenError):
        await queue.complete(w1_job.job_id, lease_id=w1_lease)

    # Job remains in waiting state
    current_job = await queue.get_job(w1_job.job_id)
    assert current_job.status == "waiting"


@pytest.mark.asyncio
async def test_redis_validate_lease_fail_closed(redis_queue):
    """
    validate_lease for a run with no queue job -> False when lease_id is given (fail closed).
    Direct engine use in tests/CLI must use lease_id=None explicitly.
    """
    queue = redis_queue
    # Non-existent run
    assert queue.validate_lease("run_non_existent", lease_id="any_lease") is False
    assert queue.validate_lease("run_non_existent", lease_id=None) is True


@pytest.mark.asyncio
async def test_redis_worker_crash_and_dead_letter_max_attempts(redis_queue):
    """
    QueueJob.attempts increments on every lease; after max_attempts (default 3),
    the job moves to 'dead_letter' with last_error, and run is marked failed with reason 'max_attempts_exceeded'.
    """
    queue = redis_queue
    job = await queue.enqueue(run_id="run_redis_dead", flow_id="flow_d", version=1, max_attempts=3)

    # Attempt 1: Worker leases and crashes (lease expires)
    j1 = await queue.lease(worker_id="w1", lease_timeout_s=0.2)
    assert j1 is not None and j1.attempts == 1
    await asyncio.sleep(0.3)

    # Attempt 2: Worker leases and crashes
    j2 = await queue.lease(worker_id="w2", lease_timeout_s=0.2)
    assert j2 is not None and j2.attempts == 2
    await asyncio.sleep(0.3)

    # Attempt 3: Worker leases and crashes
    j3 = await queue.lease(worker_id="w3", lease_timeout_s=0.2)
    assert j3 is not None and j3.attempts == 3
    await asyncio.sleep(0.3)

    # Next lease attempt detects max_attempts reached -> moves to dead_letter!
    j4 = await queue.lease(worker_id="w4", lease_timeout_s=1.0)
    assert j4 is None  # No more runnable jobs

    final_job = await queue.get_job(job.job_id)
    assert final_job.status == "dead_letter"
    assert final_job.last_error == "max_attempts_exceeded"
