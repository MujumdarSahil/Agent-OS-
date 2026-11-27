"""
Tests for Sub-milestone 2.2 Cron Scheduler, DST Transitions, and Storage Idempotency.
"""

from __future__ import annotations

from datetime import datetime, timezone
import os
import tempfile
import time
import zoneinfo
import pytest
from starlette.testclient import TestClient

from agentos.queue.in_process import InProcessQueueBackend
from agentos.storage.file import open_file_storage
from agentos.storage.models import FlowRecord, ScheduleRecord
from agentos.triggers.scheduler import FlowScheduler, InProcessLeaderLock
from agentos_server.app import create_app


@pytest.fixture
def scheduler_env():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        storage = open_file_storage(tmp_dir)
        queue = InProcessQueueBackend(storage=storage)
        app = create_app(project_path=tmp_dir, storage=storage)
        client = TestClient(app, base_url="http://localhost")
        yield {
            "tmp_dir": tmp_dir,
            "storage": storage,
            "queue": queue,
            "app": app,
            "client": client,
        }


@pytest.mark.asyncio
async def test_cron_dst_transition():
    """
    Verify croniter timezone calculation across a Daylight Saving Time (DST) transition.
    In America/New_York, at 2026-03-08 02:00:00, clocks jump forward to 03:00:00.
    A daily schedule at 02:30 AM should advance cleanly to the next valid time.
    """
    tz = zoneinfo.ZoneInfo("America/New_York")
    from croniter import croniter

    # Day before DST spring-forward
    dt_before = datetime(2026, 3, 7, 2, 30, 0, tzinfo=tz)
    itr = croniter("30 2 * * *", dt_before)
    next_dt = itr.get_next(datetime)

    # In 2026-03-08, 02:30 does not exist (clocks jump from 02:00 to 03:00).
    # croniter resolves this to 03:30 or the next calendar day 2026-03-09 02:30.
    assert next_dt is not None
    assert next_dt.tzinfo == tz
    assert next_dt > dt_before

    # Fall-back transition (extra hour)
    dt_fall_before = datetime(2026, 10, 31, 1, 30, 0, tzinfo=tz)
    itr_fall = croniter("30 1 * * *", dt_fall_before)
    next_fall = itr_fall.get_next(datetime)
    assert next_fall.year == 2026 and next_fall.month == 11 and next_fall.day == 1


@pytest.mark.asyncio
async def test_two_schedulers_competing_same_tick_storage_idempotency(scheduler_env):
    """
    Requirement 3:
    Two schedulers that both believe they are leader for the same tick ->
    storage unique index / exclusive create on idempotency_key ensures exactly ONE run is created!
    """
    env = scheduler_env
    storage = env["storage"]
    queue = env["queue"]

    # 1. Publish test flow
    flow = FlowRecord(
        id="flow_sched_idem",
        name="Sched Flow",
        entrypoint="in",
        nodes={"in": {"id": "in", "type": "webhook_trigger", "config": {}}},
        edges=[],
    )
    await storage.flows.put_draft(flow)
    await storage.flows.publish("flow_sched_idem", "dummy_sha", "dummy_pol")

    # 2. Register schedule
    sched = ScheduleRecord(
        schedule_id="sched_dual",
        name="Dual Leader Test",
        flow_id="flow_sched_idem",
        cron_expression="* * * * *",
        timezone="UTC",
        inputs={"tick": "data"},
        last_run_at=1000.0,  # simulate baseline
        enabled=True,
    )
    await storage.schedules.put(sched)

    # 3. Create two independent FlowScheduler instances sharing the same storage and queue
    # Both use an InProcessLeaderLock that reports is_leader=True
    s1 = FlowScheduler(storage=storage, queue=queue, leader_lock=InProcessLeaderLock("leader_1"))
    s2 = FlowScheduler(storage=storage, queue=queue, leader_lock=InProcessLeaderLock("leader_2"))

    # Force both schedulers to evaluate the exact same tick timestamp (e.g. 1060.0)
    fixed_tick = 1060.0

    # Execute tick concurrently
    import asyncio
    results = await asyncio.gather(
        s1.tick(now_override=fixed_tick),
        s2.tick(now_override=fixed_tick),
    )

    all_enqueued = results[0] + results[1]
    # Exactly one run created across both schedulers!
    assert len(all_enqueued) == 1, f"Expected exactly 1 run, got {len(all_enqueued)}: {all_enqueued}"

    runs = await storage.runs.list(limit=10)
    sched_runs = [r for r in runs if r.flow_id == "flow_sched_idem"]
    assert len(sched_runs) == 1


@pytest.mark.asyncio
async def test_misfire_policies(scheduler_env):
    """
    Test misfire policies:
    - 'skip': skips past missed intervals during downtime, jumps to current tick.
    - 'fire_once': fires at most once for the missed downtime window.
    """
    env = scheduler_env
    storage = env["storage"]
    queue = env["queue"]

    flow = FlowRecord(
        id="flow_misfire",
        name="Misfire Flow",
        entrypoint="in",
        nodes={"in": {"id": "in", "type": "webhook_trigger", "config": {}}},
        edges=[],
    )
    await storage.flows.put_draft(flow)
    await storage.flows.publish("flow_misfire", "dummy_sha", "dummy_pol")

    # Baseline time: 1000s
    sched_skip = ScheduleRecord(
        schedule_id="sched_skip",
        name="Skip Policy",
        flow_id="flow_misfire",
        cron_expression="* * * * *",  # every 60s
        timezone="UTC",
        misfire_policy="skip",
        last_run_at=1000.0,
        enabled=True,
    )
    await storage.schedules.put(sched_skip)

    sched_fire_once = ScheduleRecord(
        schedule_id="sched_fire_once",
        name="Fire Once Policy",
        flow_id="flow_misfire",
        cron_expression="* * * * *",
        timezone="UTC",
        misfire_policy="fire_once",
        last_run_at=1000.0,
        enabled=True,
    )
    await storage.schedules.put(sched_fire_once)

    scheduler = FlowScheduler(storage=storage, queue=queue, leader_lock=InProcessLeaderLock())

    # Simulate server restarted after 10 minutes (600s) of downtime
    now_ts = 1600.0
    runs = await scheduler.tick(now_override=now_ts)

    # Both schedules fire at most once on restart
    assert len(runs) == 2

    # Check updated metadata
    s_skip = await storage.schedules.get("sched_skip")
    s_fo = await storage.schedules.get("sched_fire_once")
    assert s_skip.last_run_at >= 1560.0
    assert s_fo.last_run_at >= 1560.0


@pytest.mark.asyncio
async def test_schedules_crud_api(scheduler_env):
    """Test CRUD API for schedules under /api/v2/schedules."""
    env = scheduler_env
    client = env["client"]
    token = env["app"].state.api_token
    auth_headers = {"Authorization": f"Bearer {token}"}

    # Create draft flow
    flow = FlowRecord(
        id="flow_sched_api",
        name="Sched API Flow",
        entrypoint="in",
        nodes={"in": {"id": "in", "type": "webhook_trigger", "config": {}}},
        edges=[],
    )
    await env["storage"].flows.put_draft(flow)

    # 1. Create schedule
    resp = client.post(
        "/api/v2/schedules",
        json={
            "name": "Nightly Backup",
            "flow_id": "flow_sched_api",
            "cron_expression": "0 2 * * *",
            "timezone": "America/New_York",
            "inputs": {"type": "full"},
            "misfire_policy": "skip",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201, resp.text
    sched_id = resp.json()["schedule_id"]

    # 2. Reject invalid cron expression
    resp_invalid_cron = client.post(
        "/api/v2/schedules",
        json={
            "name": "Bad Cron",
            "flow_id": "flow_sched_api",
            "cron_expression": "not a cron",
        },
        headers=auth_headers,
    )
    assert resp_invalid_cron.status_code == 400

    # 3. Reject invalid timezone
    resp_invalid_tz = client.post(
        "/api/v2/schedules",
        json={
            "name": "Bad TZ",
            "flow_id": "flow_sched_api",
            "cron_expression": "* * * * *",
            "timezone": "NonExistent/Zone",
        },
        headers=auth_headers,
    )
    assert resp_invalid_tz.status_code == 400

    # 4. List schedules
    list_resp = client.get("/api/v2/schedules", headers=auth_headers)
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1

    # 5. Get single schedule
    get_resp = client.get(f"/api/v2/schedules/{sched_id}", headers=auth_headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["name"] == "Nightly Backup"

    # 6. Update schedule
    put_resp = client.put(
        f"/api/v2/schedules/{sched_id}",
        json={"name": "Nightly Backup Updated", "misfire_policy": "fire_once"},
        headers=auth_headers,
    )
    assert put_resp.status_code == 200
    assert put_resp.json()["name"] == "Nightly Backup Updated"
    assert put_resp.json()["misfire_policy"] == "fire_once"

    # 7. Delete schedule
    del_resp = client.delete(f"/api/v2/schedules/{sched_id}", headers=auth_headers)
    assert del_resp.status_code == 204
    assert client.get(f"/api/v2/schedules/{sched_id}", headers=auth_headers).status_code == 404
