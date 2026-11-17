"""
Cron trigger scheduler and leader-lock infrastructure for AgentOS.

Supports:
- InProcessLeaderLock (Standalone mode).
- MongoLeaderLock (Platform mode) using Mongo server time ($$NOW) as a single shared clock.
- FlowScheduler: evaluates 5-field cron schedules with timezone and DST support via croniter,
  misfire policies ("skip" vs "fire_once"), and storage-level idempotency key enforcement.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
import time
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable
import uuid
import zoneinfo

try:
    from croniter import croniter
except ImportError:
    croniter = None  # type: ignore

CRONITER_MISSING_MSG = (
    "Cron schedules are configured but the 'croniter' package is not installed. "
    "Install it (pip install croniter==6.0.0; it is a core AgentOS dependency) or delete the schedules."
)


class CroniterMissingError(RuntimeError):
    """Schedules exist but croniter is unavailable: the scheduler cannot run them."""

from agentos.queue.ports import QueueBackend
from agentos.storage.models import RunRecord, ScheduleRecord
from agentos.storage.ports import DuplicateIdempotencyKeyError, Storage

logger = logging.getLogger(__name__)


@runtime_checkable
class LeaderLock(Protocol):
    """Protocol for distributed leader election."""

    async def acquire_or_renew(self, lease_timeout_s: float = 15.0) -> bool:
        """Returns True if this instance is the active leader, False otherwise."""
        ...

    async def release(self) -> None:
        """Release leadership."""
        ...


class InProcessLeaderLock(LeaderLock):
    """Single-process leader lock for Standalone mode."""

    def __init__(self, leader_id: Optional[str] = None) -> None:
        self.leader_id = leader_id or f"standalone_{uuid.uuid4().hex[:8]}"
        self._is_leader = True

    async def acquire_or_renew(self, lease_timeout_s: float = 15.0) -> bool:
        return self._is_leader

    async def release(self) -> None:
        self._is_leader = False


class MongoLeaderLock(LeaderLock):
    """
    Distributed leader lock for Platform mode using MongoDB.

    Clock Semantics:
        Uses a single shared clock: Mongo server time ($$NOW) is used for expiry
        calculation in pipeline updates, eliminating issues with clock skew across servers.
    """

    def __init__(
        self,
        collection: Any,
        lock_name: str = "cron_scheduler_leader",
        leader_id: Optional[str] = None,
    ) -> None:
        self._c = collection
        self.lock_name = lock_name
        self.leader_id = leader_id or f"server_{uuid.uuid4().hex}"
        self._has_leadership = False

    async def acquire_or_renew(self, lease_timeout_s: float = 15.0) -> bool:
        """
        Attempt to claim or renew leadership using Mongo server time ($$NOW).
        """
        lease_ms = int(lease_timeout_s * 1000)
        try:
            # Query current server time to check expiration safely
            # Pipeline update sets expires_at to $$NOW + lease_ms
            doc = await self._c.find_one_and_update(
                {
                    "_id": self.lock_name,
                    "$or": [
                        {"leader_id": self.leader_id},
                        {"expires_at": {"$lt": datetime.now(timezone.utc)}},
                        {"leader_id": None},
                    ],
                },
                [
                    {
                        "$set": {
                            "leader_id": self.leader_id,
                            "expires_at": {"$add": ["$$NOW", lease_ms]},
                            "updated_at": "$$NOW",
                        }
                    }
                ],
                upsert=True,
                return_document=True,
            )
            self._has_leadership = doc is not None and doc.get("leader_id") == self.leader_id
            return self._has_leadership
        except Exception as e:
            logger.warning(f"MongoLeaderLock election check failed: {e}")
            self._has_leadership = False
            return False

    async def release(self) -> None:
        if not self._has_leadership:
            return
        try:
            await self._c.update_one(
                {"_id": self.lock_name, "leader_id": self.leader_id},
                {"$set": {"leader_id": None, "expires_at": datetime.fromtimestamp(0, tz=timezone.utc)}},
            )
        except Exception:
            pass
        finally:
            self._has_leadership = False


class FlowScheduler:
    """
    Persistent cron scheduler with leader election and misfire policy handling.
    """

    def __init__(
        self,
        storage: Storage,
        queue: QueueBackend,
        leader_lock: Optional[LeaderLock] = None,
        poll_interval_s: float = 1.0,
    ) -> None:
        self.storage = storage
        self.queue = queue
        self.leader_lock = leader_lock or InProcessLeaderLock()
        self.poll_interval_s = poll_interval_s
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def resume_due_timers(self, now_override: Optional[float] = None) -> List[str]:
        """Re-enqueue runs waiting on a wait-node timer whose resume_at has passed."""
        now_ts = now_override if now_override is not None else time.time()
        resumed: List[str] = []
        for rec in await self.storage.runs.list(limit=1000):
            if rec.status != "waiting" or rec.resume_at is None or rec.resume_at > now_ts:
                continue
            if rec.flow_id is None or rec.flow_version is None:
                continue
            rec.resume_at = None  # cleared first so a due timer is enqueued once
            await self.storage.runs.put(rec)
            await self.queue.reenqueue(run_id=rec.run_id, flow_id=rec.flow_id, version=rec.flow_version, inputs={})
            resumed.append(rec.run_id)
            logger.info("Wait timer due for run %s; re-enqueued", rec.run_id)
        return resumed

    async def ensure_cron_support(self) -> None:
        """Raise CroniterMissingError if schedules exist but croniter is not installed.

        Called at server startup so a missing dependency stops the server with a clear error
        instead of every schedule being skipped silently.
        """
        if croniter is not None or not self.storage.schedules:
            return
        if await self.storage.schedules.list():
            raise CroniterMissingError(CRONITER_MISSING_MSG)

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._run_loop())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        await self.leader_lock.release()

    async def _run_loop(self) -> None:
        while self._running:
            try:
                is_leader = await self.leader_lock.acquire_or_renew(lease_timeout_s=15.0)
                if is_leader:
                    await self.tick()
            except Exception as e:
                logger.error(f"Error in FlowScheduler tick: {e}", exc_info=True)
            await asyncio.sleep(self.poll_interval_s)

    async def tick(self, now_override: Optional[float] = None) -> List[str]:
        """
        Evaluate enabled schedules against current time.
        Returns list of enqueued run_ids.
        """
        # 2.3: re-enqueue runs whose wait-node timer is due (the worker resumes them)
        await self.resume_due_timers(now_override)
        if not self.storage.schedules or not self.storage.flows:
            return []
        if croniter is None:
            # Fail loudly: silently skipping would leave every schedule unexecuted.
            raise CroniterMissingError(CRONITER_MISSING_MSG)

        now_ts = now_override if now_override is not None else time.time()
        schedules = await self.storage.schedules.list()
        enqueued_runs: List[str] = []

        for sched in schedules:
            if not sched.enabled:
                continue

            tz_str = sched.timezone or "UTC"
            try:
                tz = zoneinfo.ZoneInfo(tz_str)
            except Exception:
                tz = timezone.utc

            now_dt = datetime.fromtimestamp(now_ts, tz=tz)

            # Determine baseline time for cron evaluation
            if sched.last_run_at is None:
                # First run initialization: set next_run_at and skip past ticks
                itr = croniter(sched.cron_expression, now_dt)
                sched.next_run_at = itr.get_next(float)
                sched.last_run_at = now_ts
                await self.storage.schedules.put(sched)
                continue

            last_dt = datetime.fromtimestamp(sched.last_run_at, tz=tz)

            # Evaluate next tick from last_dt
            itr = croniter(sched.cron_expression, last_dt)
            next_tick = itr.get_next(float)

            if next_tick <= now_ts:
                # Schedule tick has arrived or was missed
                should_fire = True
                tick_to_fire = next_tick

                # Handle misfire policy if multiple ticks passed
                # Compute how many ticks occurred between last_run_at and now_ts
                missed_ticks = []
                temp_itr = croniter(sched.cron_expression, last_dt)
                while True:
                    t = temp_itr.get_next(float)
                    if t <= now_ts:
                        missed_ticks.append(t)
                    else:
                        break

                if len(missed_ticks) > 1:
                    if sched.misfire_policy == "skip":
                        # Skip older ticks, only fire the most recent one
                        tick_to_fire = missed_ticks[-1]
                    elif sched.misfire_policy == "fire_once":
                        # Fire once for the missed window
                        tick_to_fire = missed_ticks[-1]

                # Idempotency key per tick: schedule_id + integer tick timestamp
                idempotency_key = f"cron:{sched.schedule_id}:{int(tick_to_fire)}"
                run_id = f"run_{uuid.uuid4().hex}"

                # Look up latest published flow version
                flow_rec = await self.storage.flows.get_draft(sched.flow_id)
                versions = await self.storage.flows.list_versions(sched.flow_id)
                if not versions:
                    logger.warning("Schedule %s references flow %s with no published versions", sched.schedule_id, sched.flow_id)
                    sched.last_run_at = now_ts
                    await self.storage.schedules.put(sched)
                    continue

                latest_version = max(v.version for v in versions)

                # Persist RunRecord with idempotency_key first to enforce storage uniqueness
                run_record = RunRecord(
                    run_id=run_id,
                    mission_name=f"Cron {sched.name}",
                    flow_id=sched.flow_id,
                    flow_version=latest_version,
                    status="queued",
                    inputs=sched.inputs,
                    idempotency_key=idempotency_key,
                )

                try:
                    await self.storage.runs.put(run_record)
                except DuplicateIdempotencyKeyError:
                    # Another scheduler or replica already fired this tick
                    logger.info("Tick %s already fired (idempotency key %s exists)", tick_to_fire, idempotency_key)
                    sched.last_run_at = tick_to_fire
                    itr_next = croniter(sched.cron_expression, datetime.fromtimestamp(tick_to_fire, tz=tz))
                    sched.next_run_at = itr_next.get_next(float)
                    await self.storage.schedules.put(sched)
                    continue

                # Append run_started event
                await self.storage.events.append(
                    run_id=run_id,
                    type="run_started",
                    data={
                        "inputs": sched.inputs,
                        "flow_id": sched.flow_id,
                        "version": latest_version,
                        "trigger": "cron",
                        "schedule_id": sched.schedule_id,
                        "tick": tick_to_fire,
                    },
                    lease_id=None,
                )

                # Enqueue to queue backend
                await self.queue.enqueue(
                    run_id=run_id,
                    flow_id=sched.flow_id,
                    version=latest_version,
                    inputs=sched.inputs,
                )
                enqueued_runs.append(run_id)

                # Update schedule metadata
                sched.last_run_at = tick_to_fire
                itr_next = croniter(sched.cron_expression, datetime.fromtimestamp(tick_to_fire, tz=tz))
                sched.next_run_at = itr_next.get_next(float)
                await self.storage.schedules.put(sched)

        return enqueued_runs
