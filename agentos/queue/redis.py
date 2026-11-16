"""
Redis-backed QueueBackend for AgentOS Platform mode.

Provides:
- Distributed execution queue with atomic leasing via Lua scripts.
- Single shared clock: deadlines evaluated using Redis server time (redis.time()),
  eliminating clock skew issues between worker and server machines.
- Heartbeat renewal (renew_lease), universal fencing across all states,
  and dead_letter transitions with bounded attempts.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional
import uuid

try:
    import redis.asyncio as redis
except ImportError:
    redis = None  # type: ignore

from agentos.queue.ports import QueueBackend, QueueJob
from agentos.storage.ports import FencingTokenError, Storage

logger = logging.getLogger(__name__)

# Lua script to lease next available job atomically
# Keys: [pending_list_key]
# Args: [worker_id, lease_timeout_s, current_redis_time]
LUA_LEASE = """
local pending_key = KEYS[1]
local worker_id = ARGV[1]
local lease_timeout = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

-- 1. Try to get a job from pending list
local job_id = redis.call("LPOP", pending_key)
local job_key = nil
local job_raw = nil

if job_id then
    job_key = "agentos:job:" .. job_id
    job_raw = redis.call("GET", job_key)
end

-- 2. If no pending, scan leased jobs for expired leases
if not job_raw then
    local leased_jobs = redis.call("SMEMBERS", "agentos:jobs:leased")
    for _, jid in ipairs(leased_jobs) do
        local jk = "agentos:job:" .. jid
        local jdata = redis.call("GET", jk)
        if jdata then
            local job = cjson.decode(jdata)
            if job["status"] == "leased" and job["leased_until"] and tonumber(job["leased_until"]) < now then
                -- Expired lease candidate
                job_id = jid
                job_key = jk
                job_raw = jdata
                break
            end
        end
    end
end

if not job_raw then
    return nil
end

local job = cjson.decode(job_raw)

-- Check max attempts
if job["status"] == "leased" and tonumber(job["leased_until"]) < now then
    if job["attempts"] >= job["max_attempts"] then
        job["status"] = "dead_letter"
        job["lease_id"] = nil
        job["leased_until"] = nil
        if not job["last_error"] or job["last_error"] == cjson.null or job["last_error"] == "" then
            job["last_error"] = "max_attempts_exceeded"
        end
        redis.call("SET", job_key, cjson.encode(job))
        redis.call("SREM", "agentos:jobs:leased", job_id)
        redis.call("SADD", "agentos:jobs:dead_letter", job_id)
        return "DEAD_LETTER:" .. cjson.encode(job)
    end
end

-- Claim lease
local new_lease_id = ARGV[4]
job["attempts"] = job["attempts"] + 1
job["status"] = "leased"
job["worker_id"] = worker_id
job["lease_id"] = new_lease_id
job["leased_until"] = now + lease_timeout

redis.call("SET", job_key, cjson.encode(job))
redis.call("SADD", "agentos:jobs:leased", job_id)
return cjson.encode(job)
"""

LUA_RENEW = """
local job_key = "agentos:job:" .. KEYS[1]
local lease_id = ARGV[1]
local lease_timeout = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

local job_raw = redis.call("GET", job_key)
if not job_raw then
    return 0
end

local job = cjson.decode(job_raw)
if job["status"] ~= "leased" or job["lease_id"] ~= lease_id then
    return 0
end

if job["leased_until"] and tonumber(job["leased_until"]) < now then
    return 0
end

job["leased_until"] = now + lease_timeout
redis.call("SET", job_key, cjson.encode(job))
return 1
"""

LUA_COMPLETE = """
local job_key = "agentos:job:" .. KEYS[1]
local lease_id = ARGV[1]

local job_raw = redis.call("GET", job_key)
if not job_raw then
    return "NOT_FOUND"
end

local job = cjson.decode(job_raw)
if job["status"] == "completed" and job["lease_id"] == lease_id then
    return "OK"
end

if not job["lease_id"] or job["lease_id"] ~= lease_id then
    return "FENCING_ERROR:" .. tostring(job["lease_id"]) .. ":" .. tostring(job["status"])
end

job["status"] = "completed"
job["lease_id"] = nil
job["leased_until"] = nil
redis.call("SET", job_key, cjson.encode(job))
redis.call("SREM", "agentos:jobs:leased", KEYS[1])
return "OK"
"""

LUA_FAIL = """
local job_key = "agentos:job:" .. KEYS[1]
local lease_id = ARGV[1]
local error_msg = ARGV[2]

local job_raw = redis.call("GET", job_key)
if not job_raw then
    return "NOT_FOUND"
end

local job = cjson.decode(job_raw)
if (job["status"] == "failed" or job["status"] == "dead_letter") and job["lease_id"] == lease_id then
    return "OK"
end

if not job["lease_id"] or job["lease_id"] ~= lease_id then
    return "FENCING_ERROR:" .. tostring(job["lease_id"]) .. ":" .. tostring(job["status"])
end

job["last_error"] = error_msg
redis.call("SREM", "agentos:jobs:leased", KEYS[1])

if job["attempts"] >= job["max_attempts"] then
    job["status"] = "dead_letter"
    job["lease_id"] = nil
    job["leased_until"] = nil
    redis.call("SET", job_key, cjson.encode(job))
    redis.call("SADD", "agentos:jobs:dead_letter", KEYS[1])
    return "DEAD_LETTER:" .. cjson.encode(job)
else
    job["status"] = "failed"
    job["lease_id"] = nil
    job["leased_until"] = nil
    redis.call("SET", job_key, cjson.encode(job))
    return "OK"
end
"""

LUA_RELEASE_WAITING = """
local job_key = "agentos:job:" .. KEYS[1]
local lease_id = ARGV[1]

local job_raw = redis.call("GET", job_key)
if not job_raw then
    return "NOT_FOUND"
end

local job = cjson.decode(job_raw)
if job["lease_id"] ~= lease_id then
    return "FENCING_ERROR:" .. tostring(job["lease_id"]) .. ":" .. tostring(job["status"])
end

job["status"] = "waiting"
job["lease_id"] = nil
job["leased_until"] = nil
redis.call("SET", job_key, cjson.encode(job))
redis.call("SREM", "agentos:jobs:leased", KEYS[1])
return "OK"
"""


class RedisQueueBackend(QueueBackend):
    """
    Production QueueBackend backed by Redis for multi-worker Platform deployments.

    Clock Semantics:
        Uses a single shared clock: all deadlines and expirations are calculated
        against Redis server time (via redis.time()), preventing clock drift issues.
    """

    def __init__(
        self,
        redis_client: Any,
        default_max_attempts: int = 3,
        storage: Optional[Storage] = None,
    ) -> None:
        if redis is None:
            raise ImportError(
                "Redis client is not installed. Install the platform extra: pip install 'agentos[platform]'"
            )
        self._redis = redis_client
        self.default_max_attempts = default_max_attempts
        self._storage = storage
        # Local synchronous lease cache for fencing validation
        self._local_lease_cache: Dict[str, Dict[str, Any]] = {}

    def set_storage(self, storage: Storage) -> None:
        self._storage = storage

    async def _get_server_time(self) -> float:
        """Query Redis server time (seconds + microseconds)."""
        sec, micro = await self._redis.time()
        return float(sec) + float(micro) / 1_000_000.0

    async def _mark_run_dead_letter(self, job: QueueJob) -> None:
        if self._storage and self._storage.runs:
            try:
                run_rec = await self._storage.runs.get(job.run_id)
                if run_rec:
                    run_rec.status = "failed"
                    run_rec.error = "max_attempts_exceeded"
                    await self._storage.runs.put(run_rec)
            except Exception:
                pass
        if self._storage and self._storage.events:
            try:
                await self._storage.events.append(
                    run_id=job.run_id,
                    type="run_failed",
                    data={"reason": "max_attempts_exceeded", "last_error": job.last_error},
                    lease_id=None,
                )
            except Exception:
                pass

    async def enqueue(
        self,
        run_id: str,
        flow_id: str,
        version: int,
        inputs: Optional[Dict[str, Any]] = None,
        max_attempts: Optional[int] = None,
    ) -> QueueJob:
        job_id = f"job_{uuid.uuid4().hex[:12]}"
        now = await self._get_server_time()
        job = QueueJob(
            job_id=job_id,
            run_id=run_id,
            flow_id=flow_id,
            version=version,
            inputs=inputs or {},
            status="queued",
            max_attempts=max_attempts if max_attempts is not None else self.default_max_attempts,
            created_at=now,
        )
        job_key = f"agentos:job:{job_id}"
        await self._redis.set(job_key, job.model_dump_json())
        await self._redis.set(f"agentos:run_to_job:{run_id}", job_id)
        await self._redis.rpush("agentos:queue:pending", job_id)

        self._local_lease_cache[run_id] = {
            "job_id": job_id,
            "status": "queued",
            "lease_id": None,
            "leased_until": None,
        }
        return job.model_copy()

    async def lease(
        self,
        worker_id: str,
        lease_timeout_s: float = 30.0,
    ) -> Optional[QueueJob]:
        now = await self._get_server_time()
        new_lease_id = uuid.uuid4().hex

        res = await self._redis.eval(
            LUA_LEASE,
            1,
            "agentos:queue:pending",
            worker_id,
            str(lease_timeout_s),
            str(now),
            new_lease_id,
        )
        if not res:
            return None

        if isinstance(res, (bytes, str)):
            res_str = res.decode("utf-8") if isinstance(res, bytes) else res
            if res_str.startswith("DEAD_LETTER:"):
                raw_job = res_str.split("DEAD_LETTER:", 1)[1]
                job = QueueJob.model_validate_json(raw_job)
                await self._mark_run_dead_letter(job)
                return await self.lease(worker_id, lease_timeout_s)

            job = QueueJob.model_validate_json(res_str)
            self._local_lease_cache[job.run_id] = {
                "job_id": job.job_id,
                "status": "leased",
                "lease_id": job.lease_id,
                "leased_until": job.leased_until,
            }
            return job

        return None

    async def renew_lease(
        self,
        job_id: str,
        lease_id: str,
        lease_timeout_s: float = 30.0,
    ) -> bool:
        now = await self._get_server_time()
        res = await self._redis.eval(
            LUA_RENEW,
            1,
            job_id,
            lease_id,
            str(lease_timeout_s),
            str(now),
        )
        success = bool(res == 1)
        if success:
            for r_id, cache in self._local_lease_cache.items():
                if cache.get("job_id") == job_id:
                    cache["leased_until"] = now + lease_timeout_s
                    break
        return success

    async def complete(self, job_id: str, lease_id: Optional[str] = None) -> None:
        res = await self._redis.eval(
            LUA_COMPLETE,
            1,
            job_id,
            str(lease_id or ""),
        )
        res_str = res.decode("utf-8") if isinstance(res, bytes) else str(res)
        if res_str == "NOT_FOUND":
            raise ValueError(f"Job {job_id!r} not found")
        if res_str.startswith("FENCING_ERROR:"):
            parts = res_str.split(":")
            active_lease = parts[1] if len(parts) > 1 else ""
            status = parts[2] if len(parts) > 2 else ""
            raise FencingTokenError(
                f"Job {job_id} lease {lease_id!r} does not match active lease {active_lease!r} (status={status})"
            )
        for r_id, cache in self._local_lease_cache.items():
            if cache.get("job_id") == job_id:
                cache["status"] = "completed"
                cache["lease_id"] = None
                break

    async def fail(self, job_id: str, lease_id: Optional[str] = None, error: str = "") -> None:
        res = await self._redis.eval(
            LUA_FAIL,
            1,
            job_id,
            str(lease_id or ""),
            error,
        )
        res_str = res.decode("utf-8") if isinstance(res, bytes) else str(res)
        if res_str == "NOT_FOUND":
            raise ValueError(f"Job {job_id!r} not found")
        if res_str.startswith("FENCING_ERROR:"):
            parts = res_str.split(":")
            active_lease = parts[1] if len(parts) > 1 else ""
            status = parts[2] if len(parts) > 2 else ""
            raise FencingTokenError(
                f"Job {job_id} lease {lease_id!r} does not match active lease {active_lease!r} (status={status})"
            )
        if res_str.startswith("DEAD_LETTER:"):
            raw_job = res_str.split("DEAD_LETTER:", 1)[1]
            job = QueueJob.model_validate_json(raw_job)
            await self._mark_run_dead_letter(job)
            for r_id, cache in self._local_lease_cache.items():
                if cache.get("job_id") == job_id:
                    cache["status"] = "dead_letter"
                    cache["lease_id"] = None
                    break
        else:
            for r_id, cache in self._local_lease_cache.items():
                if cache.get("job_id") == job_id:
                    cache["status"] = "failed"
                    cache["lease_id"] = None
                    break

    async def release_for_waiting(self, job_id: str, lease_id: str, reason: str) -> None:
        res = await self._redis.eval(
            LUA_RELEASE_WAITING,
            1,
            job_id,
            lease_id,
        )
        res_str = res.decode("utf-8") if isinstance(res, bytes) else str(res)
        if res_str == "NOT_FOUND":
            raise ValueError(f"Job {job_id!r} not found")
        if res_str.startswith("FENCING_ERROR:"):
            parts = res_str.split(":")
            active_lease = parts[1] if len(parts) > 1 else ""
            raise FencingTokenError(
                f"Job {job_id} lease {lease_id!r} does not match active lease {active_lease!r}"
            )
        for r_id, cache in self._local_lease_cache.items():
            if cache.get("job_id") == job_id:
                cache["status"] = "waiting"
                cache["lease_id"] = None
                break

    async def reenqueue(
        self,
        run_id: str,
        flow_id: str,
        version: int,
        inputs: Optional[Dict[str, Any]] = None,
    ) -> QueueJob:
        raw_jid = await self._redis.get(f"agentos:run_to_job:{run_id}")
        if raw_jid:
            jid = raw_jid.decode("utf-8") if isinstance(raw_jid, bytes) else str(raw_jid)
            raw_job = await self._redis.get(f"agentos:job:{jid}")
            if raw_job:
                job = QueueJob.model_validate_json(raw_job)
                job.status = "queued"
                job.lease_id = None
                job.leased_until = None
                if inputs is not None:
                    job.inputs = inputs
                await self._redis.set(f"agentos:job:{jid}", job.model_dump_json())
                await self._redis.rpush("agentos:queue:pending", jid)
                self._local_lease_cache[run_id] = {
                    "job_id": jid,
                    "status": "queued",
                    "lease_id": None,
                    "leased_until": None,
                }
                return job.model_copy()

        return await self.enqueue(run_id=run_id, flow_id=flow_id, version=version, inputs=inputs)

    async def get_job(self, job_id: str) -> Optional[QueueJob]:
        raw = await self._redis.get(f"agentos:job:{job_id}")
        return QueueJob.model_validate_json(raw) if raw else None

    async def get_job_by_run_id(self, run_id: str) -> Optional[QueueJob]:
        raw_jid = await self._redis.get(f"agentos:run_to_job:{run_id}")
        if not raw_jid:
            return None
        jid = raw_jid.decode("utf-8") if isinstance(raw_jid, bytes) else str(raw_jid)
        return await self.get_job(jid)

    def validate_lease(self, run_id: str, lease_id: Optional[str]) -> bool:
        """
        Synchronous check of whether lease_id is valid for run_id.
        Fencing token rule: if a job has an active lease, lease_id must match it
        and the lease must not be expired.
        When job is in waiting or queued state, operator/system writes with lease_id=None are permitted.
        If run has no queue job: returns True only if lease_id is None (unleased direct engine use);
        if lease_id is given, returns False (fail closed).
        """
        cache = self._local_lease_cache.get(run_id)
        if not cache:
            return lease_id is None

        status = cache.get("status")
        now = time.time()
        if status == "leased":
            if cache.get("lease_id") != lease_id:
                return False
            leased_until = cache.get("leased_until")
            if leased_until is not None and leased_until < now:
                return False
            return True
        elif status in ("waiting", "queued"):
            return lease_id is None
        return False
