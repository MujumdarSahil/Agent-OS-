"""In-process QueueBackend implementation for standalone execution."""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any, Dict, Optional

from agentos.queue.ports import QueueBackend, QueueJob
from agentos.storage.ports import FencingTokenError


class InProcessQueueBackend(QueueBackend):
    """
    Thread- and async-safe in-memory queue backend.
    Supports atomic leases, lease renewal (heartbeat), expiration detection,
    and fencing token validation.
    """

    def __init__(self) -> None:
        self._jobs: Dict[str, QueueJob] = {}  # job_id -> QueueJob
        self._run_to_job: Dict[str, str] = {}  # run_id -> job_id
        self._lock = asyncio.Lock()

    async def enqueue(
        self,
        run_id: str,
        flow_id: str,
        version: int,
        inputs: Optional[Dict[str, Any]] = None,
    ) -> QueueJob:
        async with self._lock:
            job_id = f"job_{uuid.uuid4().hex[:12]}"
            job = QueueJob(
                job_id=job_id,
                run_id=run_id,
                flow_id=flow_id,
                version=version,
                inputs=inputs or {},
                status="queued",
                created_at=time.time(),
            )
            self._jobs[job_id] = job
            self._run_to_job[run_id] = job_id
            return job

    async def lease(
        self,
        worker_id: str,
        lease_timeout_s: float = 30.0,
    ) -> Optional[QueueJob]:
        async with self._lock:
            now = time.time()
            candidate: Optional[QueueJob] = None

            # Look for queued jobs first, or jobs with an expired lease
            for job in self._jobs.values():
                if job.status == "queued":
                    candidate = job
                    break
                elif job.status == "leased":
                    if job.leased_until is not None and job.leased_until < now:
                        # Lease expired! Re-lease to this worker
                        candidate = job
                        break

            if candidate is None:
                return None

            new_lease_id = uuid.uuid4().hex
            candidate.status = "leased"
            candidate.worker_id = worker_id
            candidate.lease_id = new_lease_id
            candidate.leased_until = now + lease_timeout_s
            return candidate.model_copy()

    async def renew_lease(
        self,
        job_id: str,
        lease_id: str,
        lease_timeout_s: float = 30.0,
    ) -> bool:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.status != "leased":
                return False
            if job.lease_id != lease_id:
                return False
            now = time.time()
            if job.leased_until is not None and job.leased_until < now:
                # Already expired and potentially claimed
                return False
            job.leased_until = now + lease_timeout_s
            return True

    async def complete(self, job_id: str, lease_id: Optional[str] = None) -> None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise ValueError(f"Job {job_id!r} not found")
            if job.status in ("completed", "waiting"):
                job.status = "completed"
                job.lease_id = None
                job.leased_until = None
                return
            if job.lease_id != lease_id:
                raise FencingTokenError(
                    f"Job {job_id} lease {lease_id!r} does not match active lease {job.lease_id!r}"
                )
            job.status = "completed"
            job.lease_id = None
            job.leased_until = None

    async def fail(self, job_id: str, lease_id: Optional[str] = None, error: str = "") -> None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise ValueError(f"Job {job_id!r} not found")
            if job.status in ("failed", "waiting"):
                job.status = "failed"
                job.lease_id = None
                job.leased_until = None
                return
            if job.lease_id != lease_id:
                raise FencingTokenError(
                    f"Job {job_id} lease {lease_id!r} does not match active lease {job.lease_id!r}"
                )
            job.status = "failed"
            job.lease_id = None
            job.leased_until = None

    async def release_for_waiting(self, job_id: str, lease_id: str, reason: str) -> None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise ValueError(f"Job {job_id!r} not found")
            if job.lease_id != lease_id:
                raise FencingTokenError(
                    f"Job {job_id} lease {lease_id!r} does not match active lease {job.lease_id!r}"
                )
            job.status = "waiting"
            job.lease_id = None
            job.leased_until = None

    async def reenqueue(
        self,
        run_id: str,
        flow_id: str,
        version: int,
        inputs: Optional[Dict[str, Any]] = None,
    ) -> QueueJob:
        async with self._lock:
            existing_job_id = self._run_to_job.get(run_id)
            if existing_job_id and existing_job_id in self._jobs:
                job = self._jobs[existing_job_id]
                job.status = "queued"
                job.lease_id = None
                job.leased_until = None
                job.inputs = inputs if inputs is not None else job.inputs
                return job.model_copy()

            job_id = f"job_{uuid.uuid4().hex[:12]}"
            job = QueueJob(
                job_id=job_id,
                run_id=run_id,
                flow_id=flow_id,
                version=version,
                inputs=inputs or {},
                status="queued",
                created_at=time.time(),
            )
            self._jobs[job_id] = job
            self._run_to_job[run_id] = job_id
            return job.model_copy()

    async def get_job(self, job_id: str) -> Optional[QueueJob]:
        job = self._jobs.get(job_id)
        return job.model_copy() if job else None

    async def get_job_by_run_id(self, run_id: str) -> Optional[QueueJob]:
        job_id = self._run_to_job.get(run_id)
        if not job_id:
            return None
        return await self.get_job(job_id)

    def validate_lease(self, run_id: str, lease_id: Optional[str]) -> bool:
        """
        Synchronous check of whether lease_id is valid for run_id.
        Fencing token rule: if a job has an active lease, lease_id must match it
        and the lease must not be expired.
        When job is in waiting or queued state, operator/system writes with lease_id=None are permitted.
        """
        job_id = self._run_to_job.get(run_id)
        if not job_id:
            # If run has no queue job (e.g. direct test run without queue), allow write
            return True
        job = self._jobs.get(job_id)
        if not job:
            return True
        if job.status == "leased":
            if job.lease_id != lease_id:
                return False
            if job.leased_until is not None and job.leased_until < time.time():
                return False
            return True
        elif job.status in ("waiting", "queued"):
            return lease_id is None
        # If job is completed, failed, or cancelled: write is rejected
        return False
