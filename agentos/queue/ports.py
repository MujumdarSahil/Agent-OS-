"""Queue interfaces and data models for flow execution."""

from __future__ import annotations

import time
from typing import Any, Dict, Optional, Protocol, runtime_checkable
from pydantic import BaseModel, Field

from agentos.storage.ports import FencingTokenError


class QueueJob(BaseModel):
    """
    An execution job in the flow queue.
    Carries run_id, flow_id, published version, inputs, status, and lease metadata.
    """

    job_id: str
    run_id: str
    flow_id: str
    version: int
    inputs: Dict[str, Any] = Field(default_factory=dict)
    status: str = "queued"  # queued, leased, completed, failed, waiting, dead_letter
    lease_id: Optional[str] = None
    leased_until: Optional[float] = None
    worker_id: Optional[str] = None
    attempts: int = 0
    max_attempts: int = 3
    last_error: Optional[str] = None
    created_at: float = Field(default_factory=time.time)


@runtime_checkable
class QueueBackend(Protocol):
    """Interface for flow execution queue backends."""

    async def enqueue(
        self,
        run_id: str,
        flow_id: str,
        version: int,
        inputs: Optional[Dict[str, Any]] = None,
        max_attempts: Optional[int] = None,
    ) -> QueueJob:
        """Enqueue a new flow run."""
        ...

    async def lease(
        self,
        worker_id: str,
        lease_timeout_s: float = 30.0,
    ) -> Optional[QueueJob]:
        """Lease the next available job (either queued or with an expired lease)."""
        ...

    async def renew_lease(
        self,
        job_id: str,
        lease_id: str,
        lease_timeout_s: float = 30.0,
    ) -> bool:
        """Heartbeat to renew active lease; returns False if lease was superseded or lost."""
        ...

    async def complete(self, job_id: str, lease_id: Optional[str] = None) -> None:
        """Mark job as completed. Raises FencingTokenError if lease_id is invalid."""
        ...

    async def fail(self, job_id: str, lease_id: Optional[str] = None, error: str = "") -> None:
        """Mark job as failed. Raises FencingTokenError if lease_id is invalid."""
        ...

    async def release_for_waiting(self, job_id: str, lease_id: str, reason: str) -> None:
        """Free worker when job enters waiting state (e.g. human approval)."""
        ...

    async def reenqueue(
        self,
        run_id: str,
        flow_id: str,
        version: int,
        inputs: Optional[Dict[str, Any]] = None,
    ) -> QueueJob:
        """Re-enqueue an existing run (e.g. on startup recovery or after approval)."""
        ...

    async def get_job(self, job_id: str) -> Optional[QueueJob]:
        ...

    async def get_job_by_run_id(self, run_id: str) -> Optional[QueueJob]:
        ...

    def validate_lease(self, run_id: str, lease_id: Optional[str]) -> bool:
        """
        Validate whether lease_id is the active, non-expired lease for run_id.
        Used as the fencing token validator.
        """
        ...
