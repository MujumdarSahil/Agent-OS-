"""
Data models and status transition invariants for AgentOS Job Application Agent.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set
from pydantic import BaseModel, Field, model_validator

from agentos.jobs.normalize import compute_dedupe_key


class JobStatus(str, Enum):
    """Lifecycle status states for a job opportunity."""
    NEW = "NEW"
    NOTIFIED = "NOTIFIED"
    REVIEWING = "REVIEWING"
    DRAFTED = "DRAFTED"
    APPROVED = "APPROVED"
    HANDED_OFF = "HANDED_OFF"
    APPLIED_MANUALLY = "APPLIED_MANUALLY"
    DISMISSED = "DISMISSED"
    CLOSED = "CLOSED"


class InvalidStatusTransitionError(ValueError):
    """Raised when an illegal status transition is requested."""
    pass


# Explicit transition map: Current status -> Set of legal next statuses
ALLOWED_STATUS_TRANSITIONS: Dict[JobStatus, Set[JobStatus]] = {
    JobStatus.NEW: {
        JobStatus.NOTIFIED,
        JobStatus.REVIEWING,
        JobStatus.DISMISSED,
        JobStatus.CLOSED,
    },
    JobStatus.NOTIFIED: {
        JobStatus.REVIEWING,
        JobStatus.DISMISSED,
        JobStatus.CLOSED,
    },
    JobStatus.REVIEWING: {
        JobStatus.DRAFTED,
        JobStatus.APPROVED,
        JobStatus.DISMISSED,
        JobStatus.CLOSED,
    },
    JobStatus.DRAFTED: {
        JobStatus.APPROVED,
        JobStatus.REVIEWING,
        JobStatus.DISMISSED,
        JobStatus.CLOSED,
    },
    JobStatus.APPROVED: {
        JobStatus.HANDED_OFF,
        JobStatus.APPLIED_MANUALLY,
        JobStatus.REVIEWING,
        JobStatus.DISMISSED,
        JobStatus.CLOSED,
    },
    JobStatus.HANDED_OFF: {
        JobStatus.APPLIED_MANUALLY,
        JobStatus.CLOSED,
        JobStatus.DISMISSED,
    },
    JobStatus.APPLIED_MANUALLY: {
        JobStatus.CLOSED,
        JobStatus.DISMISSED,
    },
    JobStatus.DISMISSED: {
        JobStatus.REVIEWING,
        JobStatus.CLOSED,
    },
    JobStatus.CLOSED: set(),
}


def validate_status_transition(current_status: JobStatus, new_status: JobStatus) -> None:
    """
    Validates whether transition from current_status to new_status is legal.
    Raises InvalidStatusTransitionError if the transition is illegal.
    """
    if current_status == new_status:
        return  # Identity transition is a no-op

    allowed = ALLOWED_STATUS_TRANSITIONS.get(current_status, set())
    if new_status not in allowed:
        allowed_names = sorted(s.value for s in allowed)
        raise InvalidStatusTransitionError(
            f"Illegal transition: Cannot transition job status from '{current_status.value}' to '{new_status.value}'. "
            f"Allowed destination states from '{current_status.value}': {allowed_names}"
        )


class ScoreComponent(BaseModel):
    """Component scoring breakdown entry."""
    name: str
    points: float
    reason: str


class ScoreBreakdown(BaseModel):
    """Container for scored components."""
    components: List[ScoreComponent] = Field(default_factory=list)

    @property
    def total(self) -> float:
        return sum(c.points for c in self.components)


class Job(BaseModel):
    """Job opportunity data model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: str
    source_job_id: str
    company: str
    title: str
    location: str
    url: str
    description: str = ""
    posted_at: Optional[str] = None
    first_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    dedupe_key: str = ""
    status: JobStatus = JobStatus.NEW
    score: float = 0.0
    score_breakdown: List[ScoreComponent] = Field(default_factory=list)

    @model_validator(mode="after")
    def compute_dedupe_key(self) -> Job:
        if not self.dedupe_key:
            self.dedupe_key = compute_dedupe_key(self.company, self.title, self.location)
        return self
