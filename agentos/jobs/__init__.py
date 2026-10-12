"""
AgentOS Job Application Agent package.

Phase 1 Foundation:
- Configuration and schema validation
- Data models and transition invariants
- SQLite persistence store with WAL mode and schema versioning
- Source adapter protocol
"""

from agentos.jobs.config import JobsConfig, load_jobs_config
from agentos.jobs.models import (
    Job,
    JobStatus,
    ScoreComponent,
    ScoreBreakdown,
    validate_status_transition,
    InvalidStatusTransitionError,
    ALLOWED_STATUS_TRANSITIONS,
)
from agentos.jobs.store import JobStore
from agentos.jobs.sources.base import JobSource, SourceResult

# Feature flag: default off
ENABLED: bool = False

__all__ = [
    "ENABLED",
    "JobsConfig",
    "load_jobs_config",
    "Job",
    "JobStatus",
    "ScoreComponent",
    "ScoreBreakdown",
    "validate_status_transition",
    "InvalidStatusTransitionError",
    "ALLOWED_STATUS_TRANSITIONS",
    "JobStore",
    "JobSource",
    "SourceResult",
]
