"""
AgentOS Job Application Agent package.

Phase 1 & 2:
- Configuration and schema validation
- Data models and transition invariants
- SQLite persistence store with WAL mode and schema versioning
- Normalization and deduplication key generation
- Source adapter protocol and Greenhouse public job board adapter
- Ingest execution orchestrator
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
from agentos.jobs.normalize import (
    normalize_company,
    normalize_title,
    normalize_location,
    compute_dedupe_key,
)
from agentos.jobs.store import JobStore
from agentos.jobs.sources.base import JobSource, SourceResult
from agentos.jobs.sources.greenhouse import GreenhouseSource, html_to_plain_text
from agentos.jobs.ingest import ingest, IngestSummary

__all__ = [
    "JobsConfig",
    "load_jobs_config",
    "Job",
    "JobStatus",
    "ScoreComponent",
    "ScoreBreakdown",
    "validate_status_transition",
    "InvalidStatusTransitionError",
    "ALLOWED_STATUS_TRANSITIONS",
    "normalize_company",
    "normalize_title",
    "normalize_location",
    "compute_dedupe_key",
    "JobStore",
    "JobSource",
    "SourceResult",
    "GreenhouseSource",
    "html_to_plain_text",
    "ingest",
    "IngestSummary",
]
