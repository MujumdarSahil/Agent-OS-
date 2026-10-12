"""
Base protocol and result dataclass for job opportunity source adapters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Protocol, runtime_checkable

from agentos.jobs.models import Job


@dataclass
class SourceResult:
    """Standardized result returned by any JobSource."""
    jobs: List[Job] = field(default_factory=list)
    error: Optional[str] = None
    fetched_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    raw_count: int = 0


@runtime_checkable
class JobSource(Protocol):
    """Protocol that all concrete job source adapters must implement."""
    name: str

    def fetch(self) -> SourceResult:
        """Fetches jobs from the target source."""
        ...
