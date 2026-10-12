"""
Ingestion orchestrator for job opportunity source adapters.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from agentos.jobs.config import JobsConfig
from agentos.jobs.sources.base import JobSource
from agentos.jobs.store import JobStore

logger = logging.getLogger(__name__)


@dataclass
class IngestSummary:
    """Summary of an ingest execution run."""
    run_id: str
    status: str
    jobs_discovered: int = 0
    jobs_saved: int = 0
    source_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str] = None
    error: Optional[str] = None


def ingest(
    config: JobsConfig,
    sources: List[JobSource],
    store: JobStore,
) -> IngestSummary:
    """
    Executes a single ingest run across configured source adapters:
    - Starts a run record in store
    - Fetches postings from each source
    - Upserts retrieved jobs into the store
    - Updates source_health with execution metrics and error states
    - Closes run record with final counts and status
    - Returns IngestSummary
    """
    run_id = f"run_{uuid.uuid4().hex[:12]}"
    started_at = datetime.now(timezone.utc).isoformat()
    store.record_run_start(run_id, started_at=started_at, metadata={"sources": [s.name for s in sources]})

    total_discovered = 0
    total_saved = 0
    source_details: Dict[str, Dict[str, Any]] = {}
    any_error = False

    for source in sources:
        try:
            res = source.fetch()
        except Exception as exc:
            err_msg = f"Unhandled exception in source '{source.name}': {exc}"
            logger.error(err_msg)
            store.record_source_health(
                source.name,
                success=False,
                error_message=err_msg,
                raw_count=0,
                parsed_count=0,
            )
            source_details[source.name] = {
                "ok": False,
                "raw_count": 0,
                "parsed_count": 0,
                "error": err_msg,
            }
            any_error = True
            continue

        raw_count = res.raw_count
        parsed_count = len(res.jobs)
        total_discovered += raw_count

        saved_for_source = 0
        for job in res.jobs:
            try:
                store.upsert_job(job)
                saved_for_source += 1
            except Exception as exc:
                logger.warning("Failed upserting job %s from %s: %s", job.source_job_id, job.source, exc)

        total_saved += saved_for_source
        is_ok = res.error is None
        if not is_ok:
            any_error = True

        store.record_source_health(
            source.name,
            success=is_ok,
            error_message=res.error,
            raw_count=raw_count,
            parsed_count=parsed_count,
        )

        source_details[source.name] = {
            "ok": is_ok,
            "raw_count": raw_count,
            "parsed_count": parsed_count,
            "saved_count": saved_for_source,
            "error": res.error,
        }

    finished_at = datetime.now(timezone.utc).isoformat()
    final_status = "COMPLETED" if not any_error else "PARTIAL_SUCCESS"
    store.record_run_finish(
        run_id,
        status=final_status,
        jobs_discovered=total_discovered,
        jobs_saved=total_saved,
    )

    return IngestSummary(
        run_id=run_id,
        status=final_status,
        jobs_discovered=total_discovered,
        jobs_saved=total_saved,
        source_results=source_details,
        started_at=started_at,
        finished_at=finished_at,
        error="One or more sources encountered errors" if any_error else None,
    )
