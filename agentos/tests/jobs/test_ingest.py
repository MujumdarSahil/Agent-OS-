"""
Tests for ingest pipeline, idempotency, and source health tracking.
"""

from pathlib import Path
from agentos.jobs.config import JobsConfig
from agentos.jobs.ingest import ingest
from agentos.jobs.models import Job, JobStatus
from agentos.jobs.sources.base import JobSource, SourceResult
from agentos.jobs.store import JobStore


class DummyTestSource(JobSource):
    """Deterministic in-memory JobSource for unit testing."""
    def __init__(self, name: str = "test_src", jobs=None, error=None):
        self.name = name
        self.jobs_list = jobs or []
        self.error_msg = error

    def fetch(self) -> SourceResult:
        return SourceResult(
            jobs=list(self.jobs_list),
            error=self.error_msg,
            raw_count=len(self.jobs_list),
        )


def test_ingest_idempotency_and_run_lifecycle(tmp_path: Path):
    """Confirm executing ingest multiple times does not create duplicates and updates last_seen."""
    db_file = tmp_path / "test_ingest.db"
    store = JobStore(db_file)
    cfg = JobsConfig(db_path=str(db_file), enabled=True)

    job1 = Job(
        source="dummy",
        source_job_id="1",
        company="OpenAI",
        title="ML Engineer",
        location="Remote",
        url="https://openai.com/1",
    )
    job2 = Job(
        source="dummy",
        source_job_id="2",
        company="Anthropic",
        title="Safety Researcher",
        location="San Francisco, CA",
        url="https://anthropic.com/2",
    )

    source = DummyTestSource(name="dummy", jobs=[job1, job2])

    # First ingest run
    summary1 = ingest(cfg, [source], store)
    assert summary1.status == "COMPLETED"
    assert summary1.jobs_discovered == 2
    assert summary1.jobs_saved == 2

    jobs_first_run = store.list_jobs()
    assert len(jobs_first_run) == 2
    initial_last_seen = {j.id: j.last_seen for j in jobs_first_run}

    # Second ingest run with same jobs
    summary2 = ingest(cfg, [source], store)
    assert summary2.status == "COMPLETED"
    assert summary2.jobs_discovered == 2
    assert summary2.jobs_saved == 2

    # Database must still have exactly 2 rows
    jobs_second_run = store.list_jobs()
    assert len(jobs_second_run) == 2

    # last_seen must be updated (>= initial_last_seen)
    for j in jobs_second_run:
        assert j.last_seen >= initial_last_seen[j.id]
        assert j.status == JobStatus.NEW


def test_ingest_source_health_records(tmp_path: Path):
    """Confirm source_health row is properly recorded with success, raw_count, and parsed_count."""
    db_file = tmp_path / "test_health.db"
    store = JobStore(db_file)
    cfg = JobsConfig(db_path=str(db_file), enabled=True)

    job = Job(
        source="healthy_src",
        source_job_id="100",
        company="Acme",
        title="Developer",
        location="Remote",
        url="https://acme.com/100",
    )
    healthy_source = DummyTestSource(name="healthy_src", jobs=[job])
    failing_source = DummyTestSource(name="failing_src", jobs=[], error="Connection refused")

    summary = ingest(cfg, [healthy_source, failing_source], store)
    assert summary.status == "PARTIAL_SUCCESS"
    assert summary.jobs_saved == 1

    # Check healthy source row in store
    health_ok = store.get_source_health("healthy_src")
    assert health_ok is not None
    assert health_ok["last_success_at"] is not None
    assert health_ok["consecutive_failures"] == 0
    assert health_ok["last_raw_count"] == 1
    assert health_ok["last_parsed_count"] == 1

    # Check failing source row in store
    health_fail = store.get_source_health("failing_src")
    assert health_fail is not None
    assert health_fail["last_error_at"] is not None
    assert health_fail["consecutive_failures"] == 1
    assert "Connection refused" in health_fail["last_error_message"]
    assert health_fail["last_raw_count"] == 0
    assert health_fail["last_parsed_count"] == 0
