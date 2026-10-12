"""
Tests for JobStore SQLite persistence, migrations, upsert idempotency, and audit logging.
"""

from pathlib import Path
import sqlite3
import pytest

from agentos.jobs.models import (
    Job,
    JobStatus,
    ScoreComponent,
    InvalidStatusTransitionError,
)
from agentos.jobs.store import JobStore, apply_migrations


def test_migrations_fresh_db_and_idempotence(tmp_path: Path):
    """Confirm schema migration runs on fresh DB and is idempotent on rerun."""
    db_file = tmp_path / "test_migration.db"

    # Run migrations once
    store = JobStore(db_file)
    assert store.get_schema_version() == 1

    # Re-running migrations manually must return 0 new migrations applied
    with sqlite3.connect(db_file) as conn:
        applied_again = apply_migrations(conn)
        assert applied_again == 0

    # Instantiating store a second time remains at version 1
    store2 = JobStore(db_file)
    assert store2.get_schema_version() == 1


def test_upsert_idempotency_and_last_seen_update(tmp_path: Path):
    """Confirm inserting the same job twice results in exactly 1 row with updated last_seen."""
    db_file = tmp_path / "test_upsert.db"
    store = JobStore(db_file)

    job1 = Job(
        source="hn_who_is_hiring",
        source_job_id="item-42",
        company="Stripe",
        title="Infrastructure Engineer",
        location="Remote",
        url="https://stripe.com/jobs/42",
        score=75.0,
        score_breakdown=[ScoreComponent(name="Role", points=75.0, reason="High match")],
    )

    saved1 = store.upsert_job(job1)
    assert saved1.id == job1.id
    first_seen = saved1.first_seen
    initial_last_seen = saved1.last_seen

    # Retrieve and verify single row exists
    listed = store.list_jobs()
    assert len(listed) == 1
    assert listed[0].company == "Stripe"

    # Upsert same job with updated title/score
    job2 = Job(
        source="hn_who_is_hiring",
        source_job_id="item-42",
        company="Stripe",
        title="Senior Infrastructure Engineer",
        location="Remote",
        url="https://stripe.com/jobs/42",
        score=90.0,
        score_breakdown=[ScoreComponent(name="Role", points=90.0, reason="Senior match")],
    )

    saved2 = store.upsert_job(job2)
    # Row count must remain 1
    listed_after = store.list_jobs()
    assert len(listed_after) == 1
    assert listed_after[0].id == saved1.id
    assert listed_after[0].title == "Senior Infrastructure Engineer"
    assert listed_after[0].score == 90.0
    assert listed_after[0].first_seen == first_seen
    # last_seen should be >= initial_last_seen
    assert saved2.last_seen >= initial_last_seen


def test_status_transition_and_audit_log_written(tmp_path: Path):
    """Confirm valid transition updates DB status and appends audit log record."""
    db_file = tmp_path / "test_audit.db"
    store = JobStore(db_file)

    job = Job(
        source="github_jobs",
        source_job_id="gh-101",
        company="Anthropic",
        title="Safety Researcher",
        location="San Francisco, CA",
        url="https://anthropic.com/jobs/101",
    )
    saved = store.upsert_job(job)
    assert saved.status == JobStatus.NEW

    # Verify initial discovery audit row
    audit1 = store.get_audit_log(saved.id)
    assert len(audit1) == 1
    assert audit1[0]["to_status"] == "NEW"
    assert audit1[0]["reason"] == "initial_discovery"

    # Transition NEW -> REVIEWING
    updated = store.update_job_status(saved.id, JobStatus.REVIEWING, reason="User opened opportunity")
    assert updated.status == JobStatus.REVIEWING

    # Transition REVIEWING -> DRAFTED
    updated2 = store.update_job_status(saved.id, JobStatus.DRAFTED, reason="Resume drafted")
    assert updated2.status == JobStatus.DRAFTED

    # Audit log must now have 3 records
    audit2 = store.get_audit_log(saved.id)
    assert len(audit2) == 3
    assert audit2[1]["from_status"] == "NEW"
    assert audit2[1]["to_status"] == "REVIEWING"
    assert audit2[1]["reason"] == "User opened opportunity"
    assert audit2[2]["from_status"] == "REVIEWING"
    assert audit2[2]["to_status"] == "DRAFTED"
    assert audit2[2]["reason"] == "Resume drafted"


def test_illegal_status_transition_rejected_in_store(tmp_path: Path):
    """Confirm store blocks illegal status transition without modifying DB or audit log."""
    db_file = tmp_path / "test_illegal.db"
    store = JobStore(db_file)

    job = Job(
        source="test_source",
        source_job_id="item-999",
        company="OpenAI",
        title="Research Scientist",
        location="San Francisco, CA",
        url="https://openai.com/jobs/999",
    )
    saved = store.upsert_job(job)

    # NEW -> HANDED_OFF is illegal
    with pytest.raises(InvalidStatusTransitionError):
        store.update_job_status(saved.id, JobStatus.HANDED_OFF, reason="Invalid direct handoff")

    # DB status and audit log must remain unchanged
    refreshed = store.get_job(saved.id)
    assert refreshed is not None
    assert refreshed.status == JobStatus.NEW
    logs = store.get_audit_log(saved.id)
    assert len(logs) == 1  # only the initial discovery log


def test_update_non_existent_job(tmp_path: Path):
    """Updating status of unknown job ID raises KeyError."""
    db_file = tmp_path / "test_missing.db"
    store = JobStore(db_file)
    with pytest.raises(KeyError):
        store.update_job_status("non-existent-uuid", JobStatus.REVIEWING)


def test_list_jobs_filtered(tmp_path: Path):
    """Confirm listing jobs by status filter."""
    db_file = tmp_path / "test_filter.db"
    store = JobStore(db_file)

    j1 = Job(source="s", source_job_id="1", company="A", title="T1", location="L", url="u1")
    j2 = Job(source="s", source_job_id="2", company="B", title="T2", location="L", url="u2")
    store.upsert_job(j1)
    store.upsert_job(j2)

    store.update_job_status(j2.id, JobStatus.REVIEWING)

    new_jobs = store.list_jobs(status=JobStatus.NEW)
    assert len(new_jobs) == 1
    assert new_jobs[0].id == j1.id

    reviewing_jobs = store.list_jobs(status=JobStatus.REVIEWING)
    assert len(reviewing_jobs) == 1
    assert reviewing_jobs[0].id == j2.id


def test_run_and_source_health_logging(tmp_path: Path):
    """Confirm run records and source health metrics persist properly."""
    db_file = tmp_path / "test_health.db"
    store = JobStore(db_file)

    # Record run lifecycle
    store.record_run_start("run-001", metadata={"source": "test"})
    store.record_run_finish("run-001", status="COMPLETED", jobs_discovered=10, jobs_saved=8)

    # Source health: 1 failure then 1 success
    store.record_source_health("test_feed", success=False, error_message="HTTP 500")
    store.record_source_health("test_feed", success=True)
