"""
Tests for Job models, dedupe keys, and status transition invariants.
"""

import pytest

from agentos.jobs.models import (
    Job,
    JobStatus,
    ScoreComponent,
    ScoreBreakdown,
    validate_status_transition,
    InvalidStatusTransitionError,
)


def test_job_dedupe_key_generation():
    """Confirm dedupe_key is deterministically derived from company, title, location."""
    job1 = Job(
        source="test",
        source_job_id="101",
        company="Acme Corp",
        title="Software Engineer",
        location="Remote",
        url="https://example.com/job/101",
    )
    job2 = Job(
        source="test",
        source_job_id="102",
        company="ACME CORP ",
        title="Software Engineer ",
        location=" remote",
        url="https://example.com/job/102",
    )
    assert job1.dedupe_key != ""
    assert job1.dedupe_key == job2.dedupe_key


def test_score_breakdown_total():
    """Confirm ScoreBreakdown accurately sums component points."""
    breakdown = ScoreBreakdown(
        components=[
            ScoreComponent(name="Role Match", points=40.0, reason="Title matches exactly"),
            ScoreComponent(name="Location", points=30.0, reason="Remote supported"),
            ScoreComponent(name="Seniority", points=15.5, reason="Mid-level matches profile"),
        ]
    )
    assert breakdown.total == 85.5


@pytest.mark.parametrize(
    "current_status, new_status",
    [
        (JobStatus.NEW, JobStatus.NOTIFIED),
        (JobStatus.NEW, JobStatus.REVIEWING),
        (JobStatus.NEW, JobStatus.DISMISSED),
        (JobStatus.NEW, JobStatus.CLOSED),
        (JobStatus.NOTIFIED, JobStatus.REVIEWING),
        (JobStatus.REVIEWING, JobStatus.DRAFTED),
        (JobStatus.REVIEWING, JobStatus.APPROVED),
        (JobStatus.DRAFTED, JobStatus.APPROVED),
        (JobStatus.DRAFTED, JobStatus.REVIEWING),
        (JobStatus.APPROVED, JobStatus.HANDED_OFF),
        (JobStatus.APPROVED, JobStatus.APPLIED_MANUALLY),
        (JobStatus.HANDED_OFF, JobStatus.APPLIED_MANUALLY),
        (JobStatus.HANDED_OFF, JobStatus.CLOSED),
        (JobStatus.APPLIED_MANUALLY, JobStatus.CLOSED),
        (JobStatus.DISMISSED, JobStatus.REVIEWING),
        (JobStatus.DISMISSED, JobStatus.CLOSED),
        # Identity transitions
        (JobStatus.NEW, JobStatus.NEW),
        (JobStatus.REVIEWING, JobStatus.REVIEWING),
        (JobStatus.CLOSED, JobStatus.CLOSED),
    ],
)
def test_legal_status_transitions(current_status: JobStatus, new_status: JobStatus):
    """Confirm permitted transitions pass validation without raising."""
    validate_status_transition(current_status, new_status)


@pytest.mark.parametrize(
    "current_status, new_status",
    [
        (JobStatus.NEW, JobStatus.DRAFTED),
        (JobStatus.NEW, JobStatus.APPROVED),
        (JobStatus.NEW, JobStatus.HANDED_OFF),
        (JobStatus.NEW, JobStatus.APPLIED_MANUALLY),
        (JobStatus.NOTIFIED, JobStatus.HANDED_OFF),
        (JobStatus.NOTIFIED, JobStatus.APPLIED_MANUALLY),
        (JobStatus.CLOSED, JobStatus.NEW),
        (JobStatus.CLOSED, JobStatus.DRAFTED),
        (JobStatus.CLOSED, JobStatus.REVIEWING),
        (JobStatus.CLOSED, JobStatus.APPROVED),
        (JobStatus.APPLIED_MANUALLY, JobStatus.DRAFTED),
        (JobStatus.APPLIED_MANUALLY, JobStatus.REVIEWING),
    ],
)
def test_illegal_status_transitions(current_status: JobStatus, new_status: JobStatus):
    """Confirm illegal transitions raise InvalidStatusTransitionError."""
    with pytest.raises(InvalidStatusTransitionError):
        validate_status_transition(current_status, new_status)
