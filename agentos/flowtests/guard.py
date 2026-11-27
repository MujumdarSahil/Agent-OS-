"""4.2 review fix: test runs (trigger "test") are advanced ONLY by the flow test runner.

Every other path that could resume, approve, re-enqueue, sample or alert on a run checks this first: the approve
endpoint (409), startup recovery, the flow worker, the wait-timer scheduler, notifications/alerts, review sampling,
the Overview and the Approvals page. A test run is closed by the runner when its case ends (status ``cancelled``,
event ``run_cancelled`` with reason "test case ended"), so none stays waiting.
"""

from __future__ import annotations

from typing import Any

TEST_TRIGGER = "test"
TEST_RUN_MESSAGE = "this is a test run: only the flow test runner can advance it"
TEST_CLOSED_REASON = "test case ended"


def is_test_run(run: Any) -> bool:
    return getattr(run, "trigger", None) == TEST_TRIGGER
