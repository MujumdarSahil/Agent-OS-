"""
Unit test suite for M28 Continuous Security Monitoring Engine.
"""

import os
import tempfile
import pytest

from agentos_swe.persistence import PersistentOperationalStateStore, RepositoryRegistry
from agentos_swe.monitoring import (
    ContinuousMonitoringScheduler,
    SecurityMonitoringRunner,
    MonitoringEventType,
    MonitoringHealthStatus,
)


@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    yield db_path
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError:
            pass


# Scenario 1: Schedule next run timestamp calculation
def test_scenario_1_schedule_calculation():
    next_run = ContinuousMonitoringScheduler.calculate_next_run("2026-08-23T10:00:00", "HOURLY")
    assert "2026-08-23T11:00:00" in next_run


# Scenario 2: is_due check on registered repository
def test_scenario_2_is_due_check(temp_db):
    reg = RepositoryRegistry(db_path=temp_db)
    r = reg.register_repository("repo_due", "/path/to/repo", scan_interval="HOURLY")

    sched = ContinuousMonitoringScheduler(registry=reg)
    assert sched.is_due(r) is True


# Scenario 3: Change-aware no-change optimization (NO_CHANGE)
def test_scenario_3_no_change_optimization(temp_db):
    store = PersistentOperationalStateStore(db_path=temp_db)
    reg = RepositoryRegistry(db_path=temp_db)
    reg.register_repository("repo_nc", "/path/to/repo")

    # Store initial state at commit_sha = "abc1234"
    store.save_operational_state("repo_nc", {"commit_sha": "abc1234", "summary": {"security_score": 100}})

    runner = SecurityMonitoringRunner(store=store, registry=reg)
    res = runner.run_monitoring_scan("repo_nc", "/path/to/repo", commit_sha="abc1234", force_rescan=False)

    assert res.status == "NO_CHANGE"
    assert res.change_detected is False
    assert res.events_generated[0]["event_type"] == MonitoringEventType.NO_CHANGE.value


# Scenario 4: Change-aware commit scan execution (CHANGE_DETECTED)
def test_scenario_4_change_detected_scan(temp_db):
    store = PersistentOperationalStateStore(db_path=temp_db)
    reg = RepositoryRegistry(db_path=temp_db)
    reg.register_repository("repo_cd", "/path/to/repo")

    store.save_operational_state("repo_cd", {"commit_sha": "commit_v1", "summary": {"security_score": 90}})

    runner = SecurityMonitoringRunner(store=store, registry=reg)
    res = runner.run_monitoring_scan("repo_cd", "/path/to/repo", commit_sha="commit_v2")

    assert res.status == "SCAN_SUCCESS"
    assert res.change_detected is True
    assert res.current_commit == "commit_v2"


# Scenario 5: Resilient failure recovery (preserves last_known_good_state)
def test_scenario_5_failure_recovery_preserves_state(temp_db):
    store = PersistentOperationalStateStore(db_path=temp_db)
    reg = RepositoryRegistry(db_path=temp_db)
    reg.register_repository("repo_fail", "/path/to/repo")

    # Save known-good state
    store.save_operational_state("repo_fail", {"commit_sha": "good_sha", "summary": {"security_score": 95}})

    runner = SecurityMonitoringRunner(store=store, registry=reg)

    # Monkeypatch control plane to raise an error
    runner.control_plane.process_repository_operations = lambda **kwargs: (_ for _ in ()).throw(RuntimeError("Git command failure"))

    res = runner.run_monitoring_scan("repo_fail", "/path/to/repo", commit_sha="new_sha")

    assert res.status == "SCAN_FAILED"
    # Verify last known good state is preserved in store
    preserved = store.load_operational_state("repo_fail")
    assert preserved["commit_sha"] == "good_sha"
    assert preserved["summary"]["security_score"] == 95


# Scenario 6: Differentiating SECURITY_HEALTH vs MONITORING_HEALTH
def test_scenario_6_monitoring_health_differentiation(temp_db):
    reg = RepositoryRegistry(db_path=temp_db)
    reg.register_repository("repo_m1", "/path/to/repo")

    sched = ContinuousMonitoringScheduler(registry=reg)
    m_health = sched.compute_monitoring_health()

    assert m_health.security_health == "HEALTHY"
    assert m_health.monitoring_health in ["HEALTHY", "ACTIVE"]


# Scenario 7: Scheduler tick execution across due repositories
def test_scenario_7_scheduler_tick(temp_db):
    store = PersistentOperationalStateStore(db_path=temp_db)
    reg = RepositoryRegistry(db_path=temp_db)
    reg.register_repository("repo_t1", "/path/1")
    reg.register_repository("repo_t2", "/path/2")

    runner = SecurityMonitoringRunner(store=store, registry=reg)
    sched = ContinuousMonitoringScheduler(registry=reg)

    results = sched.tick(runner=runner, force_scan=True)
    assert len(results) == 2
