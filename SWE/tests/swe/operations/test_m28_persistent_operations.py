"""
Unit test suite for M28 Persistent Security Operations Store & Repository Registry.
"""

import os
import tempfile
import pytest

from agentos_swe.persistence import (
    PersistentOperationalStateStore,
    RepositoryRegistry,
    SecurityPostureSnapshotRecord,
    MonitoringScheduleInterval,
    RepositoryMonitoringStatus,
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


# Scenario 1: Save operational state to SQLite store
def test_scenario_1_save_operational_state(temp_db):
    store = PersistentOperationalStateStore(db_path=temp_db)
    state = {
        "repository_name": "repo_alpha",
        "commit_sha": "sha_111",
        "security_score": 90,
        "health_score": 95.0,
        "summary": {"operational_status": "HEALTHY", "risk_score": 5.0},
    }
    assert store.save_operational_state("repo_alpha", state) is True


# Scenario 2: Load operational state after process/store instance recreation
def test_scenario_2_load_state_after_recreation(temp_db):
    store1 = PersistentOperationalStateStore(db_path=temp_db)
    store1.save_operational_state("repo_beta", {"repository_name": "repo_beta", "commit_sha": "sha_222", "security_score": 85})

    # Re-instantiate store (simulating process restart)
    store2 = PersistentOperationalStateStore(db_path=temp_db)
    loaded = store2.load_operational_state("repo_beta")

    assert loaded is not None
    assert loaded.get("commit_sha") == "sha_222"
    assert loaded.get("security_score") == 85


# Scenario 3: Multi-repository isolation in persistent store
def test_scenario_3_multi_repository_isolation(temp_db):
    store = PersistentOperationalStateStore(db_path=temp_db)
    store.save_operational_state("repo_x", {"commit_sha": "sha_x", "security_score": 100})
    store.save_operational_state("repo_y", {"commit_sha": "sha_y", "security_score": 70})

    repos = store.list_repositories()
    assert "repo_x" in repos
    assert "repo_y" in repos
    assert store.load_operational_state("repo_x")["security_score"] == 100
    assert store.load_operational_state("repo_y")["security_score"] == 70


# Scenario 4: Delete/clear operational state
def test_scenario_4_delete_operational_state(temp_db):
    store = PersistentOperationalStateStore(db_path=temp_db)
    store.save_operational_state("repo_del", {"commit_sha": "sha_del"})
    assert store.delete_operational_state("repo_del") is True
    assert store.load_operational_state("repo_del") is None


# Scenario 5: Save, list, load, and compare posture snapshots across commits
def test_scenario_5_snapshots_and_comparison(temp_db):
    store = PersistentOperationalStateStore(db_path=temp_db)

    snap1 = SecurityPostureSnapshotRecord(
        snapshot_id="snap_1",
        repository_name="repo_snap",
        commit_sha="sha_old",
        timestamp="2026-08-23T10:00:00",
        security_score=80,
        health_score=85.0,
    )
    snap2 = SecurityPostureSnapshotRecord(
        snapshot_id="snap_2",
        repository_name="repo_snap",
        commit_sha="sha_new",
        timestamp="2026-08-23T11:00:00",
        security_score=95,
        health_score=98.0,
    )

    store.save_snapshot("repo_snap", snap1)
    store.save_snapshot("repo_snap", snap2)

    snaps = store.list_snapshots("repo_snap")
    assert len(snaps) == 2

    cmp_res = store.compare_snapshots("repo_snap")
    assert cmp_res["status"] == "COMPARED"
    assert cmp_res["score_delta"] == 15
    assert cmp_res["direction"] == "IMPROVEMENT"


# Scenario 6: Secret protection / sanitization before writing to store
def test_scenario_6_secret_sanitization(temp_db):
    store = PersistentOperationalStateStore(db_path=temp_db)
    state = {
        "repository_name": "repo_sec",
        "api_key": "secret_key_12345",
        "auth_token": "ghp_abcdef123456",
        "summary": {"note": "Found token: ghp_9999999999"},
    }
    store.save_operational_state("repo_sec", state)
    loaded = store.load_operational_state("repo_sec")

    assert loaded["api_key"] == "[REDACTED_SECRET]"
    assert loaded["auth_token"] == "[REDACTED_SECRET]"


# Scenario 7: Corrupted JSON record resilience
def test_scenario_7_corrupted_json_resilience(temp_db):
    store = PersistentOperationalStateStore(db_path=temp_db)
    store.save_operational_state("repo_corrupt", {"commit_sha": "sha_valid"})

    # Manually overwrite with corrupted JSON payload in SQLite table
    import sqlite3
    with sqlite3.connect(temp_db) as conn:
        conn.cursor().execute("UPDATE operational_states SET state_json = 'INVALID_JSON{' WHERE repository_name = 'repo_corrupt'")
        conn.commit()

    loaded = store.load_operational_state("repo_corrupt")
    assert loaded is not None
    assert loaded.get("_corrupted") is True


# Scenario 8: Register repository in RepositoryRegistry
def test_scenario_8_register_repository(temp_db):
    reg = RepositoryRegistry(db_path=temp_db)
    r = reg.register_repository("repo_reg", "/path/to/repo", branch="dev", scan_interval="HOURLY")
    assert r.repository_name == "repo_reg"
    assert r.scan_interval == "HOURLY"

    fetched = reg.get_repository("repo_reg")
    assert fetched is not None
    assert fetched.branch == "dev"


# Scenario 9: Enable/disable monitoring on registered repository
def test_scenario_9_enable_disable_monitoring(temp_db):
    reg = RepositoryRegistry(db_path=temp_db)
    reg.register_repository("repo_toggle", "/path/to/repo")

    assert reg.disable_monitoring("repo_toggle") is True
    assert reg.get_repository("repo_toggle").monitoring_enabled is False

    assert reg.enable_monitoring("repo_toggle") is True
    assert reg.get_repository("repo_toggle").monitoring_enabled is True


# Scenario 10: Unregister repository & update schedule
def test_scenario_10_unregister_and_update_schedule(temp_db):
    reg = RepositoryRegistry(db_path=temp_db)
    reg.register_repository("repo_sched", "/path/to/repo", scan_interval="DAILY")

    reg.update_schedule("repo_sched", "WEEKLY")
    assert reg.get_repository("repo_sched").scan_interval == "WEEKLY"

    assert reg.unregister_repository("repo_sched") is True
    assert reg.get_repository("repo_sched") is None
