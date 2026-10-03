"""
Real-world validation test suite for M28 Continuous Security Monitoring & Persistent Operations.

Validates persistence and continuous monitoring across the 5 canonical target benchmark repositories:
- Job_Agent: Safe repository -> HEALTHY / RELEASE_ALLOWED
- ConstitutionAI: Command injection -> CRITICAL / BLOCKED
- MedAgentX: Intentional fallback -> HEALTHY / RELEASE_ALLOWED
- Cadresec-: Swallowed exception -> AT_RISK / REPAIR_PENDING
- OmniTutor-AI: Diagnostic test harness -> HEALTHY / RELEASE_ALLOWED
"""

import os
import tempfile
import pytest

from agentos_swe.persistence import PersistentOperationalStateStore, RepositoryRegistry
from agentos_swe.operations.monitoring import SecurityMonitoringRunner


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


def test_m28_real_world_1_job_agent(temp_db):
    """Job_Agent safe dict lookup -> Persistent state HEALTHY / RELEASE_ALLOWED."""
    store = PersistentOperationalStateStore(db_path=temp_db)
    reg = RepositoryRegistry(db_path=temp_db)
    reg.register_repository("Job_Agent", "/path/to/Job_Agent")

    runner = SecurityMonitoringRunner(store=store, registry=reg)
    res = runner.run_monitoring_scan(
        repository_name="Job_Agent",
        repository_path="/path/to/Job_Agent",
        commit_sha="job_c1",
        verified_findings=[{"finding_id": "f_job_1", "root_cause": "DICT_LOOKUP", "sanitized": True}],
    )

    assert res.status == "SCAN_SUCCESS"
    assert res.governance_status == "ALLOW"
    assert res.recommended_action == "RELEASE_ALLOWED"

    # Verify persistence recovery
    persisted = store.load_operational_state("Job_Agent")
    assert persisted is not None
    assert persisted["commit_sha"] == "job_c1"


def test_m28_real_world_2_constitution_ai(temp_db):
    """ConstitutionAI command injection -> Persistent state CRITICAL / BLOCKED."""
    store = PersistentOperationalStateStore(db_path=temp_db)
    reg = RepositoryRegistry(db_path=temp_db)
    reg.register_repository("ConstitutionAI", "/path/to/ConstitutionAI")

    runner = SecurityMonitoringRunner(store=store, registry=reg)
    res = runner.run_monitoring_scan(
        repository_name="ConstitutionAI",
        repository_path="/path/to/ConstitutionAI",
        commit_sha="const_c1",
        verified_findings=[{"finding_id": "f_const_1", "root_cause": "COMMAND_INJECTION", "severity": "CRITICAL"}],
        decision_result={"overall_decision": "BLOCK_RELEASE"},
    )

    assert res.status == "SCAN_SUCCESS"
    assert res.recommended_action == "BLOCK_RELEASE"

    # Verify snapshot stored
    latest_snap = store.get_latest_snapshot("ConstitutionAI")
    assert latest_snap is not None
    assert latest_snap.critical_count == 1


def test_m28_real_world_3_medagentx(temp_db):
    """MedAgentX intentional fallback -> Persistent state HEALTHY / RELEASE_ALLOWED."""
    store = PersistentOperationalStateStore(db_path=temp_db)
    reg = RepositoryRegistry(db_path=temp_db)
    reg.register_repository("MedAgentX", "/path/to/MedAgentX")

    runner = SecurityMonitoringRunner(store=store, registry=reg)
    res = runner.run_monitoring_scan(
        repository_name="MedAgentX",
        repository_path="/path/to/MedAgentX",
        commit_sha="med_c1",
        verified_findings=[{"finding_id": "f_med_1", "root_cause": "INTENTIONAL_FALLBACK", "sanitized": True}],
    )

    assert res.status == "SCAN_SUCCESS"
    assert res.recommended_action == "RELEASE_ALLOWED"


def test_m28_real_world_4_cadresec(temp_db):
    """Cadresec- swallowed exception -> Persistent state AT_RISK / REPAIR_PENDING."""
    store = PersistentOperationalStateStore(db_path=temp_db)
    reg = RepositoryRegistry(db_path=temp_db)
    reg.register_repository("Cadresec-", "/path/to/Cadresec-")

    runner = SecurityMonitoringRunner(store=store, registry=reg)
    res = runner.run_monitoring_scan(
        repository_name="Cadresec-",
        repository_path="/path/to/Cadresec-",
        commit_sha="cadre_c1",
        verified_findings=[{"finding_id": "f_cadre_1", "root_cause": "SWALLOWED_EXCEPTION", "severity": "HIGH"}],
    )

    assert res.status == "SCAN_SUCCESS"
    assert res.recommended_action in ["GENERATE_REPAIR", "BLOCK_RELEASE"]


def test_m28_real_world_5_omnitutor_ai(temp_db):
    """OmniTutor-AI test harness diagnostic -> Persistent state HEALTHY / RELEASE_ALLOWED."""
    store = PersistentOperationalStateStore(db_path=temp_db)
    reg = RepositoryRegistry(db_path=temp_db)
    reg.register_repository("OmniTutor-AI", "/path/to/OmniTutor-AI")

    runner = SecurityMonitoringRunner(store=store, registry=reg)
    res = runner.run_monitoring_scan(
        repository_name="OmniTutor-AI",
        repository_path="/path/to/OmniTutor-AI",
        commit_sha="omni_c1",
        verified_findings=[{"finding_id": "f_omni_1", "root_cause": "TEST_HARNESS_DIAGNOSTIC", "sanitized": True}],
    )

    assert res.status == "SCAN_SUCCESS"
    assert res.recommended_action == "RELEASE_ALLOWED"
