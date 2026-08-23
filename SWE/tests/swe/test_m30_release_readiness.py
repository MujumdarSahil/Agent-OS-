"""
Unit test suite for M30 Enterprise Release Readiness & Final Security Hardening.
Validates all 25 required synthetic scenarios.
"""

import pytest
from agentos_swe.release import (
    ReleaseReadinessEngine,
    ReleaseGateValidator,
    ReleaseReadinessCalculator,
    SecurityConfigurationAuditor,
    DependencyAuditor,
    PerformanceBenchmarker,
    ReleaseRegressionValidator,
    PackagingValidator,
    SystemCapabilityManifest,
    ReadinessLevel,
    SecurityGateStatus,
    RegressionStatus,
    PackagingStatus,
)
from agentos_swe.pr.governance_gate import GovernanceGate


# Scenario 1: Clean repository -> RELEASE_READY
def test_scenario_1_clean_repository():
    engine = ReleaseReadinessEngine()
    res = engine.evaluate_release_readiness("clean_repo")
    assert res.summary.readiness_level == ReadinessLevel.RELEASE_READY
    assert res.summary.overall_score == 100.0
    assert len(res.blockers) == 0


# Scenario 2: Unresolved critical finding -> GATE-01 fails -> BLOCKED
def test_scenario_2_unresolved_critical_finding():
    engine = ReleaseReadinessEngine()
    res = engine.evaluate_release_readiness(
        "crit_repo",
        verified_findings=[{"finding_id": "f_1", "severity": "CRITICAL", "root_cause": "COMMAND_INJECTION", "file": "main.py"}],
    )
    assert res.summary.readiness_level == ReadinessLevel.BLOCKED
    assert len(res.blockers) >= 1
    g01 = next(g for g in res.gates if g.gate_id == "GATE-01")
    assert g01.status == SecurityGateStatus.BLOCKED


# Scenario 3: Internet-exposed critical attack path -> GATE-02 fails -> BLOCKED
def test_scenario_3_critical_attack_path():
    engine = ReleaseReadinessEngine()
    res = engine.evaluate_release_readiness(
        "path_repo",
        attack_paths=[{"path_id": "ap_1", "entrypoint": "api/login", "source_type": "HTTP", "sink_type": "SUBPROCESS", "is_internet_exposed": True, "exploitable": True}],
    )
    assert res.summary.readiness_level == ReadinessLevel.BLOCKED
    g02 = next(g for g in res.gates if g.gate_id == "GATE-02")
    assert g02.status == SecurityGateStatus.BLOCKED


# Scenario 4: Active critical incident -> GATE-03 fails -> BLOCKED
def test_scenario_4_active_critical_incident():
    engine = ReleaseReadinessEngine()
    res = engine.evaluate_release_readiness(
        "inc_repo",
        incident_result={"critical_incident_count": 1},
    )
    assert res.summary.readiness_level == ReadinessLevel.BLOCKED
    g03 = next(g for g in res.gates if g.gate_id == "GATE-03")
    assert g03.status == SecurityGateStatus.BLOCKED


# Scenario 5: Governance BLOCK_RELEASE -> GATE-04 fails -> BLOCKED
def test_scenario_5_governance_block():
    engine = ReleaseReadinessEngine()
    res = engine.evaluate_release_readiness(
        "gov_repo",
        decision_result={"overall_decision": "BLOCK_RELEASE"},
    )
    assert res.summary.readiness_level == ReadinessLevel.BLOCKED
    g04 = next(g for g in res.gates if g.gate_id == "GATE-04")
    assert g04.status == SecurityGateStatus.BLOCKED


# Scenario 6: Unresolved P0 finding -> GATE-05 fails -> BLOCKED
def test_scenario_6_p0_finding():
    engine = ReleaseReadinessEngine()
    res = engine.evaluate_release_readiness(
        "p0_repo",
        prioritized_findings=[{"finding_id": "p0_1", "severity": "HIGH", "priority": "P0", "root_cause": "DESERIALIZATION", "file": "app.py"}],
    )
    assert res.summary.readiness_level == ReadinessLevel.BLOCKED
    g05 = next(g for g in res.gates if g.gate_id == "GATE-05")
    assert g05.status == SecurityGateStatus.BLOCKED


# Scenario 7: Security monitoring FAILED/STALE -> GATE-06 warning
def test_scenario_7_monitoring_failed():
    engine = ReleaseReadinessEngine()
    res = engine.evaluate_release_readiness(
        "mon_repo",
        monitoring_health={"monitoring_health": "FAILED"},
    )
    g06 = next(g for g in res.gates if g.gate_id == "GATE-06")
    assert g06.status == SecurityGateStatus.WARNING


# Scenario 8: High severity finding without repair -> GATE-07 warning
def test_scenario_8_high_severity_finding():
    engine = ReleaseReadinessEngine()
    res = engine.evaluate_release_readiness(
        "high_repo",
        verified_findings=[{"finding_id": "h_1", "severity": "HIGH", "root_cause": "SQL_INJECTION", "file": "db.py"}],
    )
    assert res.summary.readiness_level == ReadinessLevel.READY_WITH_WARNINGS
    g07 = next(g for g in res.gates if g.gate_id == "GATE-07")
    assert g07.status == SecurityGateStatus.WARNING


# Scenario 9: Reopened vulnerability -> GATE-08 warning
def test_scenario_9_reopened_vulnerability():
    engine = ReleaseReadinessEngine()
    res = engine.evaluate_release_readiness(
        "reopen_repo",
        verified_findings=[{"finding_id": "ro_1", "severity": "MEDIUM", "root_cause": "XSS", "file": "view.py", "recurrence_classification": "REOPENED"}],
    )
    g08 = next(g for g in res.gates if g.gate_id == "GATE-08")
    assert g08.status == SecurityGateStatus.WARNING


# Scenario 10: Chronic vulnerability -> GATE-09 warning
def test_scenario_10_chronic_vulnerability():
    engine = ReleaseReadinessEngine()
    res = engine.evaluate_release_readiness(
        "chronic_repo",
        verified_findings=[{"finding_id": "ch_1", "severity": "MEDIUM", "root_cause": "XSS", "file": "view.py", "recurrence_classification": "CHRONIC"}],
    )
    g09 = next(g for g in res.gates if g.gate_id == "GATE-09")
    assert g09.status == SecurityGateStatus.WARNING


# Scenario 11: Clean monitoring & resolved findings -> GATE-10 pass
def test_scenario_11_clean_monitoring_pass():
    validator = ReleaseGateValidator()
    gates = validator.evaluate_gates(verified_findings=[], monitoring_health={"monitoring_health": "ACTIVE"})
    g10 = next(g for g in gates if g.gate_id == "GATE-10")
    assert g10.status == SecurityGateStatus.PASS


# Scenario 12: Safe design patterns -> GATE-11 pass (must not block release)
def test_scenario_12_safe_patterns_pass():
    engine = ReleaseReadinessEngine()
    res = engine.evaluate_release_readiness(
        "safe_repo",
        verified_findings=[
            {"finding_id": "s_1", "root_cause": "DICT_LOOKUP", "severity": "LOW", "sanitized": True},
            {"finding_id": "s_2", "root_cause": "INTENTIONAL_FALLBACK", "severity": "MEDIUM", "sanitized": True},
            {"finding_id": "s_3", "root_cause": "TEST_HARNESS_DIAGNOSTIC", "severity": "LOW", "sanitized": True},
        ],
    )
    assert res.summary.readiness_level == ReadinessLevel.RELEASE_READY
    g11 = next(g for g in res.gates if g.gate_id == "GATE-11")
    assert g11.status == SecurityGateStatus.PASS


# Scenario 13: Unknown evidence -> GATE-12 warning
def test_scenario_13_unknown_evidence_warning():
    engine = ReleaseReadinessEngine()
    res = engine.evaluate_release_readiness(
        "unk_repo",
        verified_findings=[{"finding_id": "unk_1", "severity": "MEDIUM", "root_cause": "LOG_INJECTION", "file": "log.py", "confidence": "UNKNOWN"}],
    )
    g12 = next(g for g in res.gates if g.gate_id == "GATE-12")
    assert g12.status == SecurityGateStatus.WARNING


# Scenario 14: Readiness score calculation (0-100)
def test_scenario_14_score_calculation():
    engine = ReleaseReadinessEngine()
    res = engine.evaluate_release_readiness(
        "score_repo",
        verified_findings=[{"finding_id": "h_1", "severity": "HIGH", "root_cause": "SSRF", "file": "http.py"}],
    )
    assert 0.0 <= res.readiness_score.overall_score <= 100.0
    assert "security_score" in res.readiness_score.to_dict()


# Scenario 15: Mandatory blocking gate override rule
def test_scenario_15_mandatory_gate_override():
    """High numerical score (e.g. 95) MUST NOT override a mandatory blocking gate!"""
    validator = ReleaseGateValidator()
    gates = validator.evaluate_gates(
        attack_paths=[{"path_id": "ap_1", "entrypoint": "login", "source_type": "HTTP", "sink_type": "SUBPROCESS", "is_internet_exposed": True, "exploitable": True}],
    )
    level, score_obj, summary = ReleaseReadinessCalculator.calculate_readiness(
        repository_name="override_repo",
        commit_sha="HEAD",
        gates=gates,
        active_findings=[],
    )
    # High score but mandatory gate blocked -> Level MUST be BLOCKED!
    assert level == ReadinessLevel.BLOCKED
    assert summary.readiness_level == ReadinessLevel.BLOCKED


# Scenario 16: Security configuration audit
def test_scenario_16_configuration_audit():
    audit = SecurityConfigurationAuditor.audit_configuration()
    assert audit["status"] == "COMPLIANT"
    assert audit["compliant"] is True
    assert len(audit["checks"]) >= 5


# Scenario 17: Dependency audit without internet
def test_scenario_17_dependency_audit_offline():
    audit = DependencyAuditor.audit_dependencies()
    assert audit["vulnerability_database"] == "VULNERABILITY_DATABASE_UNAVAILABLE"
    assert "risk" in audit


# Scenario 18: Performance benchmarking
def test_scenario_18_performance_benchmarking():
    bm = PerformanceBenchmarker.benchmark_pipeline()
    assert bm["status"] == "OPTIMAL"
    assert "total_runtime_seconds" in bm
    assert "slowest_stage" in bm


# Scenario 19: Regression validator
def test_scenario_19_regression_validator():
    reg = ReleaseRegressionValidator.validate_regressions()
    assert reg["status"] == "CLEAN"
    assert reg["is_clean"] is True


# Scenario 20: Packaging validator
def test_scenario_20_packaging_validator():
    pkg = PackagingValidator.validate_packaging()
    assert pkg["status"] == "VALID"
    assert pkg["is_valid"] is True


# Scenario 21: System capability manifest generator
def test_scenario_21_system_manifest():
    manifest = SystemCapabilityManifest.generate_manifest()
    assert manifest["system_name"] == "AgentOS-SWE"
    assert manifest["version"] == "2.0.0"
    assert manifest["final_milestone"] == "M30"
    assert len(manifest["completed_milestones"]) == 31


# Scenario 22: Final release recommendation string
def test_scenario_22_release_recommendation():
    engine = ReleaseReadinessEngine()
    res = engine.evaluate_release_readiness("rec_repo")
    assert "RELEASE READY" in res.summary.recommendation


# Scenario 23: Governance integration
def test_scenario_23_governance_integration():
    engine = ReleaseReadinessEngine()
    res = engine.evaluate_release_readiness("gov_repo")
    gov_gate = GovernanceGate()
    dec = gov_gate.evaluate_release_readiness_governance(res)
    assert dec.value == "ALLOW"


# Scenario 24: Zero false release block for safe patterns
def test_scenario_24_zero_false_block_for_safe_patterns():
    engine = ReleaseReadinessEngine()
    res = engine.evaluate_release_readiness(
        "dict_repo",
        verified_findings=[{"finding_id": "d_1", "root_cause": "DICT_LOOKUP", "severity": "LOW", "sanitized": True}],
    )
    assert res.summary.readiness_level == ReadinessLevel.RELEASE_READY


# Scenario 25: Master ReleaseReadinessEngine facade
def test_scenario_25_master_facade():
    engine = ReleaseReadinessEngine()
    res = engine.evaluate_release_readiness("facade_repo")
    assert res.summary.repository_name == "facade_repo"
    assert res.manifest["system_name"] == "AgentOS-SWE"
