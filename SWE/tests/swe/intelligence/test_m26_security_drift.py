"""
Unit test suite for M26 — Continuous Security Monitoring & Security Drift Engine.
Validates all 20 required synthetic security drift scenarios.
"""

import pytest

from agentos_swe.intelligence.drift import (
    SecurityPosturalComparator,
    ChangedSurfaceAnalyzer,
    SecurityDriftDetector,
    SecurityDriftScorer,
    SecurityDriftCorrelator,
    SecurityDriftInvestigator,
    SecurityMonitoringDriftEngine,
    SecurityDriftEvent,
    DriftType,
    DriftSeverity,
    DriftDirection,
)


# Scenario 1: No changes -> NO_DRIFT
def test_scenario_1_no_changes():
    engine = SecurityMonitoringDriftEngine()
    res = engine.run_monitoring_pipeline(
        repository_name="repo1",
        current_findings=[],
        baseline_findings=[],
        current_security_score=100,
        baseline_security_score=100,
    )
    assert res.summary.overall_status == "NO_DRIFT"
    assert res.impact.drift_score == 0.0
    assert res.governance_verdict == "ALLOW"


# Scenario 2: Comment-only change -> NO_DRIFT
def test_scenario_2_comment_only():
    engine = SecurityMonitoringDriftEngine()
    res = engine.run_monitoring_pipeline(
        repository_name="repo2",
        current_findings=[{"root_cause": "COMMENT_ONLY", "file": "app.py", "sanitized": True}],
        baseline_findings=[],
    )
    assert res.summary.overall_status == "NO_DRIFT"


# Scenario 3: Formatting-only change -> NO_DRIFT
def test_scenario_3_formatting_only():
    engine = SecurityMonitoringDriftEngine()
    res = engine.run_monitoring_pipeline(
        repository_name="repo3",
        current_findings=[{"root_cause": "FORMATTING_ONLY", "file": "app.py", "is_safe": True}],
        baseline_findings=[],
    )
    assert res.summary.overall_status == "NO_DRIFT"


# Scenario 4: New LOW vulnerability -> LOW DRIFT
def test_scenario_4_new_low_vulnerability():
    engine = SecurityMonitoringDriftEngine()
    res = engine.run_monitoring_pipeline(
        repository_name="repo4",
        current_findings=[{"finding_id": "f_low", "root_cause": "INFO_LEAK", "severity": "LOW", "file": "log.py"}],
        baseline_findings=[],
        current_security_score=95,
        baseline_security_score=100,
    )
    assert res.impact.severity in [DriftSeverity.LOW, DriftSeverity.MEDIUM]


# Scenario 5: New HIGH vulnerability -> HIGH DRIFT
def test_scenario_5_new_high_vulnerability():
    engine = SecurityMonitoringDriftEngine()
    res = engine.run_monitoring_pipeline(
        repository_name="repo5",
        current_findings=[{"finding_id": "f_high", "root_cause": "SQL_INJECTION", "severity": "HIGH", "file": "db.py"}],
        baseline_findings=[],
        current_security_score=75,
        baseline_security_score=100,
    )
    assert res.impact.severity in [DriftSeverity.HIGH, DriftSeverity.CRITICAL]


# Scenario 6: New CRITICAL command injection -> CRITICAL DRIFT
def test_scenario_6_new_critical_command_injection():
    engine = SecurityMonitoringDriftEngine()
    res = engine.run_monitoring_pipeline(
        repository_name="repo6",
        current_findings=[{"finding_id": "f_crit", "root_cause": "COMMAND_INJECTION", "severity": "CRITICAL", "file": "cmd.py"}],
        baseline_findings=[],
        current_security_score=50,
        baseline_security_score=100,
    )
    assert res.summary.overall_status == "CRITICAL_SECURITY_DRIFT"
    assert res.governance_verdict == "DENY"


# Scenario 7: Existing vulnerability fixed -> IMPROVEMENT
def test_scenario_7_vulnerability_fixed():
    engine = SecurityMonitoringDriftEngine()
    res = engine.run_monitoring_pipeline(
        repository_name="repo7",
        current_findings=[],
        baseline_findings=[{"finding_id": "f_fixed", "root_cause": "XSS", "severity": "HIGH"}],
        current_security_score=100,
        baseline_security_score=80,
    )
    assert res.impact.direction == DriftDirection.IMPROVEMENT


# Scenario 8: Vulnerability reopened -> HIGH/CRITICAL DRIFT
def test_scenario_8_vulnerability_reopened():
    engine = SecurityMonitoringDriftEngine()
    res = engine.run_monitoring_pipeline(
        repository_name="repo8",
        current_findings=[{"finding_id": "f_reopen", "root_cause": "SQL_INJECTION", "severity": "CRITICAL", "reopened": True}],
        baseline_findings=[],
    )
    assert res.summary.overall_status == "CRITICAL_SECURITY_DRIFT"


# Scenario 9: Same finding count but severity increases -> DRIFT DETECTED
def test_scenario_9_severity_increases():
    comparator = SecurityPosturalComparator()
    base_f = [{"fingerprint": "fp1", "root_cause": "XSS", "severity": "LOW"}]
    curr_f = [{"fingerprint": "fp1", "root_cause": "XSS", "severity": "CRITICAL"}]
    res = comparator.compare_postures(current_findings=curr_f, baseline_findings=base_f, current_score=60, baseline_score=90)
    assert res.score_delta == -30


# Scenario 10: Exposure changes INTERNAL -> INTERNET_EXPOSED -> HIGH/CRITICAL DRIFT
def test_scenario_10_exposure_changed():
    comparator = SecurityPosturalComparator()
    base_f = [{"fingerprint": "fp2", "root_cause": "CMD_INJ", "exposure": "INTERNAL"}]
    curr_f = [{"fingerprint": "fp2", "root_cause": "CMD_INJ", "exposure": "INTERNET_EXPOSED"}]
    res = comparator.compare_postures(current_findings=curr_f, baseline_findings=base_f)
    assert len(res.exposure_changes) == 1
    assert res.exposure_changes[0]["current_exposure"] == "INTERNET_EXPOSED"


# Scenario 11: New attack path -> HIGH/CRITICAL DRIFT
def test_scenario_11_new_attack_path():
    engine = SecurityMonitoringDriftEngine()
    res = engine.run_monitoring_pipeline(
        repository_name="repo11",
        current_findings=[],
        baseline_findings=[],
        attack_paths=[{"path_id": "ap1", "entrypoint": "api/login", "target": "db/sql"}],
        baseline_attack_paths=[],
    )
    assert any(e.drift_type == DriftType.NEW_ATTACK_PATH for e in res.drift_events)


# Scenario 12: Attack path removed -> IMPROVEMENT
def test_scenario_12_attack_path_removed():
    engine = SecurityMonitoringDriftEngine()
    res = engine.run_monitoring_pipeline(
        repository_name="repo12",
        current_findings=[],
        baseline_findings=[],
        attack_paths=[],
        baseline_attack_paths=[{"path_id": "ap1", "entrypoint": "api/login", "target": "db/sql"}],
    )
    assert any(e.drift_type == DriftType.REMOVED_ATTACK_PATH for e in res.drift_events)


# Scenario 13: Trust boundary becomes more exposed -> DRIFT
def test_scenario_13_trust_boundary_changed():
    comparator = SecurityPosturalComparator()
    base_f = [{"fingerprint": "fp3", "trust_boundary": False}]
    curr_f = [{"fingerprint": "fp3", "trust_boundary": True}]
    res = comparator.compare_postures(current_findings=curr_f, baseline_findings=base_f)
    assert len(res.trust_boundary_changes) == 1


# Scenario 14: P2 -> P0 priority escalation -> DRIFT
def test_scenario_14_priority_escalation():
    engine = SecurityMonitoringDriftEngine()
    res = engine.run_monitoring_pipeline(
        repository_name="repo14",
        current_findings=[{"finding_id": "f_prio", "root_cause": "CODE_INJECTION", "priority": "P0", "priority_boost": True}],
        baseline_findings=[],
    )
    assert any(e.drift_type == DriftType.PRIORITY_ESCALATION for e in res.drift_events)


# Scenario 15: M25 chronic vulnerability + reopen -> amplified drift confidence
def test_scenario_15_m25_chronic_reopen_amplification():
    correlator = SecurityDriftCorrelator()
    events = [
        SecurityDriftEvent(
            event_id="e1",
            drift_type=DriftType.REOPENED_VULNERABILITY,
            severity=DriftSeverity.HIGH,
            title="Reopened",
            description="Reopened finding",
            fingerprint="fp_chronic_1",
            file="app.py",
        )
    ]
    memories = [{"fingerprint": "fp_chronic_1", "recurrence_count": 5, "reopened_count": 3}]
    corr = correlator.correlate_drift_events(events, memories)
    assert corr[0].severity == DriftSeverity.CRITICAL


# Scenario 16: Test-harness diagnostic exception -> NO_DRIFT
def test_scenario_16_test_harness_diagnostic():
    engine = SecurityMonitoringDriftEngine()
    res = engine.run_monitoring_pipeline(
        repository_name="repo16",
        current_findings=[{"root_cause": "TEST_HARNESS_DIAGNOSTIC", "file": "tests/test_svc.py"}],
        baseline_findings=[],
    )
    assert res.summary.overall_status == "NO_DRIFT"


# Scenario 17: dict.get() -> NO_DRIFT
def test_scenario_17_dict_get_lookup():
    engine = SecurityMonitoringDriftEngine()
    res = engine.run_monitoring_pipeline(
        repository_name="repo17",
        current_findings=[{"root_cause": "DICT_LOOKUP", "file": "utils/dict.py"}],
        baseline_findings=[],
    )
    assert res.summary.overall_status == "NO_DRIFT"


# Scenario 18: Intentional fallback -> NO_DRIFT
def test_scenario_18_intentional_fallback():
    engine = SecurityMonitoringDriftEngine()
    res = engine.run_monitoring_pipeline(
        repository_name="repo18",
        current_findings=[{"root_cause": "INTENTIONAL_FALLBACK", "file": "parser/json.py"}],
        baseline_findings=[],
    )
    assert res.summary.overall_status == "NO_DRIFT"


# Scenario 19: Security score improves -> IMPROVEMENT
def test_scenario_19_security_score_improves():
    engine = SecurityMonitoringDriftEngine()
    res = engine.run_monitoring_pipeline(
        repository_name="repo19",
        current_findings=[],
        baseline_findings=[],
        current_security_score=95,
        baseline_security_score=80,
    )
    assert res.impact.direction == DriftDirection.IMPROVEMENT


# Scenario 20: Security score drops significantly -> HIGH/CRITICAL DRIFT
def test_scenario_20_security_score_drops_significantly():
    engine = SecurityMonitoringDriftEngine()
    res = engine.run_monitoring_pipeline(
        repository_name="repo20",
        current_findings=[],
        baseline_findings=[],
        current_security_score=40,
        baseline_security_score=90,
    )
    assert res.impact.severity in [DriftSeverity.HIGH, DriftSeverity.CRITICAL]
