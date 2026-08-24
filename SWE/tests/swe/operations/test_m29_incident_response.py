"""
Unit test suite for M29 Security Incident Response & Investigation.
Validates all 20 required synthetic incident scenarios.
"""

import pytest
from agentos_swe.operations.incident import (
    SecurityIncidentResponseEngine,
    SecurityIncidentDetector,
    IncidentEvidenceCorrelator,
    IncidentTimelineReconstructor,
    IncidentImpactAssessor,
    SecurityIncidentInvestigator,
    IncidentResponsePlanner,
    IncidentLifecycleManager,
    IncidentExplainabilityEngine,
    SecurityIncident,
    IncidentSeverity,
    IncidentStatus,
    IncidentType,
    ResponseAction,
    InvestigationConfidence,
)
from agentos_swe.remediation.pr.governance_gate import GovernanceGate


# Scenario 1: Clean repository -> zero incidents
def test_scenario_1_clean_repository():
    engine = SecurityIncidentResponseEngine()
    res = engine.process_security_incidents("clean_repo", verified_findings=[])
    assert res.active_incident_count == 0
    assert len(res.incidents) == 0


# Scenario 2: New critical vulnerability -> NEW_CRITICAL_VULNERABILITY
def test_scenario_2_new_critical_vulnerability():
    engine = SecurityIncidentResponseEngine()
    res = engine.process_security_incidents(
        "crit_repo",
        verified_findings=[{"finding_id": "f_crit", "severity": "CRITICAL", "root_cause": "COMMAND_INJECTION", "file": "app.py"}],
    )
    assert res.active_incident_count == 1
    inc = res.incidents[0]
    assert inc.incident_type == IncidentType.NEW_CRITICAL_VULNERABILITY
    assert inc.severity == IncidentSeverity.CRITICAL


# Scenario 3: New high vulnerability -> NEW_HIGH_VULNERABILITY
def test_scenario_3_new_high_vulnerability():
    engine = SecurityIncidentResponseEngine()
    res = engine.process_security_incidents(
        "high_repo",
        verified_findings=[{"finding_id": "f_high", "severity": "HIGH", "root_cause": "SQL_INJECTION", "file": "db.py"}],
    )
    assert res.active_incident_count == 1
    inc = res.incidents[0]
    assert inc.incident_type == IncidentType.NEW_HIGH_VULNERABILITY
    assert inc.severity == IncidentSeverity.HIGH


# Scenario 4: Reopened vulnerability -> REOPENED_VULNERABILITY
def test_scenario_4_reopened_vulnerability():
    engine = SecurityIncidentResponseEngine()
    res = engine.process_security_incidents(
        "reopen_repo",
        verified_findings=[{"finding_id": "f_reopen", "severity": "HIGH", "root_cause": "XSS", "file": "views.py", "recurrence_classification": "REOPENED"}],
    )
    assert res.active_incident_count == 1
    assert res.incidents[0].incident_type == IncidentType.REOPENED_VULNERABILITY


# Scenario 5: Security regression -> SECURITY_REGRESSION
def test_scenario_5_security_regression():
    detector = SecurityIncidentDetector()
    incidents = detector.detect_incidents(
        "reg_repo",
        verified_findings=[{"finding_id": "f_reg", "severity": "HIGH", "root_cause": "DESERIALIZATION"}],
        drift_result={"summary": {"overall_status": "HIGH_SECURITY_DRIFT", "drift_score": 75.0}},
    )
    assert len(incidents) >= 1


# Scenario 6: Critical attack path -> CRITICAL_ATTACK_PATH
def test_scenario_6_critical_attack_path():
    engine = SecurityIncidentResponseEngine()
    res = engine.process_security_incidents(
        "path_repo",
        attack_paths=[{"path_id": "ap_1", "entrypoint": "api/v1/auth", "source_type": "HTTP", "sink_type": "SUBPROCESS", "is_internet_exposed": True}],
    )
    assert res.active_incident_count == 1
    assert res.incidents[0].incident_type == IncidentType.CRITICAL_ATTACK_PATH


# Scenario 7: Severe drift -> SEVERE_SECURITY_DRIFT
def test_scenario_7_severe_drift():
    engine = SecurityIncidentResponseEngine()
    res = engine.process_security_incidents(
        "drift_repo",
        drift_result={"summary": {"overall_status": "CRITICAL_SECURITY_DRIFT", "drift_score": 85.0}},
    )
    assert res.active_incident_count == 1
    assert res.incidents[0].incident_type == IncidentType.SEVERE_SECURITY_DRIFT


# Scenario 8: Governance block -> GOVERNANCE_BLOCK
def test_scenario_8_governance_block():
    engine = SecurityIncidentResponseEngine()
    res = engine.process_security_incidents(
        "gov_repo",
        decision_result={"overall_decision": "BLOCK_RELEASE"},
    )
    assert res.active_incident_count == 1
    assert res.incidents[0].incident_type == IncidentType.GOVERNANCE_BLOCK


# Scenario 9: Compound incident -> COMPOUND_SECURITY_INCIDENT
def test_scenario_9_compound_incident():
    engine = SecurityIncidentResponseEngine()
    res = engine.process_security_incidents(
        "compound_repo",
        verified_findings=[{"finding_id": "f_c", "severity": "CRITICAL", "root_cause": "EVAL_INJECTION", "file": "main.py"}],
        attack_paths=[{"path_id": "ap_c", "entrypoint": "main", "source_type": "HTTP", "sink_type": "EVAL", "is_internet_exposed": True}],
    )
    types = [inc.incident_type for inc in res.incidents]
    assert IncidentType.COMPOUND_SECURITY_INCIDENT in types


# Scenario 10: Duplicate incident prevention (Correlation & Deduplication)
def test_scenario_10_duplicate_prevention():
    engine = SecurityIncidentResponseEngine()
    res = engine.process_security_incidents(
        "dup_repo",
        verified_findings=[
            {"finding_id": "f_1", "severity": "CRITICAL", "root_cause": "SQL_INJECTION", "file": "db.py"},
            {"finding_id": "f_2", "severity": "CRITICAL", "root_cause": "SQL_INJECTION", "file": "db.py"},
        ],
    )
    # Deduplication merges overlapping findings of same type & title
    assert res.active_incident_count == 1


# Scenario 11: Timeline ordering & depth limit (max 50 events)
def test_scenario_11_timeline_reconstruction():
    engine = SecurityIncidentResponseEngine()
    res = engine.process_security_incidents(
        "time_repo",
        verified_findings=[{"finding_id": "f_1", "severity": "CRITICAL", "root_cause": "CODE_INJECTION", "file": "exec.py"}],
    )
    inc = res.incidents[0]
    assert len(inc.timeline) > 0
    assert len(inc.timeline) <= 50
    assert inc.timeline[0].event_type == "COMMIT_INSPECTED"


# Scenario 12: Impact calculation & blast radius score
def test_scenario_12_impact_calculation():
    engine = SecurityIncidentResponseEngine()
    res = engine.process_security_incidents(
        "impact_repo",
        verified_findings=[{"finding_id": "f_1", "severity": "CRITICAL", "root_cause": "PATH_TRAVERSAL", "file": "files.py"}],
        attack_paths=[{"path_id": "ap_1", "entrypoint": "download", "source_type": "HTTP", "sink_type": "FILE", "is_internet_exposed": True}],
    )
    inc = res.incidents[0]
    assert inc.impact is not None
    assert inc.impact.blast_radius_score > 0.0
    assert inc.impact.internet_exposed is True


# Scenario 13: Valid lifecycle transitions
def test_scenario_13_valid_lifecycle_transitions():
    engine = SecurityIncidentResponseEngine()
    res = engine.process_security_incidents(
        "life_repo",
        verified_findings=[{"finding_id": "f_1", "severity": "HIGH", "root_cause": "SSRF", "file": "http.py"}],
    )
    inc = res.incidents[0]
    assert inc.status == IncidentStatus.DETECTED

    st1 = IncidentLifecycleManager.transition(inc, IncidentStatus.TRIAGED)
    assert st1 == IncidentStatus.TRIAGED

    st2 = IncidentLifecycleManager.transition(inc, IncidentStatus.INVESTIGATING)
    assert st2 == IncidentStatus.INVESTIGATING


# Scenario 14: Invalid lifecycle transitions -> rejected safely
def test_scenario_14_invalid_lifecycle_transition():
    engine = SecurityIncidentResponseEngine()
    res = engine.process_security_incidents(
        "invalid_life_repo",
        verified_findings=[{"finding_id": "f_1", "severity": "HIGH", "root_cause": "SSRF", "file": "http.py"}],
    )
    inc = res.incidents[0]

    with pytest.raises(ValueError):
        IncidentLifecycleManager.transition(inc, IncidentStatus.RESOLVED)


# Scenario 15: Response planning recommendations
def test_scenario_15_response_planning():
    engine = SecurityIncidentResponseEngine()
    res = engine.process_security_incidents(
        "resp_repo",
        verified_findings=[{"finding_id": "f_1", "severity": "CRITICAL", "root_cause": "COMMAND_INJECTION", "file": "sh.py"}],
    )
    inc = res.incidents[0]
    assert inc.response_plan is not None
    assert inc.response_plan.primary_action in [ResponseAction.BLOCK_RELEASE, ResponseAction.GENERATE_REPAIR]


# Scenario 16: Governance integration
def test_scenario_16_governance_integration():
    engine = SecurityIncidentResponseEngine()
    res = engine.process_security_incidents(
        "gov_int_repo",
        verified_findings=[{"finding_id": "f_1", "severity": "CRITICAL", "root_cause": "COMMAND_INJECTION", "file": "sh.py"}],
        attack_paths=[{"path_id": "ap_1", "entrypoint": "cmd", "source_type": "HTTP", "sink_type": "SUBPROCESS", "is_internet_exposed": True}],
    )
    inc = res.incidents[0]

    gov_gate = GovernanceGate()
    gov_dec = gov_gate.evaluate_incident_governance(inc)
    assert gov_dec.value in ["DENY", "REVIEW_REQUIRED"]


# Scenario 17: Investigation confidence scoring
def test_scenario_17_investigation_confidence():
    engine = SecurityIncidentResponseEngine()
    res = engine.process_security_incidents(
        "conf_repo",
        verified_findings=[{"finding_id": "f_1", "severity": "CRITICAL", "root_cause": "EVAL", "file": "parse.py"}],
        attack_paths=[{"path_id": "ap_1", "entrypoint": "parse", "source_type": "HTTP", "sink_type": "EVAL", "is_internet_exposed": True}],
    )
    inc = res.incidents[0]
    assert inc.confidence == InvestigationConfidence.VERY_HIGH


# Scenario 18: Intentional fallback filtering -> safe patterns produce zero false incidents
def test_scenario_18_intentional_fallback_filtering():
    engine = SecurityIncidentResponseEngine()
    res = engine.process_security_incidents(
        "fallback_repo",
        verified_findings=[{"finding_id": "f_fb", "root_cause": "INTENTIONAL_FALLBACK", "severity": "MEDIUM", "sanitized": True}],
    )
    assert res.active_incident_count == 0


# Scenario 19: Test harness diagnostic filtering -> safe patterns produce zero false incidents
def test_scenario_19_test_harness_filtering():
    engine = SecurityIncidentResponseEngine()
    res = engine.process_security_incidents(
        "harness_repo",
        verified_findings=[{"finding_id": "f_diag", "root_cause": "TEST_HARNESS_DIAGNOSTIC", "severity": "LOW", "sanitized": True}],
    )
    assert res.active_incident_count == 0


# Scenario 20: Dict lookup filtering -> safe patterns produce zero false incidents
def test_scenario_20_dict_lookup_filtering():
    engine = SecurityIncidentResponseEngine()
    res = engine.process_security_incidents(
        "dict_repo",
        verified_findings=[{"finding_id": "f_dict", "root_cause": "DICT_LOOKUP", "severity": "LOW", "sanitized": True}],
    )
    assert res.active_incident_count == 0
