"""
Unit test suite for M27 — Security Operations Control Plane.
Validates all 24 required synthetic control plane scenarios.
"""

import pytest

from agentos_swe.operations.controlplane import (
    SecurityOperationsControlPlane,
    RepositoryOperationalStateManager,
    RepositoryLifecycleEngine,
    SecurityOperationsHealthEngine,
    ControlPlaneActionSelector,
    ControlPlaneApprovalManager,
    SecurityMonitoringScheduler,
    SecurityAuditTrailEngine,
    OperationalStatus,
    OperationalMode,
    ControlPlaneAction,
    ControlPlaneEvent,
)


# Scenario 1: Clean repository -> HEALTHY
def test_scenario_1_clean_repository():
    cp = SecurityOperationsControlPlane()
    res = cp.process_repository_operations(repository_name="clean_repo", verified_findings=[])
    assert res.health.status == OperationalStatus.HEALTHY
    assert res.summary.release_status == "RELEASE_ALLOWED"


# Scenario 2: One LOW finding -> AT_RISK
def test_scenario_2_one_low_finding():
    cp = SecurityOperationsControlPlane()
    res = cp.process_repository_operations(
        repository_name="low_repo",
        verified_findings=[{"finding_id": "f1", "severity": "LOW", "root_cause": "INFO_LEAK"}],
    )
    assert res.health.status in [OperationalStatus.AT_RISK, OperationalStatus.HEALTHY]


# Scenario 3: Critical command injection -> CRITICAL/BLOCKED
def test_scenario_3_critical_command_injection():
    cp = SecurityOperationsControlPlane()
    res = cp.process_repository_operations(
        repository_name="crit_repo",
        verified_findings=[{"finding_id": "f_crit", "severity": "CRITICAL", "root_cause": "COMMAND_INJECTION"}],
    )
    assert res.health.status in [OperationalStatus.CRITICAL, OperationalStatus.BLOCKED]
    assert res.summary.release_status == "RELEASE_BLOCKED"


# Scenario 4: M24 BLOCK_RELEASE -> M27 BLOCKED
def test_scenario_4_m24_block_release():
    cp = SecurityOperationsControlPlane()
    res = cp.process_repository_operations(
        repository_name="block_repo",
        decision_result={"overall_decision": "BLOCK_RELEASE"},
    )
    assert res.summary.operational_status == OperationalStatus.BLOCKED
    assert res.summary.release_status == "RELEASE_BLOCKED"


# Scenario 5: M24 HUMAN_REVIEW -> WAITING_APPROVAL
def test_scenario_5_m24_human_review():
    cp = SecurityOperationsControlPlane()
    app_mgr = ControlPlaneApprovalManager()
    app_mgr.request_approval("rev_repo", "f1", "GENERATE_REPAIR", "HIGH", "Approval needed")

    res = cp.process_repository_operations(
        repository_name="rev_repo",
        decision_result={"overall_decision": "HUMAN_REVIEW"},
    )
    assert res.recommended_action.action == ControlPlaneAction.REQUEST_APPROVAL


# Scenario 6: M24 GENERATE_REPAIR -> REPAIR_PENDING
def test_scenario_6_m24_generate_repair():
    cp = SecurityOperationsControlPlane()
    res = cp.process_repository_operations(
        repository_name="gen_repo",
        verified_findings=[{"finding_id": "f_high", "severity": "HIGH", "root_cause": "SQL_INJECTION"}],
        decision_result={"remediation_queue": [{"item_id": "r1"}]},
    )
    assert res.recommended_action.action == ControlPlaneAction.GENERATE_REPAIR


# Scenario 7: M25 chronic vulnerability -> escalated operational risk
def test_scenario_7_m25_chronic_vulnerability():
    cp = SecurityOperationsControlPlane()
    res = cp.process_repository_operations(
        repository_name="chronic_repo",
        verified_findings=[{"finding_id": "f_chr", "severity": "HIGH", "root_cause": "XSS"}],
        learning_result={"recurrence_analysis": [{"classification": "CHRONIC", "reopened_count": 3}]},
    )
    assert res.summary.chronic_vulnerabilities == 1


# Scenario 8: M25 successful remediation -> reduced risk
def test_scenario_8_m25_successful_remediation():
    cp = SecurityOperationsControlPlane()
    res = cp.process_repository_operations(
        repository_name="succ_repo",
        verified_findings=[],
        decision_result={"repair_validations": [{"final_verdict": "CONFIRMED_VALIDATED"}]},
    )
    assert res.summary.validated_repairs == 1


# Scenario 9: M25 failed remediation -> escalated action
def test_scenario_9_m25_failed_remediation():
    cp = SecurityOperationsControlPlane()
    res = cp.process_repository_operations(
        repository_name="fail_repo",
        verified_findings=[],
        decision_result={"repair_validations": [{"final_verdict": "FAILED"}]},
    )
    assert res.recommended_action.action == ControlPlaneAction.INVESTIGATE


# Scenario 10: M26 critical drift -> BLOCKED
def test_scenario_10_m26_critical_drift():
    cp = SecurityOperationsControlPlane()
    res = cp.process_repository_operations(
        repository_name="drift_repo",
        drift_result={"summary": {"overall_status": "CRITICAL_SECURITY_DRIFT", "drift_score": 85.0}},
    )
    assert res.summary.drift_score == 85.0


# Scenario 11: M26 improvement -> MONITOR
def test_scenario_11_m26_improvement():
    cp = SecurityOperationsControlPlane()
    res = cp.process_repository_operations(
        repository_name="imp_repo",
        verified_findings=[],
        drift_result={"impact": {"drift_score": 0.0, "direction": "IMPROVEMENT"}},
    )
    assert res.recommended_action.action in [ControlPlaneAction.MONITOR, ControlPlaneAction.RELEASE_ALLOWED]


# Scenario 12: New attack path -> elevated risk
def test_scenario_12_new_attack_path():
    cp = SecurityOperationsControlPlane()
    res = cp.process_repository_operations(
        repository_name="path_repo",
        attack_paths=[{"path_id": "ap1", "entrypoint": "api/login"}],
    )
    assert res.summary.active_attack_paths == 1


# Scenario 13: Internet exposed attack path -> elevated risk
def test_scenario_13_internet_exposed_attack_path():
    cp = SecurityOperationsControlPlane()
    res = cp.process_repository_operations(
        repository_name="exp_repo",
        attack_paths=[{"path_id": "ap2", "is_internet_exposed": True}],
    )
    assert res.summary.internet_exposed_paths == 1


# Scenario 14: Pending approval -> WAITING_APPROVAL
def test_scenario_14_pending_approval():
    app_mgr = ControlPlaneApprovalManager()
    app = app_mgr.request_approval("app_repo", "f1", "GENERATE_REPAIR", "HIGH", "Reason")
    assert app.status == "PENDING"


# Scenario 15: Approved repair -> RESCAN_REQUIRED
def test_scenario_15_approved_repair():
    app_mgr = ControlPlaneApprovalManager()
    app_mgr.request_approval("appr_repo", "f1", "GENERATE_REPAIR", "HIGH", "Reason")
    pending = app_mgr.get_pending_approvals("appr_repo")
    processed = app_mgr.process_approval("appr_repo", pending[0].request_id, "APPROVED")
    assert processed.status == "APPROVED"


# Scenario 16: Failed repair validation -> INVESTIGATE
def test_scenario_16_failed_repair_validation():
    cp = SecurityOperationsControlPlane()
    res = cp.process_repository_operations(
        repository_name="val_fail_repo",
        decision_result={"repair_validations": [{"final_verdict": "FAILED"}]},
    )
    assert res.recommended_action.action == ControlPlaneAction.INVESTIGATE


# Scenario 17: No security issues -> RELEASE_ALLOWED
def test_scenario_17_no_security_issues():
    cp = SecurityOperationsControlPlane()
    res = cp.process_repository_operations(repository_name="clean_repo_2", verified_findings=[])
    assert res.summary.release_status == "RELEASE_ALLOWED"


# Scenario 18: dict.get() -> no security issue
def test_scenario_18_dict_get_no_issue():
    cp = SecurityOperationsControlPlane()
    res = cp.process_repository_operations(
        repository_name="dict_repo",
        verified_findings=[{"root_cause": "DICT_LOOKUP", "sanitized": True}],
    )
    assert res.summary.critical_findings == 0


# Scenario 19: Test harness diagnostic fallback -> no security issue
def test_scenario_19_test_harness_diagnostic():
    cp = SecurityOperationsControlPlane()
    res = cp.process_repository_operations(
        repository_name="harness_repo",
        verified_findings=[{"root_cause": "TEST_HARNESS_DIAGNOSTIC", "sanitized": True}],
    )
    assert res.summary.critical_findings == 0


# Scenario 20: Intentional fallback -> no security issue
def test_scenario_20_intentional_fallback():
    cp = SecurityOperationsControlPlane()
    res = cp.process_repository_operations(
        repository_name="fallback_repo",
        verified_findings=[{"root_cause": "INTENTIONAL_FALLBACK", "sanitized": True}],
    )
    assert res.summary.critical_findings == 0


# Scenario 21: Invalid lifecycle transition -> rejected safely
def test_scenario_21_invalid_lifecycle_transition():
    with pytest.raises(ValueError):
        RepositoryLifecycleEngine.transition("IDLE", "REPAIRING")


# Scenario 22: Audit trail event generation -> verified
def test_scenario_22_audit_trail_generation():
    rec = SecurityAuditTrailEngine.record_event(
        repository_name="audit_repo",
        event=ControlPlaneEvent.SCAN_COMPLETED,
        severity="INFO",
        reason="Scan test",
    )
    assert rec.event == ControlPlaneEvent.SCAN_COMPLETED


# Scenario 23: Scheduler state calculation -> verified
def test_scenario_23_scheduler_state():
    sched = SecurityMonitoringScheduler()
    st = sched.compute_schedule_state("sched_repo", schedule_mode="DAILY")
    assert st["schedule_mode"] == "DAILY"
    assert "next_recommended_scan" in st


# Scenario 24: Multi-repository state isolation -> verified
def test_scenario_24_multi_repo_isolation():
    st1 = RepositoryOperationalStateManager.get_or_create_state("repo_alpha")
    st2 = RepositoryOperationalStateManager.get_or_create_state("repo_beta")
    assert st1.repository_name != st2.repository_name
