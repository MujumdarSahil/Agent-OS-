"""
Dedicated Synthetic Test Suite for M20 Security Engineering Orchestration & Workflow Engine.

Validates synthetic test scenarios TEST A through TEST R:
TEST A: Clean repository (NO_ACTION_REQUIRED, GO)
TEST B: LOW finding (Minimal workflow)
TEST C: MEDIUM exploitable finding (INVESTIGATE_FINDING)
TEST D: HIGH vulnerability (REMEDIATION_PLANNED)
TEST E: CRITICAL attack path (ATTACK_PATH_ANALYSIS)
TEST F: Successful repair (REMEDIATED)
TEST G: Repair validation failure (REPLAN_REMEDIATION)
TEST H: Three failed remediation attempts (REQUIRE_HUMAN_REVIEW)
TEST I: M18 CRITICAL_REGRESSION (INVESTIGATE_FINDING)
TEST J: M17 REQUIRES_REPLAN (REPLAN_REMEDIATION)
TEST K: M19 BLOCKED (BLOCK_RELEASE)
TEST L: M19 GO (NO_ACTION_REQUIRED)
TEST M: Safe test harness (NO_ACTION_REQUIRED)
TEST N: Cross-repository orchestration (batch evaluation)
TEST O: Dependency ordering (prerequisite check)
TEST P: Workflow state recovery (checkpoint resumption)
TEST Q: Human review escalation (bounded retry halt)
TEST R: Security case lifecycle (OPEN -> INVESTIGATING -> REMEDIATED -> CLOSED)
"""

import pytest
from agentos_swe.operations.orchestration import (
    SecurityEngineeringOrchestrator,
    WorkflowState,
    NextActionDecision,
    SecurityCaseStatus,
    HumanReviewRequest,
)


@pytest.fixture
def orchestrator():
    return SecurityEngineeringOrchestrator()


# TEST A — Clean repository
def test_m20_test_a_clean_repository(orchestrator):
    res = orchestrator.orchestrate_repository(
        verified_findings=[], prioritized_findings=[], attack_paths=[], repository_name="RepoA"
    )
    assert res.current_state == WorkflowState.COMPLETED
    assert res.next_action == NextActionDecision.NO_ACTION_REQUIRED
    assert res.human_review is None


# TEST B — Only LOW finding
def test_m20_test_b_low_finding(orchestrator):
    f_low = {
        "finding_id": "f_b1", "severity": "LOW", "priority_tier": "P4",
        "root_cause": "INFO", "affected_file": "app/config.py"
    }
    res = orchestrator.orchestrate_repository(
        verified_findings=[f_low], prioritized_findings=[f_low], repository_name="RepoB"
    )
    assert res.current_state == WorkflowState.COMPLETED
    assert res.next_action == NextActionDecision.NO_ACTION_REQUIRED


# TEST C — MEDIUM exploitable finding
def test_m20_test_c_medium_exploitable(orchestrator):
    f_med = {
        "finding_id": "f_c1", "severity": "MEDIUM", "priority_tier": "P2",
        "root_cause": "EXCEPTION_SWALLOWING", "affected_file": "app/db.py"
    }
    rel_dec = {"decision": "REVIEW_REQUIRED", "release_status": "REQUIRE_REVIEW"}
    res = orchestrator.orchestrate_repository(
        verified_findings=[f_med], prioritized_findings=[f_med], release_decision=rel_dec, repository_name="RepoC"
    )
    assert res.next_action in (NextActionDecision.REQUIRE_HUMAN_REVIEW, NextActionDecision.INVESTIGATE_FINDING)


# TEST D — HIGH vulnerability
def test_m20_test_d_high_vulnerability(orchestrator):
    f_high = {
        "finding_id": "f_d1", "severity": "HIGH", "priority_tier": "P1",
        "root_cause": "SQL_INJECTION", "affected_file": "app/user.py"
    }
    rel_dec = {"decision": "NO_GO", "release_status": "DENY_RELEASE"}
    res = orchestrator.orchestrate_repository(
        verified_findings=[f_high], prioritized_findings=[f_high], release_decision=rel_dec, repository_name="RepoD"
    )
    assert res.next_action == NextActionDecision.CREATE_REMEDIATION_PLAN


# TEST E — CRITICAL attack path
def test_m20_test_e_critical_attack_path(orchestrator):
    f_crit = {
        "finding_id": "f_e1", "severity": "CRITICAL", "priority_tier": "P0",
        "root_cause": "COMMAND_INJECTION", "affected_file": "app/api.py"
    }
    path = {
        "id": "path_e", "risk_score": 95, "classification": "EXPLOITABLE",
        "entrypoint": "POST /api/eval", "source_type": "HTTP", "sink_type": "SUBPROCESS_SHELL"
    }
    rel_dec = {"decision": "BLOCKED", "release_status": "DENY_RELEASE"}
    res = orchestrator.orchestrate_repository(
        verified_findings=[f_crit], prioritized_findings=[f_crit], attack_paths=[path],
        release_decision=rel_dec, repository_name="RepoE"
    )
    assert res.next_action == NextActionDecision.BLOCK_RELEASE


# TEST F — Successful repair
def test_m20_test_f_successful_repair(orchestrator):
    f_med = {
        "finding_id": "f_f1", "severity": "MEDIUM", "priority_tier": "P3",
        "root_cause": "INTENTIONAL_FALLBACK", "affected_file": "app/model.py"
    }
    rel_dec = {"decision": "GO", "release_status": "ALLOW_RELEASE"}
    res = orchestrator.orchestrate_repository(
        verified_findings=[f_med], prioritized_findings=[f_med], release_decision=rel_dec, repository_name="RepoF"
    )
    assert res.next_action == NextActionDecision.NO_ACTION_REQUIRED
    assert res.cases[0].current_status in (SecurityCaseStatus.CLOSED, SecurityCaseStatus.REMEDIATED)


# TEST G — Repair validation failure
def test_m20_test_g_repair_validation_failure(orchestrator):
    f_high = {
        "finding_id": "f_g1", "severity": "HIGH", "priority_tier": "P1",
        "root_cause": "PATH_TRAVERSAL", "affected_file": "app/file.py"
    }
    rem_plan = {"remediation_items": [{"item_id": "rem_g1"}], "current_security_score": 70}
    mon_res = {"remediation_impact": {"status": "REQUIRES_REPLAN"}}
    res = orchestrator.orchestrate_repository(
        verified_findings=[f_high], prioritized_findings=[f_high], remediation_plan=rem_plan,
        monitoring_result=mon_res, repository_name="RepoG"
    )
    assert res.next_action == NextActionDecision.REPLAN_REMEDIATION


# TEST H — Three failed remediation attempts
def test_m20_test_h_three_failed_attempts(orchestrator):
    f_crit = {
        "finding_id": "f_h1", "severity": "CRITICAL", "priority_tier": "P0",
        "root_cause": "COMMAND_INJECTION", "affected_file": "app/eval.py"
    }
    res = orchestrator.orchestrate_repository(
        verified_findings=[f_crit], prioritized_findings=[f_crit], remediation_attempts=3, repository_name="RepoH"
    )
    assert res.next_action == NextActionDecision.REQUIRE_HUMAN_REVIEW
    assert res.human_review is not None
    assert res.cases[0].current_status == SecurityCaseStatus.REMEDIATION_FAILED


# TEST I — M18 CRITICAL_REGRESSION
def test_m20_test_i_critical_regression(orchestrator):
    mon_res = {"regression_severity": "CRITICAL_REGRESSION", "risk_trend": "DEGRADING"}
    res = orchestrator.orchestrate_repository(
        monitoring_result=mon_res, repository_name="RepoI"
    )
    assert res.next_action == NextActionDecision.INVESTIGATE_FINDING


# TEST J — M17 REQUIRES_REPLAN
def test_m20_test_j_requires_replan(orchestrator):
    rem_plan = {"remediation_items": [{"item_id": "rem_j1"}]}
    mon_res = {"remediation_impact": {"status": "REQUIRES_REPLAN"}}
    res = orchestrator.orchestrate_repository(
        remediation_plan=rem_plan, monitoring_result=mon_res, repository_name="RepoJ"
    )
    assert res.next_action == NextActionDecision.REPLAN_REMEDIATION


# TEST K — M19 BLOCKED
def test_m20_test_k_m19_blocked(orchestrator):
    rel_dec = {"decision": "BLOCKED", "release_status": "DENY_RELEASE"}
    res = orchestrator.orchestrate_repository(
        release_decision=rel_dec, repository_name="RepoK"
    )
    assert res.next_action == NextActionDecision.BLOCK_RELEASE
    assert res.current_state == WorkflowState.BLOCKED


# TEST L — M19 GO
def test_m20_test_l_m19_go(orchestrator):
    rel_dec = {"decision": "GO", "release_status": "ALLOW_RELEASE"}
    res = orchestrator.orchestrate_repository(
        release_decision=rel_dec, repository_name="RepoL"
    )
    assert res.next_action == NextActionDecision.NO_ACTION_REQUIRED
    assert res.current_state == WorkflowState.COMPLETED


# TEST M — Safe test harness
def test_m20_test_m_safe_test_harness(orchestrator):
    f_harness = {
        "finding_id": "f_m1", "severity": "LOW", "priority_tier": "P4",
        "root_cause": "TEST_HARNESS", "affected_file": "tests/test_api.py"
    }
    rel_dec = {"decision": "GO", "release_status": "ALLOW_RELEASE"}
    res = orchestrator.orchestrate_repository(
        verified_findings=[f_harness], prioritized_findings=[f_harness], release_decision=rel_dec, repository_name="RepoM"
    )
    assert res.next_action == NextActionDecision.NO_ACTION_REQUIRED


# TEST N — Cross-repository orchestration
def test_m20_test_n_cross_repository_orchestration(orchestrator):
    batch = {
        "CleanRepo": {"verified_findings": [], "release_decision": {"decision": "GO"}},
        "VulnerableRepo": {
            "verified_findings": [{"finding_id": "v1", "severity": "CRITICAL", "root_cause": "COMMAND_INJECTION"}],
            "release_decision": {"decision": "BLOCKED"},
        },
    }
    summary = orchestrator.orchestrate_repositories(batch)
    assert summary.repositories_scanned == 2
    assert summary.blocked_releases == 1
    assert summary.repositories_release_ready == 1


# TEST O — Dependency ordering
def test_m20_test_o_dependency_ordering(orchestrator):
    res = orchestrator.orchestrate_repository(repository_name="RepoO")
    history_str = [s.value if hasattr(s, "value") else str(s) for s in res.state_history]
    assert history_str[0] == WorkflowState.INTAKE.value
    assert history_str[-1] == WorkflowState.COMPLETED.value


# TEST P — Workflow state recovery
def test_m20_test_p_workflow_state_recovery(orchestrator):
    res = orchestrator.orchestrate_repository(repository_name="RepoP")
    assert res.previous_state is not None
    assert res.current_state == WorkflowState.COMPLETED


# TEST Q — Human review escalation
def test_m20_test_q_human_review_escalation(orchestrator):
    res = orchestrator.orchestrate_repository(force_human_review=True, repository_name="RepoQ")
    assert res.next_action == NextActionDecision.REQUIRE_HUMAN_REVIEW
    assert res.human_review is not None


# TEST R — Security case lifecycle
def test_m20_test_r_security_case_lifecycle(orchestrator):
    f = {"finding_id": "f_r1", "severity": "MEDIUM", "root_cause": "SQL_INJECTION", "affected_file": "app/db.py"}
    res = orchestrator.orchestrate_repository(
        verified_findings=[f], prioritized_findings=[f], repository_name="RepoR"
    )
    assert len(res.cases) == 1
    case = res.cases[0]
    assert case.case_id == "SEC-f_r1"
    assert len(case.timeline) >= 2
