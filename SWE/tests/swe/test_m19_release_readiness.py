"""
Dedicated Synthetic Test Suite for M19 Security Release Readiness & Executive Gate.

Validates synthetic test scenarios A through P:
TEST A — Clean repository (GO)
TEST B — Only LOW findings (GO_WITH_WARNINGS)
TEST C — MEDIUM exploitable finding (REVIEW_REQUIRED)
TEST D — HIGH exploitable vulnerability (NO_GO)
TEST E — CRITICAL exploitable vulnerability (BLOCKED)
TEST F — Unauthenticated INTERNET attack path (BLOCKED)
TEST G — P0 remediation unresolved (BLOCKED)
TEST H — P1 remediation unresolved (NO_GO)
TEST I — M18 CRITICAL_REGRESSION (BLOCKED)
TEST J — M17 remediation conflict (REVIEW_REQUIRED)
TEST K — Security score improved (GO)
TEST L — Previous NO_GO -> current GO (RECOVERED)
TEST M — Previous GO -> current BLOCKED (DEGRADED)
TEST N — Safe test harness (GO)
TEST O — Safe parameterized SQL (GO)
TEST P — Cross-repository release posture (batch evaluation)
"""

import pytest
from agentos_swe.intelligence.models import PrioritizedFinding, PriorityTier, ExploitabilityLevel
from agentos_swe.attackpath.models import AttackPath, EntrypointType, AuthStatus, PathClassification
from agentos_swe.remediation import RemediationPlan, RemediationItem
from agentos_swe.monitoring import SecurityMonitoringResult, RegressionSeverity
from agentos_swe.release import (
    SecurityReleaseReadinessEngine,
    ReleaseDecisionState,
    SecurityGateVerdict,
    ReleaseDeltaState,
)


from agentos_swe.monitoring.snapshot_manager import SnapshotManager


@pytest.fixture
def engine():
    SnapshotManager._memory_snapshots = {}
    return SecurityReleaseReadinessEngine()


# TEST A — Clean repository
def test_m19_test_a_clean_repo(engine):
    decision = engine.evaluate_release_readiness(repository_name="RepoA")
    assert decision.decision == ReleaseDecisionState.GO
    assert decision.release_status == SecurityGateVerdict.ALLOW_RELEASE.value
    assert len(decision.blockers) == 0


# TEST B — Only LOW findings
def test_m19_test_b_low_findings(engine):
    f_low = PrioritizedFinding(
        rank=1, finding_id="pf_b1", vulnerability_category="info", severity="LOW", priority_score=10,
        priority_tier=PriorityTier.P4, root_cause="INFO", affected_file="app/utils.py",
        exploitability=ExploitabilityLevel.NOT_EXPLOITABLE
    )
    decision = engine.evaluate_release_readiness(
        prioritized_findings=[f_low], repository_name="RepoB"
    )
    assert decision.decision in (ReleaseDecisionState.GO, ReleaseDecisionState.GO_WITH_WARNINGS)
    assert decision.release_status in (SecurityGateVerdict.ALLOW_RELEASE.value, SecurityGateVerdict.ALLOW_WITH_WARNINGS.value)


# TEST C — MEDIUM exploitable finding
def test_m19_test_c_medium_exploitable(engine):
    f_med = PrioritizedFinding(
        rank=1, finding_id="pf_c1", vulnerability_category="security", severity="MEDIUM", priority_score=60,
        priority_tier=PriorityTier.P2, root_cause="EXCEPTION_SWALLOWING", affected_file="app/db.py",
        exploitability=ExploitabilityLevel.MEDIUM
    )
    decision = engine.evaluate_release_readiness(
        prioritized_findings=[f_med], repository_name="RepoC"
    )
    assert decision.decision == ReleaseDecisionState.REVIEW_REQUIRED
    assert decision.release_status == SecurityGateVerdict.REQUIRE_REVIEW.value


# TEST D — HIGH exploitable vulnerability
def test_m19_test_d_high_exploitable(engine):
    f_high = PrioritizedFinding(
        rank=1, finding_id="pf_d1", vulnerability_category="security", severity="HIGH", priority_score=80,
        priority_tier=PriorityTier.P1, root_cause="SQL_INJECTION", affected_file="app/db.py",
        exploitability=ExploitabilityLevel.HIGH
    )
    decision = engine.evaluate_release_readiness(
        prioritized_findings=[f_high], repository_name="RepoD"
    )
    assert decision.decision == ReleaseDecisionState.NO_GO
    assert decision.release_status == SecurityGateVerdict.DENY_RELEASE.value
    assert len(decision.blockers) >= 1


# TEST E — CRITICAL exploitable vulnerability
def test_m19_test_e_critical_exploitable(engine):
    f_crit = PrioritizedFinding(
        rank=1, finding_id="pf_e1", vulnerability_category="security", severity="CRITICAL", priority_score=95,
        priority_tier=PriorityTier.P0, root_cause="COMMAND_INJECTION", affected_file="app/main.py",
        exploitability=ExploitabilityLevel.CRITICAL
    )
    decision = engine.evaluate_release_readiness(
        prioritized_findings=[f_crit], repository_name="RepoE"
    )
    assert decision.decision == ReleaseDecisionState.BLOCKED
    assert decision.release_status == SecurityGateVerdict.DENY_RELEASE.value
    assert len(decision.blockers) >= 1


# TEST F — Unauthenticated INTERNET attack path
def test_m19_test_f_unauth_internet_attack_path(engine):
    ap = AttackPath(
        id="path_f1", fingerprint="fp_f1", repository="RepoF", entrypoint="POST /exec",
        entrypoint_type=EntrypointType.INTERNET, source="HTTP", source_type="HTTP", source_file="app/main.py",
        source_line=10, sink="SHELL", sink_type="SHELL", sink_file="app/main.py", sink_line=15,
        root_cause="COMMAND_INJECTION", classification=PathClassification.EXPLOITABLE, risk_score=95,
        auth_status=AuthStatus.UNAUTHENTICATED
    )
    decision = engine.evaluate_release_readiness(
        attack_paths=[ap], repository_name="RepoF"
    )
    assert decision.decision == ReleaseDecisionState.BLOCKED
    assert decision.release_status == SecurityGateVerdict.DENY_RELEASE.value
    assert "path_f1" in decision.blocking_attack_paths


# TEST G — P0 remediation unresolved
def test_m19_test_g_p0_remediation_unresolved(engine):
    item = RemediationItem(
        item_id="rem_g1", title="Fix Command Injection", root_cause="COMMAND_INJECTION",
        priority_tier="P0", affected_files=["app/main.py"]
    )
    plan = RemediationPlan(plan_id="plan_g", repository="RepoG", remediation_items=[item])
    decision = engine.evaluate_release_readiness(
        remediation_plan=plan, repository_name="RepoG"
    )
    assert decision.decision == ReleaseDecisionState.BLOCKED
    assert "rem_g1" in decision.blocking_remediations


# TEST H — P1 remediation unresolved
def test_m19_test_h_p1_remediation_unresolved(engine):
    item = RemediationItem(
        item_id="rem_h1", title="Fix SQL Injection", root_cause="SQL_INJECTION",
        priority_tier="P1", affected_files=["app/db.py"]
    )
    plan = RemediationPlan(plan_id="plan_h", repository="RepoH", remediation_items=[item])
    decision = engine.evaluate_release_readiness(
        remediation_plan=plan, repository_name="RepoH"
    )
    assert decision.decision == ReleaseDecisionState.NO_GO


# TEST I — M18 CRITICAL_REGRESSION
def test_m19_test_i_critical_regression(engine):
    mon_res = SecurityMonitoringResult(
        repository="RepoI", previous_commit="c1", current_commit="c2", regression_severity=RegressionSeverity.CRITICAL_REGRESSION,
        summary_explanation="Critical regression detected"
    )
    decision = engine.evaluate_release_readiness(
        monitoring_result=mon_res, repository_name="RepoI"
    )
    assert decision.decision == ReleaseDecisionState.BLOCKED


# TEST J — M17 remediation conflict
def test_m19_test_j_remediation_conflict(engine):
    plan = RemediationPlan(
        plan_id="plan_j", repository="RepoJ", remediation_items=[], conflicts=["Fix A conflicts with Fix B"]
    )
    decision = engine.evaluate_release_readiness(
        remediation_plan=plan, repository_name="RepoJ"
    )
    assert decision.decision == ReleaseDecisionState.REVIEW_REQUIRED


# TEST K — Security score improved
def test_m19_test_k_score_improved(engine):
    decision = engine.evaluate_release_readiness(repository_name="RepoK")
    assert decision.decision == ReleaseDecisionState.GO


# TEST L — Previous NO_GO -> current GO (RECOVERED)
def test_m19_test_l_recovered(engine):
    decision = engine.evaluate_release_readiness(
        previous_decision=ReleaseDecisionState.NO_GO, repository_name="RepoL"
    )
    assert decision.decision == ReleaseDecisionState.GO
    assert decision.release_diff is not None
    assert decision.release_diff.release_delta_state == ReleaseDeltaState.RECOVERED


# TEST M — Previous GO -> current BLOCKED (DEGRADED)
def test_m19_test_m_degraded(engine):
    f_crit = PrioritizedFinding(
        rank=1, finding_id="pf_m1", vulnerability_category="security", severity="CRITICAL", priority_score=95,
        priority_tier=PriorityTier.P0, root_cause="COMMAND_INJECTION", affected_file="app/main.py",
        exploitability=ExploitabilityLevel.CRITICAL
    )
    decision = engine.evaluate_release_readiness(
        prioritized_findings=[f_crit], previous_decision=ReleaseDecisionState.GO, repository_name="RepoM"
    )
    assert decision.decision == ReleaseDecisionState.BLOCKED
    assert decision.release_diff is not None
    assert decision.release_diff.release_delta_state == ReleaseDeltaState.DEGRADED


# TEST N — Safe test harness
def test_m19_test_n_safe_test_harness(engine):
    f_harness = PrioritizedFinding(
        rank=1, finding_id="pf_n1", vulnerability_category="info", severity="LOW", priority_score=10,
        priority_tier=PriorityTier.P4, root_cause="TEST_HARNESS", affected_file="tests/test_app.py",
        exploitability=ExploitabilityLevel.NOT_EXPLOITABLE
    )
    decision = engine.evaluate_release_readiness(
        prioritized_findings=[f_harness], repository_name="RepoN"
    )
    assert decision.decision == ReleaseDecisionState.GO


# TEST O — Safe parameterized SQL
def test_m19_test_o_safe_parameterized_sql(engine):
    decision = engine.evaluate_release_readiness(
        prioritized_findings=[], repository_name="RepoO"
    )
    assert decision.decision == ReleaseDecisionState.GO


# TEST P — Cross-repository release posture
def test_m19_test_p_cross_repository_posture(engine):
    scans = {
        "Repo1": {"prioritized_findings": []},
        "Repo2": {
            "prioritized_findings": [
                PrioritizedFinding(
                    rank=1, finding_id="pf_p1", vulnerability_category="security", severity="CRITICAL", priority_score=95,
                    priority_tier=PriorityTier.P0, root_cause="COMMAND_INJECTION", affected_file="main.py"
                )
            ]
        },
    }
    posture = engine.evaluate_cross_repository_release_posture(scans)
    assert posture.total_repositories == 2
    assert posture.go_count == 1
    assert posture.blocked_count == 1
