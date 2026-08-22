"""
Dedicated M18 Synthetic Test Suite — Continuous Security Monitoring & Regression Detection.

Validates synthetic test scenarios A through N:
TEST A — No code/security change (NO_REGRESSION)
TEST B — New CRITICAL finding (CRITICAL_REGRESSION)
TEST C — New HIGH finding (SIGNIFICANT_REGRESSION)
TEST D — Finding fixed (IMPROVING)
TEST E — Finding reopened (CRITICAL_REGRESSION)
TEST F — New attack path (NEW_ATTACK_PATH + CRITICAL_REGRESSION)
TEST G — Attack path removed (IMPROVING)
TEST H — Authentication weakened (AUTHENTICATION_WEAKENED)
TEST I — Internet exposure increased (EXPOSURE_INCREASED)
TEST J — M17 remediation invalidated (REQUIRES_REPLAN)
TEST K — Security score drop (SECURITY_SCORE_DROP)
TEST L — Safe parameterized SQL change (NO_REGRESSION)
TEST M — Safe test-harness modification (NO_REGRESSION)
TEST N — Cross-repository monitoring (batch trend verification)
"""

import pytest
from agentos_swe.intelligence.models import PrioritizedFinding, PriorityTier, ExploitabilityLevel
from agentos_swe.attackpath.models import AttackPath, EntrypointType, AuthStatus, PathClassification
from agentos_swe.remediation import RemediationPlan, RemediationItem, RemediationStatus
from agentos_swe.monitoring import (
    SecurityMonitor,
    RegressionSeverity,
    TrendDirection,
    AlertCategory,
    RemediationPlanStatus,
)


from agentos_swe.monitoring.snapshot_manager import SnapshotManager


@pytest.fixture
def monitor(tmp_path):
    SnapshotManager._memory_snapshots = {}
    return SecurityMonitor(storage_dir=str(tmp_path))


# TEST A — No code/security change
def test_m18_test_a_no_change(monitor):
    scan_data = {
        "metadata": {"repo_name": "RepoA", "commit": "c1"},
        "prioritized_findings": [],
        "security_score": 100,
    }

    result = monitor.monitor_repository(current_scan=scan_data, repository_name="RepoA")

    assert result.regression_severity == RegressionSeverity.NO_REGRESSION
    assert result.score_delta == 0
    assert result.governance_verdict == "ALLOW"


# TEST B — New CRITICAL finding
def test_m18_test_b_new_critical_finding(monitor):
    prev_scan = {"metadata": {"repo_name": "RepoB", "commit": "c1"}, "prioritized_findings": [], "security_score": 100}
    f_crit = PrioritizedFinding(
        rank=1, finding_id="pf_b1", vulnerability_category="security", severity="CRITICAL", priority_score=95,
        priority_tier=PriorityTier.P0, root_cause="COMMAND_INJECTION", affected_file="app/main.py"
    )
    curr_scan = {"metadata": {"repo_name": "RepoB", "commit": "c2"}, "prioritized_findings": [f_crit], "security_score": 75}

    result = monitor.monitor_repository(current_scan=curr_scan, previous_scan=prev_scan, repository_name="RepoB")

    assert result.regression_severity == RegressionSeverity.CRITICAL_REGRESSION
    assert len(result.new_findings) == 1
    assert result.governance_verdict == "REVIEW_REQUIRED"
    assert any(a.category == AlertCategory.NEW_CRITICAL_FINDING for a in result.alerts)


# TEST C — New HIGH finding
def test_m18_test_c_new_high_finding(monitor):
    prev_scan = {"metadata": {"repo_name": "RepoC", "commit": "c1"}, "prioritized_findings": [], "security_score": 100}
    f_high = PrioritizedFinding(
        rank=1, finding_id="pf_c1", vulnerability_category="security", severity="HIGH", priority_score=80,
        priority_tier=PriorityTier.P1, root_cause="SQL_INJECTION", affected_file="app/db.py"
    )
    curr_scan = {"metadata": {"repo_name": "RepoC", "commit": "c2"}, "prioritized_findings": [f_high], "security_score": 85}

    result = monitor.monitor_repository(current_scan=curr_scan, previous_scan=prev_scan, repository_name="RepoC")

    assert result.regression_severity == RegressionSeverity.SIGNIFICANT_REGRESSION
    assert any(a.category == AlertCategory.NEW_HIGH_FINDING for a in result.alerts)


# TEST D — Finding fixed
def test_m18_test_d_finding_fixed(monitor):
    f_old = PrioritizedFinding(
        rank=1, finding_id="pf_d1", vulnerability_category="security", severity="HIGH", priority_score=80,
        priority_tier=PriorityTier.P1, root_cause="SQL_INJECTION", affected_file="app/db.py"
    )
    prev_scan = {"metadata": {"repo_name": "RepoD", "commit": "c1"}, "prioritized_findings": [f_old], "security_score": 80}
    curr_scan = {"metadata": {"repo_name": "RepoD", "commit": "c2"}, "prioritized_findings": [], "security_score": 100}

    result = monitor.monitor_repository(current_scan=curr_scan, previous_scan=prev_scan, repository_name="RepoD")

    assert result.regression_severity == RegressionSeverity.NO_REGRESSION
    assert len(result.fixed_findings) == 1
    assert result.risk_trend == TrendDirection.IMPROVING


# TEST E — Finding reopened
def test_m18_test_e_finding_reopened(monitor):
    f_reopened = PrioritizedFinding(
        rank=1, finding_id="pf_e1", vulnerability_category="security", severity="HIGH", priority_score=80,
        priority_tier=PriorityTier.P1, root_cause="COMMAND_INJECTION", affected_file="app/old.py", recurrence="REOPENED"
    )
    prev_scan = {"metadata": {"repo_name": "RepoE", "commit": "c1"}, "prioritized_findings": [], "security_score": 100}
    curr_scan = {"metadata": {"repo_name": "RepoE", "commit": "c2"}, "prioritized_findings": [f_reopened], "security_score": 80}

    result = monitor.monitor_repository(current_scan=curr_scan, previous_scan=prev_scan, repository_name="RepoE")

    assert result.regression_severity == RegressionSeverity.CRITICAL_REGRESSION
    assert len(result.reopened_findings) >= 1
    assert any(a.category == AlertCategory.REOPENED_VULNERABILITY for a in result.alerts)


# TEST F — New attack path
def test_m18_test_f_new_attack_path(monitor):
    ap1 = AttackPath(
        id="path_f1", fingerprint="fp_f1", repository="RepoF", entrypoint="POST /exec",
        entrypoint_type=EntrypointType.INTERNET, source="HTTP", source_type="HTTP", source_file="app/main.py",
        source_line=10, sink="SHELL", sink_type="SHELL", sink_file="app/main.py", sink_line=15,
        root_cause="COMMAND_INJECTION", classification=PathClassification.EXPLOITABLE, risk_score=90
    )
    prev_scan = {"metadata": {"repo_name": "RepoF", "commit": "c1"}, "attack_paths": [], "security_score": 100}
    curr_scan = {"metadata": {"repo_name": "RepoF", "commit": "c2"}, "attack_paths": [ap1], "security_score": 75}

    result = monitor.monitor_repository(current_scan=curr_scan, previous_scan=prev_scan, attack_paths=[ap1], repository_name="RepoF")

    assert result.regression_severity == RegressionSeverity.CRITICAL_REGRESSION
    assert len(result.new_attack_paths) == 1


# TEST G — Attack path removed
def test_m18_test_g_attack_path_removed(monitor):
    ap1 = AttackPath(
        id="path_g1", fingerprint="fp_g1", repository="RepoG", entrypoint="POST /exec",
        entrypoint_type=EntrypointType.INTERNET, source="HTTP", source_type="HTTP", source_file="app/main.py",
        source_line=10, sink="SHELL", sink_type="SHELL", sink_file="app/main.py", sink_line=15,
        root_cause="COMMAND_INJECTION"
    )
    prev_scan = {"metadata": {"repo_name": "RepoG", "commit": "c1"}, "attack_paths": [ap1], "security_score": 75}
    curr_scan = {"metadata": {"repo_name": "RepoG", "commit": "c2"}, "attack_paths": [], "security_score": 100}

    result = monitor.monitor_repository(current_scan=curr_scan, previous_scan=prev_scan, attack_paths=[], repository_name="RepoG")

    assert len(result.removed_attack_paths) == 1
    assert result.risk_trend == TrendDirection.IMPROVING


# TEST H — Authentication weakened
def test_m18_test_h_auth_weakened(monitor):
    prev_ap = AttackPath(id="path_h1", fingerprint="fp_h1", repository="RepoH", entrypoint="/api", entrypoint_type=EntrypointType.INTERNET, source="HTTP", source_type="HTTP", source_file="app/main.py", source_line=1, sink="SHELL", sink_type="SHELL", sink_file="app/main.py", sink_line=10, root_cause="COMMAND_INJECTION", auth_status=AuthStatus.AUTHENTICATED, risk_score=50)
    curr_ap = AttackPath(id="path_h1", fingerprint="fp_h1", repository="RepoH", entrypoint="/api", entrypoint_type=EntrypointType.INTERNET, source="HTTP", source_type="HTTP", source_file="app/main.py", source_line=1, sink="SHELL", sink_type="SHELL", sink_file="app/main.py", sink_line=10, root_cause="COMMAND_INJECTION", auth_status=AuthStatus.UNAUTHENTICATED, risk_score=85)

    prev_scan = {"metadata": {"repo_name": "RepoH", "commit": "c1"}, "attack_paths": [prev_ap], "security_score": 90}
    curr_scan = {"metadata": {"repo_name": "RepoH", "commit": "c2"}, "attack_paths": [curr_ap], "security_score": 60}

    result = monitor.monitor_repository(current_scan=curr_scan, previous_scan=prev_scan, attack_paths=[curr_ap], repository_name="RepoH")

    assert result.regression_severity == RegressionSeverity.CRITICAL_REGRESSION
    assert any(c.auth_weakened for c in result.changed_attack_paths)


# TEST I — Exposure increased
def test_m18_test_i_exposure_increased(monitor):
    prev_ap = AttackPath(id="path_i1", fingerprint="fp_i1", repository="RepoI", entrypoint="CLI", entrypoint_type=EntrypointType.INTERNAL_API, source="CLI", source_type="CLI", source_file="app/main.py", source_line=1, sink="SHELL", sink_type="SHELL", sink_file="app/main.py", sink_line=10, root_cause="COMMAND_INJECTION", risk_score=50)
    curr_ap = AttackPath(id="path_i1", fingerprint="fp_i1", repository="RepoI", entrypoint="HTTP", entrypoint_type=EntrypointType.INTERNET, source="HTTP", source_type="HTTP", source_file="app/main.py", source_line=1, sink="SHELL", sink_type="SHELL", sink_file="app/main.py", sink_line=10, root_cause="COMMAND_INJECTION", risk_score=75)

    prev_scan = {"metadata": {"repo_name": "RepoI", "commit": "c1"}, "attack_paths": [prev_ap], "security_score": 90}
    curr_scan = {"metadata": {"repo_name": "RepoI", "commit": "c2"}, "attack_paths": [curr_ap], "security_score": 75}

    result = monitor.monitor_repository(current_scan=curr_scan, previous_scan=prev_scan, attack_paths=[curr_ap], repository_name="RepoI")

    assert result.regression_severity == RegressionSeverity.SIGNIFICANT_REGRESSION
    assert any(c.exposure_increased for c in result.changed_attack_paths)


# TEST J — M17 remediation invalidated
def test_m18_test_j_remediation_invalidated(monitor):
    item = RemediationItem(item_id="rem_j1", title="Fix J", root_cause="COMMAND_INJECTION", affected_files=["app/main.py"])
    plan = RemediationPlan(plan_id="plan_j", repository="RepoJ", remediation_items=[item])

    f_new = PrioritizedFinding(rank=1, finding_id="pf_j1", vulnerability_category="security", severity="MEDIUM", priority_score=60, priority_tier=PriorityTier.P2, root_cause="COMMAND_INJECTION", affected_file="app/main.py")

    prev_scan = {"metadata": {"repo_name": "RepoJ", "commit": "c1"}, "prioritized_findings": [], "security_score": 100}
    curr_scan = {"metadata": {"repo_name": "RepoJ", "commit": "c2"}, "prioritized_findings": [f_new], "security_score": 90}

    result = monitor.monitor_repository(current_scan=curr_scan, previous_scan=prev_scan, remediation_plan=plan, repository_name="RepoJ")

    assert result.remediation_impact is not None
    assert result.remediation_impact.status == RemediationPlanStatus.REQUIRES_REPLAN


# TEST K — Security score drop
def test_m18_test_k_security_score_drop(monitor):
    prev_scan = {"metadata": {"repo_name": "RepoK", "commit": "c1"}, "security_score": 95}
    curr_scan = {"metadata": {"repo_name": "RepoK", "commit": "c2"}, "security_score": 70}

    result = monitor.monitor_repository(current_scan=curr_scan, previous_scan=prev_scan, repository_name="RepoK")

    assert result.score_delta == -25
    assert result.regression_severity == RegressionSeverity.CRITICAL_REGRESSION


# TEST L — Safe parameterized SQL change
def test_m18_test_l_safe_parameterized_sql(monitor):
    prev_scan = {"metadata": {"repo_name": "RepoL", "commit": "c1"}, "prioritized_findings": [], "security_score": 100}
    curr_scan = {"metadata": {"repo_name": "RepoL", "commit": "c2"}, "prioritized_findings": [], "security_score": 100}

    result = monitor.monitor_repository(current_scan=curr_scan, previous_scan=prev_scan, repository_name="RepoL")

    assert result.regression_severity == RegressionSeverity.NO_REGRESSION


# TEST M — Safe test-harness modification
def test_m18_test_m_safe_test_harness(monitor):
    f_harness = PrioritizedFinding(rank=1, finding_id="pf_m1", vulnerability_category="info", severity="LOW", priority_score=10, priority_tier=PriorityTier.P4, root_cause="TEST_HARNESS", affected_file="tests/test_app.py", exploitability=ExploitabilityLevel.NOT_EXPLOITABLE)
    prev_scan = {"metadata": {"repo_name": "RepoM", "commit": "c1"}, "prioritized_findings": [], "security_score": 100}
    curr_scan = {"metadata": {"repo_name": "RepoM", "commit": "c2"}, "prioritized_findings": [f_harness], "security_score": 100}

    result = monitor.monitor_repository(current_scan=curr_scan, previous_scan=prev_scan, repository_name="RepoM")

    assert result.regression_severity == RegressionSeverity.NO_REGRESSION


# TEST N — Cross-repository monitoring
def test_m18_test_n_cross_repository_monitoring(monitor):
    scans = {
        "Repo1": {"metadata": {"repo_name": "Repo1", "commit": "c1"}, "security_score": 100},
        "Repo2": {"metadata": {"repo_name": "Repo2", "commit": "c2"}, "security_score": 60},
    }

    res = monitor.monitor_cross_repository(scans)

    assert res.total_repositories == 2
    assert "Repo1" in res.repository_results
    assert "Repo2" in res.repository_results
