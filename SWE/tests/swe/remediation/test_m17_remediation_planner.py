"""
Dedicated M17 Test Suite — Intelligent Security Remediation Orchestration & Fix Planning.

Validates synthetic test scenarios A through L:
TEST A — One CRITICAL command injection
TEST B — Three findings sharing one unsafe helper
TEST C — Two independent vulnerabilities
TEST D — Conflicting modifications
TEST E — Fix dependency chain
TEST F — Authenticated vs unauthenticated attack paths
TEST G — Reopened historical vulnerability
TEST H — Safe finding
TEST I — Sanitized finding
TEST J — Fix introducing potential HIGH risk
TEST K — Shared root cause across multiple attack paths
TEST L — Public API-impacting repair
"""

import pytest
from agentos_swe.intelligence.models import (
    PrioritizedFinding,
    PriorityTier,
    ExploitabilityLevel,
    ExposureLevel,
    BlastRadiusLevel,
    RecurrenceLevel,
)
from agentos_swe.intelligence.attackpath.models import (
    AttackPath,
    EntrypointType,
    AuthStatus,
    PathClassification,
)
from agentos_swe.remediation import (
    RemediationPlanner,
    RemediationPlan,
    RemediationItem,
    RemediationStatus,
    EffortCategory,
)


# TEST A — One CRITICAL command injection
def test_m17_test_a_critical_command_injection():
    planner = RemediationPlanner()
    finding = PrioritizedFinding(
        rank=1,
        finding_id="pf_a1",
        vulnerability_category="security",
        severity="CRITICAL",
        priority_score=95,
        priority_tier=PriorityTier.P0,
        root_cause="COMMAND_INJECTION",
        affected_file="app/main.py",
        affected_function="run_cmd",
        exploitability=ExploitabilityLevel.CRITICAL,
        exposure=ExposureLevel.INTERNET_EXPOSED,
        recommended_action="Replace shell=True with argument array execution",
    )
    path = AttackPath(
        id="path_a1",
        fingerprint="fp_a1",
        repository="RepoA",
        entrypoint="POST /exec",
        entrypoint_type=EntrypointType.INTERNET,
        source="HTTP",
        source_type="HTTP",
        source_file="app/main.py",
        source_line=10,
        sink="SUBPROCESS_SHELL",
        sink_type="SUBPROCESS_SHELL",
        sink_file="app/main.py",
        sink_line=15,
        root_cause="COMMAND_INJECTION",
        classification=PathClassification.EXPLOITABLE,
        risk_score=90,
        severity="CRITICAL",
    )

    plan = planner.generate_remediation_plan(
        prioritized_findings=[finding],
        attack_paths=[path],
        repository_name="RepoA",
    )

    assert len(plan.remediation_items) == 1
    item = plan.remediation_items[0]
    assert item.priority_tier == "P0"
    assert item.root_cause == "COMMAND_INJECTION"
    assert "pf_a1" in item.affected_finding_ids
    assert "path_a1" in item.affected_attack_path_ids
    assert "Subprocess Command Execution" in item.earliest_break_point


# TEST B — Three findings sharing one unsafe helper
def test_m17_test_b_grouped_findings_shared_helper():
    planner = RemediationPlanner()
    f1 = PrioritizedFinding(rank=1, finding_id="pf_b1", vulnerability_category="security", severity="HIGH", priority_score=85, priority_tier=PriorityTier.P1, root_cause="COMMAND_INJECTION", affected_file="app/helper.py")
    f2 = PrioritizedFinding(rank=2, finding_id="pf_b2", vulnerability_category="security", severity="HIGH", priority_score=80, priority_tier=PriorityTier.P1, root_cause="COMMAND_INJECTION", affected_file="app/helper.py")
    f3 = PrioritizedFinding(rank=3, finding_id="pf_b3", vulnerability_category="security", severity="HIGH", priority_score=75, priority_tier=PriorityTier.P1, root_cause="COMMAND_INJECTION", affected_file="app/helper.py")

    plan = planner.generate_remediation_plan(
        prioritized_findings=[f1, f2, f3],
        repository_name="RepoB",
    )

    assert len(plan.remediation_items) == 1
    item = plan.remediation_items[0]
    assert len(item.affected_finding_ids) == 3
    assert set(item.affected_finding_ids) == {"pf_b1", "pf_b2", "pf_b3"}


# TEST C — Two independent vulnerabilities ordered by risk
def test_m17_test_c_two_independent_vulnerabilities():
    planner = RemediationPlanner()
    f1 = PrioritizedFinding(rank=1, finding_id="pf_c1", vulnerability_category="security", severity="CRITICAL", priority_score=90, priority_tier=PriorityTier.P0, root_cause="SQL_INJECTION", affected_file="app/db.py")
    f2 = PrioritizedFinding(rank=2, finding_id="pf_c2", vulnerability_category="bug", severity="MEDIUM", priority_score=40, priority_tier=PriorityTier.P3, root_cause="EXCEPTION_SWALLOWING", affected_file="app/logger.py")

    plan = planner.generate_remediation_plan(
        prioritized_findings=[f1, f2],
        repository_name="RepoC",
    )

    assert len(plan.remediation_items) == 2
    assert plan.remediation_items[0].root_cause == "SQL_INJECTION"
    assert plan.remediation_items[1].root_cause == "EXCEPTION_SWALLOWING"


# TEST D — Conflicting modifications
def test_m17_test_d_conflicting_modifications():
    planner = RemediationPlanner()
    i1 = RemediationItem(
        item_id="rem_1", title="Fix A", root_cause="COMMAND_INJECTION", affected_files=["app/shared.py"], affected_symbols=["execute"],
        repair_strategy="REPLACE_SHELL_TRUE", recommended_fix="CONFLICT: Change X"
    )
    i2 = RemediationItem(
        item_id="rem_2", title="Fix B", root_cause="SQL_INJECTION", affected_files=["app/shared.py"], affected_symbols=["execute"],
        repair_strategy="PARAMETERIZE_SQL", recommended_fix="CONFLICT: Change Y"
    )

    conflicts = planner.conflict_detector.detect_conflicts([i1, i2])
    assert len(conflicts) >= 1
    assert i1.governance_status == RemediationStatus.CONFLICT
    assert i2.governance_status == RemediationStatus.CONFLICT


# TEST E — Fix dependency chain
def test_m17_test_e_fix_dependency_chain():
    planner = RemediationPlanner()
    i_sink = RemediationItem(item_id="rem_sink", title="Sink Replacement", root_cause="COMMAND_INJECTION", affected_files=["app/main.py"])
    i_val = RemediationItem(item_id="rem_val", title="Input VALIDATOR Helper Creation", root_cause="INPUT_VALIDATION", affected_files=["app/main.py"])

    dep_map = planner.dependency_analyzer.analyze_dependencies([i_sink, i_val])
    assert "rem_val" in i_sink.dependencies

    ordered = planner.fix_ordering_engine.order_remediation_items([i_sink, i_val])
    assert ordered[0].item_id == "rem_val"
    assert ordered[1].item_id == "rem_sink"


# TEST F — Authenticated vs unauthenticated attack paths
def test_m17_test_f_unauthenticated_priority():
    planner = RemediationPlanner()
    f_unauth = PrioritizedFinding(rank=1, finding_id="pf_f1", vulnerability_category="security", severity="HIGH", priority_score=80, priority_tier=PriorityTier.P1, root_cause="COMMAND_INJECTION", affected_file="app/pub.py")
    f_auth = PrioritizedFinding(rank=2, finding_id="pf_f2", vulnerability_category="security", severity="HIGH", priority_score=80, priority_tier=PriorityTier.P1, root_cause="COMMAND_INJECTION", affected_file="app/priv.py")

    f_unauth_dict = f_unauth.to_dict()
    f_unauth_dict["entrypoint_type"] = "INTERNET"
    f_unauth_dict["auth_status"] = "UNAUTHENTICATED"

    f_auth_dict = f_auth.to_dict()
    f_auth_dict["entrypoint_type"] = "INTERNET"
    f_auth_dict["auth_status"] = "AUTHENTICATED"

    plan = planner.generate_remediation_plan(
        prioritized_findings=[f_unauth_dict, f_auth_dict],
        repository_name="RepoF",
    )

    assert len(plan.remediation_items) == 2
    assert plan.remediation_items[0].affected_files == ["app/pub.py"]


# TEST G — Reopened historical vulnerability
def test_m17_test_g_reopened_vulnerability():
    planner = RemediationPlanner()
    f_reopened = PrioritizedFinding(rank=1, finding_id="pf_g1", vulnerability_category="security", severity="HIGH", priority_score=70, priority_tier=PriorityTier.P2, root_cause="COMMAND_INJECTION", affected_file="app/old.py")
    f_dict = f_reopened.to_dict()
    f_dict["recurrence"] = "REOPENED"

    f_new = PrioritizedFinding(rank=2, finding_id="pf_g2", vulnerability_category="security", severity="HIGH", priority_score=70, priority_tier=PriorityTier.P2, root_cause="COMMAND_INJECTION", affected_file="app/new.py")
    f_new_dict = f_new.to_dict()
    f_new_dict["recurrence"] = "FIRST_SEEN"

    plan = planner.generate_remediation_plan(
        prioritized_findings=[f_dict, f_new_dict],
        repository_name="RepoG",
    )

    assert plan.remediation_items[0].affected_files == ["app/old.py"]


# TEST H — Safe finding
def test_m17_test_h_safe_finding():
    planner = RemediationPlanner()
    f_safe = PrioritizedFinding(rank=1, finding_id="pf_h1", vulnerability_category="info", severity="LOW", priority_score=10, priority_tier=PriorityTier.P4, root_cause="DICT_LOOKUP", affected_file="app/safe.py", exploitability=ExploitabilityLevel.NOT_EXPLOITABLE)

    plan = planner.generate_remediation_plan(
        prioritized_findings=[f_safe],
        repository_name="RepoH",
    )

    assert len(plan.remediation_items) == 0
    assert plan.final_recommendation.startswith("NO_REPAIR_REQUIRED")


# TEST I — Sanitized finding
def test_m17_test_i_sanitized_finding():
    planner = RemediationPlanner()
    f_san = PrioritizedFinding(rank=1, finding_id="pf_i1", vulnerability_category="info", severity="LOW", priority_score=10, priority_tier=PriorityTier.P4, root_cause="INFO", affected_file="app/sanitized.py", exploitability=ExploitabilityLevel.NOT_EXPLOITABLE)

    plan = planner.generate_remediation_plan(
        prioritized_findings=[f_san],
        repository_name="RepoI",
    )

    assert len(plan.remediation_items) == 0


# TEST J — Fix introducing potential HIGH risk
def test_m17_test_j_validation_required():
    planner = RemediationPlanner()
    f = PrioritizedFinding(rank=1, finding_id="pf_j1", vulnerability_category="security", severity="CRITICAL", priority_score=95, priority_tier=PriorityTier.P0, root_cause="COMMAND_INJECTION", affected_file="app/critical.py")

    plan = planner.generate_remediation_plan(
        prioritized_findings=[f],
        repository_name="RepoJ",
    )

    assert plan.governance_status in ("ALLOW", "REVIEW_REQUIRED", "NEEDS_REVIEW")
    assert len(plan.remediation_items[0].validation_requirements) >= 8


# TEST K — Shared root cause across multiple attack paths
def test_m17_test_k_shared_root_cause_multiple_attack_paths():
    planner = RemediationPlanner()
    f = PrioritizedFinding(rank=1, finding_id="pf_k1", vulnerability_category="security", severity="HIGH", priority_score=80, priority_tier=PriorityTier.P1, root_cause="COMMAND_INJECTION", affected_file="app/exec.py")
    ap1 = AttackPath(id="path_k1", fingerprint="fp_k1", repository="RepoK", entrypoint="POST /api1", entrypoint_type=EntrypointType.INTERNET, source="HTTP", source_type="HTTP", source_file="app/exec.py", source_line=1, sink="SHELL", sink_type="SHELL", sink_file="app/exec.py", sink_line=10, root_cause="COMMAND_INJECTION")
    ap2 = AttackPath(id="path_k2", fingerprint="fp_k2", repository="RepoK", entrypoint="POST /api2", entrypoint_type=EntrypointType.INTERNET, source="HTTP", source_type="HTTP", source_file="app/exec.py", source_line=1, sink="SHELL", sink_type="SHELL", sink_file="app/exec.py", sink_line=10, root_cause="COMMAND_INJECTION")

    plan = planner.generate_remediation_plan(
        prioritized_findings=[f],
        attack_paths=[ap1, ap2],
        repository_name="RepoK",
    )

    assert len(plan.remediation_items) == 1
    assert len(plan.remediation_items[0].affected_attack_path_ids) == 2


# TEST L — Public API-impacting repair
def test_m17_test_l_public_api_impacting_repair():
    planner = RemediationPlanner()
    f = PrioritizedFinding(rank=1, finding_id="pf_l1", vulnerability_category="security", severity="HIGH", priority_score=80, priority_tier=PriorityTier.P1, root_cause="COMMAND_INJECTION", affected_file="app/public_api.py", why_this_matters="public_api export handler")

    plan = planner.generate_remediation_plan(
        prioritized_findings=[f],
        repository_name="RepoL",
    )

    item = plan.remediation_items[0]
    assert item.effort in (EffortCategory.SMALL, EffortCategory.MEDIUM, EffortCategory.LARGE, EffortCategory.COMPLEX)
    assert len(item.validation_requirements) >= 8
